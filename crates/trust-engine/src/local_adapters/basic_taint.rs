use crate::traits::{EngineError, TaintAndLineageEngine, TaintDecision};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use trust_sdk::manifest::{DataOriginTrust, SkillManifest};

pub struct BasicBinaryTaintTracker {
    trace_taint: Arc<RwLock<HashMap<String, DataOriginTrust>>>,
}

impl Default for BasicBinaryTaintTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl BasicBinaryTaintTracker {
    pub fn new() -> Self {
        Self {
            trace_taint: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl TaintAndLineageEngine for BasicBinaryTaintTracker {
    async fn record_tool_output(
        &self,
        tenant_id: &str,
        trace_id: &str,
        skill: &SkillManifest,
        _output: &serde_json::Value,
    ) -> Result<(), EngineError> {
        let key = format!("{}_{}", tenant_id, trace_id);
        let mut lock = self.trace_taint.write().await;
        let current = lock.entry(key).or_insert(DataOriginTrust::TrustedInternal);

        // Monotonic high-water mark: max(current, skill.data_origin_trust)
        if skill.data_origin_trust > *current {
            *current = skill.data_origin_trust;
        }
        Ok(())
    }

    async fn evaluate_taint_and_lineage(
        &self,
        tenant_id: &str,
        trace_id: &str,
        target: &SkillManifest,
        _canonical_args: &serde_json::Value,
    ) -> Result<TaintDecision, EngineError> {
        let key = format!("{}_{}", tenant_id, trace_id);
        let lock = self.trace_taint.read().await;
        let current_taint = lock
            .get(&key)
            .copied()
            .unwrap_or(DataOriginTrust::TrustedInternal);

        if current_taint == DataOriginTrust::UntrustedExternal {
            let op_kind = target.policy_defaults.operation_kind.to_lowercase();
            let risk = target.policy_defaults.default_risk_level.to_lowercase();
            let is_mutation = op_kind != "read" || risk == "high";

            if is_mutation {
                if !target.lineage_rules.is_empty() {
                    tracing::info!(
                        "Skill '{}' defines lineage rules, but cryptographic argument lineage requires Pro edition. Downgrading to human approval.",
                        target.id
                    );
                }
                return Ok(TaintDecision::DowngradeToHumanApproval {
                    reason: "taint_escalation_untrusted_context".to_string(),
                });
            }
        }

        Ok(TaintDecision::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_sdk::manifest::*;

    fn dummy_skill(origin: DataOriginTrust, op_kind: &str) -> SkillManifest {
        SkillManifest {
            schema_version: "lianxi.skill/v1".to_string(),
            id: "io.lianxi.skill.dummy@v1".to_string(),
            name: "dummy".to_string(),
            version: "1.0.0".to_string(),
            description: "desc".to_string(),
            author_did: "did:web:test".to_string(),
            data_origin_trust: origin,
            lineage_rules: vec![],
            execution: ExecutionSpec {
                runtime: RuntimeType::NativeTool,
                entrypoint: "run.sh".to_string(),
                timeout_secs: 10,
                memory_limit_mb: 256,
                allowed_interpreters: vec!["bash".to_string()],
            },
            input_schema: serde_json::json!({}),
            policy_defaults: PolicyDefaults {
                default_tier: "tier0_auto".to_string(),
                max_frequency_per_trace: 5,
                default_risk_level: "low".to_string(),
                operation_kind: op_kind.to_string(),
            },
            egress: EgressClassification {
                contains_pii: false,
                max_payload_bytes: 65536,
                allowed_fields: vec![],
            },
        }
    }

    #[tokio::test]
    async fn test_basic_taint_downgrade() {
        let tracker = BasicBinaryTaintTracker::new();
        let untrusted = dummy_skill(DataOriginTrust::UntrustedExternal, "read");
        let mutation = dummy_skill(DataOriginTrust::TrustedInternal, "write");

        // Before taint: mutation is allowed
        let dec1 = tracker
            .evaluate_taint_and_lineage("default", "tr_1", &mutation, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(dec1, TaintDecision::Allow);

        // Record output from untrusted tool
        tracker
            .record_tool_output(
                "default",
                "tr_1",
                &untrusted,
                &serde_json::json!({"data": "external"}),
            )
            .await
            .unwrap();

        // After taint: mutation is downgraded to human approval
        let dec2 = tracker
            .evaluate_taint_and_lineage("default", "tr_1", &mutation, &serde_json::json!({}))
            .await
            .unwrap();
        assert!(matches!(
            dec2,
            TaintDecision::DowngradeToHumanApproval { .. }
        ));
    }
}
