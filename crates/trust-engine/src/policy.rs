use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use trust_sdk::manifest::SkillManifest;
use trust_sdk::model::{AuthLevel, PolicyDecision, ProposedAction, Tier};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Failed to parse policy TOML: {0}")]
    ParseError(String),
    #[error("Policy signature invalid: {0}")]
    InvalidSignature(String),
}

#[derive(Debug, Deserialize, Clone)]
pub struct GovernanceConfig {
    pub policy_version: String,
    #[serde(default)]
    pub default_action: Option<String>,
    #[serde(default)]
    pub triage_agent_url: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PolicyRule {
    pub name: String,
    #[serde(default)]
    pub tool_names: Option<Vec<String>>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub min_amount_cents: Option<u64>,
    #[serde(default)]
    pub min_auth_level: Option<u8>,
    pub action: String,
    #[serde(default)]
    pub priority: i32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PolicyConfig {
    pub governance: GovernanceConfig,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

pub struct PolicyEngine {
    config: PolicyConfig,
    fingerprint: String,
}

impl PolicyEngine {
    pub fn from_toml(toml_str: &str) -> Result<Self, PolicyError> {
        let config: PolicyConfig =
            toml::from_str(toml_str).map_err(|e| PolicyError::ParseError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(toml_str.as_bytes());
        let fingerprint = format!("{:x}", hasher.finalize());

        Ok(Self {
            config,
            fingerprint,
        })
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn triage_agent_url(&self) -> Option<&str> {
        self.config.governance.triage_agent_url.as_deref()
    }

    pub fn verify_signature(
        toml_str: &str,
        sig_hex: &str,
        verifying_key: &VerifyingKey,
    ) -> Result<(), PolicyError> {
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| PolicyError::InvalidSignature(format!("Hex decode failed: {e}")))?;

        if sig_bytes.len() != 64 {
            return Err(PolicyError::InvalidSignature(
                "Signature must be exactly 64 bytes".to_string(),
            ));
        }

        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| PolicyError::InvalidSignature(e.to_string()))?;

        verifying_key
            .verify(toml_str.as_bytes(), &signature)
            .map_err(|_| PolicyError::InvalidSignature("Signature check failed".to_string()))
    }

    pub fn evaluate(&self, action: &ProposedAction, skill: &SkillManifest) -> PolicyDecision {
        self.evaluate_with_auth_level(action, skill, AuthLevel::Level3Session)
    }

    pub fn evaluate_with_auth_level(
        &self,
        action: &ProposedAction,
        skill: &SkillManifest,
        caller_auth_level: AuthLevel,
    ) -> PolicyDecision {
        // Sort rules by priority descending (higher number evaluated first)
        let mut sorted_rules = self.config.rules.clone();
        sorted_rules.sort_by_key(|a| std::cmp::Reverse(a.priority));

        let op_kind = skill.policy_defaults.operation_kind.to_lowercase();
        let extracted_amount = extract_amount_cents(&action.arguments);

        for rule in &sorted_rules {
            // Check tool_names
            if let Some(ref names) = rule.tool_names {
                if !names
                    .iter()
                    .any(|n| n == &action.tool_name || n == &skill.id)
                {
                    continue;
                }
            }

            // Check operation_kind
            if let Some(ref kind) = rule.operation_kind {
                if !kind.eq_ignore_ascii_case(&op_kind) {
                    continue;
                }
            }

            // Check min_amount_cents
            if let Some(threshold) = rule.min_amount_cents {
                if extracted_amount < threshold {
                    continue;
                }
            }

            // Match found! Check min_auth_level requirement
            if let Some(min_level) = rule.min_auth_level {
                if (caller_auth_level as u8) < min_level {
                    return PolicyDecision {
                        action_id: action.action_id.clone(),
                        tier: Tier::Tier1RequireHumanApproval,
                        policy_fingerprint: self.fingerprint.clone(),
                        reason: format!(
                            "Matched policy rule '{}' requires min_auth_level = {}, caller has {:?}",
                            rule.name, min_level, caller_auth_level
                        ),
                        matched_rule: Some(rule.name.clone()),
                        is_unmatched: false,
                    };
                }
            }

            let tier = match rule.action.to_lowercase().as_str() {
                "allow" => Tier::Tier0Auto,
                "require_approval" => Tier::Tier1RequireHumanApproval,
                "require_elevated" => Tier::Tier2RequireElevatedApproval,
                "deny" => Tier::Tier3Deny,
                _ => Tier::Tier3Deny,
            };

            return PolicyDecision {
                action_id: action.action_id.clone(),
                tier,
                policy_fingerprint: self.fingerprint.clone(),
                reason: format!(
                    "Matched policy rule '{}' (priority {})",
                    rule.name, rule.priority
                ),
                matched_rule: Some(rule.name.clone()),
                is_unmatched: false,
            };
        }

        // Zero rules matched!
        // Fallback: check configured default_action or default to Tier1RequireHumanApproval (Manual Escalation)!
        let default_tier = match self
            .config
            .governance
            .default_action
            .as_deref()
            .unwrap_or("require_approval")
            .to_lowercase()
            .as_str()
        {
            "tier0_auto" | "tier0" | "auto" | "allow" => Tier::Tier0Auto,
            "tier1_human" | "tier1" | "require_approval" | "escalate" => Tier::Tier1RequireHumanApproval,
            "tier2_elevated" | "tier2" => Tier::Tier2RequireElevatedApproval,
            "deny" => Tier::Tier3Deny,
            _ => Tier::Tier1RequireHumanApproval, // Safe default fallback to manual escalation!
        };

        PolicyDecision {
            action_id: action.action_id.clone(),
            tier: default_tier,
            policy_fingerprint: self.fingerprint.clone(),
            reason: "Unmatched action: No policy rule triggered; default escalation applied".to_string(),
            matched_rule: None,
            is_unmatched: true,
        }
    }
}

pub fn extract_amount_cents(args: &serde_json::Value) -> u64 {
    if let serde_json::Value::Object(map) = args {
        for key in &["amount_cents", "amount", "price", "cost", "total", "value"] {
            if let Some(val) = map.get(*key) {
                if let Some(n) = val.as_u64() {
                    if *key == "amount"
                        || *key == "price"
                        || *key == "cost"
                        || *key == "total"
                        || *key == "value"
                    {
                        return n * 100; // Assume major currency units -> cents
                    }
                    return n;
                }
                if let Some(f) = val.as_f64() {
                    return (f * 100.0) as u64;
                }
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_sdk::manifest::*;

    fn dummy_skill(op_kind: &str) -> SkillManifest {
        SkillManifest {
            schema_version: "lianxi.skill/v1".to_string(),
            id: "io.lianxi.skill.test@v1".to_string(),
            name: "test_tool".to_string(),
            version: "1.0.0".to_string(),
            description: "desc".to_string(),
            author_did: "did:web:lianxi.io".to_string(),
            data_origin_trust: DataOriginTrust::TrustedInternal,
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
                max_frequency_per_trace: 3,
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

    #[test]
    fn test_policy_min_auth_level_step_up() {
        let toml_content = r#"
[governance]
policy_version = "1.0.0"

[[rules]]
name = "High value payout requires WebAuthn"
tool_names = ["test_tool"]
min_auth_level = 5
action = "allow"
priority = 100
"#;

        let engine = PolicyEngine::from_toml(toml_content).unwrap();
        let action = ProposedAction {
            action_id: "act_1".to_string(),
            tool_name: "test_tool".to_string(),
            arguments: serde_json::json!({}),
            ..Default::default()
        };
        let skill = dummy_skill("write");

        // Caller with Session level 3 -> requires approval step-up
        let decision_session =
            engine.evaluate_with_auth_level(&action, &skill, AuthLevel::Level3Session);
        assert_eq!(decision_session.tier, Tier::Tier1RequireHumanApproval);
        assert!(decision_session.reason.contains("min_auth_level = 5"));

        // Caller with WebAuthn level 5 -> allowed
        let decision_webauthn =
            engine.evaluate_with_auth_level(&action, &skill, AuthLevel::Level5WebAuthn);
        assert_eq!(decision_webauthn.tier, Tier::Tier0Auto);
        assert!(!decision_webauthn.is_unmatched);
        assert_eq!(decision_webauthn.matched_rule, Some("High value payout requires WebAuthn".to_string()));
    }

    #[test]
    fn test_unmatched_action_falls_back_to_manual_escalation() {
        let toml_content = r#"
[governance]
policy_version = "1.0.0"
default_action = "require_approval"
triage_agent_url = "http://127.0.0.1:4015"

[[rules]]
name = "Allow known safe tool"
tool_names = ["safe_tool"]
action = "allow"
priority = 10
"#;

        let engine = PolicyEngine::from_toml(toml_content).unwrap();
        assert_eq!(engine.triage_agent_url(), Some("http://127.0.0.1:4015"));

        // Novel tool that matches ZERO rules
        let novel_action = ProposedAction {
            action_id: "act_novel".to_string(),
            tool_name: "novel_unmapped_tool".to_string(),
            arguments: serde_json::json!({}),
            ..Default::default()
        };
        let skill = dummy_skill("custom");

        let decision = engine.evaluate_with_auth_level(&novel_action, &skill, AuthLevel::Level3Session);
        assert!(decision.is_unmatched);
        assert_eq!(decision.matched_rule, None);
        assert_eq!(decision.tier, Tier::Tier1RequireHumanApproval);
        assert!(decision.reason.contains("default escalation applied"));
    }
}

