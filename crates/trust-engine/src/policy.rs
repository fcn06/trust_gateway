use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::RwLock;
use thiserror::Error;
use trust_sdk::manifest::SkillManifest;
use trust_sdk::model::{AuthLevel, PolicyDecision, ProposedAction, Tier};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Failed to parse policy TOML: {0}")]
    ParseError(String),
    #[error("Policy signature invalid: {0}")]
    InvalidSignature(String),
    #[error("Policy lock or persistence error: {0}")]
    PersistenceError(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GovernanceConfig {
    pub policy_version: String,
    #[serde(default)]
    pub default_action: Option<String>,
    #[serde(default)]
    pub triage_agent_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
    // Probationary Lifecycle & Guardrail Extensions
    #[serde(default)]
    pub lifecycle_state: Option<String>,
    #[serde(default)]
    pub probation_target: Option<u32>,
    #[serde(default)]
    pub confirmations_count: Option<u32>,
    #[serde(default)]
    pub required_approver_quorum: Option<u32>,
    #[serde(default)]
    pub projected_fields: Option<Vec<String>>,
    #[serde(default)]
    pub escalation_role: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyConfig {
    pub governance: GovernanceConfig,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone)]
struct PolicyLiveState {
    config: PolicyConfig,
    fingerprint: String,
}

pub struct PolicyEngine {
    state: RwLock<PolicyLiveState>,
    file_path: Option<PathBuf>,
}

impl PolicyEngine {
    fn validate_rules_invariants(rules: &[PolicyRule]) -> Result<(), PolicyError> {
        // PEP-Level Invariant: A rule in Draft or Probationary cannot grant direct bypass ('allow')
        for rule in rules {
            if let Some(ref state) = rule.lifecycle_state {
                let s = state.to_lowercase();
                if (s == "probationary" || s == "draft")
                    && rule.action.eq_ignore_ascii_case("allow")
                {
                    return Err(PolicyError::ParseError(format!(
                        "Security Invariant Violation in rule '{}': Rules with lifecycle_state = '{}' cannot grant direct bypass ('allow'). Must require approval.",
                        rule.name, state
                    )));
                }
            }
        }
        Ok(())
    }

    fn compute_config_fingerprint(config: &PolicyConfig) -> String {
        let serialized = toml::to_string(config).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn from_toml(toml_str: &str) -> Result<Self, PolicyError> {
        let config: PolicyConfig =
            toml::from_str(toml_str).map_err(|e| PolicyError::ParseError(e.to_string()))?;

        Self::validate_rules_invariants(&config.rules)?;

        let mut hasher = Sha256::new();
        hasher.update(toml_str.as_bytes());
        let fingerprint = format!("{:x}", hasher.finalize());

        Ok(Self {
            state: RwLock::new(PolicyLiveState {
                config,
                fingerprint,
            }),
            file_path: None,
        })
    }

    pub fn with_file_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    pub fn fingerprint(&self) -> String {
        match self.state.read() {
            Ok(g) => g.fingerprint.clone(),
            Err(p) => p.into_inner().fingerprint.clone(),
        }
    }

    pub fn config(&self) -> PolicyConfig {
        match self.state.read() {
            Ok(g) => g.config.clone(),
            Err(p) => p.into_inner().config.clone(),
        }
    }

    pub fn rules(&self) -> Vec<PolicyRule> {
        match self.state.read() {
            Ok(g) => g.config.rules.clone(),
            Err(p) => p.into_inner().config.rules.clone(),
        }
    }

    pub fn triage_agent_url(&self) -> Option<String> {
        match self.state.read() {
            Ok(g) => g.config.governance.triage_agent_url.clone(),
            Err(p) => p.into_inner().config.governance.triage_agent_url.clone(),
        }
    }

    /// Hot-reloads or inserts a policy rule in-memory (and optionally persists to disk),
    /// enforcing the PEP never-bypass invariant and recomputing the SHA-256 policy fingerprint.
    pub fn upsert_rule(&self, rule: PolicyRule) -> Result<String, PolicyError> {
        Self::validate_rules_invariants(std::slice::from_ref(&rule))?;

        let mut guard = self
            .state
            .write()
            .map_err(|e| PolicyError::PersistenceError(e.to_string()))?;

        if let Some(existing) = guard.config.rules.iter_mut().find(|r| r.name == rule.name) {
            *existing = rule;
        } else {
            guard.config.rules.push(rule);
        }

        Self::validate_rules_invariants(&guard.config.rules)?;
        guard.fingerprint = Self::compute_config_fingerprint(&guard.config);
        let new_fp = guard.fingerprint.clone();

        if let Some(ref path) = self.file_path {
            if let Ok(toml_out) = toml::to_string_pretty(&guard.config) {
                let _ = std::fs::write(path, toml_out);
            }
        }

        Ok(new_fp)
    }

    /// Immediately transitions a rule to `quarantined` (`action = "deny"`) upon a security or human rejection tripwire.
    pub fn quarantine_rule(
        &self,
        rule_name: &str,
        tool_names: Option<Vec<String>>,
    ) -> Result<String, PolicyError> {
        let mut guard = self
            .state
            .write()
            .map_err(|e| PolicyError::PersistenceError(e.to_string()))?;

        if let Some(existing) = guard.config.rules.iter_mut().find(|r| r.name == rule_name) {
            existing.lifecycle_state = Some("quarantined".to_string());
            existing.action = "deny".to_string();
        } else {
            guard.config.rules.push(PolicyRule {
                name: rule_name.to_string(),
                tool_names,
                operation_kind: None,
                min_amount_cents: None,
                min_auth_level: Some(3),
                action: "deny".to_string(),
                priority: 18,
                lifecycle_state: Some("quarantined".to_string()),
                probation_target: Some(5),
                confirmations_count: Some(0),
                required_approver_quorum: Some(2),
                projected_fields: None,
                escalation_role: Some("security_reviewer".to_string()),
            });
        }

        guard.fingerprint = Self::compute_config_fingerprint(&guard.config);
        let new_fp = guard.fingerprint.clone();

        if let Some(ref path) = self.file_path {
            if let Ok(toml_out) = toml::to_string_pretty(&guard.config) {
                let _ = std::fs::write(path, toml_out);
            }
        }

        Ok(new_fp)
    }

    /// Graduates a probationary rule to `graduated` (`action = "allow"`) once quorum and confirmation targets are satisfied.
    pub fn graduate_rule(
        &self,
        rule_name: &str,
        confirmations_count: u32,
    ) -> Result<String, PolicyError> {
        let mut guard = self
            .state
            .write()
            .map_err(|e| PolicyError::PersistenceError(e.to_string()))?;

        let existing = guard
            .config
            .rules
            .iter_mut()
            .find(|r| r.name == rule_name)
            .ok_or_else(|| {
                PolicyError::ParseError(format!("Rule '{rule_name}' not found for graduation"))
            })?;

        existing.lifecycle_state = Some("graduated".to_string());
        existing.action = "allow".to_string();
        existing.confirmations_count = Some(confirmations_count);

        Self::validate_rules_invariants(&guard.config.rules)?;
        guard.fingerprint = Self::compute_config_fingerprint(&guard.config);
        let new_fp = guard.fingerprint.clone();

        if let Some(ref path) = self.file_path {
            if let Ok(toml_out) = toml::to_string_pretty(&guard.config) {
                let _ = std::fs::write(path, toml_out);
            }
        }

        Ok(new_fp)
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
        let (mut sorted_rules, current_fp, default_action_cfg) = match self.state.read() {
            Ok(g) => (
                g.config.rules.clone(),
                g.fingerprint.clone(),
                g.config.governance.default_action.clone(),
            ),
            Err(p) => {
                let g = p.into_inner();
                (
                    g.config.rules.clone(),
                    g.fingerprint.clone(),
                    g.config.governance.default_action.clone(),
                )
            }
        };

        // Sort rules by priority descending (higher number evaluated first)
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
                        policy_fingerprint: current_fp,
                        reason: format!(
                            "Matched policy rule '{}' requires min_auth_level = {}, caller has {:?}",
                            rule.name, min_level, caller_auth_level
                        ),
                        matched_rule: Some(rule.name.clone()),
                        is_unmatched: false,
                    };
                }
            }

            // Check lifecycle_state enforcement (PEP level guardrail)
            if let Some(ref state) = rule.lifecycle_state {
                let s = state.to_lowercase();
                if s == "quarantined" {
                    return PolicyDecision {
                        action_id: action.action_id.clone(),
                        tier: Tier::Tier3Deny,
                        policy_fingerprint: current_fp,
                        reason: format!(
                            "Matched policy rule '{}' is in QUARANTINED status due to security tripwire; execution blocked",
                            rule.name
                        ),
                        matched_rule: Some(rule.name.clone()),
                        is_unmatched: false,
                    };
                }
                if s == "probationary" || s == "draft" {
                    let target = rule.probation_target.unwrap_or(5);
                    let count = rule.confirmations_count.unwrap_or(0);
                    return PolicyDecision {
                        action_id: action.action_id.clone(),
                        tier: Tier::Tier1RequireHumanApproval,
                        policy_fingerprint: current_fp,
                        reason: format!(
                            "Matched policy rule '{}' is in PROBATIONARY status ({}/{} confirmations). Mandatory human escalation enforced.",
                            rule.name, count, target
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
                policy_fingerprint: current_fp,
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
        let default_tier = match default_action_cfg
            .as_deref()
            .unwrap_or("require_approval")
            .to_lowercase()
            .as_str()
        {
            "tier0_auto" | "tier0" | "auto" | "allow" => Tier::Tier0Auto,
            "tier1_human" | "tier1" | "require_approval" | "escalate" => {
                Tier::Tier1RequireHumanApproval
            }
            "tier2_elevated" | "tier2" => Tier::Tier2RequireElevatedApproval,
            "deny" => Tier::Tier3Deny,
            _ => Tier::Tier1RequireHumanApproval, // Safe default fallback to manual escalation!
        };

        PolicyDecision {
            action_id: action.action_id.clone(),
            tier: default_tier,
            policy_fingerprint: current_fp,
            reason: "Unmatched action: No policy rule triggered; default escalation applied"
                .to_string(),
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
        assert_eq!(
            decision_webauthn.matched_rule,
            Some("High value payout requires WebAuthn".to_string())
        );
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
        assert_eq!(
            engine.triage_agent_url().as_deref(),
            Some("http://127.0.0.1:4015")
        );

        // Novel tool that matches ZERO rules
        let novel_action = ProposedAction {
            action_id: "act_novel".to_string(),
            tool_name: "novel_unmapped_tool".to_string(),
            arguments: serde_json::json!({}),
            ..Default::default()
        };
        let skill = dummy_skill("custom");

        let decision =
            engine.evaluate_with_auth_level(&novel_action, &skill, AuthLevel::Level3Session);
        assert!(decision.is_unmatched);
        assert_eq!(decision.matched_rule, None);
        assert_eq!(decision.tier, Tier::Tier1RequireHumanApproval);
        assert!(decision.reason.contains("default escalation applied"));
    }

    #[test]
    fn test_pep_rejects_probationary_rule_with_allow_action() {
        let toml_content = r#"
[governance]
policy_version = "1.0.0"

[[rules]]
name = "Invalid bypass candidate"
tool_names = ["novel_tool"]
action = "allow"
lifecycle_state = "probationary"
priority = 15
"#;

        let result = PolicyEngine::from_toml(toml_content);
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(err_msg.contains("Security Invariant Violation"));
        assert!(err_msg.contains("cannot grant direct bypass"));
    }

    #[test]
    fn test_pep_enforces_human_escalation_for_probationary_rule() {
        let toml_content = r#"
[governance]
policy_version = "1.0.0"

[[rules]]
name = "Probationary candidate rule"
tool_names = ["novel_tool"]
action = "require_approval"
lifecycle_state = "probationary"
probation_target = 5
confirmations_count = 2
priority = 15
"#;

        let engine = PolicyEngine::from_toml(toml_content).unwrap();
        let action = ProposedAction {
            action_id: "act_prob".to_string(),
            tool_name: "novel_tool".to_string(),
            arguments: serde_json::json!({}),
            ..Default::default()
        };
        let skill = dummy_skill("mutation");

        let decision = engine.evaluate_with_auth_level(&action, &skill, AuthLevel::Level3Session);
        assert_eq!(decision.tier, Tier::Tier1RequireHumanApproval);
        assert!(!decision.is_unmatched);
        assert!(decision
            .reason
            .contains("PROBATIONARY status (2/5 confirmations)"));
    }

    #[test]
    fn test_pep_denies_quarantined_rule() {
        let toml_content = r#"
[governance]
policy_version = "1.0.0"

[[rules]]
name = "Quarantined compromised rule"
tool_names = ["risky_tool"]
action = "require_approval"
lifecycle_state = "quarantined"
priority = 15
"#;

        let engine = PolicyEngine::from_toml(toml_content).unwrap();
        let action = ProposedAction {
            action_id: "act_quarantine".to_string(),
            tool_name: "risky_tool".to_string(),
            arguments: serde_json::json!({}),
            ..Default::default()
        };
        let skill = dummy_skill("mutation");

        let decision = engine.evaluate_with_auth_level(&action, &skill, AuthLevel::Level3Session);
        assert_eq!(decision.tier, Tier::Tier3Deny);
        assert!(decision
            .reason
            .contains("QUARANTINED status due to security tripwire"));
    }

    #[test]
    fn test_pep_permits_graduated_rule() {
        let toml_content = r#"
[governance]
policy_version = "1.0.0"

[[rules]]
name = "Graduated verified rule"
tool_names = ["graduated_tool"]
action = "allow"
lifecycle_state = "graduated"
priority = 15
"#;

        let engine = PolicyEngine::from_toml(toml_content).unwrap();
        let action = ProposedAction {
            action_id: "act_grad".to_string(),
            tool_name: "graduated_tool".to_string(),
            arguments: serde_json::json!({}),
            ..Default::default()
        };
        let skill = dummy_skill("read");

        let decision = engine.evaluate_with_auth_level(&action, &skill, AuthLevel::Level3Session);
        assert_eq!(decision.tier, Tier::Tier0Auto);
        assert_eq!(
            decision.matched_rule,
            Some("Graduated verified rule".to_string())
        );
    }

    #[test]
    fn test_live_hot_reload_probation_graduation_and_quarantine() {
        let toml_content = r#"
[governance]
policy_version = "1.0.0"
default_action = "require_approval"
"#;
        let engine = PolicyEngine::from_toml(toml_content).unwrap();
        let initial_fp = engine.fingerprint();

        let action = ProposedAction {
            action_id: "act_live".to_string(),
            tool_name: "dynamic_tool".to_string(),
            arguments: serde_json::json!({}),
            ..Default::default()
        };
        let skill = dummy_skill("read");

        // 1. Initially unmatched
        let dec0 = engine.evaluate_with_auth_level(&action, &skill, AuthLevel::Level3Session);
        assert!(dec0.is_unmatched);

        // 2. Upsert probationary rule -> matched, still requires approval, fingerprint updated
        let prob_rule = PolicyRule {
            name: "Auto-synthesized: require_approval for 'dynamic_tool'".to_string(),
            tool_names: Some(vec!["dynamic_tool".to_string()]),
            operation_kind: Some("read".to_string()),
            min_amount_cents: None,
            min_auth_level: Some(3),
            action: "require_approval".to_string(),
            priority: 15,
            lifecycle_state: Some("probationary".to_string()),
            probation_target: Some(5),
            confirmations_count: Some(1),
            required_approver_quorum: Some(2),
            projected_fields: None,
            escalation_role: Some("security_reviewer".to_string()),
        };
        let fp1 = engine.upsert_rule(prob_rule).unwrap();
        assert_ne!(initial_fp, fp1);

        let dec1 = engine.evaluate_with_auth_level(&action, &skill, AuthLevel::Level3Session);
        assert!(!dec1.is_unmatched);
        assert_eq!(dec1.tier, Tier::Tier1RequireHumanApproval);

        // 3. Graduate rule -> matched, now Tier0Auto!
        let fp2 = engine
            .graduate_rule("Auto-synthesized: require_approval for 'dynamic_tool'", 5)
            .unwrap();
        assert_ne!(fp1, fp2);

        let dec2 = engine.evaluate_with_auth_level(&action, &skill, AuthLevel::Level3Session);
        assert_eq!(dec2.tier, Tier::Tier0Auto);

        // 4. Quarantine tripwire -> immediately Tier3Deny!
        let _fp3 = engine
            .quarantine_rule(
                "Auto-synthesized: require_approval for 'dynamic_tool'",
                Some(vec!["dynamic_tool".to_string()]),
            )
            .unwrap();
        let dec3 = engine.evaluate_with_auth_level(&action, &skill, AuthLevel::Level3Session);
        assert_eq!(dec3.tier, Tier::Tier3Deny);
    }
}
