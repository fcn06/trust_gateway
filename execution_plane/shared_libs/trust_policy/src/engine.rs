// ─────────────────────────────────────────────────────────────
// Policy engine — implements the PolicyEngine trait
//
// The main policy evaluation logic: iterate sorted rules,
// find the first match, and return the corresponding decision.
// ─────────────────────────────────────────────────────────────

use trust_core::action::ActionRequest;

use trust_core::decision::ActionDecision;
use trust_core::errors::PolicyError;
use trust_core::proof::ProofRequest;
use trust_core::traits::PolicyEngine;

use crate::rules::{PolicyEffect, PolicyRule, PolicySet};

/// A policy engine backed by TOML-configured rules.
///
/// This replaces the old `safe_tools` array in `policy.json` with
/// attribute-based, priority-ordered rule evaluation.
pub struct TomlPolicyEngine {
    policy_set: PolicySet,
}

impl TomlPolicyEngine {
    /// Create a new engine from a PolicySet.
    pub fn new(policy_set: PolicySet) -> Self {
        Self { policy_set }
    }

    /// Load from a TOML file.
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let policy_set = PolicySet::from_file(path)?;
        Ok(Self::new(policy_set))
    }

    /// Load from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, toml::de::Error> {
        let policy_set = PolicySet::from_toml(toml_str)?;
        Ok(Self::new(policy_set))
    }

    /// Return the number of rules loaded.
    pub fn rule_count(&self) -> usize {
        self.policy_set.rules.len()
    }



    /// WS4.1: Add a rule from a JSON value. Re-sorts by priority after insertion.
    pub fn add_rule_from_json(&mut self, json: &serde_json::Value) -> Result<(), String> {
        let rule: PolicyRule = serde_json::from_value(json.clone())
            .map_err(|e| format!("Invalid rule JSON: {}", e))?;
        // Validate effect
        match rule.effect.as_str() {
            "allow" | "deny" | "require_approval" | "require_proof" => {}
            other => return Err(format!("Unknown effect: {}", other)),
        }
        self.policy_set.rules.push(rule);
        self.policy_set.rules.sort_by_key(|r| r.priority);
        Ok(())
    }

    /// WS4.1: Remove a rule by its ID.
    pub fn remove_rule(&mut self, rule_id: &str) -> Result<(), String> {
        let before = self.policy_set.rules.len();
        self.policy_set.rules.retain(|r| r.id != rule_id);
        if self.policy_set.rules.len() == before {
            Err(format!("Rule '{}' not found", rule_id))
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait]
impl PolicyEngine for TomlPolicyEngine {
    fn list_rules_json(&self) -> Vec<serde_json::Value> {
        self.policy_set.rules.iter().map(|r| {
            serde_json::to_value(r).unwrap_or_default()
        }).collect()
    }

    async fn evaluate(&self, req: &ActionRequest) -> Result<ActionDecision, PolicyError> {
        let sorted_rules = self.policy_set.sorted_rules();

        for rule in sorted_rules {
            if rule.matcher.matches(req) {
                tracing::info!(
                    "📋 Policy rule '{}' matched action '{}' → effect: {}",
                    rule.id,
                    req.action.name,
                    rule.effect
                );

                let effect = rule.resolve_effect();
                let decision = match effect {
                    PolicyEffect::Allow => ActionDecision::Allow {
                        policy_id: rule.id.clone(),
                    },
                    PolicyEffect::Deny { reason } => ActionDecision::Deny {
                        reason,
                        policy_id: rule.id.clone(),
                    },
                    PolicyEffect::RequireApproval { tier, reason } => {
                        ActionDecision::RequireApproval {
                            tier,
                            reason,
                            policy_id: rule.id.clone(),
                        }
                    }
                    PolicyEffect::RequireProof {
                        proof_type,
                        required_claims,
                        reason,
                    } => {
                        let proof_request = ProofRequest {
                            proof_type,
                            presentation_definition: serde_json::json!({
                                "id": format!("pd-{}", rule.id),
                                "input_descriptors": required_claims.iter().map(|claim| {
                                    serde_json::json!({
                                        "id": claim,
                                        "constraints": {
                                            "fields": [{
                                                "path": [format!("$.credentialSubject.{}", claim.split(':').next().unwrap_or("role"))],
                                                "filter": {
                                                    "type": "string",
                                                    "const": claim.split(':').nth(1).unwrap_or("")
                                                }
                                            }]
                                        }
                                    })
                                }).collect::<Vec<_>>()
                            }),
                            required_claims,
                            challenge_nonce: uuid::Uuid::new_v4().to_string(),
                        };
                        ActionDecision::RequireProof {
                            proof_request,
                            reason,
                            policy_id: rule.id.clone(),
                        }
                    }
                };

                return Ok(decision);
            }
        }

        // Default: if no rule matched, deny (fail-closed).
        tracing::warn!(
            "⚠️ No policy rule matched action '{}'. Defaulting to deny (fail-closed).",
            req.action.name
        );
        Ok(ActionDecision::Deny {
            reason: format!(
                "No policy rule matched action '{}'. Default: deny.",
                req.action.name
            ),
            policy_id: "_default_deny".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_core::action::{ActionDescriptor, OperationKind};
    use trust_core::actor::{ActorContext, AuthLevel, SourceContext};
    use trust_core::approval::ApprovalTier;
    use trust_core::proof::ProofType;
    use trust_core::Money;

    fn make_request(name: &str, op: OperationKind, amount: Option<Money>, tags: Vec<String>) -> ActionRequest {
        ActionRequest {
            action_id: "test-action".to_string(),
            tenant_id: "tenant-1".to_string(),
            actor: ActorContext {
                owner_did: "did:key:owner".to_string(),
                requester_did: "did:key:user".to_string(),
                user_did: None,
                session_jti: "jti-123".to_string(),
                auth_level: AuthLevel::Session,
            },
            source: SourceContext::ssi_agent(),
            action: ActionDescriptor {
                name: name.to_string(),
                category: "test".to_string(),
                resource: None,
                operation: op,
                amount,
                arguments: serde_json::json!({}),
                tags,
            },
        }
    }

    const TEST_POLICY: &str = r#"
[[rules]]
id = "read-auto-allow"
priority = 10
operation_kinds = ["read"]
effect = "allow"

[[rules]]
id = "calendar-create-approval"
priority = 20
action_names = ["google.calendar.event.create"]
effect = "require_approval"
tier = "tier1"
reason = "Calendar creation requires portal approval"

[[rules]]
id = "big-refund-proof"
priority = 30
action_names = ["shopify.order.refund.create"]
min_amount = "500.00 EUR"
effect = "require_proof"
proof_type = "openid4vp"
required_claims = ["role:senior_customer_service"]
reason = "Refunds above €500 require the user to present proof of authority"

[[rules]]
id = "payout-change-proof"
priority = 40
tags = ["payout_change"]
effect = "require_proof"
proof_type = "openid4vp"
required_claims = ["role:finance_approver"]
reason = "Payout changes require finance authorization proof"
"#;

    #[tokio::test]
    async fn test_read_auto_allow() {
        let engine = TomlPolicyEngine::from_toml(TEST_POLICY).unwrap();
        let req = make_request("anything.list", OperationKind::Read, None, vec![]);
        let decision = engine.evaluate(&req).await.unwrap();
        assert!(decision.is_allowed());
        assert_eq!(decision.policy_id(), "read-auto-allow");
    }

    #[tokio::test]
    async fn test_calendar_create_requires_approval() {
        let engine = TomlPolicyEngine::from_toml(TEST_POLICY).unwrap();
        let req = make_request("google.calendar.event.create", OperationKind::Create, None, vec![]);
        let decision = engine.evaluate(&req).await.unwrap();
        assert!(decision.requires_human());
        match &decision {
            ActionDecision::RequireApproval { tier, .. } => {
                assert_eq!(*tier, ApprovalTier::Tier1PortalClick);
            }
            _ => panic!("Expected RequireApproval"),
        }
    }

    #[tokio::test]
    async fn test_big_refund_requires_proof() {
        let engine = TomlPolicyEngine::from_toml(TEST_POLICY).unwrap();
        let req = make_request(
            "shopify.order.refund.create",
            OperationKind::Create,
            Some(Money::from_major(600.0, "EUR")),
            vec![],
        );
        let decision = engine.evaluate(&req).await.unwrap();
        match &decision {
            ActionDecision::RequireProof { proof_request, .. } => {
                assert_eq!(proof_request.proof_type, ProofType::OpenId4Vp);
                assert!(proof_request.required_claims.contains(&"role:senior_customer_service".to_string()));
            }
            _ => panic!("Expected RequireProof, got {:?}", decision),
        }
    }

    #[tokio::test]
    async fn test_payout_change_tag_triggers_proof() {
        let engine = TomlPolicyEngine::from_toml(TEST_POLICY).unwrap();
        let req = make_request(
            "bank.account.update",
            OperationKind::Update,
            None,
            vec!["payout_change".to_string()],
        );
        let decision = engine.evaluate(&req).await.unwrap();
        match &decision {
            ActionDecision::RequireProof { proof_request, reason, .. } => {
                assert!(reason.contains("finance"));
                assert!(proof_request.required_claims.contains(&"role:finance_approver".to_string()));
            }
            _ => panic!("Expected RequireProof, got {:?}", decision),
        }
    }

    #[tokio::test]
    async fn test_unknown_action_default_deny() {
        let engine = TomlPolicyEngine::from_toml(TEST_POLICY).unwrap();
        let req = make_request("unknown.action", OperationKind::Delete, None, vec![]);
        let decision = engine.evaluate(&req).await.unwrap();
        assert!(decision.is_denied());
    }
}
