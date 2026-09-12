pub mod call_chain;
pub use call_chain::*;

use trust_model::{PolicyDecision, ProposedAction};

pub struct CorePolicyEngine;

impl CorePolicyEngine {
    /// Pure policy decision logic based on explicit operation attributes
    pub fn evaluate(action: &ProposedAction, max_amount_cents: u64) -> PolicyDecision {
        // Layer 0: Call-chain guard
        if let Some(ref chain) = action.call_chain_context {
            let mut chain_eval = chain.clone();
            let policy = call_chain::CallChainPolicy::default();
            if let Err(err) =
                call_chain::evaluate_and_advance(&mut chain_eval, &action.tool_name, &policy)
            {
                return PolicyDecision {
                    action_id: action.action_id.clone(),
                    approved: false,
                    clearance_level: "denied".to_string(),
                    policy_fingerprint: "policy_v1_call_chain_denied".to_string(),
                    reason: format!("Call-chain guard violation: {err}"),
                };
            }
        }

        let op_kind = &action.operation_attributes.operation_kind;

        if op_kind == "destructive" {
            return PolicyDecision {
                action_id: action.action_id.clone(),
                approved: false,
                clearance_level: "denied".to_string(),
                policy_fingerprint: "policy_v1_destructive".to_string(),
                reason: "Destructive operations are blocked by default policy".to_string(),
            };
        }

        if op_kind == "financial_mutation" {
            if let Some(ref money) = action.operation_attributes.amount {
                if money.amount_cents > max_amount_cents && max_amount_cents > 0 {
                    return PolicyDecision {
                        action_id: action.action_id.clone(),
                        approved: false,
                        clearance_level: "human_approved".to_string(),
                        policy_fingerprint: "policy_v1_financial".to_string(),
                        reason: format!(
                            "Financial mutation of {} {} exceeds threshold of {} cents",
                            money.amount_cents, money.currency, max_amount_cents
                        ),
                    };
                }
            }
        }

        PolicyDecision {
            action_id: action.action_id.clone(),
            approved: true,
            clearance_level: "auto_approved".to_string(),
            policy_fingerprint: "policy_v1_allow".to_string(),
            reason: "Action permitted under default policy".to_string(),
        }
    }
}
