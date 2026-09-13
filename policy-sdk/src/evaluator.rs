use crate::layers::{HierarchicalPolicy, PolicyOutcome};

/// 4-Layer Hierarchical Policy Evaluator
///
/// Implements monotonic intersection:
/// Platform ∩ Organization ∩ Agent ∩ Transaction
pub struct PolicyEvaluator {
    policy: HierarchicalPolicy,
}

impl PolicyEvaluator {
    pub fn new(policy: HierarchicalPolicy) -> Self {
        Self { policy }
    }

    /// Evaluates an execution grant proposal against all 4 policy layers in order.
    pub fn evaluate(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_name: &str,
        amount_usd: Option<u64>,
    ) -> PolicyOutcome {
        // Layer 1: Platform Policy Invariants
        if self.policy.platform.enforce_tenant_isolation && tenant_id.is_empty() {
            return PolicyOutcome::Deny {
                reason: "Platform Policy: Missing tenant isolation context".to_string(),
            };
        }

        // Layer 2: Organization Policy
        if self
            .policy
            .organization
            .blacklisted_tools
            .contains(&tool_name.to_string())
        {
            return PolicyOutcome::Deny {
                reason: format!("Organization Policy: Tool '{tool_name}' is blacklisted"),
            };
        }
        if let Some(amt) = amount_usd {
            if amt > self.policy.organization.max_financial_limit_usd
                && self.policy.organization.max_financial_limit_usd > 0
            {
                return PolicyOutcome::Deny {
                    reason: format!(
                        "Organization Policy: Transaction amount (${}) exceeds organizational cap (${})",
                        amt, self.policy.organization.max_financial_limit_usd
                    ),
                };
            }
        }

        // Layer 3: Agent Policy
        if !self.policy.agent.agent_id.is_empty() && self.policy.agent.agent_id != agent_id {
            return PolicyOutcome::Deny {
                reason: format!(
                    "Agent Policy: Agent ID mismatch (expected '{}', got '{}')",
                    self.policy.agent.agent_id, agent_id
                ),
            };
        }
        if !self.policy.agent.allowed_tools.is_empty()
            && !self
                .policy
                .agent
                .allowed_tools
                .contains(&tool_name.to_string())
        {
            return PolicyOutcome::Deny {
                reason: format!("Agent Policy: Tool '{tool_name}' not permitted for agent profile"),
            };
        }

        // Layer 4: Transaction Policy
        if let Some(threshold) = self.policy.transaction.human_approval_threshold_usd {
            if let Some(amt) = amount_usd {
                if amt >= threshold {
                    return PolicyOutcome::RequiresHumanApproval {
                        clearance_required: "human_approved".to_string(),
                    };
                }
            }
        }

        PolicyOutcome::Allow
    }

    /// Evaluates an action using explicit OperationAttributes instead of heuristics.
    pub fn evaluate_operation(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_name: &str,
        op_attrs: &trust_model::OperationAttributes,
    ) -> PolicyOutcome {
        let amount_usd = op_attrs.amount.as_ref().map(|m| m.amount_cents / 100);

        if op_attrs.operation_kind == "financial_mutation"
            || op_attrs.operation_kind == "destructive"
        {
            if let Some(threshold) = self.policy.transaction.human_approval_threshold_usd {
                let amt = amount_usd.unwrap_or(0);
                if amt >= threshold {
                    return PolicyOutcome::RequiresHumanApproval {
                        clearance_required: "human_approved".to_string(),
                    };
                }
            }
        }

        self.evaluate(tenant_id, agent_id, tool_name, amount_usd)
    }

    /// Evaluates an action with contextual counterparty reputation evidence.
    ///
    /// If `min_reputation_successful_executions` is configured on the organization policy:
    /// - The counterparty must meet or exceed the required local successful executions, OR
    /// - Provide a verified attestation/receipt issued by one of the `trusted_peer_roots`.
    pub fn evaluate_with_reputation(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_name: &str,
        amount_usd: Option<u64>,
        local_successful_count: u64,
        has_trusted_peer_attestation: bool,
    ) -> PolicyOutcome {
        // Evaluate base policy layers first
        let base_outcome = self.evaluate(tenant_id, agent_id, tool_name, amount_usd);
        if base_outcome != PolicyOutcome::Allow {
            return base_outcome;
        }

        // Evaluate reputation requirement
        if let Some(required_count) = self
            .policy
            .organization
            .min_reputation_successful_executions
        {
            if local_successful_count < required_count && !has_trusted_peer_attestation {
                return PolicyOutcome::Deny {
                    reason: format!(
                        "Organization Policy: Insufficient reputation (requires {} successful executions or a trusted peer attestation, found {})",
                        required_count, local_successful_count
                    ),
                };
            }
        }

        PolicyOutcome::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::*;

    fn create_test_policy() -> HierarchicalPolicy {
        HierarchicalPolicy {
            platform: PlatformPolicy {
                enforce_tenant_isolation: true,
                ..Default::default()
            },
            organization: OrganizationPolicy {
                max_financial_limit_usd: 10_000,
                min_reputation_successful_executions: Some(5),
                trusted_peer_roots: vec!["did:web:trusted-partner.example".to_string()],
                ..Default::default()
            },
            agent: AgentPolicy::default(),
            transaction: TransactionPolicy::default(),
        }
    }

    #[test]
    fn test_reputation_denied_when_below_threshold() {
        let policy = create_test_policy();
        let evaluator = PolicyEvaluator::new(policy);

        let outcome = evaluator.evaluate_with_reputation(
            "tenant_1",
            "agent_1",
            "orders.create",
            Some(500),
            2,     // Only 2 successful executions, requires 5
            false, // No trusted peer attestation
        );

        match outcome {
            PolicyOutcome::Deny { reason } => {
                assert!(reason.contains("Insufficient reputation"));
            }
            _ => panic!("Expected Deny, got {:?}", outcome),
        }
    }

    #[test]
    fn test_reputation_allowed_when_local_history_sufficient() {
        let policy = create_test_policy();
        let evaluator = PolicyEvaluator::new(policy);

        let outcome = evaluator.evaluate_with_reputation(
            "tenant_1",
            "agent_1",
            "orders.create",
            Some(500),
            5, // Meets threshold of 5
            false,
        );

        assert_eq!(outcome, PolicyOutcome::Allow);
    }

    #[test]
    fn test_reputation_allowed_with_trusted_peer_attestation() {
        let policy = create_test_policy();
        let evaluator = PolicyEvaluator::new(policy);

        let outcome = evaluator.evaluate_with_reputation(
            "tenant_1",
            "agent_1",
            "orders.create",
            Some(500),
            0,    // Cold start (0 local history)
            true, // Verified peer attestation presented
        );

        assert_eq!(outcome, PolicyOutcome::Allow);
    }
}
