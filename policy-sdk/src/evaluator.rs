use crate::layers::{DynamicTrustMetrics, HierarchicalPolicy, PolicyOutcome};

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

    /// Evaluates an execution grant proposal with explicit session tier context (guest, account, step_up).
    pub fn evaluate_with_session_tier(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_name: &str,
        amount_usd: Option<u64>,
        session_tier: &str,
        is_mutation: bool,
    ) -> PolicyOutcome {
        if session_tier.eq_ignore_ascii_case("guest") && is_mutation {
            return PolicyOutcome::Deny {
                reason: "SessionTier: Guest session cannot execute mutations. Customer account authentication required.".to_string(),
            };
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
    /// Evaluates an action with comprehensive dynamic trust metrics.
    ///
    /// Evaluates against `OrganizationPolicy::reputation` if configured:
    /// - Checks historical failure rates against `max_failure_rate` ceiling.
    /// - Checks cold-start threshold `min_successful_executions` with optional peer attestation fallback.
    /// - Supports adaptive downgrade to `RequiresHumanApproval` when configured.
    /// - Checks high-value tool peer attestation score requirements.
    pub fn evaluate_with_dynamic_trust(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_name: &str,
        amount_usd: Option<u64>,
        metrics: Option<&DynamicTrustMetrics>,
    ) -> PolicyOutcome {
        // Evaluate base deterministic policy layers first
        let base_outcome = self.evaluate(tenant_id, agent_id, tool_name, amount_usd);
        if base_outcome != PolicyOutcome::Allow {
            return base_outcome;
        }

        // Check if dynamic reputation policy is configured
        if let Some(ref rep_policy) = self.policy.organization.reputation {
            let m = match metrics {
                Some(val) => val,
                None => {
                    // No telemetry provided: evaluate cold-start rule
                    if rep_policy.min_successful_executions.unwrap_or(0) > 0 {
                        if rep_policy.adaptive_downgrade {
                            return PolicyOutcome::RequiresHumanApproval {
                                clearance_required: "reputation_cold_start".to_string(),
                            };
                        } else {
                            return PolicyOutcome::Deny {
                                reason: "Organization Policy: Missing reputation telemetry for counterparty".to_string(),
                            };
                        }
                    }
                    return PolicyOutcome::Allow;
                }
            };

            // Rule 1: Hard failure rate ceiling
            if let Some(max_fail) = rep_policy.max_failure_rate {
                let total_runs = m.successful_executions + m.failed_executions;
                if total_runs >= 5 && m.failure_rate > max_fail {
                    return PolicyOutcome::Deny {
                        reason: format!(
                            "Organization Policy: Counterparty failure rate ({:.1}%) exceeds ceiling ({:.1}%)",
                            m.failure_rate * 100.0,
                            max_fail * 100.0
                        ),
                    };
                }
            }

            // Rule 2: Cold-start threshold
            if let Some(min_exec) = rep_policy.min_successful_executions {
                if m.successful_executions < min_exec {
                    let has_valid_peer =
                        m.peer_attestation_score.map(|s| s >= 0.75).unwrap_or(false);
                    if !has_valid_peer {
                        if rep_policy.adaptive_downgrade {
                            return PolicyOutcome::RequiresHumanApproval {
                                clearance_required: "reputation_downgrade_cold_start".to_string(),
                            };
                        } else {
                            return PolicyOutcome::Deny {
                                reason: format!(
                                    "Organization Policy: Insufficient reputation (requires {} successful executions, found {})",
                                    min_exec, m.successful_executions
                                ),
                            };
                        }
                    }
                }
            }

            // Rule 3: High-value tool peer attestation requirement
            if let Some(min_peer) = rep_policy.min_peer_score_for_auto_approval {
                if amount_usd.unwrap_or(0) > 1000 {
                    let score = m.peer_attestation_score.unwrap_or(0.0);
                    if score < min_peer {
                        return PolicyOutcome::RequiresHumanApproval {
                            clearance_required: "reputation_unverified_high_value".to_string(),
                        };
                    }
                }
            }
        } else if let Some(required_count) = self
            .policy
            .organization
            .min_reputation_successful_executions
        {
            // Fallback to legacy single-field reputation if reputation struct is not set
            let local_count = metrics.map(|m| m.successful_executions).unwrap_or(0);
            let has_peer = metrics
                .and_then(|m| m.peer_attestation_score)
                .map(|s| s >= 0.75)
                .unwrap_or(false);
            if local_count < required_count && !has_peer {
                return PolicyOutcome::Deny {
                    reason: format!(
                        "Organization Policy: Insufficient reputation (requires {} successful executions or a trusted peer attestation, found {})",
                        required_count, local_count
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
                reputation: Some(ReputationPolicy {
                    min_successful_executions: Some(5),
                    max_failure_rate: Some(0.10), // Max 10% failures allowed
                    min_peer_score_for_auto_approval: Some(0.80),
                    adaptive_downgrade: true,
                }),
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

    #[test]
    fn test_dynamic_trust_failure_rate_exceeded() {
        let policy = create_test_policy();
        let evaluator = PolicyEvaluator::new(policy);

        let metrics = DynamicTrustMetrics {
            successful_executions: 10,
            failed_executions: 3,
            failure_rate: 0.23, // 23% failure rate > 10%
            peer_attestation_score: Some(0.90),
            transitive_trust_score: Some(0.85),
        };

        let outcome = evaluator.evaluate_with_dynamic_trust(
            "tenant_1",
            "agent_1",
            "orders.create",
            Some(500),
            Some(&metrics),
        );

        match outcome {
            PolicyOutcome::Deny { reason } => {
                assert!(reason.contains("failure rate (23.0%) exceeds ceiling"));
            }
            _ => panic!("Expected Deny, got {:?}", outcome),
        }
    }

    #[test]
    fn test_dynamic_trust_adaptive_downgrade_cold_start() {
        let policy = create_test_policy();
        let evaluator = PolicyEvaluator::new(policy);

        let metrics = DynamicTrustMetrics {
            successful_executions: 1, // < 5 required
            failed_executions: 0,
            failure_rate: 0.0,
            peer_attestation_score: None, // No peer attestation
            transitive_trust_score: None,
        };

        let outcome = evaluator.evaluate_with_dynamic_trust(
            "tenant_1",
            "agent_1",
            "orders.create",
            Some(500),
            Some(&metrics),
        );

        // With adaptive_downgrade = true, outcome should be RequiresHumanApproval
        match outcome {
            PolicyOutcome::RequiresHumanApproval { clearance_required } => {
                assert_eq!(clearance_required, "reputation_downgrade_cold_start");
            }
            _ => panic!("Expected RequiresHumanApproval, got {:?}", outcome),
        }
    }

    #[test]
    fn test_dynamic_trust_high_value_peer_score_required() {
        let policy = create_test_policy();
        let evaluator = PolicyEvaluator::new(policy);

        // Enough executions, but peer score is 0.50 (< 0.80 required for amount > 1000)
        let metrics = DynamicTrustMetrics {
            successful_executions: 20,
            failed_executions: 0,
            failure_rate: 0.0,
            peer_attestation_score: Some(0.50),
            transitive_trust_score: Some(0.60),
        };

        let outcome = evaluator.evaluate_with_dynamic_trust(
            "tenant_1",
            "agent_1",
            "orders.create",
            Some(5000), // High value > 1000
            Some(&metrics),
        );

        match outcome {
            PolicyOutcome::RequiresHumanApproval { clearance_required } => {
                assert_eq!(clearance_required, "reputation_unverified_high_value");
            }
            _ => panic!("Expected RequiresHumanApproval, got {:?}", outcome),
        }
    }

    #[test]
    fn test_evaluate_with_session_tier() {
        let policy = create_test_policy();
        let evaluator = PolicyEvaluator::new(policy);

        // Guest session attempting mutation -> Deny
        let outcome = evaluator.evaluate_with_session_tier(
            "tenant_1",
            "agent_1",
            "orders.create",
            Some(10),
            "guest",
            true, // is_mutation
        );
        match outcome {
            PolicyOutcome::Deny { reason } => {
                assert!(reason.contains("Guest session cannot execute mutations"));
            }
            _ => panic!("Expected Deny for guest mutation, got {:?}", outcome),
        }

        // Guest session attempting read -> Allow
        let outcome_read = evaluator.evaluate_with_session_tier(
            "tenant_1",
            "agent_1",
            "orders.list",
            None,
            "guest",
            false, // is_mutation
        );
        assert_eq!(outcome_read, PolicyOutcome::Allow);
    }
}
