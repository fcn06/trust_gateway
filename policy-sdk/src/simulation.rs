use crate::evaluator::PolicyEvaluator;
use crate::layers::{HierarchicalPolicy, PolicyOutcome};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub active_outcome: PolicyOutcome,
    pub candidate_outcome: PolicyOutcome,
    pub is_divergent: bool,
    pub explanation: String,
}

pub struct SimulationEngine {
    active_evaluator: PolicyEvaluator,
    candidate_evaluator: PolicyEvaluator,
}

impl SimulationEngine {
    pub fn new(active: HierarchicalPolicy, candidate: HierarchicalPolicy) -> Self {
        Self {
            active_evaluator: PolicyEvaluator::new(active),
            candidate_evaluator: PolicyEvaluator::new(candidate),
        }
    }

    /// Evaluates a proposal against active and shadow candidate policies simultaneously.
    pub fn run_shadow(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_name: &str,
        amount_usd: Option<u64>,
    ) -> SimulationResult {
        let active_outcome = self
            .active_evaluator
            .evaluate(tenant_id, agent_id, tool_name, amount_usd);
        let candidate_outcome = self
            .candidate_evaluator
            .evaluate(tenant_id, agent_id, tool_name, amount_usd);
        let is_divergent = active_outcome != candidate_outcome;

        let explanation = if is_divergent {
            format!(
                "Policy Divergence Detected! Active: {active_outcome:?}, Shadow Candidate: {candidate_outcome:?}"
            )
        } else {
            "Active and Shadow Candidate policies produced identical outcomes.".to_string()
        };

        SimulationResult {
            active_outcome,
            candidate_outcome,
            is_divergent,
            explanation,
        }
    }

    /// Evaluates a proposal against active and shadow candidate policies with dynamic trust telemetry.
    pub fn run_shadow_with_trust(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_name: &str,
        amount_usd: Option<u64>,
        metrics: Option<&crate::layers::DynamicTrustMetrics>,
    ) -> SimulationResult {
        let active_outcome = self
            .active_evaluator
            .evaluate_with_dynamic_trust(tenant_id, agent_id, tool_name, amount_usd, metrics);
        let candidate_outcome = self
            .candidate_evaluator
            .evaluate_with_dynamic_trust(tenant_id, agent_id, tool_name, amount_usd, metrics);
        let is_divergent = active_outcome != candidate_outcome;

        let explanation = if is_divergent {
            format!(
                "Policy Divergence Detected! Active: {active_outcome:?}, Shadow Candidate: {candidate_outcome:?}"
            )
        } else {
            "Active and Shadow Candidate policies produced identical outcomes.".to_string()
        };

        SimulationResult {
            active_outcome,
            candidate_outcome,
            is_divergent,
            explanation,
        }
    }
}
