//! LLM policy router — resolves tenant policy and selects model for each request.

use super::models::{LlmPolicy, PolicyDecision, RequestType};
use super::metering::UsageMetrics;

/// Evaluate the LLM policy to produce a routing decision.
///
/// Takes the tenant's policy, the current usage metrics, and the request type,
/// and returns a `PolicyDecision` indicating which model to use (or deny).
pub fn evaluate_policy(
    policy: &LlmPolicy,
    metrics: &UsageMetrics,
    request_type: &RequestType,
) -> PolicyDecision {
    // 1. Budget check
    if metrics.tokens_used >= policy.max_tokens_per_month {
        return PolicyDecision {
            model: String::new(),
            temperature: None,
            full_audit: false,
            denied: true,
            deny_reason: Some(format!(
                "Monthly token budget exhausted ({}/{})",
                metrics.tokens_used, policy.max_tokens_per_month
            )),
        };
    }

    // 2. Rate limit check: tool calls per minute
    if metrics.tool_calls_last_minute >= policy.max_tool_calls_per_minute {
        return PolicyDecision {
            model: String::new(),
            temperature: None,
            full_audit: false,
            denied: true,
            deny_reason: Some(format!(
                "Tool call rate limit exceeded ({}/min)",
                policy.max_tool_calls_per_minute
            )),
        };
    }

    // 3. Escalation rate limit
    if *request_type == RequestType::Escalated
        && metrics.escalations_last_hour >= policy.max_escalations_per_hour
    {
        return PolicyDecision {
            model: String::new(),
            temperature: None,
            full_audit: false,
            denied: true,
            deny_reason: Some(format!(
                "Escalation rate limit exceeded ({}/hour)",
                policy.max_escalations_per_hour
            )),
        };
    }

    // 4. Model selection based on request type
    let (model, temperature, full_audit) = match request_type {
        RequestType::Standard => (
            policy.default_model.clone(),
            None,    // Use default temperature
            false,
        ),
        RequestType::Mutation => {
            // Mutations use escalation model if available, otherwise default
            let model = policy
                .escalation_model
                .clone()
                .unwrap_or_else(|| policy.default_model.clone());
            (model, Some(0.0), true) // Deterministic for mutations
        }
        RequestType::Escalated => {
            let model = policy
                .escalation_model
                .clone()
                .unwrap_or_else(|| policy.default_model.clone());
            (model, Some(0.0), true)
        }
        RequestType::ComplianceCritical => {
            // Always use the best available model with zero temperature
            let model = policy
                .escalation_model
                .clone()
                .unwrap_or_else(|| policy.default_model.clone());
            (model, Some(0.0), true)
        }
    };

    // 5. Ensure selected model is in allowed list
    let final_model = if policy.allowed_models.contains(&model) {
        model
    } else {
        // Fall back to default if selected model not allowed
        tracing::warn!(
            "Selected model '{}' not in allowed list, falling back to default '{}'",
            model,
            policy.default_model
        );
        policy.default_model.clone()
    };

    PolicyDecision {
        model: final_model,
        temperature,
        full_audit,
        denied: false,
        deny_reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> LlmPolicy {
        LlmPolicy {
            policy_id: "test".to_string(),
            default_model: "gpt-4o-mini".to_string(),
            max_tokens_per_month: 1_000_000,
            allowed_models: vec![
                "gpt-4o-mini".to_string(),
                "gpt-4o".to_string(),
            ],
            escalation_model: Some("gpt-4o".to_string()),
            max_tool_calls_per_minute: 30,
            max_escalations_per_hour: 10,
        }
    }

    #[test]
    fn test_standard_request_uses_default_model() {
        let policy = test_policy();
        let metrics = UsageMetrics::default();
        let decision = evaluate_policy(&policy, &metrics, &RequestType::Standard);
        assert!(!decision.denied);
        assert_eq!(decision.model, "gpt-4o-mini");
        assert!(decision.temperature.is_none());
    }

    #[test]
    fn test_mutation_upgrades_model() {
        let policy = test_policy();
        let metrics = UsageMetrics::default();
        let decision = evaluate_policy(&policy, &metrics, &RequestType::Mutation);
        assert!(!decision.denied);
        assert_eq!(decision.model, "gpt-4o");
        assert_eq!(decision.temperature, Some(0.0));
        assert!(decision.full_audit);
    }

    #[test]
    fn test_budget_exceeded_denies() {
        let policy = test_policy();
        let metrics = UsageMetrics {
            tokens_used: 1_000_001,
            ..Default::default()
        };
        let decision = evaluate_policy(&policy, &metrics, &RequestType::Standard);
        assert!(decision.denied);
        assert!(decision.deny_reason.unwrap().contains("exhausted"));
    }

    #[test]
    fn test_tool_rate_limit_denies() {
        let policy = test_policy();
        let metrics = UsageMetrics {
            tool_calls_last_minute: 31,
            ..Default::default()
        };
        let decision = evaluate_policy(&policy, &metrics, &RequestType::Standard);
        assert!(decision.denied);
    }

    #[test]
    fn test_escalation_rate_limit() {
        let policy = test_policy();
        let metrics = UsageMetrics {
            escalations_last_hour: 11,
            ..Default::default()
        };
        // Standard requests are not affected by escalation limits
        let standard = evaluate_policy(&policy, &metrics, &RequestType::Standard);
        assert!(!standard.denied);

        // Escalated requests are denied
        let escalated = evaluate_policy(&policy, &metrics, &RequestType::Escalated);
        assert!(escalated.denied);
    }
}
