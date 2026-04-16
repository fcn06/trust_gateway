//! LLM policy data models.

use serde::{Deserialize, Serialize};

/// LLM policy definition, determining model access and limits per tenant tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmPolicy {
    pub policy_id: String,
    /// Default model for standard inference requests.
    pub default_model: String,
    /// Maximum token budget per billing period (monthly).
    pub max_tokens_per_month: u64,
    /// Models the tenant is allowed to use.
    pub allowed_models: Vec<String>,
    /// Optional upgraded model for escalation-approved requests.
    pub escalation_model: Option<String>,
    /// Rate limit: max tool calls per minute.
    pub max_tool_calls_per_minute: u32,
    /// Rate limit: max escalations per hour.
    pub max_escalations_per_hour: u32,
}

/// The type of request being made, affecting model selection.
#[derive(Debug, Clone, PartialEq)]
pub enum RequestType {
    /// Standard inquiry — uses default model.
    Standard,
    /// Request that involves mutations (e.g., approvals, payments) — may upgrade model.
    Mutation,
    /// Elevated request after human escalation approval.
    Escalated,
    /// Compliance/audit critical — deterministic temperature, full logging.
    ComplianceCritical,
}

/// Result of a policy check before an LLM call.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// The model to use for this request.
    pub model: String,
    /// Temperature override (None = use default).
    pub temperature: Option<f32>,
    /// Whether this call requires full audit logging.
    pub full_audit: bool,
    /// Whether the call was denied (budget exceeded, rate limited, etc.).
    pub denied: bool,
    /// Human-readable reason if denied.
    pub deny_reason: Option<String>,
}
