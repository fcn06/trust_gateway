//! Tenant Registry models — re-exports from `tenant_context` plus registry-specific DTOs.

use serde::{Deserialize, Serialize};

// Re-export core types for convenience
pub use tenant_context::{Tenant, TenantContext, TenantTier, TenantStatus, KeyMode};

/// Request to create a new tenant.
#[derive(Debug, Deserialize)]
pub struct CreateTenantRequest {
    pub display_name: String,
    #[serde(default)]
    pub tier: Option<TenantTier>,
    #[serde(default)]
    pub key_mode: Option<KeyMode>,
}

/// Request to update a tenant's tier.
#[derive(Debug, Deserialize)]
pub struct UpdateTierRequest {
    pub tier: TenantTier,
}

/// Response after creating a tenant.
#[derive(Debug, Serialize)]
pub struct CreateTenantResponse {
    pub tenant_id: String,
    pub display_name: String,
    pub tier: TenantTier,
    pub status: TenantStatus,
    pub nats_account_id: String,
    pub vault_namespace: String,
}

/// Summary info for listing tenants.
#[derive(Debug, Serialize)]
pub struct TenantSummary {
    pub tenant_id: String,
    pub display_name: String,
    pub tier: TenantTier,
    pub status: TenantStatus,
}

/// LLM policy definition tied to a tenant tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmPolicy {
    pub policy_id: String,
    pub default_model: String,
    pub max_tokens_per_month: u64,
    pub allowed_models: Vec<String>,
    pub escalation_model: Option<String>,
    pub max_tool_calls_per_minute: u32,
    pub max_escalations_per_hour: u32,
}

impl LlmPolicy {
    /// Generate a default LLM policy for a given tier.
    pub fn default_for_tier(tier: &TenantTier) -> Self {
        match tier {
            TenantTier::Basic => LlmPolicy {
                policy_id: format!("policy_basic_{}", uuid::Uuid::new_v4()),
                default_model: "llama-3.2-3b".to_string(),
                max_tokens_per_month: 100_000,
                allowed_models: vec!["llama-3.2-3b".to_string()],
                escalation_model: None,
                max_tool_calls_per_minute: 5,
                max_escalations_per_hour: 0,
            },
            TenantTier::Pro => LlmPolicy {
                policy_id: format!("policy_pro_{}", uuid::Uuid::new_v4()),
                default_model: "gpt-4o-mini".to_string(),
                max_tokens_per_month: 1_000_000,
                allowed_models: vec![
                    "gpt-4o-mini".to_string(),
                    "claude-3-haiku".to_string(),
                ],
                escalation_model: Some("gpt-4o".to_string()),
                max_tool_calls_per_minute: 30,
                max_escalations_per_hour: 10,
            },
            TenantTier::Compliance => LlmPolicy {
                policy_id: format!("policy_compliance_{}", uuid::Uuid::new_v4()),
                default_model: "gpt-4o".to_string(),
                max_tokens_per_month: 5_000_000,
                allowed_models: vec![
                    "gpt-4o".to_string(),
                    "claude-3-5-sonnet".to_string(),
                ],
                escalation_model: Some("gpt-4o".to_string()),
                max_tool_calls_per_minute: 60,
                max_escalations_per_hour: 50,
            },
            TenantTier::Telco | TenantTier::Insurance => LlmPolicy {
                policy_id: format!("policy_enterprise_{}", uuid::Uuid::new_v4()),
                default_model: "gpt-4o".to_string(),
                max_tokens_per_month: 10_000_000,
                allowed_models: vec![
                    "gpt-4o".to_string(),
                    "claude-3-5-sonnet".to_string(),
                    "claude-3-opus".to_string(),
                ],
                escalation_model: Some("claude-3-opus".to_string()),
                max_tool_calls_per_minute: 120,
                max_escalations_per_hour: 100,
            },
        }
    }
}

// === Connection Model (V6): Connection Management DTOs ===

/// A stored wallet connection record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRecord {
    pub pairwise_did: String,
    pub service_did: String,
    pub ucan_token: String,
    pub connected_at: i64,
    pub status: String,  // "active", "revoked"
}

/// Request to register a new wallet connection.
#[derive(Debug, Deserialize)]
pub struct CreateConnectionRequest {
    pub pairwise_did: String,
    /// Serialized UCAN token granting capabilities
    pub ucan_token: String,
}

/// Summary of a connection for list responses.
#[derive(Debug, Serialize)]
pub struct ConnectionSummary {
    pub pairwise_did: String,
    pub connected_at: i64,
    pub status: String,
}
