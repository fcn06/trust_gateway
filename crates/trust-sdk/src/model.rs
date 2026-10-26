use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Authentication assurance hierarchy
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum AuthLevel {
    #[default]
    Level1Anonymous = 1,
    Level2ApiKey = 2,
    Level3Session = 3,
    Level4VerifiablePresentation = 4,
    Level5WebAuthn = 5,
}

/// Standard Session Claims with RFC 8176 amr and Relying Party binding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SessionClaims {
    #[serde(default = "default_tenant_id")]
    pub tenant_id: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_level: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_action_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_input_hash: Option<String>,
}

fn default_tenant_id() -> String {
    "default".to_string()
}

/// Governance clearance tier
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
    Default,
)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    #[default]
    Tier0Auto,
    Tier1RequireHumanApproval,
    Tier2RequireElevatedApproval,
    Tier3Deny,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tier0Auto => write!(f, "tier0_auto"),
            Self::Tier1RequireHumanApproval => write!(f, "tier1_require_human_approval"),
            Self::Tier2RequireElevatedApproval => write!(f, "tier2_require_elevated_approval"),
            Self::Tier3Deny => write!(f, "tier3_deny"),
        }
    }
}

/// Economic cap constraint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct EconomicCap {
    pub currency: String,
    pub max_cost_minor_units: u64,
}

/// Call-chain context carried across agent execution hops for loop and depth governance
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq, Default)]
pub struct CallChainContext {
    pub trace_id: String,
    #[serde(default)]
    pub call_stack: Vec<String>,
    #[serde(default)]
    pub invocation_counts: HashMap<String, u32>,
}

impl CallChainContext {
    pub fn new(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            call_stack: Vec::new(),
            invocation_counts: HashMap::new(),
        }
    }
}

/// Actor context for the invocation
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq, Default)]
pub struct ActorContext {
    #[serde(default)]
    pub owner_did: String,
    #[serde(default)]
    pub requester_did: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Proposed action from an agent
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Default)]
pub struct ProposedAction {
    pub action_id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default = "default_workspace_id")]
    pub workspace_id: String,
    #[serde(default)]
    pub actor: ActorContext,
    #[serde(default)]
    pub call_chain: Option<CallChainContext>,
}

fn default_workspace_id() -> String {
    "default".to_string()
}

/// Economic claim binding a payment token, credit reservation, or maximum cost limit to a grant.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq, Default)]
pub struct EconomicClaim {
    pub currency: String,
    #[serde(default, alias = "max_cost_minor")]
    pub max_cost_minor_units: u64,
    #[serde(default, alias = "quota_reservation_id")]
    pub reservation_id: String,
    #[serde(default)]
    pub payer_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_token: Option<String>,
}

/// Execution budget constraints for execution resources.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq, Default)]
pub struct ExecutionBudget {
    #[serde(default, alias = "max_duration_seconds")]
    pub max_duration_secs: u32,
    #[serde(default)]
    pub max_egress_bytes: usize,
    #[serde(default, alias = "max_external_calls", alias = "max_actions")]
    pub call_limit: u32,
}

/// State of an execution transaction
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum TransactionOutcomeState {
    #[default]
    Success,
    Failed,
    Rejected,
    TimedOut,
}

/// Final execution result returned by executors
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Default)]
pub struct ExecutionResult {
    pub action_id: String,
    pub status: TransactionOutcomeState,
    #[serde(default)]
    pub connector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_idempotency_key: Option<String>,
    #[serde(default)]
    pub reconciled: bool,
    pub output: serde_json::Value,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<serde_json::Value>,
}

/// Policy evaluation outcome
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq, Default)]
pub struct PolicyDecision {
    pub action_id: String,
    pub tier: Tier,
    pub policy_fingerprint: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(default)]
    pub is_unmatched: bool,
}

/// Generic envelope wrapper
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
pub struct TrustEnvelope<T> {
    pub trace_id: String,
    pub timestamp: i64,
    pub payload: T,
}

/// Standard audit event
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
pub struct AuditEvent {
    pub event_id: String,
    pub timestamp: i64,
    pub event_type: String,
    pub tenant_id: String,
    pub trace_id: String,
    pub action_id: Option<String>,
    pub details: serde_json::Value,
    #[serde(default)]
    pub prev_hash: Option<String>,
    #[serde(default)]
    pub hash: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_level_ordering() {
        assert!(AuthLevel::Level5WebAuthn > AuthLevel::Level3Session);
        assert!(AuthLevel::Level5WebAuthn > AuthLevel::Level4VerifiablePresentation);
        assert!(AuthLevel::Level4VerifiablePresentation > AuthLevel::Level3Session);
        assert!(AuthLevel::Level3Session > AuthLevel::Level2ApiKey);
        assert!(AuthLevel::Level2ApiKey > AuthLevel::Level1Anonymous);
    }
}
