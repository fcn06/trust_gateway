use serde::{Deserialize, Serialize};

/// How an execution grant was obtained — tracks provenance of authorization decision.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum GrantClearance {
    /// Tier 0: policy auto-allowed the action.
    #[default]
    AutoApproved,
    /// Tier 1: human clicked "approve" in the portal.
    HumanApproved,
    /// Tier 2: human re-authenticated before approving.
    ElevatedApproval,
    /// Tier 3: human presented a verifiable credential (OID4VP).
    ProofVerified,
}

impl std::fmt::Display for GrantClearance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AutoApproved => write!(f, "auto_approved"),
            Self::HumanApproved => write!(f, "human_approved"),
            Self::ElevatedApproval => write!(f, "elevated_approval"),
            Self::ProofVerified => write!(f, "proof_verified"),
        }
    }
}

/// Financial impact budget limit
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct FinancialImpact {
    pub currency: String,
    pub amount: u64,
}

/// Execution budget grant rules
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct ExecutionBudget {
    #[serde(default)]
    pub max_actions: u32,
    #[serde(default)]
    pub max_duration_seconds: u32,
    #[serde(default)]
    pub max_external_calls: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_financial_impact: Option<FinancialImpact>,
}

/// Bounded Delegation Chain metadata
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct DelegationChain {
    pub delegator: String,
    pub delegate: String,
    pub delegation_depth: u8,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub allowed_resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost: Option<u64>,
    pub valid_until: i64,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub on_behalf_of: String,
}

/// Economic claim binding a payment token, credit reservation, or maximum cost limit to a grant.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq, Default)]
pub struct EconomicClaim {
    /// Currency code (e.g. "USD", "EUR", "CREDIT").
    pub currency: String,
    /// Maximum allowable cost for this tool execution in minor units (e.g. cents).
    pub max_cost_minor: u64,
    /// Ephemeral X42/H42 payment voucher or token (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_token: Option<String>,
    /// Pre-allocated quota reservation identifier (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_reservation_id: Option<String>,
}

/// Short-lived, action-specific execution grant token claims.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct ExecutionGrant {
    /// Unique grant identifier / JTI.
    #[serde(default, alias = "jti")]
    pub grant_id: String,

    /// Unique action ID.
    #[serde(default)]
    pub action_id: String,

    /// Tenant scope.
    pub tenant_id: String,

    /// Workspace scope.
    #[serde(default = "default_workspace_id")]
    pub workspace_id: String,

    /// Subject / Resource Owner identity (DID or user ID).
    #[serde(default, alias = "subject_id")]
    pub owner_did: String,

    /// Requester / Agent identity (DID or agent ID).
    #[serde(default, alias = "agent_id")]
    pub requester_did: String,

    /// Designated executor identity.
    #[serde(default)]
    pub executor_id: String,

    /// Exact action name authorized (e.g. "google.calendar.event.create").
    #[serde(default, alias = "tool_name")]
    pub allowed_action: String,

    /// Authorized tool version digest/tag.
    #[serde(default = "default_tool_version")]
    pub tool_version: String,

    /// Clearance level obtained.
    pub clearance: GrantClearance,

    /// Expiry timestamp (Unix epoch seconds).
    #[serde(alias = "exp")]
    pub expires_at: i64,

    /// Key ID of the signing key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// SHA-256 hash of canonical JSON arguments.
    pub input_hash: String,

    /// SHA-256 digest of policy evaluated.
    #[serde(default)]
    pub policy_hash: String,

    /// SHA-256 digest of signed tool manifest.
    #[serde(default)]
    pub registry_hash: String,

    /// Bounded delegation model metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<DelegationChain>,

    /// Execution budget grant bounds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<ExecutionBudget>,

    /// Economic claim and payment authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub economic_claim: Option<EconomicClaim>,

    /// B2B Negotiated Interaction Contract ID (if action is contract-governed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,

    /// B2B Negotiated Interaction Contract SHA-256 fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_hash: Option<String>,
}

fn default_tool_version() -> String {
    "1.0.0".to_string()
}

fn default_workspace_id() -> String {
    "default".to_string()
}

impl ExecutionGrant {
    /// Deterministic provider idempotency key binding tenant, workspace, and grant ID.
    /// Strictly uses underscore '_' separator per INV-009.
    pub fn provider_idempotency_key(&self) -> String {
        format!(
            "idemp_{}_{}_{}",
            self.tenant_id, self.workspace_id, self.grant_id
        )
    }
}

/// A signed grant — JWT string alongside decoded claims.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SignedGrant {
    pub token: String,
    pub claims: ExecutionGrant,
}
