use serde::{Deserialize, Serialize};

/// Resilient Transaction Outcome States for external SaaS mutations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransactionOutcomeState {
    Succeeded,
    Failed,
    Denied,
    TimedOut,
    UnknownOutcome,
    ReconciliationRequired,
}

impl std::fmt::Display for TransactionOutcomeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Succeeded => write!(f, "succeeded"),
            Self::Failed => write!(f, "failed"),
            Self::Denied => write!(f, "denied"),
            Self::TimedOut => write!(f, "timed_out"),
            Self::UnknownOutcome => write!(f, "unknown_outcome"),
            Self::ReconciliationRequired => write!(f, "reconciliation_required"),
        }
    }
}

/// Monetary amount representation
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct Money {
    pub currency: String,
    pub amount_cents: u64,
}

/// Explicit operation metadata attached to governed tool descriptors and requests
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct OperationAttributes {
    /// Classification: "read_only" | "financial_mutation" | "data_egress" | "destructive"
    pub operation_kind: String,
    pub resource: Option<String>,
    pub amount: Option<Money>,
    pub beneficiary: Option<String>,
}

impl Default for OperationAttributes {
    fn default() -> Self {
        Self {
            operation_kind: "read_only".to_string(),
            resource: None,
            amount: None,
            beneficiary: None,
        }
    }
}

/// Proposed action envelope submitted by agents for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProposedAction {
    pub action_id: String,
    pub tenant_id: String,
    #[serde(default = "default_workspace_id")]
    pub workspace_id: String,
    pub requester_id: String,
    pub tool_name: String,
    pub operation_attributes: OperationAttributes,
    pub arguments: serde_json::Value,
    pub timestamp: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_context: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_chain_context: Option<CallChainContext>,
}

/// Call-chain context carried across agent execution hops for loop and depth governance
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct CallChainContext {
    pub trace_id: String,
    #[serde(default)]
    pub call_stack: Vec<String>,
    #[serde(default)]
    pub invocation_counts: std::collections::HashMap<String, u32>,
}

impl CallChainContext {
    pub fn new(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            call_stack: Vec::new(),
            invocation_counts: std::collections::HashMap::new(),
        }
    }
}

/// Policy evaluation outcome
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PolicyDecision {
    pub action_id: String,
    pub approved: bool,
    pub clearance_level: String, // "auto_approved" | "human_approved" | "denied"
    pub policy_fingerprint: String,
    pub reason: String,
}

/// Short-lived Ed25519-signed authorization grant
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExecutionGrant {
    pub grant_id: String,
    pub action_id: String,
    pub tenant_id: String,
    #[serde(default = "default_workspace_id")]
    pub workspace_id: String,
    pub tool_name: String,
    pub input_hash: String,
    pub issuer: String,
    pub expires_at: i64,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_hash: Option<String>,
}

impl ExecutionGrant {
    /// Deterministic provider idempotency key binding tenant, workspace, and grant ID.
    pub fn provider_idempotency_key(&self) -> String {
        format!(
            "idemp_{}_{}_{}",
            self.tenant_id, self.workspace_id, self.grant_id
        )
    }
}

fn default_workspace_id() -> String {
    "default".to_string()
}

/// Granted action payload dispatched to executors
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GrantedAction {
    pub grant: ExecutionGrant,
    pub raw_grant_jwt: String,
    pub action_arguments: serde_json::Value,
}

/// Final execution result returned by executors
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExecutionResult {
    pub action_id: String,
    pub status: TransactionOutcomeState,
    pub connector: String,
    pub external_reference: Option<String>,
    #[serde(default)]
    pub provider_idempotency_key: Option<String>,
    #[serde(default)]
    pub reconciled: bool,
    pub output: serde_json::Value,
    pub duration_ms: u64,
}

/// Generic envelope wrapper
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustEnvelope<T> {
    pub trace_id: String,
    pub timestamp: i64,
    pub payload: T,
}
