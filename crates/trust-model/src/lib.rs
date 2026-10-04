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

/// Execution budget constraints for execution resources.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq, Default)]
pub struct ExecutionBudget {
    #[serde(default)]
    pub max_duration_seconds: u32,
    #[serde(default)]
    pub max_external_calls: u32,
}

/// Short-lived Ed25519-signed authorization grant
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, Default)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub economic_claim: Option<EconomicClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<ExecutionBudget>,
}

impl ExecutionGrant {
    /// Deterministic provider idempotency key binding tenant, workspace, and grant ID.
    pub fn provider_idempotency_key(&self) -> String {
        format!(
            "idemp_{}_{}_{}",
            self.tenant_id, self.workspace_id, self.grant_id
        )
    }

    /// Fluent builder method to attach an economic claim to the grant.
    pub fn with_economic_claim(mut self, claim: Option<EconomicClaim>) -> Self {
        self.economic_claim = claim;
        self
    }

    /// Fluent builder method to attach execution budget constraints to the grant.
    pub fn with_budget(mut self, budget: Option<ExecutionBudget>) -> Self {
        self.budget = budget;
        self
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<serde_json::Value>,
}

/// Generic envelope wrapper
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustEnvelope<T> {
    pub trace_id: String,
    pub timestamp: i64,
    pub payload: T,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_grant_backward_compatibility() {
        let legacy_json = serde_json::json!({
            "grant_id": "grant_123",
            "action_id": "act_456",
            "tenant_id": "tenant_xyz",
            "workspace_id": "default",
            "tool_name": "orders.read",
            "input_hash": "sha256_hash",
            "issuer": "gateway_1",
            "expires_at": 1700000000,
            "nonce": "nonce_789"
        });

        let grant: ExecutionGrant = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(grant.grant_id, "grant_123");
        assert!(grant.economic_claim.is_none());
        assert!(grant.budget.is_none());

        // Serialized output should omit economic_claim and budget
        let serialized = serde_json::to_value(&grant).unwrap();
        assert!(serialized.get("economic_claim").is_none());
        assert!(serialized.get("budget").is_none());
    }

    #[test]
    fn test_execution_grant_with_economic_claim_and_budget() {
        let grant = ExecutionGrant {
            grant_id: "grant_eco_001".to_string(),
            action_id: "act_eco_001".to_string(),
            tenant_id: "tenant_enterprise".to_string(),
            workspace_id: "prod".to_string(),
            tool_name: "stripe.charge".to_string(),
            input_hash: "hash_abc".to_string(),
            issuer: "trust_gateway".to_string(),
            expires_at: 1750000000,
            nonce: "nonce_eco".to_string(),
            contract_id: None,
            contract_hash: None,
            economic_claim: Some(EconomicClaim {
                currency: "USD".to_string(),
                max_cost_minor: 5000,
                payment_token: Some("x42_token_payload".to_string()),
                quota_reservation_id: Some("res_12345".to_string()),
            }),
            budget: Some(ExecutionBudget {
                max_duration_seconds: 30,
                max_external_calls: 3,
            }),
        };

        let json = serde_json::to_value(&grant).unwrap();
        assert_eq!(json["economic_claim"]["currency"], "USD");
        assert_eq!(json["economic_claim"]["max_cost_minor"], 5000);
        assert_eq!(json["budget"]["max_duration_seconds"], 30);

        let roundtrip: ExecutionGrant = serde_json::from_value(json).unwrap();
        assert_eq!(roundtrip.economic_claim.unwrap().currency, "USD");
        assert_eq!(roundtrip.budget.unwrap().max_external_calls, 3);
    }
}
