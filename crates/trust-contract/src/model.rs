use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Monetary amount represented in integer minor units (e.g. cents).
/// Prevents floating-point ambiguity in financial contract terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContractMoney {
    pub amount_minor: u64,
    pub currency: String,
}

/// Identifies an authenticated enterprise party (DID-based).
/// Supports `did:web`, `did:twin`, and general verified DIDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PartyIdentity {
    pub did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
}

impl PartyIdentity {
    pub fn new_did(did: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            tenant_id: None,
            agent_id: None,
            organization_id: None,
        }
    }

    pub fn is_did_web(&self) -> bool {
        self.did.starts_with("did:web:")
    }

    pub fn is_did_twin(&self) -> bool {
        self.did.starts_with("did:twin:")
    }
}

/// Declared business purpose for an interaction contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Purpose {
    /// Machine-stable identifier (e.g. "supplier_order_management")
    pub code: String,
    /// Human-readable explanation
    pub description: String,
}

/// Stable capability bound to the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContractCapability {
    /// Reverse-DNS capability ID (e.g. "io.company.orders@v1")
    pub capability_id: String,
    /// Authorized operations (e.g. ["quote", "create", "status", "cancel"])
    pub operations: Vec<String>,
    /// Optional parameter constraint schema/rules
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter_constraints: Option<serde_json::Value>,
    /// Optional result constraints
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_constraints: Option<serde_json::Value>,
}

/// Business, operational, and financial constraints agreed upon.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContractConstraints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_transaction_value: Option<ContractMoney>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_geographies: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_terms: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom_constraints: BTreeMap<String, serde_json::Value>,
}

/// Data boundary policies for contract-governed executions.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DataPolicy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prohibited_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u32>,
}

/// Contractual obligation description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Obligation {
    pub code: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_by: Option<DateTime<Utc>>,
}

/// Commercial and settlement terms.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CommercialTerms {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_term: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_instrument: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_details: Option<serde_json::Value>,
}

/// Temporal validity of the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContractValidity {
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

impl ContractValidity {
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.valid_from && now <= self.valid_until
    }
}

/// Protocol specification binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProtocolBinding {
    pub protocol_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_semantics: Option<String>,
}

impl Default for ProtocolBinding {
    fn default() -> Self {
        Self {
            protocol_version: "nicp/1.0".to_string(),
            callback_semantics: None,
        }
    }
}

/// Cryptographic evidence of delegated authority (e.g. UCAN / VP hash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AuthorityReference {
    pub auth_type: String,
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Mutual cryptographic attestation signature record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContractAttestation {
    pub contract_id: String,
    pub contract_hash: String,
    pub signer_did: String,
    pub signature_algorithm: String,
    pub signature: String,
    pub signed_at: DateTime<Utc>,
}

/// Sealed cryptographic receipt emitted after successful contract-governed execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExecutionReceipt {
    pub receipt_id: String,
    pub grant_jti: String,
    pub contract_id: String,
    pub contract_hash: String,
    pub capability_id: String,
    pub input_hash: String,
    pub output_hash: String,
    pub issuer_did: String,
    pub counterparty_did: String,
    pub outcome: String,
    pub executed_at: DateTime<Utc>,
    pub signature: String,
}

/// Signable representation of an ExecutionReceipt for deterministic hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignableReceiptPayload {
    pub receipt_id: String,
    pub grant_jti: String,
    pub contract_id: String,
    pub contract_hash: String,
    pub capability_id: String,
    pub input_hash: String,
    pub output_hash: String,
    pub issuer_did: String,
    pub counterparty_did: String,
    pub outcome: String,
    pub executed_at: DateTime<Utc>,
}

impl From<&ExecutionReceipt> for SignableReceiptPayload {
    fn from(r: &ExecutionReceipt) -> Self {
        Self {
            receipt_id: r.receipt_id.clone(),
            grant_jti: r.grant_jti.clone(),
            contract_id: r.contract_id.clone(),
            contract_hash: r.contract_hash.clone(),
            capability_id: r.capability_id.clone(),
            input_hash: r.input_hash.clone(),
            output_hash: r.output_hash.clone(),
            issuer_did: r.issuer_did.clone(),
            counterparty_did: r.counterparty_did.clone(),
            outcome: r.outcome.clone(),
            executed_at: r.executed_at,
        }
    }
}

/// Attestation, authority, and reputation evidence container.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContractEvidence {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<ContractAttestation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_evidence: Vec<AuthorityReference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reputation_receipts: Vec<ExecutionReceipt>,
}

/// Mapping from semantic operation to concrete tool registry identifier.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CapabilityBinding {
    pub semantic_operation: String,
    pub tool_id: String,
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub operation_mappings: std::collections::HashMap<String, String>,
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub field_mappings: std::collections::HashMap<String, String>,
}

/// Lightweight contract context embedded in action requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContractContext {
    pub contract_id: String,
    pub contract_hash: String,
    pub capability_id: String,
}

/// High-level interaction contract aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InteractionContract {
    pub contract_id: String,
    pub version: u32,
    pub state: crate::state_machine::ContractState,

    pub issuer: PartyIdentity,
    pub counterparty: PartyIdentity,

    pub purpose: Purpose,

    pub capabilities: Vec<ContractCapability>,

    pub constraints: ContractConstraints,

    pub data_policy: DataPolicy,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<Obligation>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commercial_terms: Option<CommercialTerms>,

    pub validity: ContractValidity,

    pub protocol: ProtocolBinding,

    #[serde(default)]
    pub evidence: ContractEvidence,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_contract_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_contract_hash: Option<String>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Signable payload representation of an InteractionContract.
/// Excludes signatures, runtime state, and evidence for deterministic hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignableContractPayload {
    pub contract_id: String,
    pub version: u32,
    pub issuer: PartyIdentity,
    pub counterparty: PartyIdentity,
    pub purpose: Purpose,
    pub capabilities: Vec<ContractCapability>,
    pub constraints: ContractConstraints,
    pub data_policy: DataPolicy,
    pub obligations: Vec<Obligation>,
    pub commercial_terms: Option<CommercialTerms>,
    pub validity: ContractValidity,
    pub protocol: ProtocolBinding,
    pub parent_contract_id: Option<String>,
    pub previous_contract_hash: Option<String>,
}

impl From<&InteractionContract> for SignableContractPayload {
    fn from(c: &InteractionContract) -> Self {
        Self {
            contract_id: c.contract_id.clone(),
            version: c.version,
            issuer: c.issuer.clone(),
            counterparty: c.counterparty.clone(),
            purpose: c.purpose.clone(),
            capabilities: c.capabilities.clone(),
            constraints: c.constraints.clone(),
            data_policy: c.data_policy.clone(),
            obligations: c.obligations.clone(),
            commercial_terms: c.commercial_terms.clone(),
            validity: c.validity.clone(),
            protocol: c.protocol.clone(),
            parent_contract_id: c.parent_contract_id.clone(),
            previous_contract_hash: c.previous_contract_hash.clone(),
        }
    }
}
