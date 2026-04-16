// ─────────────────────────────────────────────────────────────
// Execution Grant types
//
// The narrow, action-specific JWT that replaces broad session
// tokens for connector execution. This is the "leash" concept
// refined into a strict action grant.
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// An execution grant authorizating exactly one action on one connector.
///
/// This is a short-lived, action-specific token (typically 30s TTL).
/// Connectors MUST validate this grant instead of accepting broad
/// session JWTs. This is the key architectural change that makes
/// scoped delegation real.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionGrant {
    /// Unique grant identifier.
    pub grant_id: String,
    /// The action this grant authorizes (must match `ActionRequest.action_id`).
    pub action_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// DID of the resource owner.
    pub owner_did: String,
    /// DID of the entity that requested the action.
    pub requester_did: String,
    /// Exact action name this grant allows (e.g. "google.calendar.event.create").
    /// The connector MUST verify this matches the requested action.
    pub allowed_action: String,
    /// How this grant was obtained (auto-approved, human-approved, proof-verified).
    pub clearance: GrantClearance,
    /// Expiry timestamp (Unix epoch seconds). Typically now + 30s.
    pub expires_at: i64,
}

/// How an execution grant was obtained — tracks the provenance of the
/// authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantClearance {
    /// Tier 0: policy auto-allowed the action.
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

/// A signed grant — the actual token string alongside the decoded claims.
///
/// The `token` field contains the JWT-encoded grant that is passed to
/// connectors for validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGrant {
    /// The JWT-encoded grant string.
    pub token: String,
    /// The decoded grant claims (for local use without re-parsing).
    pub claims: ExecutionGrant,
}
