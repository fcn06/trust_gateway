// ─────────────────────────────────────────────────────────────
// OID4VP Proof types — Corrected role model
//
// The HOLDER (human user) presents proof.
// The VERIFIER (Host/Gateway) requests and checks proof.
// The portal merely renders the QR code for the user to scan.
//
// This module models the proof request (what the verifier asks),
// the proof challenge (the QR/deep-link data), and the proof
// result (what came back and whether it verified).
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// The type of proof mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofType {
    /// OpenID for Verifiable Presentations (OID4VP).
    /// The standard flow using DCQL or Presentation Exchange.
    OpenId4Vp,
}

impl std::fmt::Display for ProofType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenId4Vp => write!(f, "openid4vp"),
        }
    }
}

/// Describes what proof the HOLDER (user) must present.
///
/// Created by the VERIFIER (Host/Trust Gateway) when the policy
/// engine returns `RequireProof`. This is sent to the portal,
/// which renders it as a QR code or deep-link for the user.
///
/// **Important**: The portal does NOT present proof — it renders
/// the request. The USER scans the QR with their wallet and
/// presents the credential. The Host verifies the resulting VP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequest {
    /// Type of proof mechanism to use.
    pub proof_type: ProofType,

    /// The OpenID4VP presentation_definition or DCQL query.
    ///
    /// This specifies exactly what credential(s) and claim(s)
    /// the holder must present. Passed as opaque JSON to allow
    /// flexibility between Presentation Exchange v2 and DCQL.
    pub presentation_definition: serde_json::Value,

    /// Human-readable list of required claims for display, e.g.
    /// `["role:finance_approver", "org:acme_corp"]`.
    ///
    /// These are informational — the actual enforcement comes from
    /// `presentation_definition`. But they are useful for portal UX
    /// and audit trail readability.
    pub required_claims: Vec<String>,

    /// Nonce for replay protection. The wallet must include this
    /// in the VP response.
    pub challenge_nonce: String,
}

/// The data needed to render a proof challenge in the portal (QR code / deep-link).
///
/// Returned by `ProofVerifier::create_proof_challenge()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofChallenge {
    /// The `openid4vp://authorize?...` URI that the user must open
    /// (typically via QR code scan from their wallet).
    pub authorize_uri: String,

    /// Unique identifier for this proof session, used to correlate
    /// the callback.
    pub proof_session_id: String,

    /// The approval this proof challenge is tied to.
    pub approval_id: String,

    /// When this challenge expires (portal should show a countdown).
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Callback data received when the wallet submits a VP token.
///
/// Passed to `ProofVerifier::verify_presentation()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofCallback {
    /// The proof session ID from the challenge.
    pub proof_session_id: String,

    /// The VP token submitted by the wallet.
    pub vp_token: String,

    /// Presentation submission metadata (OpenID4VP spec).
    pub presentation_submission: Option<serde_json::Value>,

    /// The state parameter echoed back.
    pub state: Option<String>,
}

/// The result of verifying a holder's verifiable presentation.
///
/// Produced by the VERIFIER (Host) after processing the VP callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResult {
    /// Whether the VP verified successfully.
    pub verified: bool,

    /// DID of the holder who presented the credential, if resolved.
    pub holder_did: Option<String>,

    /// DID or identifier of the credential issuer.
    pub credential_issuer: Option<String>,

    /// The claims that were successfully verified, e.g.
    /// `["role:finance_approver"]`.
    pub presented_claims: Vec<String>,

    /// When verification was performed.
    pub verification_timestamp: chrono::DateTime<chrono::Utc>,

    /// Reason for verification failure, if `verified == false`.
    pub failure_reason: Option<String>,
}
