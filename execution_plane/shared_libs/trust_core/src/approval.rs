// ─────────────────────────────────────────────────────────────
// Approval types
//
// Models the approval lifecycle: request → pending → resolved.
// Supports tiered approval (click, re-auth, OID4VP proof).
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// The tier of approval required for a governed action.
///
/// Higher tiers provide stronger assurance but more friction.
/// The policy engine maps actions to tiers based on risk attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalTier {
    /// Tier 0: auto-allow. No human intervention needed.
    Tier0AutoAllow,
    /// Tier 1: simple portal click. Owner sees the action and approves.
    Tier1PortalClick,
    /// Tier 2: re-authentication required (e.g. WebAuthn challenge).
    Tier2ReAuthenticate,
    /// Tier 3: the USER must present a verifiable credential via their
    /// wallet (OpenID4VP). This is the strongest assurance level.
    ///
    /// **Corrected flow**: the user/holder presents proof.
    /// The portal renders the QR code; the gateway/Host verifies.
    Tier3VerifiedPresentation,
}

impl std::fmt::Display for ApprovalTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tier0AutoAllow => write!(f, "tier0_auto_allow"),
            Self::Tier1PortalClick => write!(f, "tier1_portal_click"),
            Self::Tier2ReAuthenticate => write!(f, "tier2_re_authenticate"),
            Self::Tier3VerifiedPresentation => write!(f, "tier3_verified_presentation"),
        }
    }
}

/// A request for human approval, created when the policy engine
/// returns `RequireApproval` or `RequireProof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique identifier for this approval request.
    pub approval_id: String,
    /// The action that triggered this approval.
    pub action_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// The tier of approval required.
    pub tier: ApprovalTier,
    /// Human-readable reason for requiring approval.
    pub reason: String,
    /// ID of the policy rule that triggered this requirement.
    pub policy_id: String,
    /// Summary of the proposed action for display in the portal.
    pub action_summary: ActionSummary,
    /// Whether OID4VP proof is required (Tier 3).
    pub proof_required: bool,
    /// Timestamp when the approval request was created.
    pub requested_at: chrono::DateTime<chrono::Utc>,
    /// The full action request, preserved for asynchronous dispatch after approval.
    pub action_request: crate::action::ActionRequest,
}

/// Human-readable summary of an action, used in approval cards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSummary {
    /// Action name, e.g. "google.calendar.event.create".
    pub action_name: String,
    /// Business category, e.g. "scheduling".
    pub category: String,
    /// What kind of operation (read, create, update, delete, transfer).
    pub operation: String,
    /// Monetary amount if relevant.
    pub amount: Option<String>,
    /// Who requested the action.
    pub requester: String,
    /// Source of the request (e.g. "ssi_agent", "whatsapp").
    pub source: String,
}

/// A persisted approval record — tracks the full lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// Unique identifier matching the original `ApprovalRequest`.
    pub approval_id: String,
    /// Correlates to the `ActionRequest.action_id`.
    pub action_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// The tier that was required.
    pub tier: ApprovalTier,
    /// Human-readable reason for requiring approval.
    pub reason: String,
    /// Current status of this approval.
    pub status: ApprovalStatus,
    /// Who approved or denied (DID), if resolved.
    pub resolved_by: Option<String>,
    /// Method used to resolve (click, re-auth, openid4vp).
    pub resolution_method: Option<String>,
    /// When the request was created.
    pub requested_at: chrono::DateTime<chrono::Utc>,
    /// When the request was resolved, if applicable.
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The full action request, preserved for asynchronous dispatch after approval.
    pub action_request: crate::action::ActionRequest,
}

/// The current status of an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Waiting for human action.
    Pending,
    /// Waiting for the user to present a verifiable credential.
    PendingProof,
    /// Human approved the action.
    Approved,
    /// Human denied the action.
    Denied,
    /// Approval request expired (action timed out).
    Expired,
    /// Action was dispatched and executed successfully by the daemon.
    Executed,
    /// Action was dispatched but execution failed.
    ExecutionFailed,
}

/// The result of an approval decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResult {
    /// Who approved or denied.
    pub resolved_by: String,
    /// How (click, re-auth, openid4vp).
    pub resolution_method: String,
    /// Optional additional notes from the approver.
    pub notes: Option<String>,
    /// When the decision was made.
    pub resolved_at: chrono::DateTime<chrono::Utc>,
}

impl ApprovalStatus {
    /// Returns the set of valid target states from this status.
    ///
    /// Enforces a strict state machine:
    /// ```text
    /// Pending       → Approved | Denied | Expired
    /// PendingProof  → Approved | Denied | Expired
    /// Approved      → Executed | ExecutionFailed
    /// Denied        → (terminal)
    /// Expired       → (terminal)
    /// Executed      → (terminal)
    /// ExecutionFailed → (terminal)
    /// ```
    pub fn valid_transitions(&self) -> &'static [ApprovalStatus] {
        match self {
            Self::Pending => &[Self::Approved, Self::Denied, Self::Expired],
            Self::PendingProof => &[Self::Approved, Self::Denied, Self::Expired],
            Self::Approved => &[Self::Executed, Self::ExecutionFailed],
            Self::Denied | Self::Expired | Self::Executed | Self::ExecutionFailed => &[],
        }
    }

    /// Whether this status is a terminal (final) state.
    pub fn is_terminal(&self) -> bool {
        self.valid_transitions().is_empty()
    }

    /// Check if transitioning to `target` is valid.
    pub fn can_transition_to(&self, target: &ApprovalStatus) -> bool {
        self.valid_transitions().contains(target)
    }
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::PendingProof => write!(f, "pending_proof"),
            Self::Approved => write!(f, "approved"),
            Self::Denied => write!(f, "denied"),
            Self::Expired => write!(f, "expired"),
            Self::Executed => write!(f, "executed"),
            Self::ExecutionFailed => write!(f, "execution_failed"),
        }
    }
}
