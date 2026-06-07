// ─────────────────────────────────────────────────────────────
// Port DTOs — Data types used by the edition-agnostic port traits.
//
// These DTOs define the contract between Community and Professional
// adapter implementations. They live in trust_core so both editions
// depend on the same types.
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// Notification payload sent when an approval request is created.
/// Community edition renders this in the dashboard; Professional
/// edition can route it to Telegram, Slack, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalNotification {
    /// Unique identifier for the approval request.
    pub approval_id: String,
    /// Human-readable name of the action requiring approval.
    pub action_name: String,
    /// Approval tier (e.g., "tier1", "tier2", "tier3").
    pub tier: String,
    /// Human-readable reason from the policy rule.
    pub reason: String,
}

/// Identity resolved from an external source (OAuth2, VP, etc.).
/// Community edition always returns `None`; Professional edition
/// performs real resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedIdentity {
    /// The resolved DID.
    pub did: String,
    /// Optional display name for the resolved identity.
    pub display_name: Option<String>,
}
