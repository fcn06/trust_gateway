// ─────────────────────────────────────────────────────────────
// Policy decision types
//
// The output of the PolicyEngine: what should happen with a
// proposed action.
// ─────────────────────────────────────────────────────────────

use crate::approval::ApprovalTier;
use crate::proof::ProofRequest;
use serde::{Deserialize, Serialize};

/// The decision rendered by the `PolicyEngine` for an `ActionRequest`.
///
/// This replaces the old binary safe/unsafe tool classification
/// with a richer, attribute-based decision model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ActionDecision {
    /// Action is allowed to proceed immediately.
    /// Gateway will issue an `ExecutionGrant` and route to the executor.
    Allow {
        /// Which policy rule produced this decision.
        policy_id: String,
    },

    /// Action is denied outright.
    Deny {
        /// Human-readable reason for the denial.
        reason: String,
        /// Which policy rule produced this decision.
        policy_id: String,
    },

    /// Action requires human approval before proceeding.
    /// The gateway will create an `ApprovalRequest` and suspend execution.
    RequireApproval {
        /// The approval tier determines the UX: click, re-auth, etc.
        tier: ApprovalTier,
        /// Human-readable reason shown in the portal approval card.
        reason: String,
        /// Which policy rule produced this decision.
        policy_id: String,
    },

    /// Action requires the USER to present a verifiable credential
    /// before proceeding (OID4VP step-up).
    ///
    /// **Corrected flow**: The user/holder presents proof to the
    /// verifier (Host/Gateway). The portal merely renders the QR code
    /// for the user to scan with their wallet.
    RequireProof {
        /// Details of the proof required from the holder.
        proof_request: ProofRequest,
        /// Human-readable reason shown in the portal.
        reason: String,
        /// Which policy rule produced this decision.
        policy_id: String,
    },
}

impl ActionDecision {
    /// Returns true if the action can proceed without human intervention.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// Returns true if the action is completely blocked.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Returns true if the action requires some form of human step-up
    /// (approval click, re-auth, or verifiable presentation).
    pub fn requires_human(&self) -> bool {
        matches!(
            self,
            Self::RequireApproval { .. } | Self::RequireProof { .. }
        )
    }

    /// Returns the policy ID that produced this decision.
    pub fn policy_id(&self) -> &str {
        match self {
            Self::Allow { policy_id }
            | Self::Deny { policy_id, .. }
            | Self::RequireApproval { policy_id, .. }
            | Self::RequireProof { policy_id, .. } => policy_id,
        }
    }
}
