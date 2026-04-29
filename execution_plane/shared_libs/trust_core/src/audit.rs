// ─────────────────────────────────────────────────────────────
// Audit event types
//
// Standardized lifecycle events for the tamper-evident audit
// trail (published to NATS JetStream).
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// A single audit event in the action lifecycle.
///
/// Published to NATS JetStream subjects:
///   - `audit.action.{action_id}`
///   - `audit.session.{jti}`
///   - `audit.tenant.{tenant_id}`
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AuditEvent {
    /// Unique event identifier.
    pub event_id: String,
    /// Correlates to the `ActionRequest.action_id` (if action-related).
    pub action_id: Option<String>,
    /// Session correlation token from the original JWT.
    pub session_jti: Option<String>,
    /// Tenant scope.
    pub tenant_id: String,
    /// When this event occurred.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Which service/component emitted this event.
    pub component: String,
    /// The lifecycle event type.
    pub event_type: AuditEventType,
    /// Structured payload with event-specific data.
    pub payload: serde_json::Value,
    /// SHA-256 hash of the previous event in the chain (None for genesis).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    /// SHA-256 hash of this event's canonical form (for chain verification).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<String>,
}

/// All possible lifecycle event types in the trust gateway audit trail.
///
/// Events are ordered by their typical occurrence in the action lifecycle:
/// proposed → evaluated → (approval/proof cycle) → granted → invoked → result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // ── Action lifecycle ──

    /// An action was proposed by an agent or automation.
    ActionProposed,
    /// The policy engine evaluated the action and rendered a decision.
    PolicyEvaluated,

    // ── Approval lifecycle ──

    /// An approval request was created (Tier 1 or Tier 2).
    ApprovalRequested,
    /// A human approved the action.
    ApprovalApproved,
    /// A human denied the action.
    ApprovalDenied,

    // ── OID4VP proof lifecycle (corrected: user presents proof) ──

    /// A proof challenge was created and rendered in the portal.
    /// The user must now scan the QR with their wallet.
    ProofRequested,
    /// The user presented a verifiable credential via their wallet.
    /// The VP token was received but not yet verified.
    ProofPresented,
    /// The host verified the presented VP.
    /// Payload includes: verified (bool), credential_issuer, presented_claims.
    ProofVerified,

    // ── Execution lifecycle ──

    /// An ExecutionGrant JWT was issued.
    GrantIssued,
    /// A connector or skill executor was invoked.
    ConnectorInvoked,
    /// The action completed successfully.
    ActionSucceeded,
    /// The action failed.
    ActionFailed,
    /// A dispatch attempt failed and is being retried.
    ActionRetried,

    // ── Security events ──

    /// An ExecutionGrant JWT was replayed (same JTI presented twice).
    GrantReplayBlocked,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ActionProposed => "action.proposed",
            Self::PolicyEvaluated => "policy.evaluated",
            Self::ApprovalRequested => "approval.requested",
            Self::ApprovalApproved => "approval.approved",
            Self::ApprovalDenied => "approval.denied",
            Self::ProofRequested => "proof.requested",
            Self::ProofPresented => "proof.presented",
            Self::ProofVerified => "proof.verified",
            Self::GrantIssued => "grant.issued",
            Self::ConnectorInvoked => "connector.invoked",
            Self::ActionSucceeded => "action.succeeded",
            Self::ActionFailed => "action.failed",
            Self::ActionRetried => "action.retried",
            Self::GrantReplayBlocked => "grant.replay_blocked",
        };
        write!(f, "{}", s)
    }
}

impl AuditEvent {
    /// Create a new audit event with auto-generated ID and timestamp.
    pub fn new(
        event_type: AuditEventType,
        component: impl Into<String>,
        tenant_id: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            action_id: None,
            session_jti: None,
            tenant_id: tenant_id.into(),
            timestamp: chrono::Utc::now(),
            component: component.into(),
            event_type,
            payload,
            prev_hash: None,
            event_hash: None,
        }
    }

    /// Set the action_id for correlation.
    pub fn with_action_id(mut self, action_id: impl Into<String>) -> Self {
        self.action_id = Some(action_id.into());
        self
    }

    /// Set the session JTI for correlation.
    pub fn with_session_jti(mut self, jti: impl Into<String>) -> Self {
        self.session_jti = Some(jti.into());
        self
    }
}
