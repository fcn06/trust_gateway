// ─────────────────────────────────────────────────────────────
// Core trait definitions
//
// These traits define the contracts between gateway components.
// Implementations live in separate crates (trust_policy,
// trust_gateway, approval_service, etc.).
//
// All traits are async and Send + Sync for use in concurrent
// Tokio/Axum environments.
// ─────────────────────────────────────────────────────────────

use crate::action::{ActionRequest, ActionResult};
use crate::approval::{ApprovalRecord, ApprovalRequest, ApprovalResult};
use crate::audit::AuditEvent;
use crate::decision::ActionDecision;
use crate::errors::*;
use crate::grant::{GrantClearance, SignedGrant};
use crate::proof::{ProofCallback, ProofChallenge, ProofRequest, ProofResult};

// ── Policy Engine ──────────────────────────────────────

/// Evaluates an `ActionRequest` against the configured policy rules
/// and produces an `ActionDecision`.
///
/// Replaces the old `policy.json` safe_tools array with attribute-based
/// rule matching.
#[async_trait::async_trait]
pub trait PolicyEngine: Send + Sync {
    async fn evaluate(&self, req: &ActionRequest) -> Result<ActionDecision, PolicyError>;

    /// List all configured rules as JSON objects (for the policy management API).
    /// Default returns empty — implementations override for introspection support.
    fn list_rules_json(&self) -> Vec<serde_json::Value> {
        Vec::new()
    }
}

// ── Approval Store ─────────────────────────────────────

/// Persists and manages approval requests and their lifecycle.
///
/// The default implementation uses NATS KV.
#[async_trait::async_trait]
pub trait ApprovalStore: Send + Sync {
    /// Create a new pending approval request.
    async fn create(&self, req: ApprovalRequest) -> Result<ApprovalRecord, StoreError>;

    /// Get an approval record by its ID.
    async fn get(&self, id: &str) -> Result<Option<ApprovalRecord>, StoreError>;

    /// Mark an approval as approved.
    async fn mark_approved(&self, id: &str, result: ApprovalResult) -> Result<(), StoreError>;

    /// Mark an approval as denied.
    async fn mark_denied(&self, id: &str, result: ApprovalResult) -> Result<(), StoreError>;

    /// Mark an approval as executed (terminal — action completed successfully).
    /// Used by the daemon to prevent double-dispatch on restart.
    async fn mark_executed(&self, id: &str) -> Result<(), StoreError>;

    /// Mark an approval as execution-failed (terminal — connector error).
    async fn mark_execution_failed(&self, id: &str, error: &str) -> Result<(), StoreError>;

    /// List all pending approvals for a tenant.
    async fn list_pending(&self, tenant_id: &str) -> Result<Vec<ApprovalRecord>, StoreError>;
}

// ── Grant Issuer ───────────────────────────────────────

/// Issues narrow, action-specific ExecutionGrant JWTs.
///
/// The grant replaces broad session tokens for connector execution.
/// Each grant is tied to exactly one action, one connector, and
/// has a very short TTL (typically 30 seconds).
pub trait GrantIssuer: Send + Sync {
    fn issue_execution_grant(
        &self,
        req: &ActionRequest,
        clearance: GrantClearance,
        ttl: std::time::Duration,
    ) -> Result<SignedGrant, GrantError>;
}

// ── Connector Dispatcher ───────────────────────────────

/// Routes an authorized action to the appropriate executor
/// (MCP connector, Claw skill executor, or VP server).
///
/// The dispatcher validates the `ExecutionGrant` and delegates
/// to the correct backend based on `executor_type`.
#[async_trait::async_trait]
pub trait ConnectorDispatcher: Send + Sync {
    async fn execute(
        &self,
        req: &ActionRequest,
        grant: &SignedGrant,
    ) -> Result<ActionResult, ConnectorError>;
}

// ── Proof Verifier (OID4VP — Corrected Roles) ─────────

/// Manages the OID4VP proof flow using the corrected role model:
///
/// 1. **Verifier** (Host/Gateway) creates a presentation request
/// 2. Portal renders the request as a QR code
/// 3. **Holder** (User) scans and presents a VC via their wallet
/// 4. **Verifier** receives the VP callback and verifies it
///
/// The portal NEVER presents proof — it only renders the request.
#[async_trait::async_trait]
pub trait ProofVerifier: Send + Sync {
    /// Create a proof challenge for the portal to render.
    ///
    /// Returns a `ProofChallenge` containing the `openid4vp://authorize`
    /// URI that the user must scan with their wallet.
    async fn create_proof_challenge(
        &self,
        approval_id: &str,
        req: &ProofRequest,
    ) -> Result<ProofChallenge, ProofError>;

    /// Verify the VP submitted by the holder (user).
    ///
    /// Called when the wallet sends the VP token to the callback endpoint.
    /// Returns a `ProofResult` indicating whether the claims were verified.
    async fn verify_presentation(
        &self,
        callback: ProofCallback,
    ) -> Result<ProofResult, ProofError>;
}

// ── Audit Sink ─────────────────────────────────────────

/// Publishes audit events to the tamper-evident trail.
///
/// The primary implementation publishes to NATS JetStream subjects:
///   - `audit.action.{action_id}`
///   - `audit.session.{jti}`
///   - `audit.tenant.{tenant_id}`
#[async_trait::async_trait]
pub trait AuditSink: Send + Sync {
    async fn publish(&self, event: AuditEvent) -> Result<(), AuditError>;
    async fn flush(&self) {}
}

// ── Nonce Store (JTI Replay Prevention) ────────────────

/// A consume-once nonce store for ExecutionGrant JTI replay prevention.
///
/// Each grant_id (JTI) may only be consumed once within a TTL window.
/// Implementations must be safe for concurrent access.
///
/// The primary implementation is an in-memory HashMap with TTL-based
/// auto-expiry. For horizontally scaled executors, a NATS KV-backed
/// implementation can be substituted without changing call sites.
#[async_trait::async_trait]
pub trait NonceStore: Send + Sync {
    /// Attempt to consume a nonce. Returns Ok(()) if it has never been
    /// consumed before, or Err(NonceError::AlreadyConsumed) if it has.
    ///
    /// Implementations should auto-expire entries after `ttl` to bound
    /// memory usage.
    async fn consume(&self, jti: &str, ttl: std::time::Duration) -> Result<(), NonceError>;
}

// ── Agent Registry ─────────────────────────────────────

/// Manages the lifecycle of registered agents.
///
/// Every agent, swarm, or automation that interacts with the
/// Trust Gateway must be registered with a distinct identity.
///
/// The community implementation uses NATS KV.
/// Enterprise implementations may back this with a SQL database,
/// SCIM provider, or external identity platform.
#[async_trait::async_trait]
pub trait AgentRegistry: Send + Sync {
    /// Register a new agent. Returns the created record.
    async fn register(&self, req: crate::agent::RegisterAgentRequest)
        -> Result<crate::agent::AgentRecord, StoreError>;

    /// Look up an agent by its ID.
    async fn get(&self, agent_id: &str)
        -> Result<Option<crate::agent::AgentRecord>, StoreError>;

    /// Update an existing agent's fields.
    async fn update(&self, agent_id: &str, req: crate::agent::UpdateAgentRequest)
        -> Result<crate::agent::AgentRecord, StoreError>;

    /// List all registered agents, optionally filtered by status.
    async fn list(&self, status_filter: Option<crate::agent::AgentStatus>)
        -> Result<Vec<crate::agent::AgentRecord>, StoreError>;

    /// Activate the kill switch for an agent (immediate block).
    async fn kill(&self, agent_id: &str) -> Result<(), StoreError>;

    /// Deactivate the kill switch for an agent.
    async fn revive(&self, agent_id: &str) -> Result<(), StoreError>;

    /// Update the last_seen timestamp (called on every action proposal).
    async fn touch(&self, agent_id: &str) -> Result<(), StoreError>;

    /// Resolve an agent by source context (source_type mapping).
    /// Returns None if no agent is registered for this source.
    async fn resolve_by_source(&self, source_type: &str)
        -> Result<Option<crate::agent::AgentRecord>, StoreError>;
}

// ── Authenticator ─────────────────────────────────────

/// Abstracts the authentication mechanism so that the Community edition's
/// WebAuthn implementation can be swapped for Enterprise SSO providers
/// (Entra ID, Okta, SAML) without modifying the gateway or host crate.
///
/// ## Community Implementation
/// `WebAuthnAuthenticator` — passkey-based, self-hosted.
#[async_trait::async_trait]
pub trait Authenticator: Send + Sync {
    /// Validate a session token and return the authenticated identity.
    ///
    /// Returns `Ok(AuthenticatedIdentity)` if the token is valid,
    /// or an appropriate error if validation fails.
    async fn validate_session(
        &self,
        token: &str,
    ) -> Result<AuthenticatedIdentity, AuthError>;

    /// Initiate a re-authentication challenge (Tier 2).
    ///
    /// Returns a challenge that the frontend must present to the user.
    /// The challenge format depends on the implementation (WebAuthn
    /// assertion, OIDC step-up, etc.).
    async fn create_reauth_challenge(
        &self,
        user_id: &str,
    ) -> Result<serde_json::Value, AuthError>;

    /// Verify a re-authentication response.
    async fn verify_reauth(
        &self,
        user_id: &str,
        response: &serde_json::Value,
    ) -> Result<bool, AuthError>;
}

/// The identity extracted from a validated session token.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthenticatedIdentity {
    /// Unique user identifier (DID or internal UUID).
    pub user_id: String,
    /// Tenant the user belongs to.
    pub tenant_id: String,
    /// Display name for audit trails.
    pub display_name: Option<String>,
    /// Email address (if available from the IdP).
    ///
    /// This is `None` for authentication methods that don't provide email
    /// (e.g., WebAuthn/passkeys). Identity claims are carried by DIDs and
    /// Verifiable Credentials, not the session token. Enterprise SSO
    /// implementations (Entra ID, Okta) populate this from id_token claims.
    pub email: Option<String>,
    /// The authentication method used (webauthn, oidc, saml).
    pub auth_method: String,
    /// Session identifier for audit correlation.
    pub session_id: String,
}

/// Errors from the Authenticator.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid or expired session token: {0}")]
    InvalidToken(String),
    #[error("user not found: {user_id}")]
    UserNotFound { user_id: String },
    #[error("re-authentication required")]
    ReauthRequired,
    #[error("re-authentication failed: {0}")]
    ReauthFailed(String),
    #[error("identity provider error: {0}")]
    ProviderError(String),
    #[error("authenticator internal error: {0}")]
    Internal(String),
}

