// ─────────────────────────────────────────────────────────────
// Edition Port Traits — Dependency inversion for CE/Pro separation.
//
// These traits define the boundaries between Community and
// Professional editions. Community provides boring, local-only
// implementations. Professional provides rich external integrations.
//
// Design rules:
// - Traits are async and Send + Sync for Tokio environments.
// - No transport dependencies (no NATS, no Axum) — pure contracts.
// - Community adapters MUST NOT make external HTTP calls.
// - Professional adapters live in the private professional repository.
// ─────────────────────────────────────────────────────────────

use crate::ports_dto::{ApprovalNotification, ResolvedIdentity};

/// Notification channel for approval escalations.
///
/// - **Community**: Publishes to `ui.v1.local.events` via NATS (dashboard notification).
/// - **Professional**: Routes to Telegram, Slack, email, or custom webhook.
#[async_trait::async_trait]
pub trait ApprovalNotifier: Send + Sync {
    /// Notify that an approval has been requested.
    async fn notify_approval_requested(
        &self,
        request: &ApprovalNotification,
    ) -> anyhow::Result<()>;
}

/// External identity resolution.
///
/// - **Community**: Always returns `Ok(None)` (no external identity sources).
/// - **Professional**: Resolves via OAuth2, VP tokens, or external directory.
#[async_trait::async_trait]
pub trait ExternalIdentityResolver: Send + Sync {
    /// Attempt to resolve an external identity for the given subject.
    async fn resolve(&self, subject: &str) -> anyhow::Result<Option<ResolvedIdentity>>;
}

/// Inbound transport for external messages.
///
/// - **Community**: No-op (no external message transport).
/// - **Professional**: DIDComm, Telegram bot, or other ingress.
#[async_trait::async_trait]
pub trait TransportIngress: Send + Sync {
    /// Start the transport ingress (e.g., open a webhook listener).
    async fn start(&self) -> anyhow::Result<()>;
    /// Stop the transport ingress gracefully.
    async fn stop(&self) -> anyhow::Result<()>;
}

/// Multi-tenancy provider.
///
/// - **Community**: Always returns `"local"`.
/// - **Professional**: Resolves real tenant IDs from request context.
#[async_trait::async_trait]
pub trait TenantProvider: Send + Sync {
    /// Return the current tenant ID.
    fn current(&self) -> &str;
    /// Resolve a tenant from a hint (e.g., hostname, header value).
    async fn resolve(&self, hint: &str) -> anyhow::Result<String>;
}

/// Credential / secret provider.
///
/// - **Community**: Reads secrets from environment variables only.
/// - **Professional**: Reads from OAuth vault, cloud KMS, or secret manager.
#[async_trait::async_trait]
pub trait CredentialProvider: Send + Sync {
    /// Retrieve a secret by key name.
    async fn get_secret(&self, key: &str) -> anyhow::Result<Option<String>>;
}

/// Port for dynamic tool listing interception and stateful overlays.
///
/// - **Community (Default)**: A stateless bypass adapter that always returns the
///   flat list of default and builtin tools (a simple no-op pass-through).
/// - **Professional**: A NATS-backed stateful adapter that queries the active session's
///   `active_bundle` from `mcp_session_state` KV, filters the allowed tool list,
///   gases up the progressive unlock limits, and injects context-sensitive meta-tools.
#[async_trait::async_trait]
pub trait ToolListingOverlay: Send + Sync {
    /// Intercepts tool listing to filter, secure, and enrich the tools list.
    async fn enrich_tool_list(
        &self,
        session_jti: &str,
        base_tools: Vec<crate::tool_registry::ToolDescriptor>,
    ) -> anyhow::Result<Vec<crate::tool_registry::ToolDescriptor>>;

    /// Intercepts action dispatch to apply professional governance / meta-tool logic.
    async fn intercept_action(
        &self,
        session_jti: &str,
        req: &crate::action::ActionRequest,
    ) -> anyhow::Result<Option<crate::action::ActionResult>>;
}

/// Default stateless bypass adapter for `ToolListingOverlay` (Community Edition).
pub struct StatelessToolListingOverlay;

#[async_trait::async_trait]
impl ToolListingOverlay for StatelessToolListingOverlay {
    async fn enrich_tool_list(
        &self,
        _session_jti: &str,
        base_tools: Vec<crate::tool_registry::ToolDescriptor>,
    ) -> anyhow::Result<Vec<crate::tool_registry::ToolDescriptor>> {
        // Community Edition is strictly stateless: returns the base list as-is.
        Ok(base_tools)
    }

    async fn intercept_action(
        &self,
        _session_jti: &str,
        _req: &crate::action::ActionRequest,
    ) -> anyhow::Result<Option<crate::action::ActionResult>> {
        // Community Edition falls back to standard execution paths.
        Ok(None)
    }
}
