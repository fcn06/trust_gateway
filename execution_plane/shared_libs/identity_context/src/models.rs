// ─────────────────────────────────────────────────────────────
// Domain models for identity context (spec §6)
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// Combined identity derived from session JWT + optional _meta overlay.
///
/// This is the unified identity view that the policy engine evaluates
/// after transport normalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityContext {
    /// Tenant namespace this request belongs to.
    pub tenant_id: String,

    /// DID of the entity that owns the agent box (from JWT `iss`).
    pub owner_did: String,

    /// DID of the entity performing the action (from JWT `sub` or _meta override).
    pub requester_did: String,

    /// The raw session JWT for downstream verification.
    pub session_jwt: String,

    /// Transport-specific source metadata.
    pub source: SourceContext,
}

/// Where the action request originated — spec-aligned version.
///
/// This is the _new_ SourceContext from spec §6, which carries richer
/// metadata than `trust_core::SourceContext`. A `From` conversion bridges
/// to the existing policy engine interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceContext {
    /// Source type: "ssi_agent", "external_swarm", "mcp_client", "http_api", etc.
    pub source_type: SourceType,

    /// Registered source identifier (for external swarms) or "self" for internal.
    pub source_id: String,

    /// Transport that carried this request.
    pub transport: TransportKind,

    /// Correlation ID for request tracing across services.
    pub correlation_id: String,

    /// Remote address of the caller (if HTTP/MCP).
    pub remote_addr: Option<String>,
}

impl Default for SourceContext {
    fn default() -> Self {
        Self {
            source_type: SourceType::Internal,
            source_id: "self".to_string(),
            transport: TransportKind::Nats,
            correlation_id: uuid::Uuid::new_v4().to_string(),
            remote_addr: None,
        }
    }
}

/// Convert spec-aligned SourceContext to the existing trust_core SourceContext
/// so the policy engine continues working without modification.
impl From<SourceContext> for trust_core::SourceContext {
    fn from(ctx: SourceContext) -> Self {
        Self {
            source_type: ctx.source_type.as_str().to_string(),
            name: Some(format!("{:?} via {:?}", ctx.source_type, ctx.transport)),
            instance_id: Some(ctx.source_id),
        }
    }
}

/// Types of action request origins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    /// Internal ssi_agent via NATS.
    Internal,
    /// The native SSI agent (backward compat).
    SsiAgent,
    /// External AI agent swarm.
    ExternalSwarm,
    /// HTTP API caller (PicoClaw, webhook, etc).
    HttpApi,
    /// MCP SSE client.
    McpClient,
}

impl SourceType {
    /// String representation for policy matching.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::SsiAgent => "ssi_agent",
            Self::ExternalSwarm => "external_swarm",
            Self::HttpApi => "http_api",
            Self::McpClient => "mcp_client",
        }
    }
}

/// Transport mechanism used to deliver the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    /// Plain NATS request/reply (ssi_agent dispatch).
    Nats,
    /// HTTP POST to the gateway API.
    Http,
    /// MCP over SSE (Streamable HTTP).
    McpSse,
    /// MCP over NATS transport.
    McpNats,
}

/// A transport-neutral action proposal before policy evaluation.
///
/// All three entry points (NATS dispatch, HTTP propose, MCP tool call)
/// normalize into this structure before entering `process_action()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedAction {
    /// Unique action identifier (generated at normalization time).
    pub action_id: String,

    /// The tool/skill being requested.
    pub tool_name: String,

    /// Clean arguments with `_meta` already extracted.
    pub arguments: serde_json::Value,

    /// Derived identity context.
    pub identity: IdentityContext,

    /// Raw `_meta` payload preserved for audit logging only.
    /// MUST NEVER be forwarded to executors.
    pub raw_meta: Option<serde_json::Value>,
}
