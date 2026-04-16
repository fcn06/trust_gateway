// ─────────────────────────────────────────────────────────────
// Transport Normalizer — unifies entry points into ProposedAction
//
// Spec reference: §16.2
//
// All three gateway entry points (HTTP, MCP SSE, NATS) normalize
// into a single `ProposedAction` before entering governance.
// ─────────────────────────────────────────────────────────────

use identity_context::models::{ProposedAction, TransportKind};
use crate::meta_identity;

/// Normalize an HTTP `POST /v1/actions/propose` request.
///
/// Extracts identity from either:
/// - `_meta` block in arguments (external swarm path)
/// - `Authorization: Bearer <jwt>` header (internal path)
pub fn normalize_http_propose(
    tool_name: &str,
    mut arguments: serde_json::Value,
    session_jwt: &str,
    remote_addr: Option<String>,
) -> Result<ProposedAction, String> {
    let result = meta_identity::extract_identity_from_args(
        &mut arguments,
        session_jwt,
        TransportKind::Http,
        remote_addr,
    )
    .map_err(|e| format!("Identity extraction failed: {}", e))?;

    Ok(ProposedAction {
        action_id: uuid::Uuid::new_v4().to_string(),
        tool_name: tool_name.to_string(),
        arguments: result.clean_args,
        identity: result.identity,
        raw_meta: result.raw_meta,
    })
}

/// Normalize a NATS `mcp.v1.dispatch.<tool>` message.
///
/// NATS dispatch payloads from the ssi_agent include the session JWT
/// in the message payload. External swarms may also inject _meta.
pub fn normalize_nats_dispatch(
    tool_name: &str,
    mut arguments: serde_json::Value,
    session_jwt: &str,
    tenant_id: &str,
) -> Result<ProposedAction, String> {
    let result = meta_identity::extract_identity_from_args(
        &mut arguments,
        session_jwt,
        TransportKind::Nats,
        None,
    )
    .map_err(|e| format!("Identity extraction failed: {}", e))?;

    // For NATS dispatch, if tenant_id was provided explicitly in the
    // payload (existing behavior), ensure it's consistent.
    let mut identity = result.identity;
    if identity.tenant_id.is_empty() && !tenant_id.is_empty() {
        identity.tenant_id = tenant_id.to_string();
    }

    Ok(ProposedAction {
        action_id: uuid::Uuid::new_v4().to_string(),
        tool_name: tool_name.to_string(),
        arguments: result.clean_args,
        identity,
        raw_meta: result.raw_meta,
    })
}

/// Normalize an MCP `tools/call` request via the SSE adapter.
///
/// MCP tool calls arrive via the MCP SSE handler, which has already
/// authenticated the session via the SSE handshake.
pub fn normalize_mcp_call(
    tool_name: &str,
    mut arguments: serde_json::Value,
    session_jwt: &str,
    remote_addr: Option<String>,
) -> Result<ProposedAction, String> {
    let result = meta_identity::extract_identity_from_args(
        &mut arguments,
        session_jwt,
        TransportKind::McpSse,
        remote_addr,
    )
    .map_err(|e| format!("Identity extraction failed: {}", e))?;

    Ok(ProposedAction {
        action_id: uuid::Uuid::new_v4().to_string(),
        tool_name: tool_name.to_string(),
        arguments: result.clean_args,
        identity: result.identity,
        raw_meta: result.raw_meta,
    })
}
