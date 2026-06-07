// ─────────────────────────────────────────────────────────────
// Transport Normalizer — unifies entry points into ProposedAction
//
// Spec reference: §16.2
//
// All three gateway entry points (HTTP, MCP SSE, NATS) normalize
// into a single `ProposedAction` before entering governance.
//
// RULE[010_JWT_CONTRACTS.md]: All normalizer functions now accept
// pre-verified `&JwtClaims` from `TokenValidator::validate()`.
// The raw session_jwt string is retained only for the
// `IdentityContext.session_jwt` field (downstream audit use).
// ─────────────────────────────────────────────────────────────

use crate::meta_identity;
use identity_context::models::{ProposedAction, TransportKind};

/// Normalize an HTTP `POST /v1/actions/propose` request.
///
/// RULE[010_JWT_CONTRACTS.md]: `base_identity` contains pre-verified identity context.
pub fn normalize_http_propose(
    tool_name: &str,
    mut arguments: serde_json::Value,
    base_identity: trust_auth::IdentityContext,
    remote_addr: Option<String>,
) -> Result<ProposedAction, String> {
    let result = meta_identity::extract_identity_from_args(
        &mut arguments,
        base_identity,
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



/// Normalize an MCP `tools/call` request via the SSE adapter.
///
/// RULE[010_JWT_CONTRACTS.md]: `base_identity` contains pre-verified identity context.
pub fn normalize_mcp_call(
    tool_name: &str,
    mut arguments: serde_json::Value,
    base_identity: trust_auth::IdentityContext,
    remote_addr: Option<String>,
) -> Result<ProposedAction, String> {
    let result = meta_identity::extract_identity_from_args(
        &mut arguments,
        base_identity,
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
