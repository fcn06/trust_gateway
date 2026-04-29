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

use identity_context::jwt::JwtClaims;
use identity_context::models::{ProposedAction, TransportKind};
use crate::meta_identity;

/// Normalize an HTTP `POST /v1/actions/propose` request.
///
/// RULE[010_JWT_CONTRACTS.md]: `verified_claims` are the pre-verified
/// claims from `TokenValidator::validate()`. No re-decoding occurs.
pub fn normalize_http_propose(
    tool_name: &str,
    mut arguments: serde_json::Value,
    session_jwt: &str,
    verified_claims: &JwtClaims,
    remote_addr: Option<String>,
) -> Result<ProposedAction, String> {
    let result = meta_identity::extract_identity_from_args(
        &mut arguments,
        session_jwt,
        verified_claims,
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
/// RULE[010_JWT_CONTRACTS.md]: `verified_claims` are the pre-verified
/// claims from `AuthVerifier::verify()`. No re-decoding occurs.
pub fn normalize_nats_dispatch(
    tool_name: &str,
    mut arguments: serde_json::Value,
    session_jwt: &str,
    verified_claims: &JwtClaims,
    tenant_id: &str,
) -> Result<ProposedAction, String> {
    let result = meta_identity::extract_identity_from_args(
        &mut arguments,
        session_jwt,
        verified_claims,
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
/// RULE[010_JWT_CONTRACTS.md]: `verified_claims` are the pre-verified
/// claims. For MCP SSE, the JWT may come from the _meta block and
/// should have been verified at the transport boundary.
pub fn normalize_mcp_call(
    tool_name: &str,
    mut arguments: serde_json::Value,
    session_jwt: &str,
    verified_claims: &JwtClaims,
    remote_addr: Option<String>,
) -> Result<ProposedAction, String> {
    let result = meta_identity::extract_identity_from_args(
        &mut arguments,
        session_jwt,
        verified_claims,
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
