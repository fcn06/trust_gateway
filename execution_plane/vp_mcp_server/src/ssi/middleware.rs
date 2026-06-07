//! SSI delegation middleware for MCP server.
//!
//! This middleware intercepts MCP tool calls and verifies SSI delegation
//! headers, injecting verified identity information into the request.
//!
//! ## Security Model
//! - **Context Enforcer:** Injects `_user_did` (data-owner DID) into every tool call,
//!   providing a hard isolation boundary for data access.
//!
//! ## Simplified Architecture (2026-05-06)
//!
//! Escalation logic has been removed. The Trust Gateway's `approval_daemon`
//! is the sole authority for tool escalation and approval. This middleware
//! is now a pure **authentication + context injection** layer — it verifies
//! the caller's identity and injects `_sender_did` / `_user_did` into the
//! request, then lets the tool execute. Governance decisions happen upstream.

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use super::auth;

/// Axum middleware for SSI delegation verification.
///
/// This middleware:
/// 1. Intercepts POST requests (MCP tool calls)
/// 2. Extracts X-Envelope and X-Instruction headers (or from _meta in body)
/// 3. Verifies the SSI delegation (JWT or VP)
/// 4. Injects the verified sender DID and user DID into the request
///
/// NOTE: No escalation logic here — the Trust Gateway handles all
/// approval decisions before requests reach this server.
pub async fn ssi_delegation_middleware(request: Request<Body>, next: Next) -> Response {
    // Only intercept POST requests (likely MCP messages)
    if request.method() != axum::http::Method::POST {
        return next.run(request).await;
    }

    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
        // 10MB limit
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    let json_body: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            // If it's not JSON, just proceed (might not be an MCP message)
            let body = Body::from(bytes);
            let request = Request::from_parts(parts, body);
            return next.run(request).await;
        }
    };

    let mut x_envelope = parts
        .headers
        .get("X-Envelope")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let mut x_instruction = parts
        .headers
        .get("X-Instruction")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let mut jwt = parts
        .headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    let mut execution_grant = parts
        .headers
        .get("X-Execution-Grant")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if jwt.is_none() {
        jwt = parts
            .headers
            .get("X-Session-JWT")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
    }

    let mut json_body = json_body;
    let mut stripped_meta = false;

    // Check if it's a tools/call request
    if json_body["method"] == "tools/call" {
        // Fallback to _meta inside arguments if headers are missing.
        // This handles cases where the client cannot inject custom HTTP headers.
        if jwt.is_none() || x_envelope.is_none() || x_instruction.is_none() {
            if let Some(meta) = json_body["params"]["arguments"]["_meta"].as_object() {
                if jwt.is_none() {
                    jwt = meta
                        .get("X-Session-JWT")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if x_envelope.is_none() {
                    x_envelope = meta
                        .get("X-Envelope")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if x_instruction.is_none() {
                    x_instruction = meta
                        .get("X-Instruction")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if execution_grant.is_none() {
                    execution_grant = meta
                        .get("X-Execution-Grant")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }

                // Strip `_meta` so tools don't receive it in their parameter structs.
                if let Some(args) = json_body["params"]["arguments"].as_object_mut() {
                    args.remove("_meta");
                    stripped_meta = true;
                }
            }
        }

        // Priority 0: ExecutionGrant (Phase 5)
        let tool_name = json_body["params"]["name"].as_str().unwrap_or_default();
        let mut grant_validated = false;

        if let Some(grant_token) = &execution_grant {
            if let Some(validator) = parts.extensions.get::<std::sync::Arc<crate::grant_validator::GrantValidator>>() {
                // We pass the arguments *before* stripping _meta for validation? No, the signature
                // over input_hash is computed over the arguments stripped of _meta. Wait, trust_gateway
                // computes the hash *before* injecting _meta. We should use the stripped args.
                let mut args_for_validation = json_body["params"]["arguments"].clone();
                if let Some(obj) = args_for_validation.as_object_mut() {
                    obj.remove("_meta");
                }

                match validator.validate_with_args(grant_token, tool_name, Some(&args_for_validation)) {
                    Ok(grant) => {
                        tracing::info!(
                            "✅ ExecutionGrant verified for tool '{}'. Tenant: {}",
                            tool_name,
                            grant.tenant_id
                        );
                        // Inject context
                        if let Some(args) = json_body["params"]["arguments"].as_object_mut() {
                            args.insert("_sender_did".to_string(), json!(grant.requester_did));
                            args.insert("_user_did".to_string(), json!(grant.owner_did));
                            stripped_meta = true; // since we removed _meta above, we ensure it's removed here
                        }
                        grant_validated = true;
                    }
                    Err(e) => {
                        tracing::warn!("⚠️ ExecutionGrant validation failed: {}", e);
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({
                                "jsonrpc": "2.0",
                                "error": {
                                    "code": -32000,
                                    "message": format!("ExecutionGrant validation failed: {}", e)
                                },
                                "id": json_body["id"]
                            })),
                        ).into_response();
                    }
                }
            } else {
                tracing::warn!("⚠️ ExecutionGrant present but no GrantValidator configured");
            }
        }

        // Only fallback to Session JWT or Legacy VP if Grant wasn't provided/validated
        if !grant_validated {
            // Priority 1: JWT Session Token
        if let Some(token) = &jwt {
            match auth::verify_session_jwt(token).await {
                Ok(claims) => {
                    tracing::info!(
                        "SSI Delegation verified via JWT. Sender: {}, User: {}, Clearance: {}",
                        claims.sender_did,
                        claims.user_did,
                        claims.clearance_level
                    );

                    // Context Injection: inject both _sender_did (delegatee) and _user_did (data-owner)
                    // No escalation check here — the Trust Gateway's approval_daemon
                    // has already evaluated governance policies before this request arrived.
                    if let Some(args) = json_body["params"]["arguments"].as_object_mut() {
                        args.insert("_sender_did".to_string(), json!(claims.sender_did));
                        args.insert("_user_did".to_string(), json!(claims.user_did));
                        stripped_meta = true;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "JWT Session verification failed: {}. Falling back to Legacy VP.",
                        e
                    );
                }
            }
        }

        // Priority 2: Verifiable Presentation (Legacy)
        // Check if we haven't already inserted _sender_did
        if json_body["params"]
            .get("arguments")
            .and_then(|a| a.get("_sender_did"))
            .is_none()
        {
            match (x_instruction, x_envelope) {
                (Some(instr), Some(env)) => {
                    match auth::verify_mcp_call(&instr, &env).await {
                        Ok(sender_did) => {
                            tracing::info!(
                                "SSI Delegation verified for tool call from headers. Sender: {}",
                                sender_did
                            );

                            // Inject the verified identity into the tool arguments.
                            // Legacy VP path: _user_did defaults to sender_did (self-delegation).
                            if let Some(args) = json_body["params"]["arguments"].as_object_mut() {
                                args.insert("_sender_did".to_string(), json!(sender_did));
                                args.insert("_user_did".to_string(), json!(sender_did));
                                stripped_meta = true;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("SSI Delegation verification failed: {}", e);
                            return (
                                StatusCode::UNAUTHORIZED,
                                Json(json!({
                                    "jsonrpc": "2.0",
                                    "error": {
                                        "code": -32000,
                                        "message": format!("SSI Delegation verification failed: {}", e)
                                    },
                                    "id": json_body["id"]
                                })),
                            )
                                .into_response();
                        }
                    }
                }
                _ => {
                    let msg = "Missing mandatory SSI delegation (JWT or X-Envelope/X-Instruction).";
                    tracing::warn!("{}", msg);
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32000,
                                "message": msg
                            },
                            "id": json_body["id"]
                        })),
                    )
                        .into_response();
                }
            }
            }
        }
    }

    // Reconstruction of the request
    let body_bytes = if stripped_meta {
        serde_json::to_vec(&json_body).unwrap_or_else(|_| bytes.to_vec())
    } else {
        bytes.to_vec()
    };
    let body = Body::from(body_bytes);
    let request = Request::from_parts(parts, body);
    next.run(request).await
}
