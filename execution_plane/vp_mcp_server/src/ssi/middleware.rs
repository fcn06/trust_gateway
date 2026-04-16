//! SSI delegation middleware for MCP server.
//!
//! This middleware intercepts MCP tool calls and verifies SSI delegation
//! headers, injecting verified identity information into the request.
//!
//! ## Hybrid Security Model
//! - **Option A (Context Enforcer):** Injects `_user_did` (data-owner DID) into every tool call,
//!   providing a hard isolation boundary for data access.
//! - **Option B (Clearance Gating):** Maintains a `READ_SAFE_TOOLS` allowlist (fail-secure).
//!   Tools NOT in the allowlist require `clearance:elevated` in the JWT scope.
//!   Unknown tools are denied by default, triggering an escalation flow.

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

use crate::EscalationPolicy;

/// Axum middleware for SSI delegation verification.
///
/// This middleware:
/// 1. Intercepts POST requests (MCP tool calls)
/// 2. Extracts X-Envelope and X-Instruction headers (or from _meta in body)
/// 3. Verifies the SSI delegation
/// 4. Injects the verified sender DID and user DID into the request
/// 5. Enforces clearance gating for mutation tools (Option B)
pub async fn ssi_delegation_middleware(
    axum::extract::Extension(nats_client): axum::extract::Extension<async_nats::Client>,
    axum::extract::Extension(policy): axum::extract::Extension<std::sync::Arc<EscalationPolicy>>,
    request: Request<Body>,
    next: Next,
) -> Response {
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
        // Extract the tool name for clearance gating
        let tool_name = json_body["params"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();

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

                // Strip `_meta` so tools don't receive it in their parameter structs.
                if let Some(args) = json_body["params"]["arguments"].as_object_mut() {
                    args.remove("_meta");
                    stripped_meta = true;
                }
            }
        }

        // Priority 1: JWT Session Token
        if let Some(token) = &jwt {
            match auth::verify_session_jwt(token).await {
                Ok(claims) => {
                    tracing::info!(
                        "SSI Delegation verified via JWT. Sender: {}, User: {}, Clearance: {}",
                        claims.sender_did, claims.user_did, claims.clearance_level
                    );

                    // === Option B: Clearance Gating (ActionRequest Flow) ===
                    // If tool is NOT in READ_SAFE_TOOLS, require wallet approval via ActionRequest
                    let is_read_safe = policy.safe_tools.iter().any(|t| t == &tool_name);
                    if !is_read_safe {
                        tracing::info!("🔒 Escalating tool '{}' to Wallet...", tool_name);
                        
                        let args_json = json_body["params"]["arguments"].to_string();
                        let human_summary = format!("Execute tool: {}", tool_name);
                        let now_epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                        
                        let action_req = ssi_crypto::ucan::create_action_request(
                            &tool_name,
                            &args_json,
                            &human_summary,
                            300,
                            now_epoch,
                        );

                        let subject = format!("mcp.escalate.{}", claims.user_did);
                        let payload = serde_json::to_vec(&action_req).unwrap();

                        tracing::debug!("Publishing ActionRequest to NATS subject: {}", subject);
                        
                        // Wait up to 60 seconds for the Host/Wallet to respond
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(60),
                            nats_client.request(subject, payload.into())
                        ).await {
                            Ok(Ok(reply)) => {
                                if let Ok(resp) = serde_json::from_slice::<ssi_crypto::ucan::ActionResponse>(&reply.payload) {
                                    if !resp.approved {
                                        tracing::warn!("❌ ActionRequest rejected by user for '{}'", tool_name);
                                        return (
                                            StatusCode::FORBIDDEN,
                                            Json(json!({
                                                "jsonrpc": "2.0",
                                                "error": { "code": -32003, "message": "USER_REJECTED" },
                                                "id": json_body["id"]
                                            })),
                                        ).into_response();
                                    }
                                    tracing::info!("✅ ActionResponse approved for '{}'", tool_name);
                                } else {
                                    tracing::error!("Failed to parse ActionResponse from Host");
                                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Invalid ActionResponse"}))).into_response();
                                }
                            }
                            Ok(Err(e)) => {
                                tracing::error!("NATS request failed: {}", e);
                                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Internal NATS Error"}))).into_response();
                            }
                            Err(_) => {
                                tracing::warn!("⏱️ ActionRequest timed out waiting for wallet approval");
                                return (
                                    StatusCode::GATEWAY_TIMEOUT,
                                    Json(json!({
                                        "jsonrpc": "2.0",
                                        "error": { "code": -32004, "message": "APPROVAL_TIMEOUT" },
                                        "id": json_body["id"]
                                    })),
                                ).into_response();
                            }
                        }
                    }

                    // === Option A: Context Injection ===
                    // Inject both _sender_did (delegatee) and _user_did (data-owner)
                    if let Some(args) = json_body["params"]["arguments"].as_object_mut() {
                        args.insert("_sender_did".to_string(), json!(claims.sender_did));
                        args.insert("_user_did".to_string(), json!(claims.user_did));
                        stripped_meta = true;
                    }
                }
                Err(e) => {
                    tracing::warn!("JWT Session verification failed: {}. Falling back to Legacy VP.", e);
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
