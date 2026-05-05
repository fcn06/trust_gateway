// ─────────────────────────────────────────────────────────────
// MCP SSE Adapter — Model Context Protocol over Server-Sent Events
//
// Phase 8: Allows PicoClaw's native MCP client to connect to
// the Trust Gateway directly via the SSE transport.
//
//  GET  /v1/mcp/sse       — SSE connection (sends endpoint URL)
//  POST /v1/mcp/messages  — JSON-RPC 2.0 message handler
// ─────────────────────────────────────────────────────────────

use std::sync::Arc;
use std::convert::Infallible;
use axum::{
    extract::{Query, State},
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
    Json,
};
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt as _;
use identity_context::AuthVerifier; // RULE[010_JWT_CONTRACTS.md]

use crate::gateway::GatewayState;

// ─── JSON-RPC 2.0 Types ─────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    fn error(id: Option<serde_json::Value>, code: i64, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: None,
            }),
        }
    }
}

// ─── SSE Connection Endpoint ────────────────────────────────

/// GET /v1/mcp/sse — PicoClaw connects here to establish the MCP session.
///
/// Smart Filtering: The SSE stream is now backed by an mpsc channel
/// so that meta-tool handlers can push `notifications/tools/list_changed`
/// events dynamically. The session_id is registered in GatewayState.sse_senders.
pub async fn sse_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Host(host): axum::extract::Host,
) -> impl IntoResponse {
    // ─── Phase 1: Authentication Check ───────────────────────
    // RULE[010_JWT_CONTRACTS.md]: Use pluggable TokenValidator
    if let Err(status) = state.token_validator.validate(&headers, &state.jwt_secret).await {
        tracing::warn!("🚫 MCP SSE connection rejected: Authentication failed ({})", status);
        let mut response = status.into_response();
        if status == axum::http::StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer realm=\"trust_gateway\"")
            );
        }
        return response;
    }

    let session_id = uuid::Uuid::new_v4().to_string();

    // Determine the message endpoint URL
    // Detect scheme from headers (X-Forwarded-Proto) or host
    let scheme = headers.get("X-Forwarded-Proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_else(|| {
            if host.contains("lianxi.io") || host.contains("localhost:3000") { "https" } else { "http" }
        });

    let messages_url = format!(
        "{}://{}/v1/mcp/messages?session_id={}",
        scheme, host, session_id
    );

    tracing::info!(
        "🔌 MCP SSE connection established (session={})",
        session_id
    );

    // Create an mpsc channel for dynamic event injection.
    // The Sender is stored in the DashMap so meta-tool handlers can push
    // notifications/tools/list_changed to this specific SSE stream.
    let (tx, rx) = tokio::sync::mpsc::channel::<Event>(16);
    state.sse_senders.insert(session_id.clone(), tx);

    // Build the SSE stream:
    // 1. First event: "endpoint" with the messages URL
    // 2. Then yield events from the mpsc receiver (dynamic notifications)
    let initial = futures::stream::once(async move {
        Ok::<_, Infallible>(
            Event::default()
                .event("endpoint")
                .data(messages_url),
        )
    });

    // Convert the mpsc::Receiver into a Stream that yields Ok(Event)
    let notification_stream = tokio_stream::wrappers::ReceiverStream::new(rx)
        .map(|event| Ok::<_, Infallible>(event));

    let stream = initial.chain(notification_stream);

    // Cleanup: remove the sender from the DashMap when the stream drops.
    // We use a drop guard via a wrapper stream.
    let cleanup_state = state.clone();
    let cleanup_session = session_id.clone();
    let stream = stream.chain(futures::stream::once(async move {
        cleanup_state.sse_senders.remove(&cleanup_session);
        tracing::info!("🔌 MCP SSE session cleaned up (session={})", cleanup_session);
        // This event will never actually be sent (stream already ended)
        Ok::<_, Infallible>(Event::default().comment(""))
    }));

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
    ).into_response()
}

// ─── JSON-RPC Message Handler ───────────────────────────────

#[derive(Debug, Deserialize)]
pub struct MessageQuery {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
}

/// POST /v1/mcp/messages — receives JSON-RPC 2.0 requests from PicoClaw.
///
/// Dispatches by method:
///   - initialize       → server capabilities
///   - notifications/initialized → ack
///   - tools/list       → governed tool directory
///   - tools/call       → policy engine → dispatch → result
pub async fn messages_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<MessageQuery>,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let session_id = query.session_id.unwrap_or_default();
    tracing::info!(
        "📨 MCP message: method='{}' session='{}' id={:?}",
        req.method, session_id, req.id
    );

    let response = match req.method.as_str() {
        "initialize" => handle_initialize(req.id),
        "notifications/initialized" => {
            // Client acknowledgment — no response needed for notifications
            // but we return an empty success to avoid HTTP errors
            JsonRpcResponse::success(req.id, serde_json::json!({}))
        }
        "tools/list" => {
            // Phase 1: Authentication check for tools/list
            // We allow tools/list if:
            // 1. A valid Authorization header is present
            // 2. A 'token' query parameter is present (fallback)
            // 3. A valid session_id is present (meaning SSE handshake succeeded)
            let auth_token = crate::auth::extract_bearer_token(&headers);
            let token = auth_token.or_else(|| query.token.clone());
            
            let is_valid_session = !session_id.is_empty() && state.sse_senders.contains_key(&session_id);

            if token.is_none() && !is_valid_session {
                // If no token AND no valid session, try validating whatever we have (which will likely fail and return 401)
                if let Err(status) = state.token_validator.validate(&headers, &state.jwt_secret).await {
                    tracing::warn!("🚫 MCP tools/list rejected: No valid session or token ({})", status);
                    let mut response = status.into_response();
                    if status == axum::http::StatusCode::UNAUTHORIZED {
                        response.headers_mut().insert(
                            axum::http::header::WWW_AUTHENTICATE,
                            axum::http::HeaderValue::from_static("Bearer realm=\"trust_gateway\"")
                        );
                    }
                    return response;
                }
            }
            
            return Json(handle_tools_list(&state, req.id, &session_id).await).into_response();
        },
        "tools/call" => {
            let auth_token = crate::auth::extract_bearer_token(&headers);
            // Also check query param fallback for legacy web transports (?token=...)
            let token = auth_token.or_else(|| query.token.clone());
            handle_tools_call(state.clone(), req.id, req.params, &session_id, token).await
        },
        other => {
            tracing::warn!("🔴 Unknown MCP method: {}", other);
            JsonRpcResponse::error(
                req.id,
                -32601,
                format!("Method not found: {}", other),
            )
        }
    };

    Json(response).into_response()
}

// ─── Method Handlers ────────────────────────────────────────

/// Handle `initialize` — return server info and capabilities.
///
/// Smart Filtering: Now advertises `listChanged: true` so that MCP clients
/// know to watch for `notifications/tools/list_changed` events.
fn handle_initialize(id: Option<serde_json::Value>) -> JsonRpcResponse {
    tracing::info!("🤝 MCP initialize — advertising tool capabilities (listChanged=true)");
    JsonRpcResponse::success(id, serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {
                "listChanged": true
            }
        },
        "serverInfo": {
            "name": "trust_gateway",
            "version": "0.2.0"
        }
    }))
}

/// Handle `tools/list` — return MCP-formatted tool list filtered by active bundle.
///
/// Smart Filtering: Queries NATS KV `mcp_session_state` for the session's
/// active bundle. Returns bundle-scoped tools + default_tools + meta-tools.
pub async fn handle_tools_list(
    state: &GatewayState,
    id: Option<serde_json::Value>,
    session_id: &str,
) -> JsonRpcResponse {
    let mut tools: Vec<serde_json::Value> = Vec::new();

    // 1. Determine the active bundle from NATS KV
    let active_bundle = get_session_bundle(&state.jetstream, session_id).await;

    // 2. Pull bundle-filtered tools from ToolRegistry
    if let Some(ref registry) = state.tool_registry {
        registry.refresh_if_stale(&state.http_client, &state.connectors.host_url, &state.connectors.vp_mcp_url).await;

        // Bundle-specific tools
        for (name, entry) in registry.tools_by_category(&active_bundle).await {
            tools.push(serde_json::json!({
                "name": name,
                "description": entry.description,
                "inputSchema": entry.input_schema,
            }));
        }

        // Default tools (always visible, configured by admin)
        let existing_names: std::collections::HashSet<String> = tools.iter()
            .filter_map(|t| t.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .collect();
        for (name, entry) in registry.tools_by_names(&state.default_tools).await {
            if !existing_names.contains(&name) {
                tools.push(serde_json::json!({
                    "name": name,
                    "description": entry.description,
                    "inputSchema": entry.input_schema,
                }));
            }
        }
    }

    // 3. Always inject the 3 meta-tools for dynamic discovery
    tools.extend(meta_tool_definitions());

    tracing::info!(
        "🔎 MCP tools/list: returning {} tools (bundle='{}', session='{}')",
        tools.len(), active_bundle, session_id
    );

    JsonRpcResponse::success(id, serde_json::json!({
        "tools": tools,
    }))
}

// ─── Meta-Tool Definitions ──────────────────────────────────

/// Return the 3 meta-tool definitions that are always injected into tools/list.
fn meta_tool_definitions() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "search_skills",
            "description": "Search the full library of available skills and tools. Use this when you need a capability not in your current tool list. Returns matching tool names, descriptions, and their bundle (category). You can then use switch_context to activate the right bundle.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "A keyword or phrase describing what you need (e.g., 'weather', 'database', 'email')"
                    }
                },
                "required": ["query"]
            }
        }),
        serde_json::json!({
            "name": "switch_context",
            "description": "IMPORTANT: Activate a different set of tools by switching to a named bundle (category). After calling this, your tool list will automatically refresh via a protocol notification. Do NOT invoke any new tools until you see the updated list. Use list_bundles to see available bundle names.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "bundle_name": {
                        "type": "string",
                        "description": "The bundle/category name to activate (e.g., 'utility', 'extraction', 'vp', 'discovery')"
                    }
                },
                "required": ["bundle_name"]
            }
        }),
        serde_json::json!({
            "name": "list_bundles",
            "description": "List all available skill bundles (categories). Each bundle groups related tools together. Use switch_context to activate a specific bundle.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            }
        }),
        serde_json::json!({
            "name": "read_skill",
            "description": "Read the full documentation and procedures for a native skill. Use this before executing complex multi-step skills to understand their workflows, prerequisites, and error handling. Returns the skill's README.md content and manifest metadata.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "skill_name": {
                        "type": "string",
                        "description": "Name of the skill to read documentation for (e.g., 'claw_weather', 'claw_hello_world')"
                    }
                },
                "required": ["skill_name"]
            }
        }),
        serde_json::json!({
            "name": "discover_agent_services",
            "description": "Discover the services and capabilities (skills) of a target agent by providing its DID. Returns a list of available tools and endpoints.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_did": {
                        "type": "string",
                        "description": "The DID of the target agent to discover services from."
                    }
                },
                "required": ["target_did"]
            }
        }),
    ]
}

// ─── NATS KV Session State ──────────────────────────────────

const SESSION_KV_BUCKET: &str = "mcp_session_state";

/// Read the active bundle for a session from NATS KV.
/// Returns "discovery" if the session has no state.
async fn get_session_bundle(
    js: &async_nats::jetstream::Context,
    session_id: &str,
) -> String {
    match js.get_key_value(SESSION_KV_BUCKET).await {
        Ok(store) => {
            // RULE[020_JETSTREAM_KEYS.md]: Use _ as separator
            let key = format!("session_{}", session_id);
            match store.get(&key).await {
                Ok(Some(bytes)) => {
                    let val = String::from_utf8_lossy(&bytes);
                    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&val) {
                        obj.get("active_bundle")
                            .and_then(|v| v.as_str())
                            .unwrap_or("discovery")
                            .to_string()
                    } else {
                        "discovery".to_string()
                    }
                }
                _ => "discovery".to_string(),
            }
        }
        Err(_) => "discovery".to_string(),
    }
}

/// Write the active bundle for a session to NATS KV.
async fn set_session_bundle(
    js: &async_nats::jetstream::Context,
    session_id: &str,
    bundle: &str,
) {
    if let Ok(store) = js.get_key_value(SESSION_KV_BUCKET).await {
        // RULE[020_JETSTREAM_KEYS.md]: Use _ as separator
        let key = format!("session_{}", session_id);
        let val = serde_json::json!({
            "active_bundle": bundle,
            "last_updated": chrono::Utc::now().to_rfc3339(),
        });
        if let Err(e) = store.put(&key, val.to_string().into()).await {
            tracing::warn!("⚠️ Failed to write session state to NATS KV: {}", e);
        }
    }
}

// Meta-tool logic has been moved to router.rs to support unified governance.


/// Handle `tools/call` — translate to ActionRequest and run through
/// the Trust Gateway governance pipeline.
///
/// Identity resolution (Case A — orchestrated flow):
///   1. Extract `_meta.io.lianxi/session_jwt` → decode user DID
///   2. Extract `_meta.io.lianxi/tenant_id` → override tenant
///   3. Extract `_meta.io.lianxi/correlation_id` → trace correlation
///   4. Fallback: generic "mcp-client" identity (policy may deny)
async fn handle_tools_call(
    state: Arc<GatewayState>,
    id: Option<serde_json::Value>,
    params: serde_json::Value,
    session_id: &str,
    auth_token: Option<String>,
) -> JsonRpcResponse {
    // Extract tool name and arguments from MCP params
    let tool_name = params.get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let arguments = params.get("arguments")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    if tool_name.is_empty() {
        return JsonRpcResponse::error(
            id,
            -32602,
            "Missing required parameter: name".to_string(),
        );
    }

    // Meta-tools are now handled as first-class actions in the governance pipeline via the InternalMeta executor.
    // Proceed with identity resolution and policy evaluation.

    // ─── Phase 9: Extract _meta identity (io.lianxi/ namespace) ───
    // RULE[010_JWT_CONTRACTS.md]: Verify any JWT in _meta before using claims.
    let meta_jwt = arguments.as_object()
        .and_then(|obj| obj.get("_meta"))
        .and_then(|m| {
            m.get("io.lianxi")
                .or_else(|| m.get("io").and_then(|io| io.get("lianxi")))
                .or_else(|| m.get("lianxi"))
                .or(Some(m))
        })
        .and_then(|ag| ag.get("session_jwt").or_else(|| ag.get("X-Session-JWT")))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let token_to_verify = auth_token.or(meta_jwt).unwrap_or_default();

    let verifier = identity_context::jwt::HmacAuthVerifier::new(&state.jwt_secret);
    let verified_claims = if !token_to_verify.is_empty() {
        match verifier.verify(&token_to_verify) {
            Ok(v) => v.into_claims(),
            Err(e) => {
                tracing::warn!("MCP SSE JWT verification failed: {}", e);
                // Fallback to anonymous — policy engine will deny if needed
                identity_context::jwt::JwtClaims {
                    iss: "mcp-client".to_string(),
                    sub: format!("picoclaw:{}", session_id),
                    tenant_id: String::new(),
                    jti: String::new(),
                    scope: vec![],
                    user_did: None,
                    exp: None,
                    iat: None,
                }
            }
        }
    } else {
        // No JWT at all — anonymous MCP client
        identity_context::jwt::JwtClaims {
            iss: "mcp-client".to_string(),
            sub: format!("picoclaw:{}", session_id),
            tenant_id: String::new(),
            jti: String::new(),
            scope: vec![],
            user_did: None,
            exp: None,
            iat: None,
        }
    };

    let proposed = crate::transport_normalizer::normalize_mcp_call(
        &tool_name,
        arguments.clone(),
        &token_to_verify,
        &verified_claims,
        None,
    ).unwrap_or_else(|e| {
        tracing::warn!("MCP tools/call normalization fallback: {}", e);
        // Fallback for anonymous or internally-routed MCP
        identity_context::models::ProposedAction {
            action_id: uuid::Uuid::new_v4().to_string(),
            tool_name: tool_name.clone(),
            arguments: arguments.clone(),
            identity: identity_context::models::IdentityContext {
                tenant_id: session_id.to_string(),
                owner_did: "mcp-client".to_string(),
                requester_did: format!("picoclaw:{}", session_id),
                session_jwt: "".to_string(),
                source: identity_context::models::SourceContext {
                    source_type: identity_context::models::SourceType::McpClient,
                    source_id: session_id.to_string(),
                    transport: identity_context::models::TransportKind::McpSse,
                    correlation_id: session_id.to_string(),
                    remote_addr: None,
                },
            },
            raw_meta: None,
        }
    });

    tracing::info!(
        "🦞 MCP tools/call: '{}' (tenant='{}', correlation='{}')",
        proposed.tool_name, proposed.identity.tenant_id, proposed.identity.source.correlation_id
    );

    // Phase 2.1: Use single canonical conversion
    let action_req = crate::gateway::build_action_request(proposed);

    // Run through the governance pipeline
    let gateway_res = crate::gateway::process_action(state.clone(), action_req).await;
    
    match gateway_res {
        Ok(response) => {
            tracing::info!("🔍 Gateway processed action: status='{}' approval_id={:?}", response.status, response.approval_id);
            match response.status.as_str() {

                "succeeded" => {
                    // MCP tools/call success → wrap result in content array
                    let content = match response.result {
                        Some(result) => {
                            let text = if result.is_string() {
                                result.as_str().unwrap_or("").to_string()
                            } else {
                                serde_json::to_string_pretty(&result)
                                    .unwrap_or_default()
                            };
                            serde_json::json!([{
                                "type": "text",
                                "text": text,
                            }])
                        }
                        None => serde_json::json!([{
                            "type": "text",
                            "text": "Action completed successfully.",
                        }]),
                    };

                    // Smart Filtering: If this was a successful context switch, trigger a list_changed notification
                    if tool_name == "switch_context" {
                        if let Some(sender) = state.sse_senders.get(session_id) {
                            let notification = serde_json::json!({
                                "jsonrpc": "2.0",
                                "method": "notifications/tools/list_changed"
                            });
                            let event = Event::default()
                                .event("message")
                                .data(notification.to_string());
                            let _ = sender.send(event).await;
                            tracing::info!("📢 Context switch successful — pushed notifications/tools/list_changed to session {}", session_id);
                        }
                    }

                    JsonRpcResponse::success(id, serde_json::json!({
                        "content": content,
                        "isError": false,
                    }))
                }
                "denied" => {
                    let reason = response.error.unwrap_or("Policy denied".to_string());
                    JsonRpcResponse::success(id, serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": format!("🚫 Action denied by policy: {}", reason),
                        }],
                        "isError": true,
                    }))
                }
                "pending" | "pending_approval" | "requires_approval" => {

                    let approval_id = response.approval_id.unwrap_or_default();
                    JsonRpcResponse::success(id, serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": format!(
                                "⏳ Action requires approval (approval_id: {}). Please wait for the approval flow to complete in your Lianxi portal.",
                                approval_id
                            ),
                        }],
                        "isError": false,
                    }))
                }
                "pending_proof" | "requires_proof" => {
                    let escalation = response.escalation.unwrap_or_default();
                    JsonRpcResponse::success(id, serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": format!(
                                "🔐 Action requires verifiable credential proof: {}",
                                escalation
                            ),
                        }],
                        "isError": false, // Proof requests should be handled as a non-error prompt
                    }))
                }

                _ => {
                    let err = response.error.unwrap_or("Unknown error".to_string());
                    JsonRpcResponse::success(id, serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": format!("❌ Action failed: {}", err),
                        }],
                        "isError": true,
                    }))
                }
            }
        }
        Err(e) => {
            tracing::error!("❌ MCP tools/call gateway error: {}", e);
            JsonRpcResponse::error(
                id,
                -32603,
                format!("Internal gateway error: {}", e),
            )
        }
    }
}
