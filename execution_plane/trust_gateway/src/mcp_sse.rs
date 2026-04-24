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
/// Sends an initial `endpoint` event with the message URL, then
/// keeps the connection alive with periodic keepalive comments.
pub async fn sse_handler(
    axum::extract::Host(host): axum::extract::Host,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let session_id = uuid::Uuid::new_v4().to_string();

    // Determine the message endpoint URL
    // Use the Host header to build a routable URL
    let scheme = "http"; // Trust Gateway is internal; no TLS needed
    let messages_url = format!(
        "{}://{}/v1/mcp/messages?session_id={}",
        scheme, host, session_id
    );

    tracing::info!(
        "🔌 MCP SSE connection established (session={})",
        session_id
    );

    // Build the SSE stream:
    // 1. First event: "endpoint" with the messages URL
    // 2. Then keepalive comments every 30 seconds
    let initial = futures::stream::once(async move {
        Ok::<_, Infallible>(
            Event::default()
                .event("endpoint")
                .data(messages_url),
        )
    });

    let keepalive = tokio_stream::wrappers::IntervalStream::new(
        tokio::time::interval(std::time::Duration::from_secs(30)),
    )
    .map(|_| {
        Ok::<_, Infallible>(Event::default().comment("keepalive"))
    });

    let stream = initial.chain(keepalive);

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(30))
            .text("keepalive"),
    )
}

// ─── JSON-RPC Message Handler ───────────────────────────────

#[derive(Debug, Deserialize)]
pub struct MessageQuery {
    #[serde(default)]
    pub session_id: Option<String>,
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
        "tools/list" => handle_tools_list(&state, req.id).await,
        "tools/call" => handle_tools_call(state.clone(), req.id, req.params, &session_id).await,
        other => {
            tracing::warn!("🔴 Unknown MCP method: {}", other);
            JsonRpcResponse::error(
                req.id,
                -32601,
                format!("Method not found: {}", other),
            )
        }
    };

    Json(response)
}

// ─── Method Handlers ────────────────────────────────────────

/// Handle `initialize` — return server info and capabilities.
fn handle_initialize(id: Option<serde_json::Value>) -> JsonRpcResponse {
    tracing::info!("🤝 MCP initialize — advertising tool capabilities");
    JsonRpcResponse::success(id, serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {
                "listChanged": false
            }
        },
        "serverInfo": {
            "name": "trust_gateway",
            "version": "0.1.0"
        }
    }))
}

/// Handle `tools/list` — return MCP-formatted tool list from the ToolRegistry cache.
///
/// Phase 1.4: Now uses the shared ToolRegistry instead of directly fetching
/// from the Host, ensuring consistency with the HTTP /v1/tools/list endpoint.
async fn handle_tools_list(
    state: &GatewayState,
    id: Option<serde_json::Value>,
) -> JsonRpcResponse {
    let mut tools: Vec<serde_json::Value> = Vec::new();

    // Pull from ToolRegistry cache (same as HTTP tools_list_handler)
    if let Some(ref registry) = state.tool_registry {
        registry.refresh_if_stale(&state.http_client, &state.connectors.host_url, &state.connectors.vp_mcp_url).await;

        for (name, entry) in registry.all_tools().await {
            tools.push(serde_json::json!({
                "name": name,
                "description": entry.description,
                "inputSchema": entry.input_schema,
            }));
        }
    } else {
        // Fallback: direct fetch if no registry configured (shouldn't happen in normal operation)
        let url = format!("{}/.well-known/skills.json", state.connectors.host_url);
        let skills = match state.http_client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                resp.json::<serde_json::Value>().await.unwrap_or_default()
            }
            _ => serde_json::json!({}),
        };

        if let Some(mcp_tools) = skills.get("mcp_tools").and_then(|v| v.as_array()) {
            for tool in mcp_tools {
                tools.push(serde_json::json!({
                    "name": tool.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                    "description": tool.get("description").and_then(|v| v.as_str()).unwrap_or(""),
                    "inputSchema": tool.get("inputSchema").cloned()
                        .unwrap_or(serde_json::json!({"type": "object"})),
                }));
            }
        }
    }

    tracing::info!("🔎 MCP tools/list: returning {} tools", tools.len());

    JsonRpcResponse::success(id, serde_json::json!({
        "tools": tools,
    }))
}

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

    // ─── Phase 9: Extract _meta identity (io.lianxi/ namespace) ───
    let proposed = crate::transport_normalizer::normalize_mcp_call(
        &tool_name,
        arguments.clone(),
        "", // MCP SSE relies purely on _meta since there is no session_jwt header passed in this signature (the handshake handles it originally, but we expect external swarm calls to be injected here)
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
    match crate::gateway::process_action(state.clone(), action_req).await {
        Ok(response) => {
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
                "requires_approval" => {
                    let approval_id = response.approval_id.unwrap_or_default();
                    JsonRpcResponse::success(id, serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": format!(
                                "⏳ Action requires approval (approval_id: {}). Please wait for the approval flow to complete.",
                                approval_id
                            ),
                        }],
                        "isError": false,
                    }))
                }
                "requires_proof" => {
                    let escalation = response.escalation.unwrap_or_default();
                    JsonRpcResponse::success(id, serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": format!(
                                "🔐 Action requires verifiable credential proof: {}",
                                escalation
                            ),
                        }],
                        "isError": true,
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
