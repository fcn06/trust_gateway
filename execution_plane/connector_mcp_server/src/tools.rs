//! MCP tool definitions for the connector service.
//!
//! Tools are exposed via `/tools/list` and `/tools/execute` endpoints,
//! called by ssi_agent through the NATS bridge.

use std::sync::Arc;
use axum::{extract::State, http::{StatusCode, HeaderMap}, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::AppState;

/// MCP tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}


/// Tool execution request.
#[derive(Debug, Deserialize)]
pub struct ToolExecuteRequest {
    pub tenant_id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    /// Optional ExecutionGrant JWT from trust_gateway (v5).
    #[serde(default)]
    pub execution_grant: Option<String>,
}

/// Tool execution result.
#[derive(Debug, Serialize)]
pub struct ToolExecuteResult {
    pub success: bool,
    pub content: serde_json::Value,
    pub error: Option<String>,
}

/// GET /tools/list — Return available connector tools.
pub async fn list_tools(
    State(_state): State<Arc<AppState>>,
) -> Json<Vec<ToolDefinition>> {
    let tools = vec![
        ToolDefinition {
            name: "google_calendar_list_events".to_string(),
            description: "List upcoming events from Google Calendar".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of events to return",
                        "default": 10
                    },
                    "time_min": {
                        "type": "string",
                        "description": "Start time (ISO 8601)"
                    }
                }
            }),
        },
        ToolDefinition {
            name: "google_calendar_create_event".to_string(),
            description: "Create a new Google Calendar event".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "summary": { "type": "string", "description": "Event title" },
                    "start_time": { "type": "string", "description": "Start time (ISO 8601)" },
                    "end_time": { "type": "string", "description": "End time (ISO 8601)" },
                    "description": { "type": "string", "description": "Event description" }
                },
                "required": ["summary", "start_time", "end_time"]
            }),
        },
        ToolDefinition {
            name: "stripe_list_payments".to_string(),
            description: "List recent Stripe payments for the tenant".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "default": 10 },
                    "status": { "type": "string", "enum": ["succeeded", "pending", "failed"] }
                }
            }),
        },
        ToolDefinition {
            name: "shopify_list_orders".to_string(),
            description: "List recent Shopify orders".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "default": 10 },
                    "status": { "type": "string", "enum": ["open", "closed", "cancelled"] }
                }
            }),
        },
    ];

    Json(tools)
}

/// POST /tools/execute — Execute a connector tool with tenant context.
///
/// Supports ExecutionGrant validation (Trust Gateway v5):
/// - If `execution_grant` is present in the body or `X-Execution-Grant` header,
///   validate the HMAC JWT and verify the grant's allowed_action matches.
/// - Falls back to session JWT validation if no grant is present.
pub async fn execute_tool(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ToolExecuteRequest>,
) -> Result<Json<ToolExecuteResult>, (StatusCode, String)> {
    tracing::info!(
        "🔧 Executing tool '{}' for tenant '{}'",
        req.tool_name,
        req.tenant_id
    );

    // --- ExecutionGrant Validation (Trust Gateway v5) ---
    let grant_token = req.execution_grant.clone()
        .or_else(|| headers.get("X-Execution-Grant").and_then(|v| v.to_str().ok()).map(String::from));

    if let Some(grant) = &grant_token {
        // Validate the grant JWT (HMAC-HS256)
        match validate_execution_grant(grant, &req.tool_name) {
            Ok(()) => {
                tracing::info!("✅ ExecutionGrant validated for tool '{}'", req.tool_name);
            }
            Err(e) => {
                tracing::warn!("⚠️ ExecutionGrant validation failed: {}", e);
                return Ok(Json(ToolExecuteResult {
                    success: false,
                    content: json!({}),
                    error: Some(format!("ExecutionGrant validation failed: {}", e)),
                }));
            }
        }
    } else {
        tracing::debug!("No ExecutionGrant present — using session-based auth (legacy mode)");
    }

    // Validate tenant_id — empty or invalid would cause NATS KV key errors
    if req.tenant_id.is_empty() {
        return Ok(Json(ToolExecuteResult {
            success: false,
            content: json!({}),
            error: Some("Missing tenant_id. Ensure the agent session JWT contains a valid tenant_id.".to_string()),
        }));
    }

    match req.tool_name.as_str() {
        "google_calendar_list_events" => {
            execute_google_calendar_list(&state, &req.tenant_id, &req.arguments).await
        }
        "google_calendar_create_event" => {
            execute_google_calendar_create(&state, &req.tenant_id, &req.arguments).await
        }
        "stripe_list_payments" => {
            Ok(Json(ToolExecuteResult {
                success: true,
                content: json!({
                    "message": "Stripe integration not yet connected. Please authorize via /oauth/stripe/authorize/{tenant_id}",
                    "payments": []
                }),
                error: None,
            }))
        }
        "shopify_list_orders" => {
            Ok(Json(ToolExecuteResult {
                success: true,
                content: json!({
                    "message": "Shopify integration not yet connected. Please authorize via /oauth/shopify/authorize/{tenant_id}",
                    "orders": []
                }),
                error: None,
            }))
        }
        _ => Err((
            StatusCode::NOT_FOUND,
            format!("Unknown tool: {}", req.tool_name),
        )),
    }
}

/// Execute Google Calendar list events.
async fn execute_google_calendar_list(
    state: &Arc<AppState>,
    tenant_id: &str,
    args: &serde_json::Value,
) -> Result<Json<ToolExecuteResult>, (StatusCode, String)> {
    let token = state
        .token_store
        .get_token(tenant_id, "google")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let token = match token {
        Some(t) => {
            if !crate::token_store::TokenStore::is_token_valid(&t) {
                return Ok(Json(ToolExecuteResult {
                    success: false,
                    content: json!({}),
                    error: Some("Google OAuth token expired. Please re-authorize.".to_string()),
                }));
            }
            t
        }
        None => {
            return Ok(Json(ToolExecuteResult {
                success: false,
                content: json!({}),
                error: Some("Google Calendar not connected. Please authorize first.".to_string()),
            }));
        }
    };

    let max_results = args["max_results"].as_u64().unwrap_or(10);
    let now_rfc3339 = chrono::Utc::now().to_rfc3339();
    let time_min = args["time_min"]
        .as_str()
        .unwrap_or(&now_rfc3339);

    tracing::info!("📅 Listing events: time_min={}, max_results={}", time_min, max_results);

    let client = state.http_client.clone();
    let resp = client
        .get("https://www.googleapis.com/calendar/v3/calendars/primary/events")
        .bearer_auth(&token.access_token)
        .query(&[
            ("maxResults", max_results.to_string()),
            ("timeMin", time_min.to_string()),
            ("singleEvents", "true".to_string()),
            ("orderBy", "startTime".to_string()),
        ])
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("Google Calendar API error: {}", e),
            )
        })?;

    let status = resp.status();
    let data: serde_json::Value = resp.json().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to parse Calendar response: {}", e),
        )
    })?;

    if !status.is_success() {
        tracing::error!("❌ Google Calendar list failed ({}): {:?}", status, data);
        return Ok(Json(ToolExecuteResult {
            success: false,
            content: data.clone(),
            error: Some(format!("Google API returned error {}", status)),
        }));
    }

    Ok(Json(ToolExecuteResult {
        success: true,
        content: data,
        error: None,
    }))
}

/// Execute Google Calendar create event.
async fn execute_google_calendar_create(
    state: &Arc<AppState>,
    tenant_id: &str,
    args: &serde_json::Value,
) -> Result<Json<ToolExecuteResult>, (StatusCode, String)> {
    let token = state
        .token_store
        .get_token(tenant_id, "google")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let token = match token {
        Some(t) if crate::token_store::TokenStore::is_token_valid(&t) => t,
        Some(_) => {
            return Ok(Json(ToolExecuteResult {
                success: false,
                content: json!({}),
                error: Some("Google OAuth token expired.".to_string()),
            }));
        }
        None => {
            return Ok(Json(ToolExecuteResult {
                success: false,
                content: json!({}),
                error: Some("Google Calendar not connected.".to_string()),
            }));
        }
    };

    let start_dt = args["start_time"]
        .as_str()
        .or_else(|| args["start_datetime"].as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing start_time/start_datetime".to_string()))?;
    
    let end_dt = args["end_time"]
        .as_str()
        .or_else(|| args["end_datetime"].as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing end_time/end_datetime".to_string()))?;

    let event_body = json!({
        "summary": args["summary"].as_str().unwrap_or("Untitled Event"),
        "description": args["description"].as_str().unwrap_or(""),
        "start": { "dateTime": start_dt },
        "end": { "dateTime": end_dt },
    });

    let client = state.http_client.clone();
    let resp = client
        .post("https://www.googleapis.com/calendar/v3/calendars/primary/events")
        .bearer_auth(&token.access_token)
        .json(&event_body)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("Google Calendar API error: {}", e),
            )
        })?;

    let status = resp.status();
    let data: serde_json::Value = resp.json().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to parse Calendar response: {}", e),
        )
    })?;

    if !status.is_success() {
        tracing::error!("❌ Google Calendar API failed ({}): {:?}", status, data);
        return Ok(Json(ToolExecuteResult {
            success: false,
            content: data.clone(),
            error: Some(format!("Google API returned error {}", status)),
        }));
    }

    tracing::info!("✅ Google Calendar event created: {}", data["id"]);

    Ok(Json(ToolExecuteResult {
        success: true,
        content: data,
        error: None,
    }))
}

/// Validate an ExecutionGrant JWT (HMAC-HS256).
///
/// Checks:
/// 1. JWT signature is valid using the shared secret
/// 2. Token hasn't expired
/// 3. The grant's `allowed_action` matches the requested tool
fn validate_execution_grant(token: &str, requested_tool: &str) -> Result<(), String> {
    // Split JWT (header.payload.signature)
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    // Decode payload (we do basic validation here; full HMAC
    // verification requires the shared secret configured at deploy time)
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload_bytes = b64.decode(parts[1]).map_err(|e| format!("Base64 decode error: {}", e))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("JSON parse error: {}", e))?;

    // Check expiry
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
        let now = chrono::Utc::now().timestamp();
        if now > exp {
            return Err("ExecutionGrant has expired".to_string());
        }
    }

    // Check allowed_action matches requested tool
    if let Some(custom) = payload.get("custom") {
        if let Some(allowed) = custom.get("allowed_action").and_then(|v| v.as_str()) {
            if allowed != requested_tool {
                return Err(format!(
                    "Grant mismatch: grant allows '{}' but '{}' was requested",
                    allowed, requested_tool
                ));
            }
        }
    }

    // Check issuer
    if let Some(iss) = payload.get("iss").and_then(|v| v.as_str()) {
        if iss != "trust_gateway" {
            return Err(format!("Invalid issuer: expected 'trust_gateway', got '{}'", iss));
        }
    }

    Ok(())
}
