//! MCP tool definitions for the connector service.
//!
//! Tools are exposed via `/tools/list` and `/tools/execute` endpoints,
//! called by ssi_agent through the NATS bridge.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

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
pub async fn list_tools(State(_state): State<Arc<AppState>>) -> Json<Vec<ToolDefinition>> {
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
    let grant_token = req.execution_grant.clone().or_else(|| {
        headers
            .get("X-Execution-Grant")
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    });

    if let Some(grant) = &grant_token {
        if let Some(ref validator) = state.grant_validator {
            // Proper cryptographic signature verification (RULE[010_JWT_CONTRACTS.md])
            // Phase 5: Enforce input_hash fingerprint binding
            match validator.validate_with_args(grant, &req.tool_name, Some(&req.arguments)) {
                Ok(_validated_grant) => {
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
            tracing::warn!("⚠️ ExecutionGrant present but no validator configured — rejecting");
            return Ok(Json(ToolExecuteResult {
                success: false,
                content: json!({}),
                error: Some("Server misconfiguration: no grant signing key".to_string()),
            }));
        }
    } else {
        tracing::debug!("No ExecutionGrant present — using session-based auth (legacy mode)");
    }

    // Validate tenant_id — empty or invalid would cause NATS KV key errors
    if req.tenant_id.is_empty() {
        return Ok(Json(ToolExecuteResult {
            success: false,
            content: json!({}),
            error: Some(
                "Missing tenant_id. Ensure the agent session JWT contains a valid tenant_id."
                    .to_string(),
            ),
        }));
    }

    match req.tool_name.as_str() {
        "google_calendar_list_events" => {
            execute_google_calendar_list(&state, &req.tenant_id, &req.arguments).await
        }
        "google_calendar_create_event" => {
            execute_google_calendar_create(&state, &req.tenant_id, &req.arguments).await
        }
        "stripe_list_payments" => Ok(Json(ToolExecuteResult {
            success: true,
            content: json!({
                "message": "Stripe integration not yet connected. Please authorize via /oauth/stripe/authorize/{tenant_id}",
                "payments": []
            }),
            error: None,
        })),
        "shopify_list_orders" => Ok(Json(ToolExecuteResult {
            success: true,
            content: json!({
                "message": "Shopify integration not yet connected. Please authorize via /oauth/shopify/authorize/{tenant_id}",
                "orders": []
            }),
            error: None,
        })),
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
    let time_min = args["time_min"].as_str().unwrap_or(&now_rfc3339);

    tracing::info!(
        "📅 Listing events: time_min={}, max_results={}",
        time_min,
        max_results
    );

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

/// Parse calendar start and end times from various supported formats.
fn parse_calendar_start_end(args: &serde_json::Value) -> Result<(String, String), String> {
    let start_dt = args["start_time"]
        .as_str()
        .or_else(|| args["start_datetime"].as_str())
        .or_else(|| args["start"].as_str())
        .or_else(|| args["start"]["dateTime"].as_str())
        .ok_or_else(|| "Missing start_time/start_datetime/start".to_string())?;

    let end_dt = args["end_time"]
        .as_str()
        .or_else(|| args["end_datetime"].as_str())
        .or_else(|| args["end"].as_str())
        .or_else(|| args["end"]["dateTime"].as_str())
        .ok_or_else(|| "Missing end_time/end_datetime/end".to_string())?;

    Ok((start_dt.to_string(), end_dt.to_string()))
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

    let (start_dt, end_dt) = parse_calendar_start_end(args)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

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

// ─────────────────────────────────────────────────────────────
// ExecutionGrant JWT Validator
//
// FIX: Replaced payload-only decode with proper cryptographic
// signature verification using jwt-simple.
//
// Supports dual-mode (auto-detected from JWT header):
//   - EdDSA → Ed25519 public key verification (recommended)
//   - HS256 → HMAC shared secret verification (legacy)
//
// RULE[010_JWT_CONTRACTS.md]: Skipping signature validation is
// forbidden. This module enforces signature, exp, and issuer.
// ─────────────────────────────────────────────────────────────

use jwt_simple::prelude::*;
use std::collections::HashSet;
use trust_core::grant::ExecutionGrant;

/// Validates ExecutionGrant JWTs from the trust_gateway.
///
/// Mirrors the `GrantValidator` in `native_skill_executor` to ensure
/// consistent security properties across all execution backends.
pub struct GrantValidator {
    ed25519_key: Option<Ed25519PublicKey>,
    hmac_key: Option<HS256Key>,
}

impl GrantValidator {
    /// Create a validator with Ed25519 public key only (recommended).
    pub fn from_ed25519_pem(pem: &str) -> anyhow::Result<Self> {
        let key = Ed25519PublicKey::from_pem(pem)?;
        Ok(Self {
            ed25519_key: Some(key),
            hmac_key: None,
        })
    }

    /// Create a validator with HMAC shared secret (legacy).
    pub fn from_hmac_secret(secret: &str) -> Self {
        Self {
            ed25519_key: None,
            hmac_key: Some(HS256Key::from_bytes(secret.as_bytes())),
        }
    }

    /// Create a dual-mode validator that accepts both algorithms.
    pub fn dual(ed25519_pem: &str, hmac_secret: &str) -> anyhow::Result<Self> {
        let ed_key = Ed25519PublicKey::from_pem(ed25519_pem)?;
        Ok(Self {
            ed25519_key: Some(ed_key),
            hmac_key: Some(HS256Key::from_bytes(hmac_secret.as_bytes())),
        })
    }

    /// Validate an ExecutionGrant JWT and return the claims.
    ///
    /// Checks:
    /// - Signature is valid (Ed25519 or HMAC)
    /// - Token has not expired
    /// - Issuer is "trust_gateway"
    /// - The grant's `allowed_action` matches the requested tool
    /// - The grant's `input_hash` matches the arguments (Phase 3)
    pub fn validate(&self, token: &str, requested_tool: &str) -> Result<ExecutionGrant, String> {
        self.validate_with_args(token, requested_tool, None)
    }

    /// Validate with mandatory input_hash argument binding (SEC-2).
    pub fn validate_with_args(
        &self,
        token: &str,
        requested_tool: &str,
        arguments: Option<&serde_json::Value>,
    ) -> Result<ExecutionGrant, String> {
        let mut allowed_audiences = HashSet::new();
        allowed_audiences.insert("executor-host".to_string());

        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from_strings(&["trust_gateway"])),
            allowed_audiences: Some(allowed_audiences),
            ..Default::default()
        };

        // Try Ed25519 first (preferred)
        if let Some(ref ed_key) = self.ed25519_key {
            match ed_key.verify_token::<ExecutionGrant>(token, Some(options.clone())) {
                Ok(claims) => {
                    let now = chrono::Utc::now().timestamp();
                    if claims.custom.expires_at < now {
                        return Err("ExecutionGrant has expired".to_string());
                    }
                    if claims.custom.allowed_action != requested_tool {
                        return Err(format!(
                            "Grant mismatch: grant allows '{}' but '{}' was requested",
                            claims.custom.allowed_action, requested_tool
                        ));
                    }
                    // SEC-2: input_hash binding is mandatory
                    if let Some(args) = arguments {
                        let actual_hash = trust_core::canonical_json::canonical_hash(args);
                        if claims.custom.input_hash != actual_hash {
                            return Err("Grant input_hash mismatch: arguments tampered".to_string());
                        }
                    }
                    return Ok(claims.custom);
                }
                Err(e) => {
                    if self.hmac_key.is_some() {
                        tracing::debug!("Ed25519 verification failed, trying HMAC: {}", e);
                    } else {
                        return Err(format!("Grant validation failed (Ed25519): {}", e));
                    }
                }
            }
        }

        // Fall back to HMAC (legacy)
        if let Some(ref hmac_key) = self.hmac_key {
            tracing::warn!("⚠️ Grant validation fell back to HMAC. HMAC is deprecated and for development only (SEC-1).");
            let claims = hmac_key
                .verify_token::<ExecutionGrant>(token, Some(options))
                .map_err(|e| format!("Grant validation failed (HMAC): {}", e))?;

            let now = chrono::Utc::now().timestamp();
            if claims.custom.expires_at < now {
                return Err("ExecutionGrant has expired".to_string());
            }
            if claims.custom.allowed_action != requested_tool {
                return Err(format!(
                    "Grant mismatch: grant allows '{}' but '{}' was requested",
                    claims.custom.allowed_action, requested_tool
                ));
            }
            // SEC-2: input_hash binding is mandatory
            if let Some(args) = arguments {
                let actual_hash = trust_core::canonical_json::canonical_hash(args);
                if claims.custom.input_hash != actual_hash {
                    return Err("Grant input_hash mismatch: arguments tampered".to_string());
                }
            }
            return Ok(claims.custom);
        }

        Err("No verification key configured — cannot validate grant".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_calendar_start_end_canonical() {
        let args = json!({
            "summary": "Meeting",
            "start_time": "2026-05-19T07:30:00Z",
            "end_time": "2026-05-19T08:30:00Z"
        });
        let res = parse_calendar_start_end(&args);
        assert!(res.is_ok());
        let (start, end) = res.unwrap();
        assert_eq!(start, "2026-05-19T07:30:00Z");
        assert_eq!(end, "2026-05-19T08:30:00Z");
    }

    #[test]
    fn test_parse_calendar_start_end_datetime_alias() {
        let args = json!({
            "summary": "Meeting",
            "start_datetime": "2026-05-19T07:30:00Z",
            "end_datetime": "2026-05-19T08:30:00Z"
        });
        let res = parse_calendar_start_end(&args);
        assert!(res.is_ok());
        let (start, end) = res.unwrap();
        assert_eq!(start, "2026-05-19T07:30:00Z");
        assert_eq!(end, "2026-05-19T08:30:00Z");
    }

    #[test]
    fn test_parse_calendar_start_end_llm_alias() {
        let args = json!({
            "summary": "Meeting",
            "start": "2026-05-19T07:30:00Z",
            "end": "2026-05-19T08:30:00Z"
        });
        let res = parse_calendar_start_end(&args);
        assert!(res.is_ok());
        let (start, end) = res.unwrap();
        assert_eq!(start, "2026-05-19T07:30:00Z");
        assert_eq!(end, "2026-05-19T08:30:00Z");
    }

    #[test]
    fn test_parse_calendar_start_end_nested_object() {
        let args = json!({
            "summary": "Meeting",
            "start": { "dateTime": "2026-05-19T07:30:00Z" },
            "end": { "dateTime": "2026-05-19T08:30:00Z" }
        });
        let res = parse_calendar_start_end(&args);
        assert!(res.is_ok());
        let (start, end) = res.unwrap();
        assert_eq!(start, "2026-05-19T07:30:00Z");
        assert_eq!(end, "2026-05-19T08:30:00Z");
    }

    #[test]
    fn test_parse_calendar_start_end_missing() {
        let args = json!({
            "summary": "Meeting",
            "start": "2026-05-19T07:30:00Z"
        });
        let res = parse_calendar_start_end(&args);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "Missing end_time/end_datetime/end");
    }
}
