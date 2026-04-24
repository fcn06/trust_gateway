// ─────────────────────────────────────────────────────────────
// HTTP API — Trust Gateway public endpoints
//
//  POST /v1/actions/propose  — propose an action for governance
//  GET  /v1/tools/list       — discover governed tools (PicoClaw)
//  GET  /health              — health check
// ─────────────────────────────────────────────────────────────

use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post, delete},
    extract::State,
    http::Method,
    Json,
    response::sse::{Event, Sse},
};
use tower_http::cors::CorsLayer;

use trust_core::action::OperationKind;

use crate::gateway::{GatewayState, GatewayResponse, ProposeActionRequest};

/// Build the Axum router with all gateway routes.
pub fn build_router(state: Arc<GatewayState>) -> Router {
    let allowed_origins: Vec<axum::http::HeaderValue> = state.allowed_origins
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods(vec![Method::GET, Method::POST, Method::PATCH, Method::DELETE, Method::OPTIONS])
        .allow_headers(vec![
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ]);

    Router::new()
        .route("/v1/actions/propose", post(propose_action_handler))
        .route("/v1/tools/list", get(tools_list_handler))
        // Phase 2: Standalone Registry
        .route("/v1/tools/registry", get(crate::standalone_registry::registry_handler))
        // Agent Registry API
        .route("/v1/agents", get(crate::agent_api::list_agents_handler)
            .post(crate::agent_api::register_agent_handler))
        .route("/v1/agents/:agent_id", get(crate::agent_api::get_agent_handler)
            .patch(crate::agent_api::update_agent_handler)
            .delete(crate::agent_api::revoke_agent_handler))
        .route("/v1/agents/:agent_id/kill", post(crate::agent_api::kill_agent_handler))
        .route("/v1/agents/:agent_id/revive", post(crate::agent_api::revive_agent_handler))
        // Phase 4: Standalone Approval API
        .route("/v1/approvals", get(crate::approval_http::list_approvals_handler))
        .route("/v1/approvals/:approval_id", get(crate::approval_http::get_approval_handler))
        .route("/v1/approvals/:approval_id/decision", post(crate::approval_http::submit_decision_handler))
        // Phase 5: Action status polling (async approval flow)
        .route("/v1/actions/status/:action_id", get(crate::approval_http::action_status_handler))
        .route("/v1/mcp/sse", get(crate::mcp_sse::sse_handler)
            .post(crate::mcp_sse::messages_handler))
        .route("/v1/mcp/messages", post(crate::mcp_sse::messages_handler))
        // Timeline API (Trust Replay)
        .route("/api/actions", get(list_actions_handler))
        .route("/api/actions/:action_id", get(get_action_handler))
        .route("/api/actions/:action_id/timeline", get(get_action_timeline_handler))
        // WS3.1: Live SSE timeline stream
        .route("/api/actions/:action_id/live", get(action_live_sse_handler))
        // WS4.1: Policy CRUD API
        .route("/api/policy/rules", get(crate::policy_api::list_rules_handler)
            .post(crate::policy_api::create_rule_handler))
        .route("/api/policy/rules/:rule_id", delete(crate::policy_api::delete_rule_handler))
        .route("/api/policy/simulate", post(crate::policy_api::simulate_handler))
        .route("/health", get(health_handler))
        .with_state(state)
        .layer(cors)
}

/// Extract Bearer token from the Authorization header.
fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// POST /v1/actions/propose — the main gateway entry point.
///
/// Receives an action proposal, runs it through the governance
/// pipeline (validate → policy → branch), and returns the result.
///
/// ## Phase 3.1: Triple-JWT Fix
///
/// The session JWT is resolved from a priority chain:
///   1. `Authorization: Bearer <jwt>` header (canonical, preferred)
///   2. `session_jwt` field in the JSON body (backward compatible)
///   3. `_meta.io.lianxi.session_jwt` in arguments (external swarm protocol)
///
/// This means external swarms only need to place the JWT in the Authorization
/// header — the gateway auto-injects it into `_meta` for identity resolution.
async fn propose_action_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ProposeActionRequest>,
) -> Json<GatewayResponse> {
    tracing::info!("📥 HTTP action proposal: {}", req.action_name);

    // Phase 3.1: Resolve JWT from priority chain (header > body > _meta)
    let session_jwt = extract_bearer_token(&headers)
        .unwrap_or(req.session_jwt.clone());

    // Phase 3.1: Auto-inject JWT into _meta if the caller used the header shortcut
    let mut arguments = req.arguments.clone();
    if !session_jwt.is_empty() {
        if let Some(obj) = arguments.as_object_mut() {
            if let Some(meta) = obj.get_mut("_meta") {
                // _meta exists — ensure session_jwt is present in io.lianxi
                if let Some(ag) = meta.get_mut("io.lianxi") {
                    if ag.get("session_jwt").is_none() {
                        if let Some(ag_obj) = ag.as_object_mut() {
                            ag_obj.insert("session_jwt".to_string(), serde_json::json!(session_jwt));
                        }
                    }
                }
            }
        }
    }

    // Phase 9: Unified identity extraction
    let proposed = crate::transport_normalizer::normalize_http_propose(
        &req.action_name,
        arguments.clone(),
        &session_jwt,
        None, // remote_addr not easily available in this simple handler signature
    ).unwrap_or_else(|e| {
        tracing::error!("HTTP propose normalization failed: {}", e);
        
        let tenant_id = req.tenant_id
            .or_else(|| identity_context::jwt::extract_tenant_id_from_jwt(&session_jwt))
            .unwrap_or_default();
            
        let jti = identity_context::jwt::extract_jti_from_jwt(&session_jwt)
            .unwrap_or_default();
            
        let (owner_did, requester_did) = if !session_jwt.is_empty() {
            identity_context::jwt::extract_dids_from_jwt(&session_jwt)
                .unwrap_or(("unknown".to_string(), "unknown".to_string()))
        } else {
            ("unknown".to_string(), "unknown".to_string())
        };

        let source = match req.source_type.as_deref() {
            Some("picoclaw") => identity_context::models::SourceContext {
                source_type: identity_context::models::SourceType::HttpApi,
                source_id: "picoclaw".to_string(),
                transport: identity_context::models::TransportKind::Http,
                correlation_id: jti.clone(),
                remote_addr: None,
            },
            _ => identity_context::models::SourceContext::default(),
        };
            
        // Fallback for errors
        identity_context::models::ProposedAction {
            action_id: uuid::Uuid::new_v4().to_string(),
            tool_name: req.action_name.clone(),
            arguments: arguments.clone(),
            identity: identity_context::models::IdentityContext {
                tenant_id,
                owner_did,
                requester_did,
                session_jwt: session_jwt.clone(),
                source,
            },
            raw_meta: None,
        }
    });

    // Phase 2.1: Use single canonical conversion
    let action_req = crate::gateway::build_action_request(proposed);

    match crate::gateway::process_action(state.clone(), action_req).await {
        Ok(response) => Json(response),
        Err(e) => Json(GatewayResponse {
            action_id: uuid::Uuid::new_v4().to_string(),
            status: "error".to_string(),
            result: None,
            error: Some(format!("{}", e)),
            approval_id: None,
            escalation: None,
        }),
    }
}

/// GET /v1/tools/list — Tool discovery for external runtimes (PicoClaw).
///
/// Proxies the Host's /.well-known/skills.json and transforms it
/// into a flat MCP-compatible tool list with routing metadata.
async fn tools_list_handler(
    State(state): State<Arc<GatewayState>>,
) -> Json<serde_json::Value> {
    let mut tools = Vec::new();

    // Pull from ToolRegistry cache (Phase 6 centralization)
    if let Some(ref registry) = state.tool_registry {
        // Ensure cache is populated (including VP MCP tools)
        registry.refresh_if_stale(&state.http_client, &state.connectors.host_url, &state.connectors.vp_mcp_url).await;
        
        for (name, entry) in registry.all_tools().await {
            tools.push(serde_json::json!({
                "name": name,
                "description": entry.description,
                "inputSchema": entry.input_schema,
                "executor_type": entry.executor_type,
                "tags": [],
                "operation_kind": infer_operation(&name),
                "category": entry.category.unwrap_or_else(|| "unknown".to_string()),
            }));
        }
    }

    let total = tools.len();
    tracing::info!("🔎 Tools list: returning {} tools from cache", total);

    Json(serde_json::json!({
        "tools": tools,
        "total": total,
    }))
}




/// GET /health — simple health check.
async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "trust_gateway",
        "version": "0.1.0",
    }))
}

/// Infer operation kind from action name conventions.
pub(crate) fn infer_operation(name: &str) -> OperationKind {
    let lower = name.to_lowercase();
    if lower.contains("list") || lower.contains("get") || lower.contains("read") || lower.contains("search") || lower.contains("fetch") {
        OperationKind::Read
    } else if lower.contains("create") || lower.contains("add") || lower.contains("new") || lower.contains("insert") {
        OperationKind::Create
    } else if lower.contains("update") || lower.contains("edit") || lower.contains("modify") || lower.contains("set") {
        OperationKind::Update
    } else if lower.contains("delete") || lower.contains("remove") || lower.contains("cancel") {
        OperationKind::Delete
    } else if lower.contains("refund") || lower.contains("transfer") || lower.contains("send") || lower.contains("pay") {
        OperationKind::Transfer
    } else {
        OperationKind::Create
    }
}

/// Infer category from action name prefix.
pub(crate) fn infer_category(name: &str) -> String {
    // Try dot notation first: "google.calendar.event.create" → "google"
    if let Some(first) = name.split('.').next() {
        if first != name {
            return first.to_string();
        }
    }
    // Try underscore: "google_calendar_list_events" → "google"
    name.split('_').next().unwrap_or("unknown").to_string()
}

// ──────────────────────────────────────────────────────────
// Timeline API handlers (Trust Replay)
// ──────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct ListActionsQuery {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize { 50 }

/// GET /api/actions — List all tracked actions with summary.
async fn list_actions_handler(
    State(state): State<Arc<GatewayState>>,
    axum::extract::Query(query): axum::extract::Query<ListActionsQuery>,
) -> Json<serde_json::Value> {
    let kv_store = match state.jetstream.get_key_value("action_timelines").await {
        Ok(store) => store,
        Err(e) => {
            tracing::warn!("Cannot access action_timelines KV: {}", e);
            return Json(serde_json::json!({ "actions": [], "total": 0, "error": format!("{}", e) }));
        }
    };

    let mut actions = Vec::new();
    // List all keys in the KV bucket
    match kv_store.keys().await {
        Ok(mut keys) => {
            while let Some(Ok(key)) = tokio_stream::StreamExt::next(&mut keys).await {
                if let Ok(Some(entry)) = kv_store.get(&key).await {
                    if let Ok(timeline) = serde_json::from_slice::<crate::audit_projector::ActionTimeline>(&entry) {
                        // Apply filters
                        if let Some(ref status_filter) = query.status {
                            if timeline.summary.status != *status_filter {
                                continue;
                            }
                        }
                        if let Some(ref tenant_filter) = query.tenant_id {
                            if timeline.tenant_id != *tenant_filter {
                                continue;
                            }
                        }
                        actions.push(serde_json::json!({
                            "action_id": timeline.action_id,
                            "tenant_id": timeline.tenant_id,
                            "approval_id": timeline.approval_id,
                            "title": timeline.summary.title,
                            "action_name": timeline.summary.action_name,
                            "source_type": timeline.summary.source_type,
                            "status": timeline.summary.status,
                            "risk_level": timeline.summary.risk_level,
                            "event_count": timeline.timeline.len(),
                            "created_at": timeline.summary.created_at,
                            "last_updated_at": timeline.last_updated_at,
                        }));
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!("Cannot list action_timelines keys: {}", e);
        }
    }

    // Sort descending by created_at
    actions.sort_by(|a, b| {
        let ts_a = a.get("created_at").and_then(|t| t.as_str()).unwrap_or("");
        let ts_b = b.get("created_at").and_then(|t| t.as_str()).unwrap_or("");
        ts_b.cmp(ts_a)
    });

    let total = actions.len();
    if actions.len() > query.limit {
        actions.truncate(query.limit);
    }

    Json(serde_json::json!({
        "actions": actions,
        "total": total,
    }))
}

/// GET /api/actions/:action_id — Full action detail with timeline.
async fn get_action_handler(
    State(state): State<Arc<GatewayState>>,
    axum::extract::Path(action_id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let kv_store = match state.jetstream.get_key_value("action_timelines").await {
        Ok(store) => store,
        Err(e) => {
            return Json(serde_json::json!({ "error": format!("KV access failed: {}", e) }));
        }
    };

    match kv_store.get(&action_id).await {
        Ok(Some(entry)) => {
            match serde_json::from_slice::<crate::audit_projector::ActionTimeline>(&entry) {
                Ok(timeline) => Json(serde_json::to_value(timeline).unwrap_or_default()),
                Err(e) => Json(serde_json::json!({ "error": format!("Deserialize error: {}", e) })),
            }
        }
        Ok(None) => Json(serde_json::json!({ "error": "Action not found" })),
        Err(e) => Json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/actions/:action_id/timeline — Timeline events only.
async fn get_action_timeline_handler(
    State(state): State<Arc<GatewayState>>,
    axum::extract::Path(action_id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let kv_store = match state.jetstream.get_key_value("action_timelines").await {
        Ok(store) => store,
        Err(e) => {
            return Json(serde_json::json!({ "error": format!("KV access failed: {}", e) }));
        }
    };

    match kv_store.get(&action_id).await {
        Ok(Some(entry)) => {
            match serde_json::from_slice::<crate::audit_projector::ActionTimeline>(&entry) {
                Ok(timeline) => Json(serde_json::json!({
                    "action_id": timeline.action_id,
                    "status": timeline.summary.status,
                    "timeline": timeline.timeline,
                })),
                Err(e) => Json(serde_json::json!({ "error": format!("Deserialize error: {}", e) })),
            }
        }
        Ok(None) => Json(serde_json::json!({ "error": "Action not found" })),
        Err(e) => Json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

// ──────────────────────────────────────────────────────────
// WS3.1: Live SSE timeline stream
// ──────────────────────────────────────────────────────────

/// GET /api/actions/:action_id/live — SSE stream of timeline events.
///
/// Subscribes to NATS subject `audit.v1.events` and filters for events
/// matching the given action_id. Streams them as SSE `event: timeline`.
async fn action_live_sse_handler(
    State(state): State<Arc<GatewayState>>,
    axum::extract::Path(action_id): axum::extract::Path<String>,
) -> Sse<impl futures::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let nats = state.nats.clone();
    let aid = action_id.clone();

    let stream = async_stream::stream! {
        // Send initial snapshot
        if let Ok(kv) = state.jetstream.get_key_value("action_timelines").await {
            if let Ok(Some(entry)) = kv.get(&aid).await {
                if let Ok(timeline) = serde_json::from_slice::<crate::audit_projector::ActionTimeline>(&entry) {
                    let data = serde_json::to_string(&timeline).unwrap_or_default();
                    yield Ok(Event::default().event("snapshot").data(data));
                }
            }
        }

        // Subscribe to audit events and filter for this action
        match nats.subscribe("audit.v1.events").await {
            Ok(mut sub) => {
                while let Some(msg) = futures::StreamExt::next(&mut sub).await {
                    if let Ok(evt) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                        if evt.get("action_id").and_then(|a| a.as_str()) == Some(&aid) {
                            let data = serde_json::to_string(&evt).unwrap_or_default();
                            yield Ok(Event::default().event("timeline").data(data));
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("SSE: Could not subscribe to audit events: {}", e);
                yield Ok(Event::default().event("error").data(format!("Subscribe failed: {}", e)));
            }
        }
    };

    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::new())
}
