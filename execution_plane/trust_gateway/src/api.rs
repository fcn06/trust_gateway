// ─────────────────────────────────────────────────────────────
// HTTP API — Trust Gateway public endpoints
//
//  POST /v1/actions/propose  — propose an action for governance
//  GET  /v1/tools/list       — discover governed tools (PicoClaw)
//  GET  /health              — health check
// ─────────────────────────────────────────────────────────────

use axum::{
    extract::State,
    http::Method,
    response::sse::{Event, Sse},
    routing::{delete, get, post},
    Json, Router,
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use crate::gateway::{GatewayResponse, GatewayState, ProposeActionRequest};
use tracing::Instrument;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;

/// Build the Axum router with all gateway routes.
pub fn build_router(state: Arc<GatewayState>) -> Router {
    let allowed_origins: Vec<axum::http::HeaderValue> = state
        .allowed_origins
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods(vec![
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(vec![
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
        ])
        .allow_credentials(true);

    Router::new()
        .route("/v1/actions/propose", post(propose_action_handler))
        .route("/v1/tools/list", get(tools_list_handler))
        // Phase 2: Standalone Registry
        .route(
            "/v1/tools/registry",
            get(crate::standalone_registry::registry_handler),
        )
        // Agent Registry API
        .route(
            "/v1/agents",
            get(crate::agent_api::list_agents_handler)
                .post(crate::agent_api::register_agent_handler),
        )
        .route(
            "/v1/agents/:agent_id",
            get(crate::agent_api::get_agent_handler)
                .patch(crate::agent_api::update_agent_handler)
                .delete(crate::agent_api::revoke_agent_handler),
        )
        .route(
            "/v1/agents/:agent_id/kill",
            post(crate::agent_api::kill_agent_handler),
        )
        .route(
            "/v1/agents/:agent_id/revive",
            post(crate::agent_api::revive_agent_handler),
        )
        // Webhooks API
        .route(
            "/v1/webhooks/:provider",
            post(crate::webhook_handler::webhook_post_handler),
        )
        // Phase 4: Standalone Approval API
        .route(
            "/v1/approvals",
            get(crate::approval_http::list_approvals_handler),
        )
        .route(
            "/v1/approvals/:approval_id",
            get(crate::approval_http::get_approval_handler),
        )
        .route(
            "/v1/approvals/:approval_id/decision",
            post(crate::approval_http::submit_decision_handler),
        )
        // Portal Compatibility: Direct escalation management
        .route(
            "/api/escalation_requests",
            get(crate::approval_http::list_escalations_handler),
        )
        .route(
            "/api/escalation_requests/:id/approve",
            post(crate::approval_http::approve_escalation_handler),
        )
        .route(
            "/api/escalation_requests/:id/deny",
            post(crate::approval_http::deny_escalation_handler),
        )
        // Phase 5: Action status polling (async approval flow)
        .route(
            "/v1/actions/status/:action_id",
            get(crate::approval_http::action_status_handler),
        )
        .route(
            "/v1/mcp/sse",
            get(crate::mcp_sse::sse_handler).post(crate::mcp_sse::messages_handler),
        )
        .route("/v1/mcp/messages", post(crate::mcp_sse::messages_handler))
        // OAuth Proxy (Redirect to Connector MCP Server)
        .route(
            "/oauth/*path",
            get(connector_proxy_handler).post(connector_proxy_handler),
        )
        // OAuth2/OIDC endpoints (proxied to standalone OAuth2 Service)
        .route(
            "/.well-known/openid-configuration",
            get(oauth_service_proxy_handler),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_service_proxy_handler),
        )
        .route(
            "/auth/authorize",
            get(oauth_service_proxy_handler),
        )
        .route(
            "/authorize",
            get(oauth_service_proxy_handler),
        )
        .route(
            "/auth/authorize/consent",
            post(oauth_service_proxy_handler),
        )
        .route(
            "/authorize/consent",
            post(oauth_service_proxy_handler),
        )
        .route("/auth/token", post(oauth_service_proxy_handler))
        .route("/token", post(oauth_service_proxy_handler))
        // Timeline API (Trust Replay)
        .route("/api/actions", get(list_actions_handler))
        .route("/api/actions/:action_id", get(get_action_handler))
        .route(
            "/api/actions/:action_id/timeline",
            get(get_action_timeline_handler),
        )
        // WS3.1: Live SSE timeline stream
        .route("/api/actions/:action_id/live", get(action_live_sse_handler))
        // WS4.1: Policy CRUD API
        .route(
            "/api/policy/rules",
            get(crate::policy_api::list_rules_handler).post(crate::policy_api::create_rule_handler),
        )
        .route(
            "/api/policy/rules/:rule_id",
            delete(crate::policy_api::delete_rule_handler),
        )
        .route(
            "/api/policy/simulate",
            post(crate::policy_api::simulate_handler),
        )
        .route("/health", get(health_handler))
        .route("/healthz", get(healthz_handler))
        .route("/readyz", get(readyz_handler))
        .fallback(host_proxy_handler)
        .with_state(state)
        .layer(cors)
}

/// Fallback handler that proxies unmatched requests to the Host service.
/// This allows the portal to access WebAuthn, Identity, and other APIs
/// through the Trust Gateway's single domain.
async fn host_proxy_handler(
    State(state): State<Arc<GatewayState>>,
    req: Request,
) -> impl IntoResponse {
    let path_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    let method = req.method().clone();
    let headers = req.headers().clone();

    // Extract body
    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to read request body: {}", e),
            )
                .into_response()
        }
    };

    let target_url = format!(
        "{}{}",
        state.connectors.host_url.trim_end_matches('/'),
        path_query
    );

    tracing::debug!("🔀 Proxying {} {} to Host...", method, path_query);

    let mut proxy_req = state
        .http_client
        .request(method, &target_url)
        .body(body_bytes);

    for (key, value) in headers.iter() {
        // Skip host header and security headers that we might want to override
        if key != header::HOST && key != header::CONTENT_LENGTH {
            proxy_req = proxy_req.header(key, value);
        }
    }

    match proxy_req.send().await {
        Ok(res) => {
            let status = res.status();
            let headers = res.headers().clone();
            let body = match res.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        format!("Failed to read response from Host: {}", e),
                    )
                        .into_response()
                }
            };

            let mut axum_res = axum::response::Response::builder()
                .status(status)
                .body(Body::from(body))
                .unwrap()
                .into_response();

            {
                let axum_headers = axum_res.headers_mut();
                for (key, value) in headers.iter() {
                    let key_str = key.as_str().to_lowercase();
                    if key != header::TRANSFER_ENCODING
                        && key != header::CONTENT_LENGTH
                        && !key_str.starts_with("access-control-")
                    {
                        axum_headers.append(key, value.clone());
                    }
                }
            }

            axum_res
        }
        Err(e) => {
            tracing::error!("❌ Proxy error to Host: {:?}", e);
            (StatusCode::BAD_GATEWAY, format!("Proxy error: {:?}", e)).into_response()
        }
    }
}

/// Fallback handler that proxies OAuth requests to the Connector MCP service.
async fn connector_proxy_handler(
    State(state): State<Arc<GatewayState>>,
    req: Request,
) -> impl IntoResponse {
    let path_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    let method = req.method().clone();
    let headers = req.headers().clone();

    // Extract body
    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to read request body: {}", e),
            )
                .into_response()
        }
    };

    let target_url = format!(
        "{}{}",
        state.connectors.connector_mcp_url.trim_end_matches('/'),
        path_query
    );

    tracing::debug!("🔀 Proxying {} {} to Connector...", method, path_query);

    let mut proxy_req = state
        .http_client
        .request(method, &target_url)
        .body(body_bytes);

    for (key, value) in headers.iter() {
        if key != header::HOST && key != header::CONTENT_LENGTH {
            proxy_req = proxy_req.header(key, value);
        }
    }

    match proxy_req.send().await {
        Ok(res) => {
            let status = res.status();
            let headers = res.headers().clone();
            let body = match res.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        format!("Failed to read response from Connector: {}", e),
                    )
                        .into_response()
                }
            };

            let mut axum_res = axum::response::Response::builder()
                .status(status)
                .body(Body::from(body))
                .unwrap()
                .into_response();

            {
                let axum_headers = axum_res.headers_mut();
                for (key, value) in headers.iter() {
                    let key_str = key.as_str().to_lowercase();
                    if key != header::TRANSFER_ENCODING
                        && key != header::CONTENT_LENGTH
                        && !key_str.starts_with("access-control-")
                    {
                        axum_headers.append(key, value.clone());
                    }
                }
            }

            axum_res
        }
        Err(e) => {
            tracing::error!("❌ Proxy error to Connector: {}", e);
            (StatusCode::BAD_GATEWAY, format!("Proxy error: {}", e)).into_response()
        }
    }
}

/// Fallback handler that proxies OAuth requests to the standalone OAuth2 Service if configured.
async fn oauth_service_proxy_handler(
    State(state): State<Arc<GatewayState>>,
    req: Request,
) -> impl IntoResponse {
    let oauth2_url = match &state.connectors.oauth2_service_url {
        Some(url) => url,
        None => {
            return (
                StatusCode::NOT_IMPLEMENTED,
                "OAuth2 authorization is only available in the Professional/Enterprise edition."
            ).into_response();
        }
    };

    let mut path_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    // Normalize path to ensure /auth prefix is present when calling Standalone OAuth2 Service
    if path_query.starts_with("/authorize") {
        path_query = format!("/auth{}", path_query);
    } else if path_query.starts_with("/token") {
        path_query = format!("/auth{}", path_query);
    }

    let method = req.method().clone();
    let headers = req.headers().clone();

    // Extract body
    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to read request body: {}", e),
            )
                .into_response()
        }
    };

    let target_url = format!(
        "{}{}",
        oauth2_url.trim_end_matches('/'),
        path_query
    );

    tracing::debug!("🔀 Proxying {} {} to OAuth2 Service...", method, path_query);

    let mut proxy_req = state
        .http_client
        .request(method, &target_url)
        .body(body_bytes);

    for (key, value) in headers.iter() {
        if key != header::HOST && key != header::CONTENT_LENGTH {
            proxy_req = proxy_req.header(key, value);
        }
    }

    match proxy_req.send().await {
        Ok(res) => {
            let status = res.status();
            let headers = res.headers().clone();
            let body = match res.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        format!("Failed to read response from OAuth2 Service: {}", e),
                    )
                        .into_response()
                }
            };

            let mut axum_res = axum::response::Response::builder()
                .status(status)
                .body(Body::from(body))
                .unwrap()
                .into_response();

            {
                let axum_headers = axum_res.headers_mut();
                for (key, value) in headers.iter() {
                    let key_str = key.as_str().to_lowercase();
                    if key != header::TRANSFER_ENCODING
                        && key != header::CONTENT_LENGTH
                        && !key_str.starts_with("access-control-")
                    {
                        axum_headers.append(key, value.clone());
                    }
                }
            }

            axum_res
        }
        Err(e) => {
            tracing::error!("❌ Proxy error to OAuth2 Service: {}", e);
            (StatusCode::BAD_GATEWAY, format!("Proxy error: {}", e)).into_response()
        }
    }
}

/// Extract Bearer token from the Authorization header.
///
/// Delegates to [`crate::auth::extract_bearer_token`] — this wrapper
/// exists for backward-compatibility within this module.
pub(crate) fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    crate::auth::extract_bearer_token(headers)
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
) -> axum::response::Response {
    let trace_id = headers.get("x-trace-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            req.arguments.get("_meta")
                .and_then(|m| m.get("io.lianxi"))
                .and_then(|i| i.get("correlation_id"))
                .and_then(|c| c.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
        });

    let span = tracing::info_span!("propose_action", trace_id = %trace_id);

    async move {
        tracing::info!("📥 HTTP action proposal: {}", req.action_name);

        // Phase 3.1: Resolve JWT from priority chain (header > body > _meta)
        let session_jwt = extract_bearer_token(&headers).unwrap_or_else(|| req.session_jwt.clone());

        // CRITICAL FIX: The gateway must validate the cryptographic signature of the token!
        // If the token was provided in the body instead of the header, we construct a
        // synthetic HeaderMap to pass to the TokenValidator trait.
        let mut validation_headers = headers.clone();
        if !session_jwt.is_empty() && extract_bearer_token(&validation_headers).is_none() {
            if let Ok(auth_val) = format!("Bearer {}", session_jwt).parse() {
                validation_headers.insert(axum::http::header::AUTHORIZATION, auth_val);
            }
        }

        let validation_res = state
            .token_validator
            .validate(&validation_headers, &state.jwt_secret)
            .await;

        if let Err(e) = validation_res {
            tracing::error!("Authentication failed: {}", e);

            // TODO: In Phase 2, implement a strict DID-to-Tenant lookup instead of defaulting.
            // Extract tenant_id from token for the audit log
            let mut tenant_id = identity_context::jwt::extract_tenant_id_from_jwt(&session_jwt)
                .unwrap_or_else(|| "default".to_string());

            let mut agent_did = "unknown".to_string();
            let mut owner_did = "unknown".to_string();

            if tenant_id == "default" || tenant_id == "unknown" {
                if let Some(payload_str) = session_jwt.split('.').nth(1) {
                    use base64::Engine;
                    if let Ok(decoded) =
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_str)
                    {
                        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&decoded) {
                            if json.get("vp").is_some() {
                                if let Some(aud) = json.get("aud").and_then(|v| v.as_str()) {
                                    owner_did = aud.to_string();

                                    // Try to resolve the actual tenant_id for this DID from the agent registry
                                    if let Ok(Some(agent)) =
                                        state.agent_registry.resolve_by_source(aud).await
                                    {
                                        tenant_id = agent.owner;
                                    }
                                }
                                if let Some(iss) = json.get("iss").and_then(|v| v.as_str()) {
                                    agent_did = iss.to_string();
                                }
                            }
                        }
                    } else {
                        tracing::error!("Failed to decode VP payload payload_str: {}", payload_str);
                    }
                }
            }

            tracing::info!(
                "Extracted from failed auth -> tenant_id: {}, owner_did: {}, agent_did: {}",
                tenant_id,
                owner_did,
                agent_did
            );

            let action_id = uuid::Uuid::new_v4().to_string();

            // Emit an audit event so the rejection appears in the user's activity log!
            let state_emit = state.clone();
            let action_id_emit = action_id.clone();
            let err_msg = format!("Authentication failed: {}", e);
            let action_name = req.action_name.clone();
            tokio::spawn(async move {
                crate::audit_sink::emit_audit(
                    &*state_emit.security.audit_sink,
                    &tenant_id,
                    trust_core::audit::AuditEventType::ActionFailed,
                    "trust_gateway.api",
                    &action_id_emit,
                    serde_json::json!({
                        "reason": err_msg,
                        "stage": "authentication",
                        "action_name": action_name,
                        "actor": agent_did,
                        "owner_did": owner_did,
                    }),
                )
                .await;
            });

            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(GatewayResponse {
                    action_id,
                    status: "denied".to_string(),
                    error: Some(format!("Authentication failed: {}", e)),
                    result: None,
                    approval_id: None,
                    escalation: None,
                }),
            )
                .into_response();
        }
        let verified_identity = validation_res.unwrap();

        // Phase 3.1: Auto-inject JWT into _meta if the caller used the header shortcut
        let mut arguments = req.arguments.clone();
        if !session_jwt.is_empty() {
            if let Some(obj) = arguments.as_object_mut() {
                if let Some(meta) = obj.get_mut("_meta") {
                    // _meta exists — ensure session_jwt is present in io.lianxi
                    if let Some(ag) = meta.get_mut("io.lianxi") {
                        if ag.get("session_jwt").is_none() {
                            if let Some(ag_obj) = ag.as_object_mut() {
                                ag_obj
                                    .insert("session_jwt".to_string(), serde_json::json!(session_jwt));
                            }
                        }
                    }
                }
            }
        }

        // Phase 9: Unified identity extraction
        // RULE[010_JWT_CONTRACTS.md]: Pass fully normalized base_identity from TokenValidator
        let mut proposed = crate::transport_normalizer::normalize_http_propose(
            &req.action_name,
            arguments.clone(),
            verified_identity.clone(),
            None, // remote_addr not easily available in this simple handler signature
        )
        .unwrap_or_else(|e| {
            tracing::error!("HTTP propose normalization failed: {}", e);

            // RULE[010_JWT_CONTRACTS.md]: In the fallback path, use the pre-verified identity directly
            let mut identity = verified_identity.clone();
            if let Some(req_tenant) = req.tenant_id {
                identity.tenant_id = req_tenant;
            }

            identity.source = match req.source_type.as_deref() {
                Some("picoclaw") => identity_context::models::SourceContext {
                    source_type: identity_context::models::SourceType::HttpApi,
                    source_id: "picoclaw".to_string(),
                    transport: identity_context::models::TransportKind::Http,
                    correlation_id: trace_id.clone(),
                    remote_addr: None,
                },
                _ => identity_context::models::SourceContext {
                    correlation_id: trace_id.clone(),
                    ..identity_context::models::SourceContext::default()
                },
            };

            // Fallback for errors — uses verified claims, no raw decode
            identity_context::models::ProposedAction {
                action_id: uuid::Uuid::new_v4().to_string(),
                tool_name: req.action_name.clone(),
                arguments: arguments.clone(),
                identity,
                raw_meta: None,
            }
        });

        // Set the trace_id in source correlation_id
        proposed.identity.source.correlation_id = trace_id.clone();

        // Phase 2.1: Use single canonical conversion
        let action_req = match crate::gateway::build_action_request(proposed) {
            Ok(req) => req,
            Err(e) => {
                tracing::error!("Strict tenant enforcement failed: {}", e);
                return axum::Json(GatewayResponse {
                    action_id: uuid::Uuid::new_v4().to_string(),
                    status: "denied".to_string(),
                    result: None,
                    error: Some(format!("Validation error: {}", e)),
                    approval_id: None,
                    escalation: None,
                })
                .into_response();
            }
        };

        use axum::response::IntoResponse;
        match crate::gateway::process_action(state.clone(), action_req).await {
            Ok(response) => Json(response).into_response(),
            Err(e) => Json(GatewayResponse {
                action_id: uuid::Uuid::new_v4().to_string(),
                status: "error".to_string(),
                result: None,
                error: Some(format!("{}", e)),
                approval_id: None,
                escalation: None,
            })
            .into_response(),
        }
    }.instrument(span).await
}

/// GET /v1/tools/list — Tool discovery for external runtimes (PicoClaw).
///
/// Proxies the Host's /.well-known/skills.json and transforms it
/// into a flat MCP-compatible tool list with routing metadata.
/// GET /v1/tools/list
///
/// Legacy PicoClaw endpoint. Now protected by authentication and uses
/// the same Smart Filtering logic as the MCP SSE endpoints.
async fn tools_list_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // 1. Enforce Authentication
    let verified = match state
        .token_validator
        .validate(&headers, &state.jwt_secret)
        .await
    {
        Ok(v) => v,
        Err(status) => {
            tracing::warn!(
                "🚫 /v1/tools/list rejected: Authentication failed ({})",
                status
            );
            let mut response = status.into_response();
            if status == axum::http::StatusCode::UNAUTHORIZED {
                response.headers_mut().insert(
                    axum::http::header::WWW_AUTHENTICATE,
                    axum::http::HeaderValue::from_static("Bearer realm=\"trust_gateway\""),
                );
            }
            return response;
        }
    };

    // Prioritize requester_did/owner_did to align NATS KV lookups, fallback to session_jwt
    let session_id = if !verified.requester_did.is_empty() {
        verified.requester_did.clone()
    } else if !verified.owner_did.is_empty() {
        verified.owner_did.clone()
    } else {
        verified.session_jwt.clone()
    };

    // 2. Reuse the shared MCP filtering logic (which injects meta-tools)
    let mcp_response = crate::mcp_sse::handle_tools_list(&state, None, &session_id).await;

    // 3. Return the response (JsonRpcResponse serializes directly)
    Json(mcp_response).into_response()
}

/// GET /health — simple health check.
async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "trust_gateway",
        "version": "0.1.0",
    }))
}

async fn healthz_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "alive",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

async fn readyz_handler(
    State(state): State<Arc<GatewayState>>,
) -> impl IntoResponse {
    let nats_state = state.nats.connection_state();
    let is_connected = nats_state == async_nats::connection::State::Connected;

    // Retrieve active policy engine's loaded rules
    let rules_count = state.security.policy_engine.list_rules_json().len();

    // Retrieve the statuses of background tasks
    let mut tasks = serde_json::Map::new();
    for entry in state.task_statuses.iter() {
        tasks.insert(
            entry.key().clone(),
            serde_json::to_value(entry.value().clone()).unwrap_or(serde_json::Value::Null),
        );
    }

    let ready = is_connected;
    let status = if ready { "ready" } else { "not_ready" };
    let status_code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status_code,
        Json(serde_json::json!({
            "status": status,
            "nats_connected": is_connected,
            "nats_state": format!("{:?}", nats_state),
            "loaded_rules": rules_count,
            "background_tasks": tasks,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        })),
    )
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

fn default_limit() -> usize {
    50
}

/// GET /api/actions — List all tracked actions with summary.
///
/// P2/H1 fix: Uses the `tenant_action_index` KV bucket for efficient
/// tenant-scoped lookups (O(1) instead of O(n) full table scan).
/// Falls back gracefully to the legacy full-scan if the index is
/// unavailable.
async fn list_actions_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ListActionsQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Phase 2: Mandatory authentication (via pluggable TokenValidator trait)
    // RULE[010_JWT_CONTRACTS.md]: validate() returns IdentityContext
    let verified = state
        .token_validator
        .validate(&headers, &state.jwt_secret)
        .await
        .map_err(|e| e)?;
    let my_did = verified.requester_did.clone();

    let kv_store = match state.jetstream.get_key_value("action_timelines").await {
        Ok(store) => store,
        Err(e) => {
            tracing::warn!("Cannot access action_timelines KV: {}", e);
            return Ok(Json(
                serde_json::json!({ "actions": [], "total": 0, "error": format!("{}", e) }),
            ));
        }
    };

    // ── P2/H1: Try indexed lookup first, fall back to full scan ──────
    let candidate_ids = collect_candidate_action_ids(
        &state.jetstream,
        &verified.tenant_id,
        &my_did,
        None, // user_did is currently not represented in IdentityContext
    )
    .await;

    let mut actions = Vec::new();

    match candidate_ids {
        Some(ids) => {
            // Fast path: fetch only the action IDs from the index
            tracing::debug!("📋 Using tenant index: {} candidate action IDs", ids.len());
            for action_id in ids {
                if let Ok(Some(entry)) = kv_store.get(&action_id).await {
                    if let Ok(timeline) =
                        serde_json::from_slice::<crate::audit_projector::ActionTimeline>(&entry)
                    {
                        if let Some(action) =
                            filter_and_format_action(&timeline, &my_did, &verified, &query)
                        {
                            actions.push(action);
                        }
                    }
                }
            }
        }
        None => {
            // Fallback: full scan (legacy behavior when index is unavailable)
            tracing::debug!("📋 Tenant index unavailable — falling back to full KV scan");
            match kv_store.keys().await {
                Ok(mut keys) => {
                    while let Some(Ok(key)) = tokio_stream::StreamExt::next(&mut keys).await {
                        if let Ok(Some(entry)) = kv_store.get(&key).await {
                            if let Ok(timeline) = serde_json::from_slice::<
                                crate::audit_projector::ActionTimeline,
                            >(&entry)
                            {
                                if let Some(action) =
                                    filter_and_format_action(&timeline, &my_did, &verified, &query)
                                {
                                    actions.push(action);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Cannot list action_timelines keys: {}", e);
                }
            }
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

    Ok(Json(serde_json::json!({
        "actions": actions,
        "total": total,
    })))
}

/// P2/H1: Collect candidate action IDs from the tenant index.
///
/// Queries multiple index keys (tenant, DID) and deduplicates.
/// Returns None if the index KV bucket is unavailable (triggering full-scan fallback).
async fn collect_candidate_action_ids(
    js: &async_nats::jetstream::Context,
    tenant_id: &str,
    my_did: &str,
    user_did: Option<&str>,
) -> Option<Vec<String>> {
    let index_store = js.get_key_value("tenant_action_index").await.ok()?;
    let tenant_id = if tenant_id.is_empty() {
        "default"
    } else {
        tenant_id
    };

    let mut all_ids = std::collections::HashSet::new();

    // 1. Tenant index
    if !tenant_id.is_empty() {
        let safe_tenant = tenant_id.replace(':', "_");
        let key = format!("tenant_{}", safe_tenant);
        if let Ok(Some(entry)) = index_store.get(&key).await {
            if let Ok(ids) = serde_json::from_slice::<Vec<String>>(&entry) {
                all_ids.extend(ids);
            }
        }
    }

    // 2. DID-based index (owner/requester visibility)
    for did in [Some(my_did), user_did].into_iter().flatten() {
        if !did.is_empty() && did != "unknown" {
            let safe_did = did.replace(':', "_");
            let key = format!("did_{}", safe_did);
            if let Ok(Some(entry)) = index_store.get(&key).await {
                if let Ok(ids) = serde_json::from_slice::<Vec<String>>(&entry) {
                    all_ids.extend(ids);
                }
            }
        }
    }

    // 3. Also include "default" and "unknown" tenant actions for Community Edition
    for fallback_tenant in &["default", "unknown"] {
        let key = format!("tenant_{}", fallback_tenant);
        if let Ok(Some(entry)) = index_store.get(&key).await {
            if let Ok(ids) = serde_json::from_slice::<Vec<String>>(&entry) {
                all_ids.extend(ids);
            }
        }
    }

    Some(all_ids.into_iter().collect())
}

/// Filter and format a single action timeline for the list response.
///
/// Returns None if the action doesn't belong to the requester or
/// doesn't match the query filters.
fn filter_and_format_action(
    timeline: &crate::audit_projector::ActionTimeline,
    my_did: &str,
    verified_identity: &trust_auth::IdentityContext,
    query: &ListActionsQuery,
) -> Option<serde_json::Value> {
    let is_owner = timeline
        .summary
        .owner_did
        .as_ref()
        .map(|d| d == my_did)
        .unwrap_or(false);
    let is_requester = timeline
        .summary
        .requester_did
        .as_ref()
        .map(|d| d == my_did)
        .unwrap_or(false);

    let tenant_match = timeline.tenant_id == verified_identity.tenant_id
        || timeline.tenant_id == "default"
        || timeline.tenant_id == "unknown";

    let belongs_to_me = is_owner || is_requester || tenant_match;

    tracing::trace!(
        "Timeline filter check -> action_id: {}, my_did: {}, owner_did: {:?}, requester_did: {:?}, tenant_id: {}, verified_identity.tenant_id: {}, belongs: {}",
        timeline.action_id, my_did, timeline.summary.owner_did, timeline.summary.requester_did, timeline.tenant_id, verified_identity.tenant_id, belongs_to_me
    );

    if !belongs_to_me {
        return None;
    }

    // Apply additional filters
    if let Some(ref status_filter) = query.status {
        if timeline.summary.status != *status_filter {
            return None;
        }
    }
    if let Some(ref tenant_filter) = query.tenant_id {
        if !(is_owner || is_requester) && timeline.tenant_id != *tenant_filter {
            return None;
        }
    }

    Some(serde_json::json!({
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
    }))
}

/// GET /api/actions/:action_id — Full action detail with timeline.
async fn get_action_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(action_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // RULE[010_JWT_CONTRACTS.md]: validate() returns IdentityContext
    let verified = state
        .token_validator
        .validate(&headers, &state.jwt_secret)
        .await
        .map_err(|e| e)?;
    let my_did = verified.requester_did.clone();

    let kv_store = match state.jetstream.get_key_value("action_timelines").await {
        Ok(store) => store,
        Err(e) => {
            return Ok(Json(
                serde_json::json!({ "error": format!("KV access failed: {}", e) }),
            ));
        }
    };

    match kv_store.get(&action_id).await {
        Ok(Some(entry)) => {
            match serde_json::from_slice::<crate::audit_projector::ActionTimeline>(&entry) {
                Ok(timeline) => {
                    let is_owner = timeline
                        .summary
                        .owner_did
                        .as_ref()
                        .map(|d| d == &my_did)
                        .unwrap_or(false);
                    let is_requester = timeline
                        .summary
                        .requester_did
                        .as_ref()
                        .map(|d| d == &my_did)
                        .unwrap_or(false);
                    let tenant_match =
                        !timeline.tenant_id.is_empty() && timeline.tenant_id == verified.tenant_id;

                    let belongs_to_me = is_owner || is_requester || tenant_match;

                    if !belongs_to_me {
                        return Err(StatusCode::FORBIDDEN);
                    }

                    Ok(Json(serde_json::to_value(timeline).unwrap_or_default()))
                }
                Err(e) => Ok(Json(
                    serde_json::json!({ "error": format!("Deserialize error: {}", e) }),
                )),
            }
        }
        Ok(None) => Ok(Json(serde_json::json!({ "error": "Action not found" }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": format!("{}", e) }))),
    }
}

/// GET /api/actions/:action_id/timeline — Timeline events only.
async fn get_action_timeline_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(action_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // RULE[010_JWT_CONTRACTS.md]: validate() returns IdentityContext
    let verified = state
        .token_validator
        .validate(&headers, &state.jwt_secret)
        .await
        .map_err(|e| e)?;
    let my_did = verified.requester_did.clone();

    let kv_store = match state.jetstream.get_key_value("action_timelines").await {
        Ok(store) => store,
        Err(e) => {
            return Ok(Json(
                serde_json::json!({ "error": format!("KV access failed: {}", e) }),
            ));
        }
    };

    match kv_store.get(&action_id).await {
        Ok(Some(entry)) => {
            match serde_json::from_slice::<crate::audit_projector::ActionTimeline>(&entry) {
                Ok(timeline) => {
                    // Check ownership
                    let mut belongs_to_me = false;
                    if let Some(ref owner) = timeline.summary.owner_did {
                        if owner == &my_did {
                            belongs_to_me = true;
                        }
                    }
                    if let Some(ref req) = timeline.summary.requester_did {
                        if req == &my_did {
                            belongs_to_me = true;
                        }
                    }

                    if !belongs_to_me {
                        return Err(StatusCode::FORBIDDEN);
                    }

                    Ok(Json(serde_json::json!({
                        "action_id": timeline.action_id,
                        "status": timeline.summary.status,
                        "timeline": timeline.timeline,
                    })))
                }
                Err(e) => Ok(Json(
                    serde_json::json!({ "error": format!("Deserialize error: {}", e) }),
                )),
            }
        }
        Ok(None) => Ok(Json(serde_json::json!({ "error": "Action not found" }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": format!("{}", e) }))),
    }
}

// ──────────────────────────────────────────────────────────
// WS3.1: Live SSE timeline stream
// ──────────────────────────────────────────────────────────

/// GET /api/actions/:action_id/live — SSE stream of timeline events.
///
/// Subscribes to NATS subject `ui.v1.<tenant>.events` and filters for events
/// matching the given action_id. Streams them as SSE `event: timeline`.
async fn action_live_sse_handler(
    State(state): State<Arc<GatewayState>>,
    axum::extract::Path(action_id): axum::extract::Path<String>,
) -> Sse<impl futures::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let aid = action_id.clone();
    let nats = state.nats.clone();

    let stream = async_stream::stream! {
        let mut tenant_id = None;

        // Send initial snapshot
        if let Ok(kv) = state.jetstream.get_key_value("action_timelines").await {
            if let Ok(Some(entry)) = kv.get(&aid).await {
                if let Ok(timeline) = serde_json::from_slice::<crate::audit_projector::ActionTimeline>(&entry) {
                    tenant_id = Some(timeline.tenant_id.clone());
                    let data = serde_json::to_string(&timeline).unwrap_or_default();
                    yield Ok(Event::default().event("snapshot").data(data));
                }
            }
        }

        // Subscribe to sanitized UI events and filter for this action
        // Use tenant-specific subject if known, otherwise wildcard
        let sub_subject = if let Some(tid) = tenant_id {
            format!("ui.v1.{}.events", tid.replace(':', "_"))
        } else {
            "ui.v1.*.events".to_string()
        };

        match nats.subscribe(sub_subject).await {
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
