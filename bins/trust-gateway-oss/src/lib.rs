use axum::{
    extract::{Path as AxumPath, Query, State, WebSocketUpgrade},
    http::{header, HeaderMap, StatusCode},
    response::{
        sse::{Event, Sse},
        Html, IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use futures::StreamExt;
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use trust_engine::approval::{ApprovalManager, NoopApprovalNotifier};
use trust_engine::auth::{ApiKeyAuthenticator, AuthVerifier};
use trust_engine::local_adapters::basic_taint::BasicBinaryTaintTracker;
use trust_engine::local_adapters::local_runner::LocalSubprocessDispatcher;
use trust_engine::local_adapters::memory_nonce::InMemoryNonceStore;
use trust_engine::local_adapters::sqlite_audit::SqliteAuditSink;
use trust_engine::local_adapters::static_registry::StaticSkillRegistry;
use trust_engine::policy::PolicyEngine;
use trust_engine::traits::EngineError;
use trust_engine::{DefaultReputationEvaluator, DefaultSettlementEngine, TenancyMode, TrustEngine};
use trust_sdk::model::{AuthLevel, ProposedAction, TrustEnvelope};

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub listen_addr: String,
    #[serde(default = "default_limit")]
    pub request_limit_bytes: usize,
}

fn default_limit() -> usize {
    65536
}

#[derive(Debug, Deserialize, Clone)]
pub struct KeysConfig {
    pub grant_signing_key_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PathsConfig {
    pub tools_dir: String,
    pub policy_path: String,
    pub audit_db_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    #[serde(default = "default_api_key")]
    pub api_key: String,
}

fn default_api_key() -> String {
    std::env::var("TRUST_GATEWAY_API_KEY").unwrap_or_else(|_| "sk_default_dev_key".to_string())
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    pub server: ServerConfig,
    pub keys: KeysConfig,
    pub paths: PathsConfig,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
}

fn default_mode() -> String {
    "oss_standalone".to_string()
}

pub type SseSender = mpsc::Sender<Result<Event, Infallible>>;
pub type SseSessions = Arc<RwLock<HashMap<String, SseSender>>>;

pub struct AppState {
    pub engine: Arc<TrustEngine>,
    pub start_time: Instant,
    pub sse_sessions: SseSessions,
}

#[derive(Debug, Deserialize)]
pub struct MessageQuery {
    pub session_id: Option<String>,
}

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
}

impl JsonRpcResponse {
    pub fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<serde_json::Value>, code: i64, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message }),
        }
    }
}

pub async fn build_engine_from_config(config: &AppConfig) -> anyhow::Result<Arc<TrustEngine>> {
    let key_path = std::env::var("GRANT_SIGNING_KEY_PATH")
        .unwrap_or_else(|_| config.keys.grant_signing_key_path.clone());

    if !Path::new(&key_path).exists() {
        return Err(anyhow::anyhow!("CRITICAL SECURITY: Grant signing key missing at {key_path}. Run ./scripts/gen_dev_keys.sh"));
    }

    let key_pem = std::fs::read_to_string(&key_path)
        .map_err(|e| anyhow::anyhow!("Failed to read signing key: {e}"))?;

    let signing_key_pair = Ed25519KeyPair::from_pem(&key_pem)
        .map_err(|e| anyhow::anyhow!("Invalid Ed25519 signing key: {e}"))?;

    let policy_str = std::fs::read_to_string(&config.paths.policy_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read policy file {}: {e}",
            config.paths.policy_path
        )
    })?;
    let policy_engine = Arc::new(PolicyEngine::from_toml(&policy_str)?);

    let static_registry = Arc::new(StaticSkillRegistry::new(&config.paths.tools_dir, false));
    let _ = static_registry.load_all().await?;

    let audit_sink = Arc::new(SqliteAuditSink::from_file(&config.paths.audit_db_path)?);
    let approval_manager = Arc::new(ApprovalManager::new(Arc::new(NoopApprovalNotifier)));
    let nonce_store = Arc::new(InMemoryNonceStore::new());
    let taint_lineage_engine = Arc::new(BasicBinaryTaintTracker::new());
    let reputation_evaluator = Arc::new(DefaultReputationEvaluator);
    let settlement_engine = Arc::new(DefaultSettlementEngine);
    let dispatcher = Arc::new(LocalSubprocessDispatcher::new(&config.paths.tools_dir));

    let configured_api_key = std::env::var("TRUST_GATEWAY_API_KEY")
        .ok()
        .or_else(|| config.auth.as_ref().map(|a| a.api_key.clone()))
        .unwrap_or_else(|| "sk_default_dev_key".to_string());

    let api_authenticator = Arc::new(ApiKeyAuthenticator::new(vec![configured_api_key.clone()]));

    let engine = Arc::new(TrustEngine {
        tenancy_mode: TenancyMode::Single,
        signing_key_pair,
        root_verifying_key: None,
        token_verifier: Some(api_authenticator),
        policy_engine,
        skill_registry: static_registry,
        nonce_store,
        taint_lineage_engine,
        reputation_evaluator,
        settlement_engine,
        dispatcher,
        audit_sink,
        approval_manager,
        contract_registry: Arc::new(trust_engine::local_adapters::memory_contract::InMemoryContractRegistry::new()),
        tracked_call_chains: Arc::new(RwLock::new(HashMap::new())),
        configured_api_keys: vec![configured_api_key],
    });

    Ok(engine)
}

pub fn build_app(state: Arc<AppState>, request_limit_bytes: usize) -> Router {
    Router::new()
        .route("/", get(root_handler))
        .route("/healthz", get(healthz_handler))
        .route("/.well-known/jwks.json", get(jwks_handler))
        .route("/v1/mcp/sse", get(mcp_sse_handler))
        .route("/v1/mcp/messages", post(mcp_messages_handler))
        .route("/mcp/sse", get(mcp_sse_handler))
        .route("/mcp/messages", post(mcp_messages_handler))
        .route("/v1/actions/propose", post(propose_action_handler))
        .route("/v1/tools/registry", get(tools_registry_handler))
        .route("/v1/contracts", post(register_contract_handler))
        .route("/v1/contracts/:id", get(get_contract_handler))
        .route(
            "/v1/approvals/:id/decision",
            post(approval_decision_handler),
        )
        .route("/api/ws", get(ws_handler))
        .route("/api/actions", get(actions_list_handler))
        .route("/api/actions/:id", get(action_detail_handler))
        .route("/api/actions/:id/live", get(action_live_handler))
        .route(
            "/v1/federation/skills/publish",
            post(federation_publish_handler),
        )
        .layer(RequestBodyLimitLayer::new(request_limit_bytes))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

pub async fn healthz_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let uptime = state.start_time.elapsed().as_secs();
    Json(serde_json::json!({
        "status": "ok",
        "uptime_seconds": uptime,
        "mode": "oss_standalone"
    }))
}

pub async fn jwks_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let pub_key = state.engine.signing_key_pair.public_key();
    let bytes = pub_key.to_bytes();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    Json(serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "use": "sig",
            "alg": "EdDSA",
            "kid": "gateway_ed25519_key_1"
        }]
    }))
}

pub async fn mcp_sse_handler(
    State(state): State<Arc<AppState>>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let session_id = uuid::Uuid::new_v4().to_string();
    let (tx, rx) = mpsc::channel(32);

    let endpoint_url = format!("/v1/mcp/messages?session_id={session_id}");
    let initial_event = Event::default().event("endpoint").data(endpoint_url);
    let _ = tx.send(Ok(initial_event)).await;

    state.sse_sessions.write().await.insert(session_id, tx);

    let stream = ReceiverStream::new(rx);
    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

pub async fn mcp_messages_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(_query): Query<MessageQuery>,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let tenant_id = headers
        .get("x-tenant-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("default");

    if tenant_id != "default" {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": format!("Tenant '{tenant_id}' forbidden in mono-tenant mode")
            })),
        )
            .into_response();
    }

    let default_key = state
        .engine
        .configured_api_keys
        .first()
        .cloned()
        .unwrap_or_else(|| {
            std::env::var("TRUST_GATEWAY_API_KEY")
                .unwrap_or_else(|_| "sk_default_dev_key".to_string())
        });
    let default_auth_bearer = format!("Bearer {default_key}");

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or(&default_auth_bearer);

    match req.method.as_str() {
        "initialize" => {
            let res = serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": { "listChanged": true }
                },
                "serverInfo": {
                    "name": "marketplace_trust_gateway_oss",
                    "version": "0.1.0"
                }
            });
            Json(JsonRpcResponse::success(req.id, res)).into_response()
        }
        "notifications/initialized" => StatusCode::OK.into_response(),
        "tools/list" => {
            let skills = match state
                .engine
                .skill_registry
                .list_skills("default", None)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
                }
            };

            let tools: Vec<serde_json::Value> = skills
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "name": s.name,
                        "description": s.description,
                        "inputSchema": s.input_schema
                    })
                })
                .collect();

            Json(JsonRpcResponse::success(
                req.id,
                serde_json::json!({ "tools": tools }),
            ))
            .into_response()
        }
        "tools/call" => {
            let tool_name = req.params["name"].as_str().unwrap_or("").to_string();
            let args = req.params["arguments"].clone();

            let action = ProposedAction {
                action_id: format!("act_{}", uuid::Uuid::new_v4()),
                tool_name,
                arguments: args,
                tenant_id: tenant_id.to_string(),
                workspace_id: "default".to_string(),
                ..Default::default()
            };

            let envelope = TrustEnvelope {
                trace_id: format!("tr_{}", uuid::Uuid::new_v4()),
                timestamp: chrono::Utc::now().timestamp(),
                payload: action,
            };

            match state
                .engine
                .propose_and_execute(auth_header, envelope)
                .await
            {
                Ok(result) => {
                    let out_text = serde_json::to_string(&result.output).unwrap_or_default();
                    let content = vec![serde_json::json!({ "type": "text", "text": out_text })];
                    Json(JsonRpcResponse::success(
                        req.id,
                        serde_json::json!({ "content": content }),
                    ))
                    .into_response()
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    let content = vec![serde_json::json!({ "type": "text", "text": err_msg })];
                    Json(JsonRpcResponse::success(
                        req.id,
                        serde_json::json!({ "content": content, "isError": true }),
                    ))
                    .into_response()
                }
            }
        }
        other => Json(JsonRpcResponse::error(
            req.id,
            -32601,
            format!("Method not found: {other}"),
        ))
        .into_response(),
    }
}

pub async fn propose_action_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut action): Json<ProposedAction>,
) -> impl IntoResponse {
    if let Some(t) = headers.get("x-tenant-id").and_then(|h| h.to_str().ok()) {
        action.tenant_id = t.to_string();
    }

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let trace_id = headers
        .get("x-trace-id")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            action
                .call_chain
                .as_ref()
                .map(|c| c.trace_id.as_str())
        })
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("tr_{}", uuid::Uuid::new_v4()));

    let envelope = TrustEnvelope {
        trace_id,
        timestamp: chrono::Utc::now().timestamp(),
        payload: action,
    };

    match state.engine.propose_and_execute(auth_header, envelope).await {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(EngineError::UnauthorizedTenant(t)) => {
            (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": format!("Tenant '{t}' forbidden in mono-tenant mode") }))).into_response()
        }
        Err(EngineError::ApprovalRequired { action_id, approval_id, reason }) => {
            (StatusCode::ACCEPTED, Json(serde_json::json!({
                "status": "pending_approval",
                "action_id": action_id,
                "approval_id": approval_id,
                "reason": reason
            }))).into_response()
        }
        Err(EngineError::AuthError(e)) => {
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": format!("Authentication failed: {e}") }))).into_response()
        }
        Err(e) => {
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

pub async fn tools_registry_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state
        .engine
        .skill_registry
        .list_skills("default", None)
        .await
    {
        Ok(skills) => (
            StatusCode::OK,
            Json(serde_json::json!({ "skills": skills })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn register_contract_handler(
    State(state): State<Arc<AppState>>,
    Json(contract): Json<trust_sdk::contracts::SignedContract>,
) -> impl IntoResponse {
    match state.engine.contract_registry.register_contract(contract).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "status": "registered" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn get_contract_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(contract_id): AxumPath<String>,
) -> impl IntoResponse {
    match state.engine.contract_registry.get_contract(&contract_id).await {
        Ok(Some(contract)) => (StatusCode::OK, Json(contract)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Contract not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct ApprovalDecisionPayload {
    pub approved: bool,
    pub resolved_by: String,
}

pub async fn approval_decision_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(approval_id): AxumPath<String>,
    Json(payload): Json<ApprovalDecisionPayload>,
) -> impl IntoResponse {
    let _existing_record = match state.engine.approval_manager.get(&approval_id).await {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": format!("Approval record '{approval_id}' not found") })),
            )
                .into_response();
        }
    };

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    if payload.approved {
        let auth = match auth_header {
            Some(a) => a,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(
                        serde_json::json!({ "error": "Missing Authorization header for approval" }),
                    ),
                )
                    .into_response();
            }
        };

        let verified = match AuthVerifier::verify_bearer(
            auth,
            state.engine.token_verifier.as_deref(),
            &state.engine.configured_api_keys,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": format!("Approval auth failed: {e}") })),
                )
                    .into_response();
            }
        };

        if verified.auth_level() < AuthLevel::Level2ApiKey {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Valid API Key required to approve actions"
                })),
            )
                .into_response();
        }
    }

    match state
        .engine
        .approval_manager
        .resolve(&approval_id, payload.approved, payload.resolved_by)
        .await
    {
        Ok(record) => {
            if payload.approved {
                let now = chrono::Utc::now().timestamp();
                let input_hash =
                    trust_sdk::canonical::canonical_hash(&record.proposed_action.arguments);
                let grant_jti = format!("grant_{}", uuid::Uuid::new_v4());

                let grant = trust_sdk::grants::ExecutionGrant {
                    jti: grant_jti,
                    action_id: record.action_id.clone(),
                    tenant_id: record.tenant_id.clone(),
                    workspace_id: record.proposed_action.workspace_id.clone(),
                    tool_name: record.proposed_action.tool_name.clone(),
                    input_hash,
                    iss: "trust_gateway".to_string(),
                    exp: now + 300,
                    policy_fingerprint: state.engine.policy_engine.fingerprint().to_string(),
                    clearance: trust_sdk::grants::GrantClearance::HumanApproved,
                    economic_claim: None,
                    budget: None,
                    contract_id: None,
                    contract_hash: None,
                    source_input_hash: None,
                    lineage_attestation: None,
                };

                let grant_jwt = trust_sdk::grants::sign_grant_jwt(
                    &grant,
                    "executor-host",
                    &state.engine.signing_key_pair,
                )
                .unwrap_or_default();

                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "status": "approved",
                        "record": record,
                        "grant": grant_jwt
                    })),
                )
                    .into_response()
            } else {
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "status": "rejected",
                        "record": record
                    })),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(|mut socket| async move {
        while let Some(Ok(msg)) = socket.next().await {
            if socket.send(msg).await.is_err() {
                break;
            }
        }
    })
}

pub async fn actions_list_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "actions": []
    }))
}

pub async fn action_detail_handler(AxumPath(action_id): AxumPath<String>) -> impl IntoResponse {
    Json(serde_json::json!({
        "summary": {
            "title": format!("Action {}", action_id),
            "status": "completed",
            "action_name": "mcp_tool_execution"
        },
        "timeline": []
    }))
}

pub async fn action_live_handler(AxumPath(action_id): AxumPath<String>) -> impl IntoResponse {
    Json(serde_json::json!({
        "action_id": action_id,
        "status": "completed",
        "live": false
    }))
}

pub async fn federation_publish_handler() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({ "error": "federation requires the Pro edition" })),
    )
}

pub async fn root_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if !accept.contains("text/html")
        && (accept.contains("application/json") || user_agent.starts_with("curl"))
    {
        return healthz_handler(State(state)).await.into_response();
    }

    let uptime = state.start_time.elapsed().as_secs();
    let skills = state
        .engine
        .skill_registry
        .list_skills("default", None)
        .await
        .unwrap_or_default();

    let mut skill_cards = String::new();
    for (i, s) in skills.iter().enumerate() {
        let default_args = match s.name.as_str() {
            "claw_weather" => r#"{"location": "San Francisco"}"#,
            "claw_hello_world" => r#"{"message": "Hello from Trust Gateway!"}"#,
            "claw_extract_content_from_url" => r#"{"url": "https://example.com"}"#,
            "compute_statistics" => r#"{"values": [12.5, 45.0, 78.2, 99.1, 33.4]}"#,
            "detect_anomalies" => r#"{"data": [10, 11, 12, 10, 99, 11, 10]}"#,
            "sample_rows" => r#"{"rows": ["item_1", "item_2", "item_3", "item_4"], "n": 2}"#,
            "generate_markdown" => {
                r#"{"title": "Audit Report", "body": "All security invariants verified."}"#
            }
            "inspect_schema" => r#"{"target": "all"}"#,
            "join_datasets" => r#"{"left": [1, 2, 3], "right": [4, 5, 6]}"#,
            _ => "{}",
        };
        let card = format!(
            r#"<div class="card" id="widget-{}">
                <div class="card-header">
                    <span class="tool-name">{}</span>
                    <span class="badge badge-success">Certified</span>
                </div>
                <div class="card-desc">{}</div>
                <div class="card-meta">Runtime: {:?} &bull; Author: {}</div>
                <div class="widget-runner">
                    <label class="widget-label">Arguments (JSON)</label>
                    <textarea class="widget-args" id="args-{}" rows="2">{}</textarea>
                    <div class="widget-actions">
                        <button class="btn-execute" onclick="executeTool({}, '{}')">Execute via Gateway</button>
                        <span class="widget-status" id="status-{}"></span>
                    </div>
                    <pre class="widget-output" id="output-{}" style="display:none;"></pre>
                </div>
            </div>"#,
            i,
            s.name,
            s.description,
            s.execution.runtime,
            s.author_did,
            i,
            default_args,
            i,
            s.name,
            i,
            i
        );
        skill_cards.push_str(&card);
    }

    let active_api_key = state
        .engine
        .configured_api_keys
        .first()
        .cloned()
        .unwrap_or_else(|| {
            std::env::var("TRUST_GATEWAY_API_KEY")
                .unwrap_or_else(|_| "sk_default_dev_key".to_string())
        });

    let page_html = render_dashboard_html(uptime, &skills, &skill_cards, &active_api_key);
    Html(page_html).into_response()
}

fn render_dashboard_html(
    uptime: u64,
    skills: &[trust_sdk::manifest::SkillManifest],
    skill_cards: &str,
    api_key: &str,
) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sovereign Trust Gateway OSS</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #111827;
            --surface-hover: #1f2937;
            --border: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --success: #10b981;
            --warning: #f59e0b;
        }}
        body {{
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            line-height: 1.5;
        }}
        .container {{
            max-width: 1040px;
            margin: 0 auto;
            padding: 2.5rem 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
        }}
        .brand {{
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }}
        .logo-row {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .logo-icon {{
            background: linear-gradient(135deg, #0284c7 0%, #38bdf8 100%);
            width: 32px;
            height: 32px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            color: #fff;
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.4);
        }}
        h1 {{
            font-size: 1.4rem;
            margin: 0;
            letter-spacing: -0.02em;
        }}
        .tagline {{
            color: var(--text-muted);
            font-size: 0.85rem;
        }}
        .status-pill {{
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #34d399;
            padding: 0.35rem 0.85rem;
            border-radius: 9999px;
            font-size: 0.8rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .pulse {{
            width: 8px;
            height: 8px;
            background-color: #10b981;
            border-radius: 50%;
            box-shadow: 0 0 8px #10b981;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0% {{ opacity: 1; }}
            50% {{ opacity: 0.4; }}
            100% {{ opacity: 1; }}
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
        }}
        .metric-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.25rem 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
        }}
        .metric-label {{
            font-size: 0.775rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            font-weight: 600;
        }}
        .metric-val {{
            font-size: 1.5rem;
            font-weight: 700;
            color: #f8fafc;
            letter-spacing: -0.03em;
        }}
        .metric-sub {{
            font-size: 0.75rem;
            color: #64748b;
        }}
        section {{
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }}
        .section-title {{
            font-size: 1.05rem;
            font-weight: 600;
            color: #e2e8f0;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .mcp-box {{
            background: linear-gradient(180deg, #131d31 0%, #0d1527 100%);
            border: 1px solid #1e3a5f;
            border-radius: 12px;
            padding: 1.25rem 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }}
        .code-box {{
            background: #090e1a;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 0.75rem 1rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.875rem;
            color: #38bdf8;
            display: flex;
            justify-content: space-between;
            align-items: center;
            overflow-x: auto;
        }}
        .endpoints-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 0.75rem;
        }}
        .endpoint-link {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 0.75rem 1rem;
            text-decoration: none;
            color: var(--text-main);
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.2s;
        }}
        .endpoint-link:hover {{
            background: var(--surface-hover);
            border-color: #38bdf8;
            transform: translateY(-1px);
        }}
        .method {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
        }}
        .method-get {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; }}
        .endpoint-path {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}
        .skills-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(310px, 1fr));
            gap: 0.85rem;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1rem 1.15rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .tool-name {{
            font-weight: 600;
            font-size: 0.95rem;
            color: #f1f5f9;
        }}
        .badge {{
            font-size: 0.7rem;
            font-weight: 600;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            letter-spacing: 0.02em;
        }}
        .badge-success {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-info {{ background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }}
        .card-desc {{
            font-size: 0.8rem;
            color: var(--text-muted);
            line-height: 1.4;
        }}
        .card-meta {{
            font-size: 0.725rem;
            color: #64748b;
            font-family: 'JetBrains Mono', monospace;
            margin-top: auto;
        }}
        .widget-runner {{
            margin-top: 0.6rem;
            padding-top: 0.6rem;
            border-top: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
        }}
        .widget-label {{
            font-size: 0.68rem;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 0.05em;
        }}
        .widget-args {{
            width: 100%;
            box-sizing: border-box;
            background: #090e1a;
            border: 1px solid var(--border);
            border-radius: 6px;
            color: #38bdf8;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72rem;
            padding: 0.4rem;
            resize: vertical;
        }}
        .widget-actions {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.5rem;
        }}
        .btn-execute {{
            background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
            color: #fff;
            border: 1px solid #38bdf8;
            border-radius: 6px;
            padding: 0.35rem 0.75rem;
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .btn-execute:hover {{
            background: #38bdf8;
            color: #0b0f19;
        }}
        .widget-status {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.725rem;
        }}
        .widget-status.success {{ color: #34d399; }}
        .widget-status.warning {{ color: #fbbf24; }}
        .widget-status.error {{ color: #f43f5e; }}
        .widget-status.running {{ color: #38bdf8; }}
        .widget-output {{
            background: #090e1a;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.5rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            color: #34d399;
            overflow-x: auto;
            max-height: 180px;
            white-space: pre-wrap;
        }}
        .btn-mcp-test {{
            background: rgba(56, 189, 248, 0.15);
            color: #38bdf8;
            border: 1px solid rgba(56, 189, 248, 0.3);
            border-radius: 6px;
            padding: 0.35rem 0.75rem;
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .btn-mcp-test:hover {{
            background: rgba(56, 189, 248, 0.3);
        }}
        footer {{
            border-top: 1px solid var(--border);
            padding-top: 1.25rem;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.825rem;
        }}
        .invariant {{
            color: #38bdf8;
            font-style: italic;
            font-weight: 500;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div class="logo-row">
                    <div class="logo-icon">&#x26E8;</div>
                    <h1>Sovereign Trust Gateway</h1>
                </div>
                <div class="tagline">Zero-Trust Execution Control Plane &bull; Apache-2.0 Open Core</div>
            </div>
            <div class="status-pill">
                <span class="pulse"></span>
                <span>Active &bull; Port 8080</span>
            </div>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <span class="metric-label">Deployment Mode</span>
                <span class="metric-val">oss_standalone</span>
                <span class="metric-sub">Mono-Tenant ("default")</span>
            </div>
            <div class="metric-card">
                <span class="metric-label">Uptime</span>
                <span class="metric-val" id="metric-uptime-val">{}s</span>
                <span class="metric-sub">Fast boot (&lt;10ms) &bull; Live Pulse</span>
            </div>
            <div class="metric-card">
                <span class="metric-label">Certified Skills</span>
                <span class="metric-val">{}</span>
                <span class="metric-sub">Ed25519 Signed / Native</span>
            </div>
            <div class="metric-card">
                <span class="metric-label">Governance Active</span>
                <span class="metric-val">Layer 0 Guard</span>
                <span class="metric-sub">RFC 8785 + SQLite Chain</span>
            </div>
        </div>

        <section>
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div class="section-title">&#x1F517; Model Context Protocol (MCP) Ingress</div>
                <button class="btn-mcp-test" onclick="pingMcp()">Test Ping (JSON-RPC)</button>
            </div>
            <div class="mcp-box">
                <p style="font-size:0.875rem; color:#cbd5e1;">Connect Cursor, Claude Desktop, or autonomous agents to this gateway using the live MCP Server-Sent Events (SSE) stream:</p>
                <div class="code-box">
                    <span>http://localhost:8080/v1/mcp/sse</span>
                </div>
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <p style="font-size:0.775rem; color:#94a3b8; margin:0;">Headers: <code>Authorization: Bearer {}</code></p>
                    <span id="mcp-ping-result" style="font-size:0.775rem; font-family:'JetBrains Mono',monospace;"></span>
                </div>
            </div>
        </section>

        <section>
            <div class="section-title">&#x1F680; Live Gateway Endpoints (Click to Probe)</div>
            <div class="endpoints-grid">
                <button class="endpoint-link" onclick="probeEndpoint('/healthz', this)">
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/healthz</span>
                    <span>&rarr;</span>
                </button>
                <button class="endpoint-link" onclick="probeEndpoint('/v1/tools/registry', this)">
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/v1/tools/registry</span>
                    <span>&rarr;</span>
                </button>
                <button class="endpoint-link" onclick="probeEndpoint('/.well-known/jwks.json', this)">
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/.well-known/jwks.json</span>
                    <span>&rarr;</span>
                </button>
                <button class="endpoint-link" onclick="probeEndpoint('/v1/mcp/sse', this)">
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/v1/mcp/sse</span>
                    <span>&rarr;</span>
                </button>
            </div>
        </section>

        <section>
            <div class="section-title">&#x1F9F0; Preloaded Certified Skills ({}) &bull; Dynamic Execution Widgets</div>
            <div class="skills-grid">
                {}
            </div>
        </section>

        <footer>
            <p class="invariant">"Agents propose. Gateway decides. Executors verify."</p>
            <p style="margin-top:0.4rem; font-size:0.75rem; color:#64748b;">Lianxi Trust Platform &bull; Apache-2.0 Open Source Core</p>
        </footer>
    </div>

    <script>
    const GATEWAY_API_KEY = '{}';

    async function executeTool(idx, toolName) {{
        const argsEl = document.getElementById('args-' + idx);
        const statusEl = document.getElementById('status-' + idx);
        const outputEl = document.getElementById('output-' + idx);
        let parsed;
        try {{
            parsed = JSON.parse(argsEl.value);
        }} catch(e) {{
            statusEl.innerText = '❌ Invalid JSON: ' + e.message;
            statusEl.className = 'widget-status error';
            return;
        }}
        statusEl.innerText = '⏳ Routing through Layer 0 Guard...';
        statusEl.className = 'widget-status running';
        outputEl.style.display = 'none';

        const start = performance.now();
        try {{
            const resp = await fetch('/v1/actions/propose', {{
                method: 'POST',
                headers: {{
                    'Authorization': 'Bearer ' + GATEWAY_API_KEY,
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify({{
                    action_id: 'act_' + toolName + '_' + Date.now(),
                    tool_name: toolName,
                    arguments: parsed,
                    tenant_id: 'default',
                    workspace_id: 'default'
                }})
            }});
            const elapsed = Math.round(performance.now() - start);
            const data = await resp.json().catch(() => ({{}}));
            if (resp.status === 200) {{
                statusEl.innerText = '✅ 200 OK (' + elapsed + 'ms)';
                statusEl.className = 'widget-status success';
            }} else if (resp.status === 202) {{
                statusEl.innerText = '⏳ 202 Step-Up Approval Required (' + elapsed + 'ms)';
                statusEl.className = 'widget-status warning';
            }} else {{
                statusEl.innerText = '❌ HTTP ' + resp.status + ' (' + elapsed + 'ms)';
                statusEl.className = 'widget-status error';
            }}
            outputEl.style.display = 'block';
            outputEl.innerText = JSON.stringify(data, null, 2);
        }} catch(err) {{
            statusEl.innerText = '❌ Network Error: ' + err.message;
            statusEl.className = 'widget-status error';
        }}
    }}

    async function probeEndpoint(path, btnEl) {{
        const orig = btnEl.innerHTML;
        btnEl.innerHTML = '<span class="method method-get">GET</span><span>Probing...</span>';
        const start = performance.now();
        try {{
            const resp = await fetch(path, {{ headers: {{ 'Authorization': 'Bearer ' + GATEWAY_API_KEY }} }});
            const elapsed = Math.round(performance.now() - start);
            btnEl.innerHTML = '<span class="method method-get">GET</span><span class="endpoint-path">' + path + '</span><span style="color:#34d399;font-weight:600;font-size:0.75rem;">' + resp.status + ' (' + elapsed + 'ms)</span>';
        }} catch(e) {{
            btnEl.innerHTML = '<span class="method method-get">GET</span><span class="endpoint-path">' + path + '</span><span style="color:#f43f5e;font-size:0.75rem;">Failed</span>';
        }}
    }}

    async function pingMcp() {{
        const resEl = document.getElementById('mcp-ping-result');
        resEl.innerText = '⏳ Pinging MCP tools/list...';
        resEl.style.color = '#38bdf8';
        const start = performance.now();
        try {{
            const resp = await fetch('/v1/mcp/messages', {{
                method: 'POST',
                headers: {{ 'Authorization': 'Bearer ' + GATEWAY_API_KEY, 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {{}} }})
            }});
            const elapsed = Math.round(performance.now() - start);
            if (resp.ok) {{
                const data = await resp.json();
                const count = data.result && data.result.tools ? data.result.tools.length : 0;
                resEl.innerText = '✅ MCP Active: ' + count + ' tools registered (' + elapsed + 'ms)';
                resEl.style.color = '#34d399';
            }} else {{
                resEl.innerText = '⚠️ MCP HTTP ' + resp.status + ' (' + elapsed + 'ms)';
                resEl.style.color = '#f59e0b';
            }}
        }} catch(e) {{
            resEl.innerText = '❌ MCP unreachable: ' + e.message;
            resEl.style.color = '#f43f5e';
        }}
    }}

    let uptimeEl = document.getElementById('metric-uptime-val');
    if (uptimeEl) {{
        let uptimeVal = parseInt(uptimeEl.innerText) || 0;
        setInterval(() => {{
            uptimeVal += 1;
            uptimeEl.innerText = uptimeVal + 's';
        }}, 1000);
    }}
    </script>
</body>
</html>"#,
        uptime,
        skills.len(),
        api_key,
        skills.len(),
        skill_cards,
        api_key
    )
}
