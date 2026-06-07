// ─────────────────────────────────────────────────────────────
// Native Tool Executor (Claw Backend)
//
// Executes dynamic CLI native tools from /native_tools/*/manifest.json.
// Each tool is a directory containing a manifest and a script.
// The executor validates the ExecutionGrant JWT, resolves the
// tool, spawns the script, and captures output.
//
// Runs OUTSIDE the Wasm sandbox (native execution).
//
// Phase 2.1: GET /tools/{name}/docs — on-demand documentation
// Phase 4.1: NATS publish on tool changes (hot-reload events)
// ─────────────────────────────────────────────────────────────

mod executor;
mod grant_validator;
mod jetstream_nonce_store;
mod nonce_store;
mod registry;

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::{Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "native_tool_executor")]
#[command(about = "Native Tool Executor (Claw) — dynamic CLI tool runner")]
struct Args {
    /// HTTP listen address
    #[arg(long, env = "TOOL_EXECUTOR_LISTEN", default_value = "0.0.0.0:3070")]
    listen: String,

    /// Path to native tools directory
    #[arg(long, env = "NATIVE_TOOLS_DIR", default_value = "native_tools")]
    tools_dir: String,

    /// JWT signing secret (must match trust_gateway) — REQUIRED
    #[arg(long, env = "JWT_SECRET")]
    jwt_secret: String,

    /// Execution timeout in seconds
    #[arg(long, env = "EXEC_TIMEOUT", default_value = "30")]
    exec_timeout: u64,

    /// NATS URL for publishing tool change events (optional)
    #[arg(long, env = "NATS_URL", default_value = "nats://127.0.0.1:4222")]
    nats_url: String,

    /// Tool rescan interval in seconds (0 = disabled)
    #[arg(long, env = "RESCAN_INTERVAL", default_value = "60")]
    rescan_interval: u64,

    /// Comma-separated list of allowed CORS origins (default: http://localhost:8080)
    #[arg(long, env = "ALLOWED_ORIGINS", default_value = "http://localhost:8080")]
    allowed_origins: String,
}

/// Shared state for the executor.
pub struct ExecutorState {
    pub tool_registry: registry::NativeToolRegistry,
    pub grant_validator: grant_validator::GrantValidator,
    pub exec_timeout: std::time::Duration,
    pub nats: Option<async_nats::Client>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,native_tool_executor=debug".into()),
        )
        .init();

    dotenvy::dotenv().ok();
    let args = Args::parse();

    tracing::info!("🦞 Native Tool Executor starting...");
    tracing::info!("   Listen:          {}", args.listen);
    tracing::info!("   Tools Dir:       {}", args.tools_dir);
    tracing::info!("   Timeout:         {}s", args.exec_timeout);
    tracing::info!("   NATS URL:        {}", args.nats_url);
    tracing::info!("   Rescan:          {}s", args.rescan_interval);

    // Scan tools directory
    let tool_registry = registry::NativeToolRegistry::scan(&args.tools_dir)?;
    tracing::info!("✅ Loaded {} native tools", tool_registry.count());

    for tool in tool_registry.list() {
        let docs_marker = if tool.documentation_available {
            "📖"
        } else {
            ""
        };
        tracing::info!(
            "   🦞 {}: {} [{}] {}",
            tool.name,
            tool.description,
            tool.category.as_deref().unwrap_or("general"),
            docs_marker
        );
    }

    // Connect to NATS (optional — for hot-reload event publishing)
    let mut nats_options = async_nats::ConnectOptions::new();
    if let Ok(seed) = std::env::var("NATS_NKEY_SEED") {
        nats_options = async_nats::ConnectOptions::with_nkey(seed);
    }

    let nats_client = match async_nats::connect_with_options(&args.nats_url, nats_options).await {
        Ok(nc) => {
            tracing::info!("✅ Connected to NATS for tool change events");
            Some(nc)
        }
        Err(e) => {
            tracing::warn!("⚠️ NATS connection failed (hot-reload disabled): {}", e);
            None
        }
    };

    // ── WS1: Build grant validator (Ed25519 preferred, HMAC fallback) ──
    let grant_validator = {
        if let Ok(key_path) = std::env::var("GRANT_VERIFY_KEY_PATH") {
            match std::fs::read_to_string(&key_path) {
                Ok(pem) => {
                    // Try dual mode first (Ed25519 + HMAC for migration)
                    match grant_validator::GrantValidator::dual(&pem, &args.jwt_secret) {
                        Ok(v) => {
                            tracing::info!(
                                "✅ Ed25519 + HMAC grant validation enabled (dual mode)"
                            );
                            v
                        }
                        Err(e) => {
                            tracing::warn!(
                                "⚠️ Ed25519+HMAC dual mode failed ({}), trying Ed25519 only",
                                e
                            );
                            grant_validator::GrantValidator::from_ed25519_pem(&pem)
                                .expect("Failed to load Ed25519 public key")
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Cannot read key file {}: {} — using HMAC only",
                        key_path,
                        e
                    );
                    grant_validator::GrantValidator::from_hmac_secret(&args.jwt_secret)
                }
            }
        } else {
            tracing::info!(
                "ℹ️ Using HMAC grant validation (set GRANT_VERIFY_KEY_PATH for Ed25519)"
            );
            grant_validator::GrantValidator::from_hmac_secret(&args.jwt_secret)
        }
    };

    // Attach JTI replay prevention nonce store
    let nonce_store: Arc<dyn trust_core::traits::NonceStore> =
        Arc::new(nonce_store::InMemoryNonceStore::new());
    let grant_validator = grant_validator.with_nonce_store(nonce_store);
    tracing::info!("✅ JTI replay prevention enabled (in-memory nonce store)");

    let state = Arc::new(ExecutorState {
        tool_registry,
        grant_validator,
        exec_timeout: std::time::Duration::from_secs(args.exec_timeout),
        nats: nats_client.clone(),
    });

    // Spawn periodic rescan task
    if args.rescan_interval > 0 {
        let rescan_state = state.clone();
        let interval = std::time::Duration::from_secs(args.rescan_interval);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // Skip first immediate tick
            loop {
                ticker.tick().await;
                let new_tools = rescan_state.tool_registry.rescan();
                if !new_tools.is_empty() {
                    tracing::info!(
                        "🔄 Detected {} new native tools: {:?}",
                        new_tools.len(),
                        new_tools
                    );
                    // Publish NATS event for each new tool
                    if let Some(ref nc) = rescan_state.nats {
                        for tool_name in &new_tools {
                            let event = serde_json::json!({
                                "event": "tool_added",
                                "tool_name": tool_name,
                                "timestamp": chrono::Utc::now().to_rfc3339()
                            });
                            if let Err(e) = nc
                                .publish(
                                    "claw.v1.tools.changed".to_string(),
                                    event.to_string().into(),
                                )
                                .await
                            {
                                tracing::warn!("⚠️ Failed to publish tool change event: {}", e);
                            } else {
                                tracing::info!(
                                    "📡 Published claw.v1.tools.changed for '{}'",
                                    tool_name
                                );
                            }
                        }
                    }
                }
            }
        });
        tracing::info!(
            "✅ Native tool rescan task started (every {}s)",
            args.rescan_interval
        );
    }

    let allowed_origins: Vec<axum::http::HeaderValue> = args
        .allowed_origins
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods(vec![Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(vec![
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ]);

    let app = Router::new()
        .route("/invoke", post(invoke_handler))
        .route("/tools", get(list_tools_handler))
        .route("/skills", get(list_tools_handler)) // Keep legacy compatibility route
        .route("/tools/{tool_name}/docs", get(tool_docs_handler))
        .route("/skills/{tool_name}/docs", get(tool_docs_handler)) // Keep legacy compatibility route
        .route("/health", get(health_handler))
        .with_state(state)
        .layer(cors);

    let addr: std::net::SocketAddr = args
        .listen
        .parse()
        .expect("Invalid listen address provided");
    tracing::info!("🦞 Native Tool Executor listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// POST /invoke — execute a tool with grant validation.
async fn invoke_handler(
    State(state): State<Arc<ExecutorState>>,
    Json(mut req): Json<executor::InvokeRequest>,
) -> Json<executor::InvokeResponse> {
    tracing::info!("📥 Invoke request for native tool: {}", req.skill_name);

    // 1. Validate ExecutionGrant and extract claims
    if let Some(ref grant_token) = req.execution_grant {
        tracing::debug!("🔐 Validating execution grant for '{}'...", req.skill_name);
        match state.grant_validator.validate_bound(grant_token, &req.skill_name, &req.arguments).await {
            Ok(grant) => {
                // Verify the grant is for the requested action
                if grant.allowed_action != req.skill_name {
                    return Json(executor::InvokeResponse::error(
                        &req.action_id.unwrap_or_default(),
                        format!(
                            "Grant mismatch: grant allows '{}' but '{}' was requested",
                            grant.allowed_action, req.skill_name
                        ),
                    ));
                }

                // Enrich tenant_id from the signed grant (authoritative source).
                if req.tenant_id.is_empty() && !grant.tenant_id.is_empty() {
                    tracing::info!(
                        "📋 Enriched tenant_id from ExecutionGrant: '{}'",
                        grant.tenant_id
                    );
                    req.tenant_id = grant.tenant_id;
                }

                tracing::info!(
                    "✅ Grant validated for '{}' (tenant: '{}')",
                    req.skill_name,
                    req.tenant_id
                );
            }
            Err(e) => {
                return Json(executor::InvokeResponse::error(
                    &req.action_id.unwrap_or_default(),
                    format!("Invalid execution grant: {}", e),
                ));
            }
        }
    } else {
        tracing::error!("🚫 No execution grant provided — rejecting execution");
        return Json(executor::InvokeResponse::error(
            &req.action_id.unwrap_or_default(),
            "Execution denied: no ExecutionGrant JWT provided. All invocations must include a valid grant from the Trust Gateway.".to_string(),
        ));
    }

    // 2. Resolve tool
    let tool = match state.tool_registry.get(&req.skill_name) {
        Some(t) => t,
        None => {
            return Json(executor::InvokeResponse::error(
                &req.action_id.unwrap_or_default(),
                format!("Native tool not found: {}", req.skill_name),
            ));
        }
    };

    // 3. Execute
    match executor::execute_native_tool(&tool, &req, state.exec_timeout).await {
        Ok(mut response) => {
            // Apply egress filter to scrub PII and secrets
            trust_core::egress_filter::redact_json(&mut response.output);
            if let Some(ref mut err) = response.error {
                *err = trust_core::egress_filter::redact(err);
            }

            // Apply Deterministic Egress Validator
            let serialized_output = serde_json::to_string(&response.output).unwrap_or_default();
            let egress_config = trust_core::egress_validator::EgressConfig::default();

            if let Err(violation) =
                trust_core::egress_validator::validate_egress(&serialized_output, &egress_config)
            {
                tracing::error!("🚫 Egress validation failed: {}", violation);
                return Json(executor::InvokeResponse::error(
                    &req.action_id.unwrap_or_default(),
                    format!("Execution output blocked by egress policy: {}", violation),
                ));
            }

            Json(response)
        }
        Err(e) => {
            tracing::error!("❌ Native tool execution failed: {}", e);
            Json(executor::InvokeResponse::error(
                &req.action_id.unwrap_or_default(),
                format!(
                    "Execution failed: {}",
                    trust_core::egress_filter::redact(&e.to_string())
                ),
            ))
        }
    }
}

/// GET /tools — list available native tools.
async fn list_tools_handler(
    State(state): State<Arc<ExecutorState>>,
) -> Json<Vec<registry::NativeToolInfo>> {
    Json(state.tool_registry.list())
}

/// GET /tools/{tool_name}/docs — read full documentation for a native tool.
async fn tool_docs_handler(
    State(state): State<Arc<ExecutorState>>,
    Path(tool_name): Path<String>,
) -> impl IntoResponse {
    match state.tool_registry.get_docs(&tool_name) {
        Some(docs) => Json(serde_json::json!(docs)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Native tool '{}' not found", tool_name),
                "available_tools": state.tool_registry.list()
                    .iter()
                    .map(|s| s.name.clone())
                    .collect::<Vec<_>>()
            })),
        )
            .into_response(),
    }
}

/// GET /health
async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "native_tool_executor",
        "version": "0.2.0",
        "features": ["tool_docs", "hot_reload", "extended_manifests"],
    }))
}
