// ─────────────────────────────────────────────────────────────
// Native Skill Executor (Claw Backend)
//
// Executes dynamic CLI skills from /skills/*/manifest.json.
// Each skill is a directory containing a manifest and a script.
// The executor validates the ExecutionGrant JWT, resolves the
// skill, spawns the script, and captures output.
//
// Runs OUTSIDE the Wasm sandbox (native execution).
//
// Phase 2.1: GET /skills/{name}/docs — on-demand documentation
// Phase 4.1: NATS publish on skill changes (hot-reload events)
// ─────────────────────────────────────────────────────────────

mod executor;
mod registry;
mod grant_validator;

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post},
    extract::{State, Path},
    http::{Method, StatusCode},
    response::IntoResponse,
    Json,
};
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "native_skill_executor")]
#[command(about = "Native Skill Executor (Claw) — dynamic CLI skill runner")]
struct Args {
    /// HTTP listen address
    #[arg(long, env = "SKILL_EXECUTOR_LISTEN", default_value = "0.0.0.0:3070")]
    listen: String,

    /// Path to skills directory
    #[arg(long, env = "SKILLS_DIR", default_value = "skills")]
    skills_dir: String,

    /// JWT signing secret (must match trust_gateway) — REQUIRED
    #[arg(long, env = "JWT_SECRET")]
    jwt_secret: String,

    /// Execution timeout in seconds
    #[arg(long, env = "EXEC_TIMEOUT", default_value = "30")]
    exec_timeout: u64,

    /// NATS URL for publishing skill change events (optional)
    #[arg(long, env = "NATS_URL", default_value = "nats://127.0.0.1:4222")]
    nats_url: String,

    /// Skill rescan interval in seconds (0 = disabled)
    #[arg(long, env = "RESCAN_INTERVAL", default_value = "60")]
    rescan_interval: u64,

    /// Comma-separated list of allowed CORS origins (default: http://localhost:8080)
    #[arg(long, env = "ALLOWED_ORIGINS", default_value = "http://localhost:8080")]
    allowed_origins: String,
}

/// Shared state for the executor.
pub struct ExecutorState {
    pub skill_registry: registry::SkillRegistry,
    pub grant_validator: grant_validator::GrantValidator,
    pub exec_timeout: std::time::Duration,
    pub nats: Option<async_nats::Client>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,native_skill_executor=debug".into()),
        )
        .init();

    dotenvy::dotenv().ok();
    let args = Args::parse();

    tracing::info!("🦞 Native Skill Executor starting...");
    tracing::info!("   Listen:       {}", args.listen);
    tracing::info!("   Skills Dir:   {}", args.skills_dir);
    tracing::info!("   Timeout:      {}s", args.exec_timeout);
    tracing::info!("   NATS URL:     {}", args.nats_url);
    tracing::info!("   Rescan:       {}s", args.rescan_interval);

    // Scan skills directory
    let skill_registry = registry::SkillRegistry::scan(&args.skills_dir)?;
    tracing::info!("✅ Loaded {} skills", skill_registry.count());

    for skill in skill_registry.list() {
        let docs_marker = if skill.documentation_available { "📖" } else { "" };
        tracing::info!(
            "   🦞 {}: {} [{}] {}",
            skill.name,
            skill.description,
            skill.category.as_deref().unwrap_or("general"),
            docs_marker
        );
    }

    // Connect to NATS (optional — for hot-reload event publishing)
    let nats_client = match async_nats::connect(&args.nats_url).await {
        Ok(nc) => {
            tracing::info!("✅ Connected to NATS for skill change events");
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
                            tracing::info!("✅ Ed25519 + HMAC grant validation enabled (dual mode)");
                            v
                        }
                        Err(e) => {
                            tracing::warn!("⚠️ Ed25519+HMAC dual mode failed ({}), trying Ed25519 only", e);
                            grant_validator::GrantValidator::from_ed25519_pem(&pem)
                                .expect("Failed to load Ed25519 public key")
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("⚠️ Cannot read key file {}: {} — using HMAC only", key_path, e);
                    grant_validator::GrantValidator::from_hmac_secret(&args.jwt_secret)
                }
            }
        } else {
            tracing::info!("ℹ️ Using HMAC grant validation (set GRANT_VERIFY_KEY_PATH for Ed25519)");
            grant_validator::GrantValidator::from_hmac_secret(&args.jwt_secret)
        }
    };

    let state = Arc::new(ExecutorState {
        skill_registry,
        grant_validator,
        exec_timeout: std::time::Duration::from_secs(args.exec_timeout),
        nats: nats_client.clone(),
    });

    // Phase 4.1: Spawn periodic rescan task
    if args.rescan_interval > 0 {
        let rescan_state = state.clone();
        let interval = std::time::Duration::from_secs(args.rescan_interval);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // Skip first immediate tick
            loop {
                ticker.tick().await;
                let new_skills = rescan_state.skill_registry.rescan();
                if !new_skills.is_empty() {
                    tracing::info!("🔄 Detected {} new skills: {:?}", new_skills.len(), new_skills);
                    // Publish NATS event for each new skill
                    if let Some(ref nc) = rescan_state.nats {
                        for skill_name in &new_skills {
                            let event = serde_json::json!({
                                "event": "skill_added",
                                "skill_name": skill_name,
                                "timestamp": chrono::Utc::now().to_rfc3339()
                            });
                            if let Err(e) = nc.publish(
                                "claw.v1.skills.changed".to_string(),
                                event.to_string().into(),
                            ).await {
                                tracing::warn!("⚠️ Failed to publish skill change event: {}", e);
                            } else {
                                tracing::info!("📡 Published claw.v1.skills.changed for '{}'", skill_name);
                            }
                        }
                    }
                }
            }
        });
        tracing::info!("✅ Skill rescan task started (every {}s)", args.rescan_interval);
    }

    let allowed_origins: Vec<axum::http::HeaderValue> = args.allowed_origins
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
        .route("/skills", get(list_skills_handler))
        .route("/skills/{skill_name}/docs", get(skill_docs_handler))
        .route("/health", get(health_handler))
        .with_state(state)
        .layer(cors);

    let addr: std::net::SocketAddr = args
        .listen
        .parse()
        .expect("Invalid listen address provided");
    tracing::info!("🦞 Native Skill Executor listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// POST /invoke — execute a skill with grant validation.
async fn invoke_handler(
    State(state): State<Arc<ExecutorState>>,
    Json(req): Json<executor::InvokeRequest>,
) -> Json<executor::InvokeResponse> {
    tracing::info!("📥 Invoke request for skill: {}", req.skill_name);

    // 1. Validate ExecutionGrant
    if let Some(ref grant_token) = req.execution_grant {
        match state.grant_validator.validate(grant_token) {
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
                tracing::info!("✅ Grant validated for '{}'", req.skill_name);
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

    // 2. Resolve skill
    let skill = match state.skill_registry.get(&req.skill_name) {
        Some(s) => s,
        None => {
            return Json(executor::InvokeResponse::error(
                &req.action_id.unwrap_or_default(),
                format!("Skill not found: {}", req.skill_name),
            ));
        }
    };

    // 3. Execute
    match executor::execute_skill(&skill, &req, state.exec_timeout).await {
        Ok(response) => Json(response),
        Err(e) => {
            tracing::error!("❌ Skill execution failed: {}", e);
            Json(executor::InvokeResponse::error(
                &req.action_id.unwrap_or_default(),
                format!("Execution failed: {}", e),
            ))
        }
    }
}

/// GET /skills — list available skills (with extended metadata).
async fn list_skills_handler(
    State(state): State<Arc<ExecutorState>>,
) -> Json<Vec<registry::SkillInfo>> {
    Json(state.skill_registry.list())
}

/// GET /skills/{skill_name}/docs — read full documentation for a skill.
///
/// Phase 2.1: This endpoint enables the `read_skill` meta-tool.
/// Returns the skill's README.md content along with manifest metadata,
/// enabling the LLM to understand complex procedural skills before
/// executing them (the skills.md "lazy-loading" philosophy).
async fn skill_docs_handler(
    State(state): State<Arc<ExecutorState>>,
    Path(skill_name): Path<String>,
) -> impl IntoResponse {
    match state.skill_registry.get_docs(&skill_name) {
        Some(docs) => Json(serde_json::json!(docs)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Skill '{}' not found", skill_name),
                "available_skills": state.skill_registry.list()
                    .iter()
                    .map(|s| s.name.clone())
                    .collect::<Vec<_>>()
            })),
        ).into_response(),
    }
}

/// GET /health
async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "native_skill_executor",
        "version": "0.2.0",
        "features": ["skill_docs", "hot_reload", "extended_manifests"],
    }))
}
