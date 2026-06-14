// ─────────────────────────────────────────────────────────────
// Trust Gateway — main entry point
//
// Evolved from mcp_nats_bridge. Provides:
// 1. HTTP API: POST /v1/actions/propose
// 2. NATS listener: trust.v1.*.action.propose
// 3. Policy-driven action governance
// 4. ExecutionGrant JWT issuance
// 5. Dual-backend connector routing (MCP + Claw)
// ─────────────────────────────────────────────────────────────

mod audit_projector;
mod audit_sink;
mod gateway;
mod grant;
mod normalizer;
mod router;
// mod session; — REMOVED: dead passthrough to identity_context::jwt (Phase 1.1)
mod agent_api;
mod agent_registry;
mod amount_extractor;
mod api;
mod approval_daemon;
mod approval_http;
mod approval_store;
pub mod auth;
mod cron_scheduler;
mod mcp_sse;
mod meta_identity;
pub mod oauth;
mod policy_api;
mod policy_fingerprint;
mod source_registry;
mod standalone_registry;
mod transport_normalizer;
// mod ui_projector; — REMOVED: legacy activity feed projector (Phase 4b)
mod webhook_handler;

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use gateway::GatewayState;

#[derive(Parser, Debug)]
#[command(name = "trust_gateway")]
#[command(about = "Sovereign Trust Gateway — policy-driven action governance")]
struct Args {
    /// NATS server URL
    #[arg(long, env = "NATS_URL", default_value = "nats://127.0.0.1:4222")]
    nats_url: String,

    /// HTTP listen address for the gateway API
    #[arg(long, env = "GATEWAY_LISTEN", default_value = "127.0.0.1:3060")]
    listen: String,

    /// Path to the policy TOML file
    #[arg(long, env = "POLICY_PATH", default_value = "config/policy.toml")]
    policy_path: String,


    /// Connector MCP server URL
    #[arg(
        long,
        env = "CONNECTOR_MCP_URL",
        default_value = "http://127.0.0.1:3050"
    )]
    connector_mcp_url: String,

    /// Host URL (for internal API proxies)
    #[arg(long, env = "HOST_URL", default_value = "http://127.0.0.1:3000")]
    host_url: String,

    /// Public Portal URL (for external UI redirects like login)
    #[arg(long, env = "PORTAL_URL", default_value = "http://127.0.0.1:3000")]
    portal_url: String,


    /// JWT signing secret (shared with Host's ssi_vault)
    #[arg(long, env = "JWT_SECRET")]
    jwt_secret: Option<String>,

    /// Path to the agents TOML bootstrap file
    #[arg(long, env = "AGENTS_PATH", default_value = "config/agents.toml")]
    agents_path: String,

    /// Enable tool registry hot-reload
    #[arg(long, env = "ENABLE_HOT_RELOAD", default_value_t = false)]
    enable_hot_reload: bool,

    /// Comma-separated list of allowed CORS origins
    #[arg(
        long,
        env = "ALLOWED_ORIGINS",
        default_value = "http://localhost:8080,http://localhost:8083"
    )]
    allowed_origins: String,

    /// Comma-separated list of tool names that are always visible in MCP tools/list,
    /// regardless of the active context bundle. These are the "default tools" for
    /// the Smart Filtering system.
    #[arg(long, env = "DEFAULT_TOOLS", default_value = "")]
    default_tools: String,
}

async fn run_supervised<F, Fut, E>(
    name: &'static str,
    token: tokio_util::sync::CancellationToken,
    statuses: Option<std::sync::Arc<dashmap::DashMap<String, gateway::TaskStatus>>>,
    mut job: F,
) where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = std::result::Result<(), E>> + Send + 'static,
    E: std::fmt::Display,
{
    let mut backoff = std::time::Duration::from_secs(1);
    let max_backoff = std::time::Duration::from_secs(30);
    let mut restart_count = 0;

    loop {
        if token.is_cancelled() {
            tracing::info!("🛑 Supervisor [{}] shutting down", name);
            if let Some(ref map) = statuses {
                map.insert(name.to_string(), gateway::TaskStatus {
                    last_started: chrono::Utc::now(),
                    restart_count,
                    status: "stopped".to_string(),
                });
            }
            break;
        }

        tracing::info!("🚀 Supervisor starting daemon: {}", name);
        if let Some(ref map) = statuses {
            map.insert(name.to_string(), gateway::TaskStatus {
                last_started: chrono::Utc::now(),
                restart_count,
                status: "running".to_string(),
            });
        }

        let fut = job();
        
        tokio::select! {
            _ = token.cancelled() => {
                tracing::info!("🛑 Supervisor [{}] cancelled during execution", name);
                if let Some(ref map) = statuses {
                    map.insert(name.to_string(), gateway::TaskStatus {
                        last_started: chrono::Utc::now(),
                        restart_count,
                        status: "stopped".to_string(),
                    });
                }
                break;
            }
            res = fut => {
                match res {
                    Ok(_) => {
                        tracing::warn!("⚠️ Supervisor [{}] exited cleanly. Restarting...", name);
                    }
                    Err(e) => {
                        tracing::error!("❌ Supervisor [{}] crashed: {}. Restarting...", name, e);
                    }
                }
            }
        }

        restart_count += 1;
        if let Some(ref map) = statuses {
            map.insert(name.to_string(), gateway::TaskStatus {
                last_started: chrono::Utc::now(),
                restart_count,
                status: "failed".to_string(),
            });
        }

        // Apply backoff
        tokio::select! {
            _ = token.cancelled() => {
                break;
            }
            _ = tokio::time::sleep(backoff) => {}
        }

        backoff = std::cmp::min(backoff * 2, max_backoff);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,trust_gateway=debug".into()),
        )
        .init();

    dotenvy::dotenv().ok();
    let args = Args::parse();

    tracing::info!("🚀 Trust Gateway starting...");

    let jwt_secret_wrapper = if let Some(ref sec) = args.jwt_secret {
        identity_context::SecretString::new(sec.clone())
    } else {
        identity_context::load_secret("JWT_SECRET")
            .expect("JWT_SECRET must be configured via environment variable, systemd LoadCredential, or --jwt-secret argument")
    };
    let jwt_secret_raw = jwt_secret_wrapper.expose_secret();

    // ── WS6: Dev-secret detection guard ─────────────────────
    // Refuse to start with the known dev secret unless explicitly
    // in development mode. Prevents accidental production deployment.
    let lianxi_env = std::env::var("LIANXI_ENV").unwrap_or_else(|_| "development".to_string());
    if jwt_secret_raw.contains("dev-secret") && lianxi_env != "development" {
        tracing::error!(
            "🚨 CRITICAL: JWT_SECRET contains the known dev secret but LIANXI_ENV={}. \
             Refusing to start. Set a strong secret via: export JWT_SECRET=$(openssl rand -base64 32)",
            lianxi_env
        );
        std::process::exit(1);
    }
    if jwt_secret_raw.contains("dev-secret") {
        tracing::warn!(
            "⚠️ Using development JWT secret — NOT suitable for production. \
             Set JWT_SECRET to a strong random value and LIANXI_ENV=production for deployment."
        );
    }

    tracing::info!("   NATS URL:          {}", args.nats_url);
    tracing::info!("   HTTP Listen:       {}", args.listen);
    tracing::info!("   Policy:            {}", args.policy_path);

    // Load policy engine
    let policy_engine = trust_policy::TomlPolicyEngine::from_file(&args.policy_path)
        .map_err(|e| anyhow::anyhow!("Failed to load policy: {}", e))?;
    let policy_fp = policy_fingerprint::load_and_fingerprint(
        &std::fs::read_to_string(&args.policy_path).unwrap_or_default(),
        Some(std::path::Path::new(&args.policy_path)),
        policy_engine.rule_count(),
    )?;
    tracing::info!(
        "✅ Loaded policy ({} rules, fingerprint={})",
        policy_engine.rule_count(),
        &policy_fp.hash[..16]
    );
    tracing::info!("🔐 JWT secret loaded (len={})", jwt_secret_raw.len());

    // Load OAuth config (Phase 1)
    let oauth_config = None;

    // Connect to NATS
    // WS-H4: Authenticate with nkey if seed is provided
    let mut nats_options = if let Some(seed) = identity_context::load_secret("NATS_NKEY_SEED") {
        async_nats::ConnectOptions::with_nkey(seed.expose_secret().to_string())
    } else {
        async_nats::ConnectOptions::new()
    };
    nats_options = nats_options
        .request_timeout(Some(std::time::Duration::from_secs(25)))
        .retry_on_initial_connect()
        .max_reconnects(60) // Try for up to ~30 minutes with backoff
        .reconnect_delay_callback(|attempts| {
            // Exponential backoff capped at 30 seconds
            let delay = std::cmp::min(2u64.pow(attempts as u32), 30);
            std::time::Duration::from_secs(delay)
        })
        .event_callback(|event| async move {
            match event {
                async_nats::Event::Disconnected => {
                    tracing::error!("🚨 NATS client disconnected!");
                }
                async_nats::Event::Connected => {
                    tracing::info!("✅ NATS client connected");
                }
                async_nats::Event::SlowConsumer(sc) => {
                    tracing::warn!("⚠️ NATS client slow consumer detected on subject: {}", sc);
                }
                _ => {}
            }
        });

    let nc = async_nats::connect_with_options(&args.nats_url, nats_options)
        .await
        .context("Failed to connect to NATS")?;
    tracing::info!("✅ Connected to NATS");

    // Setup JetStream for audit
    let js = async_nats::jetstream::new(nc.clone());

    // Create durable audit stream (idempotent)
    // Try to reuse existing agent_audit_stream first (it already owns audit.action.> subjects),
    // then fall back to creating a new AUDIT_EVENTS stream.
    let audit_stream_name: String;
    {
        use async_nats::jetstream::stream;
        if let Ok(mut existing) = js.get_stream("agent_audit_stream").await {
            let info = existing.info().await.ok();
            let msg_count = info.as_ref().map(|i| i.state.messages).unwrap_or(0);
            tracing::info!(
                "✅ Using existing JetStream stream 'agent_audit_stream' ({} messages)",
                msg_count
            );
            audit_stream_name = "agent_audit_stream".to_string();
        } else {
            let stream_config = stream::Config {
                name: "AUDIT_EVENTS".to_string(),
                subjects: vec!["audit.action.>".to_string()],
                retention: stream::RetentionPolicy::Limits,
                max_age: std::time::Duration::from_secs(90 * 24 * 3600), // 90 days
                storage: stream::StorageType::File,
                ..Default::default()
            };
            match js.get_or_create_stream(stream_config).await {
                Ok(mut stream) => {
                    let info = stream.info().await.ok();
                    let msg_count = info.as_ref().map(|i| i.state.messages).unwrap_or(0);
                    tracing::info!(
                        "✅ JetStream stream AUDIT_EVENTS ready ({} messages)",
                        msg_count
                    );
                    audit_stream_name = "AUDIT_EVENTS".to_string();
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Failed to create audit stream (audit will fallback to plain NATS): {}",
                        e
                    );
                    audit_stream_name = String::new();
                }
            }
        }

        // Create KV buckets for action reviews and timelines
        use async_nats::jetstream::kv;
        for bucket_name in &[
            "action_reviews",
            "action_timelines",
            "approval_records",
            "agent_registry",
            "agent_source_index",
            "audit_chain_heads",
            "tenant_action_index",
            "mcp_session_state",
            "did_web_cache",
            "did_twin_cache",
        ] {
            // WS-H1: Approval records get a 24-hour TTL to prevent unbounded
            // state growth. Unresolved approvals expire automatically.
            // Other high-turnover ephemeral state buckets get a 7-day TTL
            // to prevent unbounded Idempotency tracking / DID caches.
            let max_age = if *bucket_name == "approval_records" {
                std::time::Duration::from_secs(24 * 3600) // 24 hours
            } else if *bucket_name == "mcp_session_state" || *bucket_name == "tenant_action_index" {
                std::time::Duration::from_secs(7 * 24 * 3600) // 7 days
            } else if *bucket_name == "did_web_cache" {
                let secs = std::env::var("DID_WEB_CACHE_TTL_SECS")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(300);
                std::time::Duration::from_secs(secs)
            } else if *bucket_name == "did_twin_cache" {
                let secs = std::env::var("DID_TWIN_CACHE_TTL_SECS")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(300);
                std::time::Duration::from_secs(secs)
            } else {
                std::time::Duration::from_secs(90 * 24 * 3600) // 90 days
            };

            let kv_config = kv::Config {
                bucket: bucket_name.to_string(),
                history: 5,
                max_age,
                ..Default::default()
            };
            match js.create_key_value(kv_config).await {
                Ok(_) => tracing::info!(
                    "✅ JetStream KV bucket '{}' ready (max_age: {:?})",
                    bucket_name,
                    max_age
                ),
                Err(e) => {
                    // Bucket may already exist — try to get it
                    match js.get_key_value(bucket_name.to_string()).await {
                        Ok(_) => tracing::info!(
                            "✅ JetStream KV bucket '{}' already exists",
                            bucket_name
                        ),
                        Err(_) => {
                            tracing::warn!("⚠️ Failed to create KV bucket '{}': {}", bucket_name, e)
                        }
                    }
                }
            }
        }
    }

    // WS1.2: Initialize per-connector circuit breakers
    let mut circuit_breakers = std::collections::HashMap::new();
    let cb_threshold = 5; // 5 consecutive failures → open
    let cb_timeout = std::time::Duration::from_secs(30); // 30s recovery window
    circuit_breakers.insert(
        "connector_mcp".to_string(),
        router::CircuitBreaker::new(cb_threshold, cb_timeout),
    );
    circuit_breakers.insert(
        "claw_executor".to_string(),
        router::CircuitBreaker::new(cb_threshold, cb_timeout),
    );
    circuit_breakers.insert(
        "vp_mcp".to_string(),
        router::CircuitBreaker::new(cb_threshold, cb_timeout),
    );
    tracing::info!(
        "✅ Circuit breakers initialized for {} connectors",
        circuit_breakers.len()
    );

    // Build audit sink (trait object)
    let audit_sink: Arc<dyn trust_core::traits::AuditSink> =
        Arc::new(audit_sink::JetStreamAuditSink::new(js.clone(), nc.clone()));

    // Build approval store (trait object)
    let approval_store: Arc<dyn trust_core::traits::ApprovalStore> =
        Arc::new(approval_store::JetStreamApprovalStore::new(js.clone()));

    // Build agent registry (trait object)
    let agent_registry: Arc<dyn trust_core::traits::AgentRegistry> =
        Arc::new(agent_registry::JetStreamAgentRegistry::new(js.clone()));

    // Bootstrap agents from TOML config
    agent_registry::bootstrap_from_toml_direct(&js, &args.agents_path).await;
    tracing::info!("✅ Agent Registry initialized");

    // ── WS1 & SEC-1: Build grant issuer (Ed25519 required in prod, HMAC dev fallback) ──
    let grant_issuer: Arc<dyn trust_core::traits::GrantIssuer> = {
        if let Ok(key_path) = std::env::var("GRANT_SIGNING_KEY_PATH") {
            // Ed25519 asymmetric signing — private key stays in the gateway
            match std::fs::read_to_string(&key_path) {
                Ok(pem) => {
                    let kid = std::env::var("GRANT_SIGNING_KEY_ID")
                        .unwrap_or_else(|_| "gateway-ed25519-1".to_string());
                    match grant::Ed25519GrantIssuer::from_pem(&pem, kid.clone()) {
                        Ok(issuer) => {
                            tracing::info!("✅ Ed25519 grant signing enabled (kid={})", kid);
                            Arc::new(issuer)
                        }
                        Err(e) => {
                            tracing::error!(
                                "❌ Failed to load Ed25519 key from {}: {}",
                                key_path,
                                e
                            );
                            // Fall through to dev check
                            let env = std::env::var("LIANXI_ENV").unwrap_or_default();
                            if env != "development" {
                                panic!("HMAC grant signing is disabled in non-development environments. Fix Ed25519 key.");
                            }
                            tracing::warn!("⚠️ Falling back to HMAC grant signing (development only — SEC-1)");
                            Arc::new(grant::HmacGrantIssuer::new(jwt_secret_raw))
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("❌ Cannot read Ed25519 key file {}: {}", key_path, e);
                    // Fall through to dev check
                    let env = std::env::var("LIANXI_ENV").unwrap_or_default();
                    if env != "development" {
                        panic!("HMAC grant signing is disabled in non-development environments. Fix Ed25519 key.");
                    }
                    tracing::warn!("⚠️ Falling back to HMAC grant signing (development only — SEC-1)");
                    Arc::new(grant::HmacGrantIssuer::new(jwt_secret_raw))
                }
            }
        } else {
            // SEC-1: Gate HMAC fallback
            let env = std::env::var("LIANXI_ENV").unwrap_or_default();
            if env != "development" {
                panic!(
                    "HMAC grant signing is disabled in non-development environments. \
                     Set GRANT_SIGNING_KEY_PATH to an Ed25519 private key PEM file."
                );
            }
            tracing::warn!("⚠️ Using HMAC grant signing (development only — SEC-1 deprecation)");
            Arc::new(grant::HmacGrantIssuer::new(jwt_secret_raw))
        }
    };

    // ── WS-H2: Load JSON Schema snapshots for ingress validation ──
    let schema_validator = {
        // Look for snapshots relative to the trust_core crate
        let possible_dirs = [
            std::path::PathBuf::from("../shared_libs/trust_core/snapshots"),
            std::path::PathBuf::from("../../execution_plane/shared_libs/trust_core/snapshots"),
            std::path::PathBuf::from("shared_libs/trust_core/snapshots"),
        ];

        let mut validator = None;
        for dir in &possible_dirs {
            if dir.exists() {
                match trust_core::schema_validator::SchemaValidator::from_directory(dir) {
                    Ok(v) => {
                        tracing::info!(
                            "✅ Schema validator loaded: {} schemas from {:?} ({})",
                            v.loaded_schemas().len(),
                            dir,
                            v.loaded_schemas().join(", ")
                        );
                        validator = Some(v);
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("⚠️ Failed to load schemas from {:?}: {}", dir, e);
                    }
                }
            }
        }

        if validator.is_none() {
            tracing::warn!("⚠️ No schema snapshots found — ingress validation disabled");
        }

        validator
    };

    // Build shared gateway state
    let did_web_cache = js.get_key_value("did_web_cache").await.ok();

    #[cfg(feature = "professional")]
    let tool_listing_overlay: Arc<dyn trust_core::ports::ToolListingOverlay> = {
        if std::env::var("PROFESSIONAL_EDITION").unwrap_or_default() == "true" {
            tracing::info!("🚀 Professional Edition Environment detected! Injecting stateful ToolListingOverlay...");
            Arc::new(professional_core::ProfessionalToolListingOverlay::new(js.clone()))
        } else {
            tracing::info!("ℹ️ Community Mode active. Using StatelessToolListingOverlay.");
            Arc::new(trust_core::ports::StatelessToolListingOverlay)
        }
    };

    #[cfg(not(feature = "professional"))]
    let tool_listing_overlay: Arc<dyn trust_core::ports::ToolListingOverlay> = Arc::new(trust_core::ports::StatelessToolListingOverlay);

    let allowed_origins: Vec<String> = args
        .allowed_origins
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    for origin in &allowed_origins {
        if origin == "*" || origin.contains('*') {
            anyhow::bail!("CORS wildcard '*' is forbidden in ALLOWED_ORIGINS to prevent security vulnerabilities");
        }
    }

    let state = Arc::new(GatewayState {
        security: gateway::SecurityState {
            policy_engine: Arc::new(policy_engine),
            grant_issuer,
            audit_sink,
        },
        connectors: gateway::ConnectorConfig {
            connector_mcp_url: args.connector_mcp_url.clone(),
            host_url: args.host_url.clone(),
            portal_url: args.portal_url.clone(),
            oauth2_service_url: std::env::var("OAUTH2_SERVICE_URL").ok(),
        },
        approval_store,
        agent_registry,
        nats: nc.clone(),
        jetstream: js.clone(),
        http_client: {
            let client = reqwest::Client::builder()
                .pool_max_idle_per_host(10)
                .timeout(std::time::Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default();
            client
        },
        tool_registry: Some(router::ToolRegistry::new(
            std::time::Duration::from_secs(300), // 5-minute TTL
        )),
        circuit_breakers,
        allowed_origins,
        oauth_config,
        jwt_secret: jwt_secret_raw.to_string(),
        // Phase 1 SSI Identity: Use SsiTokenValidator to handle VP tokens,
        // with automatic fallback to StandardJwtValidator for UI sessions.
        // NOTE: Reuses the same hardened reqwest::Client as the rest of the
        // gateway (TLS, timeouts, redirect policy) — do NOT use Client::new().
        token_validator: Arc::new(auth::SsiTokenValidator {
            fallback: auth::StandardJwtValidator,
            http_client: reqwest::Client::builder()
                .pool_max_idle_per_host(10)
                .timeout(std::time::Duration::from_secs(10)) // Tighter for DID resolution
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            did_web_cache,
        }),
        // Smart Filtering: Active SSE session senders
        sse_senders: dashmap::DashMap::new(),
        // Smart Filtering: Admin-configured default tools
        default_tools: args
            .default_tools
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        // WS-H2: Schema validator for ingress payloads
        schema_validator,
        tool_listing_overlay,
        policy_fingerprint: policy_fp.hash.clone(),
        task_statuses: std::sync::Arc::new(dashmap::DashMap::new()),
    });

    let cancel_token = tokio_util::sync::CancellationToken::new();
    let mut background_tasks = tokio_util::task::TaskTracker::new();

    // Phase 4: Emit PolicyLoaded audit event at startup
    audit_sink::emit_audit(
        &*state.security.audit_sink,
        "system",
        trust_core::audit::AuditEventType::PolicyLoaded,
        "trust_gateway",
        "startup",
        serde_json::json!({
            "policy_fingerprint": policy_fp.hash,
            "rule_count": policy_fp.rule_count,
            "signature_verified": policy_fp.signature_verified,
        }),
    )
    .await;

    // Phase 4a: Spawn canonical trust.v1.*.action.propose listener
    let trust_v1_state = state.clone();
    let trust_v1_client = nc.clone();
    let token = cancel_token.clone();
    background_tasks.spawn(run_supervised(
        "trust_v1_listener",
        token,
        Some(state.task_statuses.clone()),
        move || {
            let client = trust_v1_client.clone();
            let state = trust_v1_state.clone();
            async move {
                gateway::run_trust_v1_listener(client, state).await
            }
        }
    ));

    // Phase 4b: Spawn NATS tools.list listener for bundle-aware discovery
    let tools_list_state = state.clone();
    let tools_list_client = nc.clone();
    let tools_list_token = cancel_token.clone();
    background_tasks.spawn(run_supervised(
        "tools_list_listener",
        tools_list_token,
        Some(state.task_statuses.clone()),
        move || {
            let client = tools_list_client.clone();
            let state = tools_list_state.clone();
            async move {
                gateway::run_tools_list_listener(client, state).await
            }
        }
    ));


    // Spawn audit timeline projector (Trust Replay)
    let projector_js = async_nats::jetstream::new(nc.clone());
    let ui_projector_stream_name = audit_stream_name.clone();
    if !audit_stream_name.is_empty() {
        let token = cancel_token.clone();
        background_tasks.spawn(run_supervised(
            "audit_projector",
            token,
            Some(state.task_statuses.clone()),
            move || {
                let js = projector_js.clone();
                let stream = ui_projector_stream_name.clone();
                async move {
                    match audit_projector::spawn_projector(js, &stream).await {
                        Ok(handle) => {
                            if let Err(e) = handle.await {
                                Err(anyhow::anyhow!("Projector task failed: {}", e))
                            } else {
                                Ok(())
                            }
                        }
                        Err(e) => Err(anyhow::anyhow!("Failed to spawn projector: {}", e)),
                    }
                }
            }
        ));
    } else {
        tracing::warn!("⚠️ No audit stream available — projector disabled");
    }



    // WS1.5: Subscribe to tool registry hot-reload events
    // Gated behind ENABLE_HOT_RELOAD — nothing currently publishes to these subjects
    if args.enable_hot_reload {
        let hotreload_state = state.clone();
        let hotreload_nc = nc.clone();
        let cancel_token_1 = cancel_token.clone();
        background_tasks.spawn(async move {
            tokio::select! {
                _ = cancel_token_1.cancelled() => {
                    tracing::info!("🛑 Tool registry hot-reload subscription cancelled");
                }
                res = async {
                    match hotreload_nc.subscribe("host.v1.tools.changed").await {
                        Ok(mut sub) => {
                            tracing::info!("✅ Subscribed to host.v1.tools.changed for tool registry hot-reload");
                            while let Some(_msg) = futures::StreamExt::next(&mut sub).await {
                                tracing::info!("🔄 Tool registry hot-reload triggered");
                                if let Some(ref registry) = hotreload_state.tool_registry {
                                    registry.force_refresh(
                                        &hotreload_state.http_client,
                                        &hotreload_state.connectors.host_url,
                                    ).await;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("⚠️ Could not subscribe to tools.changed: {} (hot-reload disabled)", e);
                        }
                    }
                } => res
            }
        });

        // Phase 4.2: Subscribe to Claw skill changes for registry invalidation
        let claw_state = state.clone();
        let claw_nc = nc.clone();
        let cancel_token_2 = cancel_token.clone();
        background_tasks.spawn(async move {
            tokio::select! {
                _ = cancel_token_2.cancelled() => {
                    tracing::info!("🛑 Claw skill hot-reload subscription cancelled");
                }
                res = async {
                    match claw_nc.subscribe("claw.v1.skills.changed").await {
                        Ok(mut sub) => {
                            tracing::info!("✅ Subscribed to claw.v1.skills.changed for Claw skill hot-reload");
                            while let Some(msg) = futures::StreamExt::next(&mut sub).await {
                                let payload = String::from_utf8_lossy(&msg.payload);
                                tracing::info!("🔄 Claw skill change detected — refreshing registry: {}", payload);
                                if let Some(ref registry) = claw_state.tool_registry {
                                    registry.force_refresh(
                                        &claw_state.http_client,
                                        &claw_state.connectors.host_url,
                                    ).await;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("⚠️ Could not subscribe to claw.v1.skills.changed: {} (Claw hot-reload disabled)", e);
                        }
                    }
                } => res
            }
        });
    } else {
        tracing::info!("ℹ️ Hot-reload subscriptions disabled (set ENABLE_HOT_RELOAD=1 to enable)");
    }

    // Spawn the asynchronous supervisor daemon for outbox processing
    let token = cancel_token.clone();
    let s1 = state.clone();
    background_tasks.spawn(run_supervised(
        "execution_daemon",
        token,
        Some(state.task_statuses.clone()),
        move || {
            let state = s1.clone();
            async move {
                approval_daemon::run_execution_daemon(state).await;
                Ok::<(), anyhow::Error>(())
            }
        }
    ));

    let token = cancel_token.clone();
    let s2 = state.clone();
    background_tasks.spawn(run_supervised(
        "decision_listener",
        token,
        Some(state.task_statuses.clone()),
        move || {
            let state = s2.clone();
            async move {
                approval_daemon::run_decision_listener(state).await;
                Ok::<(), anyhow::Error>(())
            }
        }
    ));

    let token = cancel_token.clone();
    let s_sweeper = state.clone();
    background_tasks.spawn(run_supervised(
        "escalation_sweeper",
        token,
        Some(state.task_statuses.clone()),
        move || {
            let state = s_sweeper.clone();
            async move {
                approval_daemon::run_escalation_sweeper(state).await;
                Ok::<(), anyhow::Error>(())
            }
        }
    ));

    let token = cancel_token.clone();
    let s3 = state.clone();
    background_tasks.spawn(run_supervised(
        "cron_scheduler",
        token,
        Some(state.task_statuses.clone()),
        move || {
            let state = s3.clone();
            async move {
                cron_scheduler::run_cron_scheduler(state).await;
                Ok::<(), anyhow::Error>(())
            }
        }
    ));

    background_tasks.close();

    let shutdown_state = state.clone();
    let app = api::build_router(state);

    let addr: std::net::SocketAddr = args
        .listen
        .parse()
        .expect("Invalid listen address provided");
    tracing::info!("🚀 Trust Gateway listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Graceful shutdown: drain NATS + stop HTTP on SIGTERM/Ctrl+C
    let shutdown_nc = nc.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("Failed to install SIGTERM handler");

            #[cfg(unix)]
            tokio::select! {
                _ = ctrl_c => {},
                _ = sigterm.recv() => {},
            }
            #[cfg(not(unix))]
            ctrl_c.await.ok();

            tracing::info!("🛑 Shutdown signal received — stopping HTTP and signalling tasks...");

            // Signal all background tasks to stop
            cancel_token.cancel();

            // Wait for all tracked tasks to finish their current iterations
            tokio::time::timeout(std::time::Duration::from_secs(5), background_tasks.wait())
                .await
                .ok();

            // WS-B3: Explicitly drop handles to ensure audit sinks stop producing
            drop(background_tasks);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            tracing::info!("🧹 Waiting for final NATS flush...");
            // WS-B3: Flush audit sink explicitly before flushing NATS connection
            shutdown_state.security.audit_sink.flush().await;
            let _ = shutdown_nc.flush().await;
            tracing::info!("👋 Trust Gateway shut down cleanly");
        })
        .await?;

    Ok(())
}
