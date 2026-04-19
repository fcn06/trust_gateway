// ─────────────────────────────────────────────────────────────
// Trust Gateway — main entry point
//
// Evolved from mcp_nats_bridge. Provides:
// 1. HTTP API: POST /v1/actions/propose
// 2. NATS listener: mcp.v1.dispatch.> (backward compat)
// 3. Policy-driven action governance
// 4. ExecutionGrant JWT issuance
// 5. Dual-backend connector routing (MCP + Claw)
// ─────────────────────────────────────────────────────────────

mod gateway;
mod grant;
mod audit_sink;
mod normalizer;
mod audit_projector;
mod router;
// mod session; — REMOVED: dead passthrough to identity_context::jwt (Phase 1.1)
mod api;
mod mcp_sse;
mod amount_extractor;
mod policy_api;
mod meta_identity;
mod transport_normalizer;
mod source_registry;
mod standalone_registry;
mod agent_registry;
mod agent_api;
mod approval_http;
mod approval_store;
mod approval_daemon;

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
    #[arg(long, env = "GATEWAY_LISTEN", default_value = "0.0.0.0:3060")]
    listen: String,

    /// Path to the policy TOML file
    #[arg(long, env = "POLICY_PATH", default_value = "config/policy.toml")]
    policy_path: String,

    /// Connector MCP server URL
    #[arg(long, env = "CONNECTOR_MCP_URL", default_value = "http://127.0.0.1:3050")]
    connector_mcp_url: String,

    /// Native Skill Executor URL (Claw backend)
    #[arg(long, env = "SKILL_EXECUTOR_URL", default_value = "http://127.0.0.1:3070")]
    skill_executor_url: String,

    /// Restaurant State Service URL
    #[arg(long, env = "RESTAURANT_SERVICE_URL", default_value = "http://127.0.0.1:3080")]
    restaurant_service_url: String,

    /// VP MCP server URL
    #[arg(long, env = "VP_MCP_URL", default_value = "http://127.0.0.1:4000/sse")]
    vp_mcp_url: String,

    /// Host URL (for approval callbacks)
    #[arg(long, env = "HOST_URL", default_value = "http://127.0.0.1:3000")]
    host_url: String,

    /// NATS subject to subscribe to (backward compat with mcp_nats_bridge)
    #[arg(long, default_value = "mcp.v1.dispatch.>")]
    nats_subject: String,

    /// JWT signing secret (shared with Host's ssi_vault)
    #[arg(long, env = "JWT_SECRET")]
    jwt_secret: String,

    /// Path to the agents TOML bootstrap file
    #[arg(long, env = "AGENTS_PATH", default_value = "config/agents.toml")]
    agents_path: String,

    /// Enable tool registry hot-reload
    #[arg(long, env = "ENABLE_HOT_RELOAD", default_value_t = false)]
    enable_hot_reload: bool,

    /// Comma-separated list of allowed CORS origins
    #[arg(long, env = "ALLOWED_ORIGINS", default_value = "http://localhost:8080,http://localhost:8083")]
    allowed_origins: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,trust_gateway=debug".into()),
        )
        .init();

    dotenvy::dotenv().ok();
    let args = Args::parse();

    tracing::info!("🚀 Trust Gateway starting...");
    tracing::info!("   NATS URL:          {}", args.nats_url);
    tracing::info!("   HTTP Listen:       {}", args.listen);
    tracing::info!("   Policy:            {}", args.policy_path);
    tracing::info!("   Connector MCP:     {}", args.connector_mcp_url);
    tracing::info!("   Skill Executor:    {}", args.skill_executor_url);
    tracing::info!("   Restaurant Svc:    {}", args.restaurant_service_url);
    tracing::info!("   NATS Subject:      {}", args.nats_subject);
    tracing::info!("   VP MCP URL:        {}", args.vp_mcp_url);

    // Load policy engine
    let policy_engine = trust_policy::TomlPolicyEngine::from_file(&args.policy_path)
        .map_err(|e| anyhow::anyhow!("Failed to load policy: {}", e))?;
    tracing::info!("✅ Loaded policy ({} rules)", policy_engine.rule_count());

    // Connect to NATS
    let nats_options = async_nats::ConnectOptions::new()
        .request_timeout(Some(std::time::Duration::from_secs(25)));
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
            tracing::info!("✅ Using existing JetStream stream 'agent_audit_stream' ({} messages)", msg_count);
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
                    tracing::info!("✅ JetStream stream AUDIT_EVENTS ready ({} messages)", msg_count);
                    audit_stream_name = "AUDIT_EVENTS".to_string();
                }
                Err(e) => {
                    tracing::warn!("⚠️ Failed to create audit stream (audit will fallback to plain NATS): {}", e);
                    audit_stream_name = String::new();
                }
            }
        }

        // Create KV buckets for action reviews and timelines
        use async_nats::jetstream::kv;
        for bucket_name in &["action_reviews", "action_timelines", "approval_records", "agent_registry", "agent_source_index"] {
            let kv_config = kv::Config {
                bucket: bucket_name.to_string(),
                history: 5,
                max_age: std::time::Duration::from_secs(90 * 24 * 3600),
                ..Default::default()
            };
            match js.create_key_value(kv_config).await {
                Ok(_) => tracing::info!("✅ JetStream KV bucket '{}' ready", bucket_name),
                Err(e) => {
                    // Bucket may already exist — try to get it
                    match js.get_key_value(bucket_name.to_string()).await {
                        Ok(_) => tracing::info!("✅ JetStream KV bucket '{}' already exists", bucket_name),
                        Err(_) => tracing::warn!("⚠️ Failed to create KV bucket '{}': {}", bucket_name, e),
                    }
                }
            }
        }
    }

    // WS1.2: Initialize per-connector circuit breakers
    let mut circuit_breakers = std::collections::HashMap::new();
    let cb_threshold = 5;  // 5 consecutive failures → open
    let cb_timeout = std::time::Duration::from_secs(30); // 30s recovery window
    circuit_breakers.insert("connector_mcp".to_string(), router::CircuitBreaker::new(cb_threshold, cb_timeout));
    circuit_breakers.insert("claw_executor".to_string(), router::CircuitBreaker::new(cb_threshold, cb_timeout));
    circuit_breakers.insert("vp_mcp".to_string(), router::CircuitBreaker::new(cb_threshold, cb_timeout));
    circuit_breakers.insert("restaurant_service".to_string(), router::CircuitBreaker::new(cb_threshold, cb_timeout));
    tracing::info!("✅ Circuit breakers initialized for {} connectors", circuit_breakers.len());

    // Build audit sink (trait object)
    let audit_sink: Arc<dyn trust_core::traits::AuditSink> = Arc::new(
        audit_sink::JetStreamAuditSink::new(js.clone(), nc.clone())
    );

    // Build approval store (trait object)
    let approval_store: Arc<dyn trust_core::traits::ApprovalStore> = Arc::new(
        approval_store::JetStreamApprovalStore::new(js.clone())
    );

    // Build agent registry (trait object)
    let agent_registry: Arc<dyn trust_core::traits::AgentRegistry> = Arc::new(
        agent_registry::JetStreamAgentRegistry::new(js.clone())
    );

    // Bootstrap agents from TOML config
    agent_registry::bootstrap_from_toml_direct(&js, &args.agents_path).await;
    tracing::info!("✅ Agent Registry initialized");

    // Build shared gateway state
    let state = Arc::new(GatewayState {
        policy_engine: Arc::new(policy_engine),
        grant_issuer: Arc::new(grant::HmacGrantIssuer::new(&args.jwt_secret)),
        audit_sink,
        approval_store,
        agent_registry,
        nats: nc.clone(),
        jetstream: js,
        http_client: reqwest::Client::new(),
        connector_mcp_url: args.connector_mcp_url.clone(),
        skill_executor_url: args.skill_executor_url.clone(),
        restaurant_service_url: args.restaurant_service_url.clone(),
        vp_mcp_url: args.vp_mcp_url.clone(),
        host_url: args.host_url.clone(),
        tool_registry: Some(router::ToolRegistry::new(
            std::time::Duration::from_secs(300), // 5-minute TTL
        )),
        circuit_breakers,
        allowed_origins: args.allowed_origins.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    });

    // Spawn NATS listener (backward compat with mcp_nats_bridge)
    let nats_state = state.clone();
    let nats_subject = args.nats_subject.clone();
    let nats_client = nc.clone();
    tokio::spawn(async move {
        if let Err(e) = gateway::run_nats_listener(nats_client, nats_subject, nats_state).await {
            tracing::error!("❌ NATS listener error: {}", e);
        }
    });

    // Spawn audit timeline projector (Trust Replay)
    let projector_js = async_nats::jetstream::new(nc.clone());
    if !audit_stream_name.is_empty() {
        match audit_projector::spawn_projector(projector_js, &audit_stream_name).await {
            Ok(_handle) => {
                tracing::info!("✅ Audit timeline projector spawned (stream: {})", audit_stream_name);
            }
            Err(e) => {
                tracing::warn!("⚠️ Could not start audit projector: {} (timeline will be unavailable)", e);
            }
        }
    } else {
        tracing::warn!("⚠️ No audit stream available — projector disabled");
    }

    // WS1.5: Subscribe to tool registry hot-reload events
    // Gated behind ENABLE_HOT_RELOAD — nothing currently publishes to these subjects
    if args.enable_hot_reload {
        let hotreload_state = state.clone();
        let hotreload_nc = nc.clone();
        tokio::spawn(async move {
            match hotreload_nc.subscribe("host.v1.tools.changed").await {
                Ok(mut sub) => {
                    tracing::info!("✅ Subscribed to host.v1.tools.changed for tool registry hot-reload");
                    while let Some(_msg) = futures::StreamExt::next(&mut sub).await {
                        tracing::info!("🔄 Tool registry hot-reload triggered");
                        if let Some(ref registry) = hotreload_state.tool_registry {
                            registry.force_refresh(
                                &hotreload_state.http_client,
                                &hotreload_state.host_url,
                                &hotreload_state.vp_mcp_url,
                            ).await;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("⚠️ Could not subscribe to tools.changed: {} (hot-reload disabled)", e);
                }
            }
        });

        // Phase 4.2: Subscribe to Claw skill changes for registry invalidation
        let claw_state = state.clone();
        let claw_nc = nc.clone();
        tokio::spawn(async move {
            match claw_nc.subscribe("claw.v1.skills.changed").await {
                Ok(mut sub) => {
                    tracing::info!("✅ Subscribed to claw.v1.skills.changed for Claw skill hot-reload");
                    while let Some(msg) = futures::StreamExt::next(&mut sub).await {
                        let payload = String::from_utf8_lossy(&msg.payload);
                        tracing::info!("🔄 Claw skill change detected — refreshing registry: {}", payload);
                        if let Some(ref registry) = claw_state.tool_registry {
                            registry.force_refresh(
                                &claw_state.http_client,
                                &claw_state.host_url,
                                &claw_state.vp_mcp_url,
                            ).await;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("⚠️ Could not subscribe to claw.v1.skills.changed: {} (Claw hot-reload disabled)", e);
                }
            }
        });
    } else {
        tracing::info!("ℹ️ Hot-reload subscriptions disabled (set ENABLE_HOT_RELOAD=1 to enable)");
    }

    // Spawn the asynchronous supervisor daemon for outbox processing
    approval_daemon::spawn_execution_daemon(state.clone()).await;

    // Build and run HTTP server with graceful shutdown
    let app = api::build_router(state);

    let addr: std::net::SocketAddr = args.listen.parse()
        .unwrap_or_else(|_| "0.0.0.0:3060".parse().unwrap());
    tracing::info!("🚀 Trust Gateway listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Graceful shutdown: drain NATS + stop HTTP on SIGTERM/Ctrl+C
    let shutdown_nc = nc.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            ).expect("Failed to install SIGTERM handler");

            #[cfg(unix)]
            tokio::select! {
                _ = ctrl_c => {},
                _ = sigterm.recv() => {},
            }
            #[cfg(not(unix))]
            ctrl_c.await.ok();

            tracing::info!("🛑 Shutdown signal received — stopping HTTP and closing NATS...");

            // Give in-flight requests a moment to complete
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            // async_nats::Client does not have a `drain()` method, so we let it drop
            // normally, allowing pending flushes to complete in the background.
            // Give background tasks a moment to finish before terminating
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            tracing::info!("👋 Trust Gateway shut down cleanly");
        })
        .await?;

    Ok(())
}
