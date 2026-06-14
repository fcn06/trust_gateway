use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::{HashMap, HashSet};
use tokio_util::sync::CancellationToken;
use clap::Parser;
use tokio::sync::mpsc;
use axum::{
    Router,
    routing::{get, post},
    http::{Method},
};
use tower_http::cors::CorsLayer;
use wasmtime::{Engine, Config};
use tracing_subscriber::EnvFilter;

// Use host library modules and types
use host::commands::{VaultCommand, AclCommand};
use host::shared_state::{WebauthnSharedState, CliArgs};
use host::{init, auth, loops, handlers, linker, registry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. CLI Args & Config
    let args = CliArgs::parse();
    let config = init::load_config()?;
    
    // Override log level
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", &args.log_level);
    }
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("🚀 Starting Host...");

    // 2. Setup NATS & KV
    tracing::info!("🔌 Connecting to NATS...");
    let (nc, kv_stores) = init::setup_nats(&config).await?;
    tracing::info!("✅ Connected to NATS and initialized KV stores");

    // Backfill thid index for O(1) handshake status lookups (idempotent migration)
    if let Some(sovereign_kv) = kv_stores.get("sovereign_kv") {
        init::backfill_thid_index(sovereign_kv).await;
    }

    // 3. Load Keys
    let keys = init::load_server_keys()?;
    // jwt_key is now managed by AuthVault within shared_state


    // 4. Setup WebAuthn
    let webauthn = init::setup_webauthn(&config)?;

    let (vault_cmd_tx, vault_cmd_rx) = mpsc::channel(100);

    let (acl_cmd_tx, acl_cmd_rx) = mpsc::channel(100);

    // Create a shared HTTP client with connection pooling
    let http_client = reqwest::Client::builder()
        .pool_max_idle_per_host(10)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("Failed to build HTTP client");

    // Initialize community approval notifier adapter
    let approval_notifier = Arc::new(community_adapters::notifier::LocalDashboardNotifier::new(nc.clone()));

    // 6. Shared State
    let shared = Arc::new(WebauthnSharedState::new(
        config.clone(),
        vault_cmd_tx.clone(),
        acl_cmd_tx.clone(),
        approval_notifier,
        Some(nc.clone()),
        Some(kv_stores.clone()),
        keys.jwt_key_bytes,
        webauthn,
        keys.house_salt,
        kv_stores.get("tenant_connections").cloned(),
        http_client,
        None,
        None,
        None,
    ));

    // 7. Wasm Engine & Linker
    let mut wasm_config = Config::new();
    wasm_config.wasm_component_model(true);
    wasm_config.async_support(true);
    let engine = Engine::new(&wasm_config)?;

    tracing::info!("🔗 Configuring Linker...");
    let linker = linker::setup_linker(&engine).await?;

    // 8. Load Components
    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    tracing::info!("📦 Loading Wasm components via registry ({} profile)...", profile);
    
    let config_path = std::path::Path::new("config/components.toml");
    let mut component_registry = registry::ComponentRegistry::new(engine.clone());
    
    if config_path.exists() {
        component_registry.load_config(config_path)?;
        component_registry.load_enabled()?;
        tracing::info!("✅ Loaded {} components from config", component_registry.list_loaded().len());
    } else {
        tracing::warn!("⚠️ components.toml not found, using hardcoded paths");
        // Fallback paths — community edition loads core components only
        let components = vec!["ssi_vault", "acl_store"];
        for name in components {
            let path = format!("../target/wasm32-wasip2/{}/{}.wasm", profile, name);
            if std::path::Path::new(&path).exists() {
                component_registry.load_component(name, std::path::Path::new(&path))?;
            } else {
                tracing::warn!("⚠️ Component not found: {}", path);
            }
        }
    }

    let vault_comp = component_registry.require("ssi_vault").clone();

    // 9. Spawn Loops (Logic separated per component)
    tracing::info!("🏁 Spawning independent command loop tasks...");

    // Specialized linkers for Vault/ACL (persistence binding)
    let vault_linker = linker::create_specialized_linker(&linker, |s| s.vault_store.clone()).await?;

    loops::spawn_vault_loop(engine.clone(), shared.clone(), vault_comp, vault_linker, vault_cmd_rx);
    loops::spawn_acl_loop(shared.clone(), acl_cmd_rx);

    // 10. Global Subscriptions
    tracing::info!("🔄 Restoring global subscriptions...");
    loops::subscribe_to_escalation_requests(shared.clone());
    loops::subscribe_to_escalation_results(shared.clone());
    loops::subscribe_to_discovery_requests(shared.clone());
    loops::spawn_mcp_escalation_loop(shared.clone());
    handlers::oid4vp::subscribe_oid4vp_get_request(shared.clone());
    handlers::oid4vp::subscribe_oid4vp_submit_response(shared.clone());

    // 11. API Router
    // Convert allowed_origins strings to HeaderValues
    let allowed_origins: Vec<axum::http::HeaderValue> = shared.config.allowed_origins
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods(vec![Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(vec![
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
        ])
        .allow_credentials(true);

    let auth_routes = Router::new()
        .route("/register/start", post(auth::start_registration_handler))
        .route("/register/finish", post(auth::finish_registration_handler))
        .route("/login/start", post(auth::start_login_handler))
        .route("/login/finish", post(auth::finish_login_handler))
        .route("/profile", get(auth::get_profile_handler).post(auth::update_profile_handler))
        .route("/handshake/status/:thid", get(auth::check_handshake_status_handler));

    let app = Router::new()
        .route("/api/link-remote", post(auth::link_remote_access_handler))
        .nest("/api/webauthn", auth_routes)
        .route("/api/identities", post(handlers::api::create_identity_handler).get(handlers::api::list_identities_handler))
        .route("/api/identities/generate_did_web", post(handlers::api::generate_did_web_handler))
        .route("/api/identities/publish", post(handlers::api::publish_identity_handler))
        .route("/api/identities/enrich", post(handlers::api::enrich_identity_handler))
        .route("/api/invitations/generate", get(handlers::api::generate_invitation_handler));
        
    let app = app
        .route("/api/invitations/accept", post(handlers::api::accept_invitation_handler))
        .route("/api/acl/policies", get(handlers::api::get_acl_policies_handler).post(handlers::api::update_acl_policy_handler))
        .route("/api/identities/published", get(handlers::api::get_published_dids_handler))
        .route("/api/identities/active", get(handlers::api::get_active_did_handler))
        .route("/api/identities/activate", post(handlers::api::activate_identity_handler))
        
        .route("/api/profile/get", get(handlers::api::get_profile_handler))
        .route("/api/profile/update", post(handlers::api::update_profile_handler))
        
        // Escalation Request Routes (Agent Authorization)
        .route("/api/escalation_requests", get(handlers::api::get_escalation_requests_handler))
        .route("/api/escalation_requests/:id/approve", post(handlers::api::approve_escalation_handler))
        .route("/api/escalation_requests/:id/deny", post(handlers::api::deny_escalation_handler))
        
        // Unified Skill Registry (Phase 2)
        .route("/.well-known/skills.json", get(handlers::api::skills_registry_handler))
        .route("/api/tenant/current/audit/export", get(handlers::api::export_audit_events_handler))
        
        // Tenant management
        .route("/api/tenant/info", get(auth::get_tenant_info_handler))
        .route("/api/tenant/invite", post(auth::generate_tenant_invite_handler))
        
        .with_state(shared.clone())
        .layer(cors);

    // 12. Graceful Shutdown Token
    let cancel = CancellationToken::new();
    let cancel_for_signal = cancel.clone();

    // 13. Run Server
    let addr: std::net::SocketAddr = config.api_listen_url.parse().expect("Invalid api_listen_url provided in configuration");
    tracing::info!("🚀 Host listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    let shutdown_nats = shared.nats.clone();
    
    // Register Telegram Webhook if enabled
    let telegram_enabled = std::env::var("TELEGRAM_BOT_ENABLED").map(|v| v == "true").unwrap_or(false);
    if telegram_enabled {
        let token_wrapper = identity_context::load_secret("TELEGRAM_BOT_TOKEN");
        let token = token_wrapper.as_ref().map(|w| w.expose_secret().to_string()).unwrap_or_default();
        if let Ok(url) = std::env::var("TELEGRAM_WEBHOOK_URL") {
            if !token.is_empty() && token != "YOUR_TELEGRAM_BOT_TOKEN" && token != "your_telegram_bot_token" {
                let set_webhook_url = format!("https://api.telegram.org/bot{}/setWebhook", token);
                let payload = serde_json::json!({
                    "url": format!("{}/api/telegram/webhook", url)
                });
                tracing::info!("📞 Registering Telegram Webhook: {}/api/telegram/webhook", url);
                match shared.http_client.post(&set_webhook_url).json(&payload).send().await {
                    Ok(res) => if !res.status().is_success() {
                        tracing::warn!("⚠️ Failed to register Telegram Webhook: {}", res.status());
                    } else {
                        tracing::info!("✅ Telegram Webhook registered successfully.");
                    },
                    Err(e) => tracing::warn!("⚠️ Failed to reach Telegram API: {}", e),
                }
            } else {
                tracing::info!("ℹ️ Telegram bot is enabled but token is placeholder/empty. Skipping registration.");
            }
        }
    }

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

            tracing::info!("🛑 Shutdown signal received — stopping HTTP and signalling tasks...");
            cancel_for_signal.cancel();

            // Allow loops some time to process any remaining events
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            if let Some(nc) = shutdown_nats {
                tracing::info!("🔄 Flushing NATS connection before exit...");
                let _ = nc.flush().await;
            }
        })
        .await?;

    tracing::info!("✅ Host shutdown complete");

    Ok(())
}
