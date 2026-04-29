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

// === Modular Architecture Modules ===
pub mod commands;
pub mod shared_state;
pub mod dto;
pub mod handlers; // Contains api.rs
pub mod registry;
pub mod logic;
pub mod auth;
pub mod loops;
pub mod linker;
pub mod init;
pub mod audit;
pub mod bindings;

// Re-exports
use commands::{VaultCommand, AclCommand};
use dto::IncomingMessage;
use shared_state::{WebauthnSharedState, CliArgs};

// Top-level `bindgen!` generates the `crate::sovereign` module required by
// `handlers/api.rs`, `logic.rs`, etc. for shared WIT types (e.g. `Permission`,
// `ConnectionPolicy`). Component-specific bindgen calls live in `bindings.rs`.

wasmtime::component::bindgen!({
    interfaces: "
        import sovereign:gateway/vault;
        import sovereign:gateway/identity;
        import sovereign:gateway/messaging-sender;
        import sovereign:gateway/messaging-handler;
        import sovereign:gateway/acl;
        import sovereign:gateway/persistence;
        import sovereign:gateway/delegation;
        import sovereign:gateway/mls-session;
        import sovereign:gateway/contact-store;
        import sovereign:gateway/http-egress;
    ",
    path: "../wit",
    async: true,
    additional_derives: [serde::Serialize, serde::Deserialize],
});

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. CLI Args & Config
    let args = CliArgs::parse();
    let mut config = init::load_config()?;
    
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

    // 3. Load Keys
    let keys = init::load_server_keys()?;
    let jwt_key = jwt_simple::prelude::HS256Key::from_bytes(&keys.jwt_key_bytes);


    // 4. Setup WebAuthn
    let webauthn = init::setup_webauthn(&config)?;

    let (vault_cmd_tx, vault_cmd_rx) = mpsc::channel(100);

    let (acl_cmd_tx, acl_cmd_rx) = mpsc::channel(100);

    // Messaging channels — only active in Professional/Enterprise builds
    #[cfg(feature = "messaging")]
    let (messaging_cmd_tx, messaging_cmd_rx) = mpsc::channel(100);
    #[cfg(not(feature = "messaging"))]
    let (messaging_cmd_tx, _messaging_cmd_rx) = mpsc::channel::<IncomingMessage>(1);

    #[cfg(feature = "messaging")]
    let (mls_cmd_tx, _mls_cmd_rx) = mpsc::channel(100);
    #[cfg(not(feature = "messaging"))]
    let (mls_cmd_tx, _mls_cmd_rx_stub) = mpsc::channel::<commands::MlsSessionCommand>(1);

    #[cfg(feature = "messaging")]
    let (contact_cmd_tx, contact_cmd_rx) = mpsc::channel(100);
    #[cfg(not(feature = "messaging"))]
    let (contact_cmd_tx, _contact_cmd_rx_stub) = mpsc::channel::<commands::ContactStoreCommand>(1);

    // Create a shared HTTP client with connection pooling
    let http_client = reqwest::Client::builder()
        .pool_max_idle_per_host(10)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("Failed to build HTTP client");

    // 6. Shared State
    let shared = Arc::new(WebauthnSharedState {
        registration_sessions: RwLock::new(HashMap::new()),
        authentication_sessions: RwLock::new(HashMap::new()),
        user_credentials: RwLock::new(HashMap::new()),
        vault_cmd_tx: vault_cmd_tx.clone(),
        messaging_cmd_tx: messaging_cmd_tx.clone(),
        acl_cmd_tx: acl_cmd_tx.clone(),

        mls_cmd_tx: mls_cmd_tx.clone(),
        contact_cmd_tx: contact_cmd_tx.clone(),
        nats: Some(nc.clone()),
        webauthn,
        kv_stores: Some(kv_stores.clone()),
        jwt_key,
        config: config.clone(),
        active_subscriptions: RwLock::new(HashSet::new()),
        target_id_map: RwLock::new(HashMap::new()),
        portal_id_map: RwLock::new(HashMap::new()),
        house_salt: keys.house_salt,
        gateway_url: config.gateway_url.clone(),
        connections_kv: kv_stores.get("tenant_connections").cloned().expect("Connections KV missing"),
        oid4vp_client_id: std::env::var("OID4VP_CLIENT_ID")
            .unwrap_or_else(|_| "did:web:example.com".to_string()),
        oid4vp_rsa_pem: std::env::var("OID4VP_RSA_PEM")
            .unwrap_or_default()
            .replace("\\n", "\n"),
        active_conversations: RwLock::new(HashMap::new()),
        http_client,
    });

    // 7. Wasm Engine & Linker
    let mut wasm_config = Config::new();
    wasm_config.wasm_component_model(true);
    wasm_config.async_support(true);
    let engine = Engine::new(&wasm_config)?;

    tracing::info!("🔗 Configuring Linker...");
    let mut linker = linker::setup_linker(&engine).await?;

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
        #[cfg(feature = "messaging")]
        let components = vec!["ssi_vault", "messaging_service", "acl_store", "mls_session", "contact_store"];
        #[cfg(not(feature = "messaging"))]
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

    #[cfg(feature = "messaging")]
    let messaging_comp = component_registry.get("messaging_service").cloned();
    let acl_comp = component_registry.require("acl_store").clone();
    #[cfg(feature = "messaging")]
    let contact_comp = component_registry.get("contact_store").cloned();

    // 9. Spawn Loops (Logic separated per component)
    tracing::info!("🏁 Spawning independent command loop tasks...");

    // Specialized linkers for Vault/ACL (persistence binding)
    let vault_linker = linker::create_specialized_linker(&linker, |s| s.vault_store.clone()).await?;
    let acl_linker = linker::create_specialized_linker(&linker, |s| s.acl_store.clone()).await?;
    // Generic linker for others
    let generic_linker = linker.clone();

    loops::spawn_vault_loop(engine.clone(), shared.clone(), vault_comp, vault_linker, vault_cmd_rx);
    loops::spawn_acl_loop(engine.clone(), shared.clone(), acl_comp, acl_linker, acl_cmd_rx);


    #[cfg(feature = "messaging")]
    if let Some(comp) = messaging_comp {
        loops::spawn_messaging_loop(engine.clone(), shared.clone(), comp, generic_linker.clone(), messaging_cmd_rx, profile);
    } else {
        tracing::warn!("⚠️ messaging_service component not found — messaging features disabled");
    }

    // Contact Store loop (optional — logs warning if component not compiled)
    #[cfg(feature = "messaging")]
    if let Some(cc) = contact_comp {
        let contact_linker = linker::create_specialized_linker(&linker, |s| {
            s.shared.kv_stores.as_ref().and_then(|m| m.get("contact_store").cloned())
        }).await?;
        loops::spawn_contact_store_loop(engine.clone(), shared.clone(), cc, contact_linker, contact_cmd_rx);
    } else {
        #[cfg(feature = "messaging")]
        tracing::warn!("⚠️ contact_store component not found — contact store features disabled");
    }

    // 10. Global Subscriptions
    tracing::info!("🔄 Restoring global subscriptions...");
    #[cfg(feature = "messaging")]
    auth::subscribe_to_global_logins(shared.clone()).await;
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
        .route("/recovery/config", post(auth::set_recovery_config_handler))
        .route("/link/remote", post(auth::link_remote_access_handler))
        .route("/handshake/status/:thid", get(auth::check_handshake_status_handler));

    let app = Router::new()
        .route("/api/link-remote", post(auth::link_remote_access_handler))
        .route("/api/recovery", post(auth::set_recovery_config_handler))
        .nest("/api/webauthn", auth_routes)
        .route("/api/identities", post(handlers::api::create_identity_handler).get(handlers::api::list_identities_handler))
        .route("/api/identities/generate_did_web", post(handlers::api::generate_did_web_handler))
        .route("/api/identities/publish", post(handlers::api::publish_identity_handler))
        .route("/api/identities/enrich", post(handlers::api::enrich_identity_handler))
        .route("/api/invitations/generate", get(handlers::api::generate_invitation_handler))
        .route("/api/gateway/register", post(handlers::api::register_gateway_did_handler));
        
    // Messaging routes — only available in Professional/Enterprise builds
    #[cfg(feature = "messaging")]
    let app = app
        .route("/api/messaging/send", post(handlers::api::send_message_handler))
        .route("/api/messaging/send_ledgerless", post(handlers::api::send_ledgerless_request_handler))
        .route("/api/messaging/messages", get(handlers::api::get_messages_handler))
        .route("/api/invitations/accept", post(handlers::api::accept_invitation_handler))
        // Contact Requests
        .route("/api/contact_requests", get(handlers::api::get_contact_requests_handler))
        .route("/api/contact_requests/:id/accept", post(handlers::api::accept_contact_request_handler))
        .route("/api/contact_requests/:id/refuse", post(handlers::api::refuse_contact_request_handler))
        // Protocol Routes
        .route("/didcomm/messaging/:subject", post(handlers::api::receive_didcomm_http_wrapper));

    // Non-messaging routes continue for all editions
    #[cfg(not(feature = "messaging"))]
    let app = app
        .route("/api/invitations/accept", post(handlers::api::accept_invitation_handler));

    let app = app
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
        
        // Restaurant proxy (authenticated customer portal → restaurant_state_service)
        .route("/api/restaurant/invoke", post(handlers::api::restaurant_invoke_handler))
        .route("/api/restaurant/menu", get(handlers::api::restaurant_menu_handler))
        
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
