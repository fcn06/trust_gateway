//! OAuth Connector MCP Server — tenant-scoped third-party integrations.
//!
//! Provides MCP tool definitions for agent-accessible OAuth services:
//! - Google Calendar
//! - Stripe (payments)
//! - Shopify (orders/inventory)
//!
//! Each tool call passes through tenant-scoped OAuth token management,
//! ensuring tenant isolation of credentials and API access.

mod oauth;
mod token_store;
mod tools;

use async_nats::jetstream;
use axum::{routing, Router};
use clap::Parser;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "connector-mcp-server")]
struct Cli {
    /// NATS server URL
    #[arg(long, env = "NATS_URL", default_value = "nats://127.0.0.1:4222")]
    nats_url: String,

    /// Listen address
    #[arg(long, env = "CONNECTOR_LISTEN", default_value = "0.0.0.0:3050")]
    listen: String,

    /// Google OAuth client ID
    #[arg(long, env = "GOOGLE_CLIENT_ID", default_value = "")]
    google_client_id: String,

    /// Google OAuth client secret
    #[arg(long, env = "GOOGLE_CLIENT_SECRET", default_value = "")]
    google_client_secret: String,
}

pub struct AppState {
    pub js: jetstream::Context,
    pub nats: async_nats::Client,
    pub token_store: token_store::TokenStore,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub http_client: reqwest::Client,
    /// Grant validator for ExecutionGrant JWTs from the Trust Gateway.
    /// Initialized from GRANT_SIGNING_SECRET (HMAC) or GRANT_ED25519_PUB_PEM (Ed25519).
    pub grant_validator: Option<tools::GrantValidator>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    tracing::info!("🔌 Connector MCP Server starting...");

    let mut nats_options = async_nats::ConnectOptions::new();
    if let Ok(seed) = std::env::var("NATS_NKEY_SEED") {
        nats_options = async_nats::ConnectOptions::with_nkey(seed);
    }
    let nats = async_nats::connect_with_options(&cli.nats_url, nats_options).await?;
    let js = jetstream::new(nats.clone());

    let token_store = token_store::TokenStore::new(js.clone()).await?;

    let http_client = reqwest::Client::builder()
        .pool_max_idle_per_host(10)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // Initialize GrantValidator from environment
    // Priority: Ed25519 PEM inline → Ed25519 PEM file → HMAC secret → JWT_SECRET (legacy)
    let grant_validator = if let Ok(pem) = std::env::var("GRANT_ED25519_PUB_PEM") {
        // Option 1: Inline PEM content in env var
        match tools::GrantValidator::from_ed25519_pem(&pem) {
            Ok(v) => {
                tracing::info!("✅ Grant validation: Ed25519 (inline PEM)");
                Some(v)
            }
            Err(e) => {
                tracing::warn!(
                    "⚠️ Failed to load Ed25519 public key from GRANT_ED25519_PUB_PEM: {}",
                    e
                );
                None
            }
        }
    } else if let Ok(key_path) = std::env::var("GRANT_VERIFY_KEY_PATH") {
        // Option 2: Ed25519 public key file path (matches native_skill_executor pattern)
        match std::fs::read_to_string(&key_path) {
            Ok(pem) => match tools::GrantValidator::from_ed25519_pem(pem.trim()) {
                Ok(v) => {
                    tracing::info!("✅ Grant validation: Ed25519 (file: {})", key_path);
                    Some(v)
                }
                Err(e) => {
                    tracing::warn!("⚠️ Failed to parse Ed25519 key from '{}': {}", key_path, e);
                    None
                }
            },
            Err(e) => {
                tracing::warn!("⚠️ Cannot read GRANT_VERIFY_KEY_PATH '{}': {}", key_path, e);
                None
            }
        }
    } else if let Ok(secret) = std::env::var("GRANT_SIGNING_SECRET") {
        tracing::info!("✅ Grant validation: HMAC-HS256 (GRANT_SIGNING_SECRET)");
        Some(tools::GrantValidator::from_hmac_secret(&secret))
    } else if let Ok(secret) = std::env::var("JWT_SECRET") {
        // Legacy fallback: shared JWT_SECRET used by trust_gateway for HMAC signing
        tracing::info!("✅ Grant validation: HMAC-HS256 (JWT_SECRET legacy fallback)");
        Some(tools::GrantValidator::from_hmac_secret(&secret))
    } else {
        tracing::warn!("⚠️ No grant signing key configured — ExecutionGrant validation disabled");
        None
    };

    let state = Arc::new(AppState {
        js,
        nats,
        token_store,
        google_client_id: cli.google_client_id,
        google_client_secret: cli.google_client_secret,
        http_client,
        grant_validator,
    });

    let cors = tower_http::cors::CorsLayer::permissive();

    let app = Router::new()
        .route("/health", routing::get(|| async { "OK" }))
        // OAuth flow endpoints
        .route(
            "/oauth/google/authorize/{tenant_id}",
            routing::get(oauth::google_authorize),
        )
        .route(
            "/oauth/google/callback",
            routing::get(oauth::google_callback),
        )
        .route(
            "/oauth/status/{tenant_id}",
            routing::get(oauth::integration_status),
        )
        // MCP tool endpoints (called by ssi_agent via NATS bridge)
        .route("/tools/list", routing::get(tools::list_tools))
        .route("/tools/execute", routing::post(tools::execute_tool))
        .layer(cors)
        .with_state(state);

    let addr: std::net::SocketAddr = cli.listen.parse()?;
    tracing::info!("🚀 Connector MCP Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
