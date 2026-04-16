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
mod tools;
mod token_store;

use std::sync::Arc;
use axum::{routing, Router};
use clap::Parser;
use async_nats::jetstream;

#[derive(Parser, Debug)]
#[command(name = "connector-mcp-server")]
struct Cli {
    /// NATS server URL
    #[arg(long, env = "NATS_URL", default_value = "nats://127.0.0.1:4222")]
    nats_url: String,

    /// Listen address
    #[arg(long, default_value = "0.0.0.0:3050")]
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    tracing::info!("🔌 Connector MCP Server starting...");

    let nats = async_nats::connect(&cli.nats_url).await?;
    let js = jetstream::new(nats.clone());

    let token_store = token_store::TokenStore::new(js.clone()).await?;

    let state = Arc::new(AppState {
        js,
        nats,
        token_store,
        google_client_id: cli.google_client_id,
        google_client_secret: cli.google_client_secret,
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
        .route(
            "/tools/list",
            routing::get(tools::list_tools),
        )
        .route(
            "/tools/execute",
            routing::post(tools::execute_tool),
        )
        .layer(cors)
        .with_state(state);

    let addr: std::net::SocketAddr = cli.listen.parse()?;
    tracing::info!("🚀 Connector MCP Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
