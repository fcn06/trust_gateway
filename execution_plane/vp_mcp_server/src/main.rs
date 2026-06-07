//! Agent MCP Server.
//!
//! A standalone MCP server providing weather and search tools, protected by SSI delegation.

use axum::http::Method;
use axum::{middleware, response::Html, routing::get, Router};
use clap::Parser;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use std::{net::SocketAddr, time::Duration};
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, Level};
use tracing_subscriber::{filter, fmt, layer::SubscriberExt, Layer, Registry};

mod services;
mod ssi;
mod grant_validator;

// Replaced by claw like weather tool
use services::weather::WeatherMcpService;

use ssi::middleware::ssi_delegation_middleware;

use config::{Config as ConfigLoader, File};
use serde::Deserialize;

/// Server Configuration
#[derive(Debug, Deserialize)]
struct ServerConfig {
    host: String,
    port: u16,
    sse_path: String,
    message_path: String,
    disable_auth: Option<bool>,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Log level (trace, debug, info, warn, error)
    #[clap(long, default_value = "info")]
    log_level: String,
}

async fn index() -> Html<&'static str> {
    Html("<h1>Agent MCP Server</h1><p>Running with weather and search tools.</p>")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Attempt to load .env from workspace root
    dotenvy::dotenv().ok();

    // Load configuration
    let config = ConfigLoader::builder()
        .add_source(File::with_name("config"))
        .build()?;

    let server_config: ServerConfig = config.try_deserialize()?;

    // Setting proper log level
    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = Registry::default().with(
        fmt::layer()
            .compact()
            .with_ansi(true)
            .with_filter(filter::LevelFilter::from_level(log_level)),
    );

    tracing::subscriber::set_global_default(subscriber).unwrap();

    let bind_address = format!("{}:{}", server_config.host, server_config.port);
    let addr: SocketAddr = bind_address.parse()?;
    info!("Agent MCP Server starting on {}", bind_address);

    let cancel_token = CancellationToken::new();

    // Create StreamableHttp server configuration (rmcp 1.3)
    let sse_config = StreamableHttpServerConfig::default()
        .with_sse_keep_alive(Some(Duration::from_secs(15)))
        .with_cancellation_token(cancel_token.clone());

    // Create session manager (in-memory, local)
    let session_manager = std::sync::Arc::new(LocalSessionManager::default());

    // Create the StreamableHttp service with the search MCP service factory
    let service = StreamableHttpService::new(
        || Ok(crate::services::search::SearchMcpService::new()),
        session_manager,
        sse_config,
    );

    // Build the main Axum application
    let mut app = Router::new().route("/", get(index));

    // Mount the MCP service at the configured paths (supports GET, POST, DELETE)
    app = app.route(
        &server_config.sse_path,
        axum::routing::any(move |req: axum::extract::Request| {
            let svc = service.clone();
            async move { svc.handle(req).await }
        }),
    );

    // Apply SSI delegation middleware if auth is enabled
    if !server_config.disable_auth.unwrap_or(false) {
        app = app.layer(middleware::from_fn(ssi_delegation_middleware));
    }

    // Initialize GrantValidator
    let grant_validator = if let Ok(key_path) = std::env::var("GRANT_VERIFY_KEY_PATH") {
        match std::fs::read_to_string(&key_path) {
            Ok(pem) => match grant_validator::GrantValidator::from_ed25519_pem(pem.trim()) {
                Ok(v) => {
                    info!("✅ Grant validation: Ed25519 (file: {})", key_path);
                    Some(std::sync::Arc::new(v))
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
        info!("✅ Grant validation: HMAC-HS256 (GRANT_SIGNING_SECRET)");
        Some(std::sync::Arc::new(grant_validator::GrantValidator::from_hmac_secret(&secret)))
    } else if let Ok(secret) = std::env::var("JWT_SECRET") {
        info!("✅ Grant validation: HMAC-HS256 (JWT_SECRET legacy fallback)");
        Some(std::sync::Arc::new(grant_validator::GrantValidator::from_hmac_secret(&secret)))
    } else {
        tracing::warn!("⚠️ No grant signing key configured — ExecutionGrant validation disabled");
        None
    };

    if let Some(validator) = grant_validator {
        app = app.layer(axum::Extension(validator));
    }

    let app = app.layer(
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers(Any),
    );

    // Start the server
    info!("Agent MCP Server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    let shutdown_token = cancel_token.clone();

    // NOTE: Escalation policy and NATS client removed (2026-05-06).
    // The Trust Gateway's approval_daemon is the sole authority for
    // tool escalation. This server is a pure executor.
    let app = app;

    let server_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown_token.cancelled().await;
                info!("Server received shutdown signal");
            })
            .await
        {
            error!("Server error: {}", e);
        }
    });

    // Handle Ctrl+C
    tokio::select! {
        res = tokio::signal::ctrl_c() => {
            match res {
                Ok(()) => info!("Received Ctrl+C, shutting down"),
                Err(e) => error!("Failed to listen for Ctrl+C: {}", e),
            }
        }
        _ = server_handle => {
            info!("Server stopped");
        }
    }

    cancel_token.cancel();
    Ok(())
}
