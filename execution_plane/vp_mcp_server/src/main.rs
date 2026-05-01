//! Agent MCP Server.
//!
//! A standalone MCP server providing weather and search tools, protected by SSI delegation.

use axum::{middleware, response::Html, routing::get, Router};
use clap::Parser;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager};
use std::{net::SocketAddr, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, Level};
use tracing_subscriber::{filter, fmt, layer::SubscriberExt, Layer, Registry};
use tower_http::cors::{CorsLayer, Any};
use axum::http::Method;

mod services;
mod ssi;

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
    /// Path to the escalation policy JSON file
    #[serde(default = "default_policy_path")]
    policy_path: String,
}

fn default_policy_path() -> String {
    "../../agents/ssi_agent/configuration/policy.json".to_string()
}

/// Escalation policy loaded from policy.json.
#[derive(Debug, Clone, Deserialize)]
pub struct EscalationPolicy {
    #[serde(default)]
    pub description: String,
    pub safe_tools: Vec<String>,
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
    let mut app = Router::new()
        .route("/", get(index));

    // Mount the MCP service at the configured paths (supports GET, POST, DELETE)
    app = app.route(&server_config.sse_path, axum::routing::any(move |req: axum::extract::Request| {
        let svc = service.clone();
        async move {
            svc.handle(req).await
        }
    }));

    // Apply SSI delegation middleware if auth is enabled
    if !server_config.disable_auth.unwrap_or(false) {
        app = app.layer(middleware::from_fn(ssi_delegation_middleware));
    }

    let app = app.layer(
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers(Any),
    );

    // Connect to NATS
    let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let nats_client = async_nats::connect(&nats_url).await?;
    info!("Connected to NATS ({}) for escalation routing", nats_url);

    // Start the server
    info!("Agent MCP Server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    let shutdown_token = cancel_token.clone();
    
    // Load escalation policy from policy.json
    let policy = match std::fs::read_to_string(&server_config.policy_path) {
        Ok(contents) => {
            match serde_json::from_str::<EscalationPolicy>(&contents) {
                Ok(p) => {
                    info!("✅ Loaded escalation policy from '{}' ({} safe tools)", server_config.policy_path, p.safe_tools.len());
                    for tool in &p.safe_tools {
                        info!("   🟢 Safe: {}", tool);
                    }
                    p
                }
                Err(e) => {
                    error!("❌ Failed to parse policy file '{}': {}. Using empty safe list.", server_config.policy_path, e);
                    EscalationPolicy { description: String::new(), safe_tools: vec![] }
                }
            }
        }
        Err(e) => {
            error!("⚠️ Could not read policy file '{}': {}. Using empty safe list (all tools require escalation).", server_config.policy_path, e);
            EscalationPolicy { description: String::new(), safe_tools: vec![] }
        }
    };

    // We pass both the nats_client and the policy to the middleware via Extension.
    let app = app
        .layer(axum::extract::Extension(nats_client))
        .layer(axum::extract::Extension(std::sync::Arc::new(policy)));

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
