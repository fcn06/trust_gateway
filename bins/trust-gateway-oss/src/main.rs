use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use trust_gateway_oss::*;

#[derive(Parser, Debug)]
#[command(author, version, about = "Sovereign Trust Gateway OSS Binary")]
struct Cli {
    #[arg(short, long, default_value = "lianxi_market.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let start_time = Instant::now();

    let cli = Cli::parse();
    let config_content = std::fs::read_to_string(&cli.config)
        .map_err(|e| anyhow::anyhow!("Failed to read config file {}: {e}", cli.config))?;

    let config: AppConfig = toml::from_str(&config_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse config: {e}"))?;

    let engine = build_engine_from_config(&config).await?;

    let state = Arc::new(AppState {
        engine,
        start_time,
        sse_sessions: Arc::new(RwLock::new(HashMap::new())),
    });

    let app = build_app(state, config.server.request_limit_bytes);

    let addr: SocketAddr = config
        .server
        .listen_addr
        .parse()
        .expect("listen_addr must be a valid socket address e.g. 127.0.0.1:8080");

    tracing::info!("Trust Gateway OSS listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("Shutting down gateway gracefully...");
        })
        .await?;

    Ok(())
}
