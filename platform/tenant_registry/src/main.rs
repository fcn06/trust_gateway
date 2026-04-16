//! Tenant Registry — Multi-tenant control plane for Agent-in-a-Box.
//!
//! Provides REST API for tenant lifecycle management:
//! - POST   /tenants          — Create tenant + provision NATS namespaces
//! - GET    /tenants          — List all tenants
//! - GET    /tenants/:id      — Get a specific tenant
//! - PATCH  /tenants/:id/tier — Update tenant tier (+ LLM policy)
//! - DELETE /tenants/:id      — Soft-delete tenant
//! - GET    /tenants/:id/policy — Get tenant's LLM policy

mod handlers;
mod models;
mod provisioner;
mod store;
mod audit_api;
mod anchoring;

use std::sync::Arc;

use async_nats::jetstream;
use async_nats::jetstream::kv::Store as KvStore;
use axum::{routing, Router};
use clap::Parser;
use tower_http::cors::{Any, CorsLayer};

use store::TenantStore;

/// Shared application state for all handlers.
pub struct AppState {
    pub store: TenantStore,
    pub js: jetstream::Context,
    pub llm_policy_store: KvStore,
    pub connections_kv: KvStore,
}

#[derive(Parser)]
#[command(name = "tenant-registry", about = "Multi-tenant control plane")]
struct Cli {
    /// NATS server URL
    #[arg(long, env = "NATS_URL", default_value = "nats://127.0.0.1:4222")]
    nats_url: String,

    /// HTTP listen address
    #[arg(long, default_value = "0.0.0.0:3010")]
    listen: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tenant_registry=info".into()),
        )
        .init();

    let cli = Cli::parse();

    tracing::info!("🔌 Connecting to NATS at {}", cli.nats_url);
    let nats = async_nats::connect(&cli.nats_url).await?;
    let js = jetstream::new(nats);

    // Create the tenant store (backed by NATS KV)
    let tenant_store = TenantStore::new(js.clone()).await?;

    // Create the LLM policy KV bucket
    let llm_policy_store = js
        .create_key_value(jetstream::kv::Config {
            bucket: "llm_policies".to_string(),
            description: "LLM routing policies per tenant".to_string(),
            history: 3,
            ..Default::default()
        })
        .await?;

    // Create the connections KV bucket for wallet connections
    let connections_kv = js
        .create_key_value(jetstream::kv::Config {
            bucket: "tenant_connections".to_string(),
            description: "Wallet connection records per tenant".to_string(),
            history: 1,
            ..Default::default()
        })
        .await?;

    let state = Arc::new(AppState {
        store: tenant_store,
        js,
        llm_policy_store,
        connections_kv,
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/tenants", routing::post(handlers::create_tenant))
        .route("/tenants", routing::get(handlers::list_tenants))
        .route("/tenants/{id}", routing::get(handlers::get_tenant))
        .route("/tenants/{id}/tier", routing::patch(handlers::update_tier))
        .route("/tenants/{id}", routing::delete(handlers::delete_tenant))
        .route(
            "/tenants/{id}/policy",
            routing::get(handlers::get_tenant_policy),
        )
        .route(
            "/api/tenant/{id}/audit/export",
            routing::get(audit_api::export_audit),
        )
        .route(
            "/api/tenant/{id}/metrics",
            routing::get(audit_api::get_metrics),
        )
        // Connection Model (V6): Wallet connection management
        .route(
            "/tenants/{id}/connections",
            routing::get(handlers::list_connections),
        )
        .route(
            "/tenants/{id}/connections",
            routing::post(handlers::create_connection),
        )
        .route(
            "/tenants/{id}/connections/{did}",
            routing::delete(handlers::revoke_connection),
        )
        .layer(cors)
        .with_state(state);

    tracing::info!("🏢 Tenant Registry listening on {}", cli.listen);
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
