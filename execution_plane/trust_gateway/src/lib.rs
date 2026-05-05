// ─────────────────────────────────────────────────────────────
// Trust Gateway — Library Crate
//
// Exposes the Trust Gateway as an embeddable library so that
// the professional/enterprise edition can import it from a
// separate private repository and inject its own components
// (e.g. SSI token validator, custom policy engines) without
// forking or modifying this codebase.
//
// ## Usage from Enterprise Binary
//
// ```rust,ignore
// use trust_gateway::auth::{TokenValidator, StandardJwtValidator};
// use trust_gateway::api::build_router;
// use trust_gateway::gateway::GatewayState;
//
// let state = GatewayState {
//     token_validator: Arc::new(MyEnterpriseValidator {
//         fallback: StandardJwtValidator,
//     }),
//     // ... other fields ...
// };
//
// let app = build_router(Arc::new(state));
// axum::serve(listener, app).await.unwrap();
// ```
// ─────────────────────────────────────────────────────────────

// Core modules — public API for enterprise consumers
pub mod auth;
pub mod vp_verifier;
pub mod api;
pub mod gateway;

// Internal modules — not exposed as public API
mod grant;
mod audit_sink;
mod normalizer;
mod audit_projector;
mod router;
pub mod oauth;
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
pub mod webhook_handler;
pub mod cron_scheduler;
