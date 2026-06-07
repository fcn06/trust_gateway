// ─────────────────────────────────────────────────────────────
// Standalone Tool Registry — Host-independent tool discovery
//
// Spec reference: §19
//
// Aggregates tool definitions directly from each executor
// when the Host is absent or as a supplementary source.
// ─────────────────────────────────────────────────────────────

use axum::{extract::State, response::{Json, IntoResponse}};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::gateway::GatewayState;

/// A unified tool definition from any executor backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Tool name (unique across all executors).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Which executor handles this tool.
    pub executor_type: String,
    /// JSON Schema for input arguments.
    pub input_schema: serde_json::Value,
    /// Optional category tag.
    pub category: Option<String>,
    /// Optional tags for filtering.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Risk hint for policy evaluation.
    pub risk_hint: Option<String>,
    /// Procedure type: "read", "write", "execute".
    pub procedure_type: Option<String>,
    /// Optional cron schedule string.
    pub cron: Option<String>,
}

/// Response from `GET /v1/tools/registry`.
#[derive(Debug, Serialize)]
pub struct RegistryResponse {
    /// When this registry snapshot was generated.
    pub generated_at: String,
    /// Sources that were aggregated.
    pub sources: Vec<String>,
    /// All discovered tools.
    pub tools: Vec<ToolDefinition>,
    /// Total count.
    pub total: usize,
}

pub async fn registry_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
) -> impl axum::response::IntoResponse {
    // Enforce Authentication
    if let Err(status) = state
        .token_validator
        .validate(&headers, &state.jwt_secret)
        .await
    {
        tracing::warn!(
            "🚫 /v1/tools/registry rejected: Authentication failed ({})",
            status
        );
        let mut response = status.into_response();
        if status == axum::http::StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer realm=\"trust_gateway\""),
            );
        }
        return response;
    }

    let mut tools = Vec::new();
    let mut sources = Vec::new();

    // Source 1: Existing ToolRegistry (Host skills.json + VP MCP)
    if let Some(ref registry) = state.tool_registry {
        registry
            .refresh_if_stale(
                &state.http_client,
                &state.connectors.host_url,
            )
            .await;

        for (name, entry) in registry.all_tools().await {
            tools.push(ToolDefinition {
                name,
                description: entry.description,
                executor_type: entry.executor_type,
                input_schema: entry.input_schema,
                category: entry.category,
                tags: vec![],
                risk_hint: None,
                procedure_type: None,
                cron: entry.cron.clone(),
            });
        }
        sources.push("host_skills_json".to_string());
        sources.push("vp_mcp_server".to_string());
    }

    // Future sources (Phase 2+):
    // - Direct connector MCP discovery
    // - Native skill executor listing
    // These will be added when ToolCatalogProvider trait is implemented.

    let total = tools.len();
    axum::response::IntoResponse::into_response(Json(RegistryResponse {
        generated_at: chrono::Utc::now().to_rfc3339(),
        sources,
        tools,
        total,
    }))
}
