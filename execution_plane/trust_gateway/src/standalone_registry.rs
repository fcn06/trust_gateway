// ─────────────────────────────────────────────────────────────
// Standalone Tool Registry — Host-independent tool discovery
//
// Spec reference: §19
//
// Aggregates tool definitions directly from each executor
// when the Host is absent or as a supplementary source.
// ─────────────────────────────────────────────────────────────

use std::sync::Arc;
use axum::{extract::State, response::Json};
use serde::{Deserialize, Serialize};

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

/// Handler for `GET /v1/tools/registry`.
///
/// Returns a unified view of all available tools, aggregated from
/// the existing ToolRegistry (which already sources from Host + VP MCP).
pub async fn registry_handler(
    State(state): State<Arc<GatewayState>>,
) -> Json<RegistryResponse> {
    let mut tools = Vec::new();
    let mut sources = Vec::new();

    // Source 1: Existing ToolRegistry (Host skills.json + VP MCP)
    if let Some(ref registry) = state.tool_registry {
        registry
            .refresh_if_stale(&state.http_client, &state.host_url, &state.vp_mcp_url)
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
    Json(RegistryResponse {
        generated_at: chrono::Utc::now().to_rfc3339(),
        sources,
        tools,
        total,
    })
}
