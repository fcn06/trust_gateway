//! Search MCP Service.
//!
//! Provides a tool to search the internet via DuckDuckGo Instant Answer API.

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};
use serde_json::json;

static DUCKDUCK_SEARCH_URL_PART1: &str = r#"https://api.duckduckgo.com/?q="#;
static DUCKDUCK_SEARCH_URL_PART2: &str = r#"&format=json"#;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SearchParams {
    #[schemars(description = "An entity (a person, a country, an animal) to search for")]
    pub search_query: String,
}

/// Search MCP service.
#[derive(Clone)]
pub struct SearchMcpService {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl SearchMcpService {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Search for an entity on the internet")]
    async fn vp_search(
        &self,
        params: Parameters<SearchParams>,
    ) -> Result<CallToolResult, McpError> {
        let search_query = &params.0.search_query;
        let duckduckgo_url = format!(
            "{}{}{}",
            DUCKDUCK_SEARCH_URL_PART1, search_query, DUCKDUCK_SEARCH_URL_PART2
        );

        let client = reqwest::Client::new();

        let response = client
            .get(&duckduckgo_url)
            .send()
            .await
            .map_err(|e| {
                McpError::invalid_request(
                    e.to_string(),
                    Some(json!({"messages": duckduckgo_url.to_string()})),
                )
            })?;

        let parsed_json_response: serde_json::Value =
            response.json().await.map_err(|e| {
                McpError::invalid_request(
                    e.to_string(),
                    Some(json!({"messages": duckduckgo_url.to_string()})),
                )
            })?;

        let extract_from_response =
            if let Some(extract_text) = parsed_json_response["Abstract"].as_str() {
                extract_text
            } else {
                "'Abstract' field not found or not a string."
            };

        let result = format!(
            "VP Search result for '{}' : '{}'",
            search_query, extract_from_response
        );

        Ok(CallToolResult::success(vec![Content::text(result)]))
    }
}

#[tool_handler]
impl ServerHandler for SearchMcpService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder()
                .enable_tools()
                .build())
            .with_instructions("This server provides a 'vp_search' function to search the internet.")
    }
}
