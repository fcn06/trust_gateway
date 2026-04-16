//! Weather MCP Service.
//!
//! Provides a tool to get current weather for a given location.

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};
use serde_json::json;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct WeatherParams {
    #[schemars(description = "Location for which you desire to know weather")]
    pub location: String,
    #[schemars(description = "Temperature unit to use. You can specify Celsius or Fahrenheit")]
    pub unit: Option<String>,
}

/// Weather MCP service.
#[derive(Clone)]
pub struct WeatherMcpService {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl WeatherMcpService {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    // #[tool(description = "Get the current weather in a given location")]
    #[allow(dead_code)]
    async fn get_current_weather(
        &self,
        params: Parameters<WeatherParams>,
    ) -> Result<CallToolResult, McpError> {
        let _location = &params.0.location;
        let unit = params
            .0
            .unit
            .unwrap_or_else(|| "Celsius".to_string());

        let result_value = json!({
            "temperature": "24",
            "unit": unit,
            "description": "Sunny"
        });

        Ok(CallToolResult::success(vec![Content::text(
            result_value.to_string(),
        )]))
    }
}

#[tool_handler]
impl ServerHandler for WeatherMcpService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder()
                .enable_prompts()
                .enable_resources()
                .enable_tools()
                .build())
            .with_instructions("This server provides a function 'get_current_weather' to retrieve weather from a specific location.")
    }
}
