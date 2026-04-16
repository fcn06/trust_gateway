//! MCP Runtime providing a higher-level abstraction over MCP client.
//!
//! This module provides the `McpRuntime` struct that wraps an MCP client
//! with configuration-aware initialization and tool execution.

use anyhow::Result;
use configuration::McpRuntimeConfig;
use llm_api::chat::ToolCall;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, InitializeRequestParams,
    Implementation, ListToolsResult, Tool,
};

use crate::mcp_client::transport::{create_transport, McpClient};

/// Runtime wrapper for MCP client operations.
///
/// Provides a stateful wrapper around an MCP client that maintains
/// configuration and provides convenient methods for tool operations.
#[allow(dead_code)]
pub struct McpRuntime {
    agent_mcp_config: McpRuntimeConfig,
    client: McpClient,
}

impl McpRuntime {
    /// Initialize a new MCP runtime with the given configuration.
    ///
    /// # Arguments
    /// * `agent_mcp_config` - Configuration containing server URL and API key
    ///
    /// # Returns
    /// An initialized `McpRuntime` ready for tool operations
    pub async fn initialize_mcp_client_v2(
        agent_mcp_config: McpRuntimeConfig,
    ) -> anyhow::Result<Self> {
        let mcp_server_url_string = agent_mcp_config
            .agent_mcp_server_url
            .clone()
            .expect("Missing mcp server Url");
        let mcp_server_url = mcp_server_url_string.as_str();

        let api_key = agent_mcp_config.agent_mcp_server_api_key.clone();

        let transport = create_transport(mcp_server_url, api_key);

        let client_info = InitializeRequestParams::new(
            ClientCapabilities::default(),
            Implementation::new("tool execution client", "0.0.1"),
        );

        let client = rmcp::serve_client(client_info, transport).await?;

        Ok(Self {
            agent_mcp_config,
            client,
        })
    }

    /// Get a reference to the underlying MCP client.
    pub fn get_client(&self) -> anyhow::Result<&McpClient> {
        Ok(&self.client)
    }

    /// Get the list of available tools from the MCP server.
    pub async fn get_tools_list_v2(&self) -> anyhow::Result<Vec<Tool>> {
        let list_tools: ListToolsResult = self.client.list_tools(Default::default()).await?;
        Ok(list_tools.tools)
    }

    /// Execute a tool call against the MCP server.
    ///
    /// # Arguments
    /// * `tool_call` - The tool call to execute
    ///
    /// # Returns
    /// The result of the tool execution
    pub async fn execute_tool_call_v2(&self, tool_call: ToolCall) -> anyhow::Result<CallToolResult> {
        let args: Result<serde_json::Value, _> =
            serde_json::from_str(&tool_call.function.arguments);

        let tool_result = match args {
            Ok(parsed_args) => {
                self.client
                    .call_tool(CallToolRequestParams::new(tool_call.function.name.clone())
                        .with_arguments(parsed_args.as_object().cloned().unwrap_or_default()))
                    .await?
            }
            Err(e) => {
                tracing::error!(
                    "Failed to parse arguments for {}: {}",
                    tool_call.function.name,
                    e
                );
                CallToolResult::error(vec![])
            }
        };

        tracing::info!("Tool result: {tool_result:#?}");

        Ok(tool_result)
    }
}