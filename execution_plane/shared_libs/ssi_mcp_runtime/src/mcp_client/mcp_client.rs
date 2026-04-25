//! MCP Client implementation for tool execution.
//!
//! Provides functions to initialize MCP clients and execute tool calls
//! against an MCP server.

use anyhow::Result;
use configuration::McpRuntimeConfig;
use llm_api::chat::ToolCall;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, InitializeRequestParams,
    Implementation, ListToolsResult, Tool,
};
use std::sync::Arc;

use crate::mcp_client::transport::{create_transport, McpClient};

/// Initializes the MCP client and connects to the server.
///
/// # Arguments
/// * `agent_mcp_config` - Configuration containing server URL and API key
///
/// # Returns
/// An initialized `McpClient` ready for tool calls
pub async fn initialize_mcp_client_v2(
    agent_mcp_config: McpRuntimeConfig,
    client: reqwest::Client,
) -> anyhow::Result<McpClient> {
    let mcp_server_url_string = agent_mcp_config
        .agent_mcp_server_url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing mcp server Url"))?;
    let mcp_server_url = mcp_server_url_string.as_str();

    let api_key = agent_mcp_config.agent_mcp_server_api_key.clone();

    let transport = create_transport(mcp_server_url, api_key, client);

    let client_info = InitializeRequestParams::new(
        ClientCapabilities::default(),
        Implementation::new("tool execution client", "0.0.1"),
    );

    let client = rmcp::serve_client(client_info, transport).await?;

    Ok(client)
}

/// Get the list of available tools from the MCP server.
///
/// # Arguments
/// * `client` - An Arc reference to the initialized MCP client
///
/// # Returns
/// A vector of `Tool` definitions from the server
pub async fn get_tools_list_v2(client: Arc<McpClient>) -> anyhow::Result<Vec<Tool>> {
    let list_tools: ListToolsResult = client.list_tools(Default::default()).await?;
    Ok(list_tools.tools)
}

/// Retrieve tools dynamically over NATS from mcp_nats_bridge
pub async fn get_tools_list_over_nats(
    nats_client: Arc<async_nats::Client>,
    dispatch_subject: &str,
) -> anyhow::Result<Vec<Tool>> {
    let subject = format!("{}.list_tools", dispatch_subject);
    let reply = nats_client.request(subject, "".into()).await?;
    let response: serde_json::Value = serde_json::from_slice(&reply.payload)?;
    
    // Determine the tools array from various response formats
    let tools_value = if let Some(tools_array) = response.get("tools") {
        tools_array.clone()
    } else if response.is_array() {
        response
    } else if let Some(err) = response.get("error") {
        anyhow::bail!("Bridge error: {}", err)
    } else {
        tracing::warn!("Unexpected list_tools response format, returning empty tools");
        return Ok(vec![]);
    };

    // Manually construct Tool objects to handle both snake_case and camelCase field names
    let empty_vec = vec![];
    let items = tools_value.as_array().unwrap_or(&empty_vec);
    let mut tools = Vec::new();
    for item in items {
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let description = item.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
        // Handle both "input_schema" (connector format) and "inputSchema" (MCP format)
        let schema = item.get("inputSchema")
            .or_else(|| item.get("input_schema"))
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        
        if !name.is_empty() {
            tools.push(Tool::new_with_raw(name, Some(description.into()), schema));
        }
    }
    
    tracing::info!("📦 Loaded {} tools over NATS", tools.len());
    Ok(tools)
}

/// Execute a tool call against the MCP server.
///
/// # Arguments
/// * `client` - An Arc reference to the initialized MCP client
/// * `tool_call` - The tool call to execute
/// * `auth_data` - Optional SSI authentication data to inject into the call
///
/// # Returns
/// The result of the tool execution
pub async fn execute_tool_call_v2(
    nats_client: Arc<async_nats::Client>,
    dispatch_subject: &str,
    tool_call: ToolCall,
    auth_data: Option<crate::SsiAuthenticationData>,
) -> anyhow::Result<CallToolResult> {
    let args: Result<serde_json::Value, _> = serde_json::from_str(&tool_call.function.arguments);
    let mut parsed_args = match args {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to parse arguments for {}: {}", tool_call.function.name, e);
            return Ok(CallToolResult::error(vec![
                rmcp::model::Content::text(format!(
                    "Failed to parse tool arguments: {}", e
                ))
            ]));
        }
    };

    if let Some(auth) = auth_data {
        if let Some(map) = parsed_args.as_object_mut() {
            let mut meta_fields = serde_json::Map::new();
            if let Some(env) = auth.x_envelope {
                meta_fields.insert("X-Envelope".to_string(), serde_json::Value::String(env));
            }
            if let Some(inst) = auth.x_instruction {
                meta_fields.insert("X-Instruction".to_string(), serde_json::Value::String(inst));
            }
            if let Some(jwt) = auth.jwt {
                meta_fields.insert("X-Session-JWT".to_string(), serde_json::Value::String(jwt));
            }
            if let Some(tid) = auth.tenant_id {
                meta_fields.insert("X-Tenant-ID".to_string(), serde_json::Value::String(tid));
            }
            map.insert("_meta".to_string(), serde_json::Value::Object(meta_fields));
        }
    }

    let payload = serde_json::json!({
        "tool_name": tool_call.function.name,
        "arguments": parsed_args,
        "verified_did": "", // WS-A3: DID is resolved from JWT `iss` claim by the trust_gateway
        "original_request": {}
    });

    let subject = format!("{}.{}", dispatch_subject, tool_call.function.name);
    tracing::info!("Publishing tool call to NATS: {}", subject);
    
    let payload_bytes = serde_json::to_vec(&payload)?;

    match nats_client.request(subject, payload_bytes.into()).await {
        Ok(response) => {
            let bridge_response: serde_json::Value = serde_json::from_slice(&response.payload)?;
            if let Some(res) = bridge_response.get("result") {
                let call_result: CallToolResult = serde_json::from_value(res.clone())?;
                tracing::info!("Tool result from NATS: {call_result:#?}");
                Ok(call_result)
            } else if let Some(err) = bridge_response.get("error") {
                tracing::error!("Bridge error: {}", err);
                Ok(CallToolResult::error(vec![
                    rmcp::model::Content::text(format!(
                        "Bridge error: {}", err
                    ))
                ]))
            } else {
                tracing::error!("Unexpected response format from NATS bridge: {:?}", bridge_response);
                Ok(CallToolResult::error(vec![
                    rmcp::model::Content::text(format!(
                        "Unexpected response format from NATS bridge: {:?}", bridge_response
                    ))
                ]))
            }
        }
        Err(e) => {
            tracing::error!("NATS request failed: {}", e);
            Ok(CallToolResult::error(vec![
                rmcp::model::Content::text(format!(
                    "NATS request failed: {}", e
                ))
            ]))
        }
    }
}