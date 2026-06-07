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

/// Retrieve tools dynamically over NATS from the Trust Gateway (bundle-aware)
pub async fn get_tools_list_over_nats(
    nats_client: Arc<async_nats::Client>,
    dispatch_subject: &str,
    session_id: &str,
) -> anyhow::Result<Vec<Tool>> {
    let subject = if dispatch_subject.starts_with("trust.") {
        format!("{}.default.tools.list", dispatch_subject)
    } else {
        format!("{}.tools.list", dispatch_subject)
    };
    
    let payload = serde_json::json!({
        "session_id": session_id
    });
    
    let reply = nats_client.request(subject.clone(), serde_json::to_string(&payload)?.into()).await?;
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
/// The result of the tool execution
pub async fn execute_tool_call_v2(
    nats_client: Arc<async_nats::Client>,
    dispatch_subject: &str,
    tool_call: ToolCall,
    auth_data: Option<crate::SsiAuthenticationData>,
) -> anyhow::Result<CallToolResult> {
    let args: Result<serde_json::Value, _> = serde_json::from_str(&tool_call.function.arguments);
    let parsed_args = match args {
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

    // Construct the ProposeActionRequest payload for the Trust Gateway
    let tenant_id = auth_data.as_ref().and_then(|a| a.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let jwt = auth_data.as_ref().and_then(|a| a.jwt.clone()).unwrap_or_default();
    if jwt.is_empty() {
        tracing::warn!("⚠️ No JWT found in authentication data for tool call '{}'", tool_call.function.name);
    }
    
    let payload = serde_json::json!({
        "tenant_id": tenant_id.clone(),
        "requester_id": auth_data.as_ref().and_then(|a| a.tenant_id.clone()).unwrap_or_else(|| "default".to_string()),
        "source_type": "ssi_agent",
        "auth_method": "jwt",
        "auth_level": "tier1",
        "scopes": [],
        "tool_server": "trust_gateway",
        "tool_name": tool_call.function.name.clone(),
        "action_name": tool_call.function.name.clone(),
        "action_arguments": parsed_args.clone(),
        "payload": {
            "session_jwt": jwt,
            "action_name": tool_call.function.name,
            "arguments": parsed_args,
            "tenant_id": tenant_id.clone(),
            "source_type": "ssi_agent"
        }
    });

    // Subject format: trust.v1.<tenant>.action.propose
    let safe_tenant = tenant_id.replace(':', "_");
    let subject = if dispatch_subject.starts_with("trust.") {
        format!("{}.{}.action.propose", dispatch_subject, safe_tenant)
    } else {
        // Fallback for non-standard subjects
        format!("{}.{}.action.propose", dispatch_subject, safe_tenant)
    };
    
    tracing::info!("🚀 Publishing modern action proposal to NATS: {}", subject);
    
    let payload_bytes = serde_json::to_vec(&payload)?;

    match nats_client.request(subject, payload_bytes.into()).await {
        Ok(response) => {
            let gateway_response: serde_json::Value = serde_json::from_slice(&response.payload)?;
            
            // Check for gateway-level error (ensure it's not null)
            if let Some(err) = gateway_response.get("error").filter(|v| !v.is_null()) {
                tracing::error!("Trust Gateway error: {}", err);
                return Ok(CallToolResult::error(vec![
                    rmcp::model::Content::text(format!("Trust Gateway error: {}", err))
                ]));
            }

            let status = gateway_response.get("status").and_then(|v| v.as_str()).unwrap_or("failed");
            
            match status {
                "succeeded" => {
                    if let Some(result_val) = gateway_response.get("result") {
                        // Map the standardized gateway result (MCP content array) to CallToolResult
                        let call_result: CallToolResult = serde_json::from_value(result_val.clone())
                            .unwrap_or_else(|_| CallToolResult::success(vec![rmcp::model::Content::text(result_val.to_string())]));
                        Ok(call_result)
                    } else {
                        Ok(CallToolResult::success(vec![rmcp::model::Content::text("Action succeeded but returned no data.")]))
                    }
                }
                "pending_approval" | "pending_proof" => {
                    let approval_id = gateway_response.get("approval_id").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let escalation = gateway_response.get("escalation").and_then(|v| v.as_str()).unwrap_or("standard");
                    Ok(CallToolResult::success(vec![
                        rmcp::model::Content::text(format!(
                            "This action requires {} approval. Approval ID: {}. Please check the portal to approve.",
                            escalation, approval_id
                        ))
                    ]))
                }
                _ => {
                    tracing::error!("Action failed or rejected by Gateway: {}", status);
                    Ok(CallToolResult::error(vec![
                        rmcp::model::Content::text(format!("Action {} by Trust Gateway.", status))
                    ]))
                }
            }
        }
        Err(e) => {
            tracing::error!("NATS request to Gateway failed: {}", e);
            Ok(CallToolResult::error(vec![
                rmcp::model::Content::text(format!("NATS communication failure: {}", e))
            ]))
        }
    }
}