//! MCP NATS Bridge
//!
//! This binary subscribes to NATS subject `mcp.v1.dispatch.>` and forwards
//! MCP tool calls to external MCP servers via SSE using `ssi_mcp_runtime`.
//!
//! ## Escalation Policy
//! Tools are checked against a `policy.json` file that defines which tools
//! are "safe" (can execute without user approval). Any tool NOT in the safe
//! list triggers the escalation flow, requiring explicit user approval via
//! the Local SSI Portal before execution proceeds.

use anyhow::{Context, Result};
use clap::Parser;
use futures::StreamExt;
use serde::{Deserialize, Serialize};

use std::sync::Arc;

use rmcp::model::{CallToolRequestParams, CallToolResult};
use ssi_mcp_runtime::mcp_client::mcp_client::initialize_mcp_client_v2;

/// Payload received from the host's gatekeeper
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DispatchPayload {
    tool_name: String,
    arguments: serde_json::Value,
    verified_did: String,
    #[serde(default)]
    original_request: serde_json::Value,
}

/// Escalation policy loaded from `policy.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EscalationPolicy {
    #[serde(default)]
    description: String,
    /// Tools in this list can execute without user approval.
    /// Any tool NOT in this list requires escalation.
    safe_tools: Vec<String>,
}

impl EscalationPolicy {
    fn load(path: &str) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read policy file: {}", path))?;
        let policy: Self = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse policy file: {}", path))?;
        Ok(policy)
    }

    fn is_safe(&self, tool_name: &str) -> bool {
        self.safe_tools.iter().any(|t| t == tool_name)
    }
}

#[derive(Parser, Debug)]
#[command(name = "mcp_nats_bridge")]
#[command(about = "Bridges NATS MCP dispatch requests to external MCP servers via SSE")]
struct Args {
    /// NATS server URL
    #[arg(long, env = "NATS_URL", default_value = "nats://127.0.0.1:4222")]
    nats_url: String,

    /// Path to MCP runtime config TOML file
    #[arg(long, env = "MCP_CONFIG_PATH",default_value = "configurations/mcp_runtime_config.toml")]
    mcp_config_path: String,

    /// Path to escalation policy JSON file
    #[arg(long, env = "BRIDGE_POLICY_PATH", default_value = "configuration/policy.json")]
    policy_path: String,

    /// NATS subject to subscribe to
    #[arg(long, default_value = "mcp.v1.dispatch.>")]
    subject: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,mcp_nats_bridge=debug".into()),
        )
        .init();

    dotenvy::dotenv().ok();
    let args = Args::parse();

    tracing::info!("🚀 MCP NATS Bridge starting...");
    tracing::info!("   NATS URL: {}", args.nats_url);
    tracing::info!("   MCP Config: {}", args.mcp_config_path);
    tracing::info!("   Policy: {}", args.policy_path);
    tracing::info!("   Subject: {}", args.subject);

    // Load escalation policy
    let policy = Arc::new(EscalationPolicy::load(&args.policy_path)
        .context("Failed to load escalation policy")?);   
    tracing::info!("✅ Loaded escalation policy ({} safe tools)", policy.safe_tools.len());
    for tool in &policy.safe_tools {
        tracing::info!("   🟢 Safe: {}", tool);
    }

    // Connect to NATS
    let nats_options = async_nats::ConnectOptions::new()
        .request_timeout(Some(std::time::Duration::from_secs(25)));
    let nc = async_nats::connect_with_options(&args.nats_url, nats_options)
        .await
        .context("Failed to connect to NATS")?;
    tracing::info!("✅ Connected to NATS");

    // Load MCP config from TOML file
    let mcp_config = configuration::McpRuntimeConfig::load_agent_config(&args.mcp_config_path)
        .context("Failed to load MCP runtime config")?;

    tracing::info!("✅ Loaded MCP config");
    if let Some(ref url) = mcp_config.agent_mcp_server_url {
        tracing::info!("   MCP Server URL: {}", url);
    }

    // Setup HTTP client for calling the connector_mcp_server and for the MCP client transport
    let http_client = reqwest::Client::builder()
        .pool_max_idle_per_host(10)
        .connect_timeout(std::time::Duration::from_secs(10))
        // WS-FIX: Removed .timeout(30s) as it kills long-lived SSE streams
        .build()
        .unwrap_or_default();
    
    let mcp_client = initialize_mcp_client_v2(mcp_config, http_client.clone())
        .await
        .context("Failed to initialize MCP client")?;
    let mcp_client = Arc::new(mcp_client);
    tracing::info!("✅ Connected to MCP Server");
    
    let http_client = Arc::new(http_client);
    let connector_mcp_url = std::env::var("CONNECTOR_MCP_URL").unwrap_or_else(|_| "http://127.0.0.1:3050".to_string());
    tracing::info!("   Connector MCP URL: {}", connector_mcp_url);

    // Subscribe to NATS subject
    let mut subscriber = nc
        .subscribe(args.subject.clone())
        .await
        .context("Failed to subscribe to NATS")?;
    tracing::info!("📬 Subscribed to {}", args.subject);

    // Clone NATS client for reply path
    let nc = Arc::new(nc);

    // Process messages
    while let Some(msg) = subscriber.next().await {
        let reply_subject = msg.reply.clone();
        let payload_bytes = msg.payload.to_vec();
        let mcp_client = mcp_client.clone();
        let nc = nc.clone();
        let http_client = http_client.clone();
        let connector_mcp_url = connector_mcp_url.clone();
        let policy = policy.clone();

        tokio::spawn(async move {
            let subject = msg.subject.as_str();

            if subject.ends_with(".list_tools") {
                tracing::info!("Received list_tools request on {}", subject);
                
                // Fetch tools from standard MCP Server (SseServer)
                let mut all_tools = match mcp_client.list_tools(Default::default()).await {
                    Ok(res) => res.tools,
                    Err(e) => {
                         tracing::error!("Failed to fetch tools from VP server: {}", e);
                         vec![]
                    }
                };
                
                // Fetch tools from Host Skills Registry (v5 Trust Gateway Architecture)
                let skills_url = "http://127.0.0.1:3000/.well-known/skills.json";
                match http_client.get(skills_url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(skills_registry) = resp.json::<serde_json::Value>().await {
                            // Extract MCP Tools
                            if let Some(mcp_tools) = skills_registry.get("mcp_tools").and_then(|v| v.as_array()) {
                                for ct in mcp_tools {
                                    let name = ct["name"].as_str().unwrap_or("").to_string();
                                    let description = ct["description"].as_str().unwrap_or("").to_string();
                                    let mut input_schema = ct["input_schema"].clone();
                                    if let Some(schema_obj) = input_schema.as_object_mut() {
                                        if !schema_obj.contains_key("type") {
                                            schema_obj.insert("type".to_string(), "object".into());
                                        }
                                    }
                                    
                                    all_tools.push(rmcp::model::Tool::new_with_raw(
                                        name,
                                        Some(description.into()),
                                        input_schema.as_object().unwrap_or(&serde_json::Map::new()).clone()
                                    ));
                                }
                            }
                            
                            // Extract Claw Skills (Phase 3.3: enhanced descriptions)
                            if let Some(claw_skills) = skills_registry.get("claw_skills").and_then(|v| v.as_array()) {
                                for ct in claw_skills {
                                    let name = ct["name"].as_str().unwrap_or("").to_string();
                                    let raw_desc = ct["description"].as_str().unwrap_or("").to_string();
                                    let category = ct["category"].as_str().unwrap_or("general");
                                    let has_docs = ct["documentation_available"].as_bool().unwrap_or(false);
                                    
                                    // Enhance description with taxonomy metadata for LLM awareness
                                    let description = if has_docs {
                                        format!(
                                            "{} [Native Skill | Category: {} | Use `read_skill(\"{}\")` for full documentation]",
                                            raw_desc, category, name
                                        )
                                    } else {
                                        format!(
                                            "{} [Native Skill | Category: {}]",
                                            raw_desc, category
                                        )
                                    };
                                    
                                    let mut input_schema = ct["input_schema"].clone();
                                    if let Some(schema_obj) = input_schema.as_object_mut() {
                                        if !schema_obj.contains_key("type") {
                                            schema_obj.insert("type".to_string(), "object".into());
                                        }
                                    }
                                    
                                    all_tools.push(rmcp::model::Tool::new_with_raw(
                                        name,
                                        Some(description.into()),
                                        input_schema.as_object().unwrap_or(&serde_json::Map::new()).clone()
                                    ));
                                }
                            }
                        }
                    }
                    Ok(resp) => tracing::error!("Skills registry HTTP error: {}", resp.status()),
                    Err(e) => tracing::error!("Failed to fetch tools from Skills registry: {}", e),
                }

                // Add built-in discover_agent_services tool
                all_tools.push(rmcp::model::Tool::new_with_raw(
                    "discover_agent_services",
                    Some("Discover the services and capabilities (skills) of a target agent providing its DID.".into()),
                    serde_json::json!({
                        "type": "object",
                        "properties": {
                            "target_did": {
                                "type": "string",
                                "description": "The DID of the target agent to discover services from."
                            }
                        },
                        "required": ["target_did"]
                    }).as_object().unwrap().clone()
                ));

                // Phase 2.2: Add read_skill meta-tool for skills.md philosophy
                all_tools.push(rmcp::model::Tool::new_with_raw(
                    "read_skill",
                    Some("Read the full documentation and procedures for a native skill. Use this before executing complex multi-step skills to understand their workflows, prerequisites, and error handling. Returns the skill's README.md content and manifest metadata.".into()),
                    serde_json::json!({
                        "type": "object",
                        "properties": {
                            "skill_name": {
                                "type": "string",
                                "description": "Name of the skill to read documentation for (e.g., 'claw_weather', 'claw_hello_world')"
                            }
                        },
                        "required": ["skill_name"]
                    }).as_object().unwrap().clone()
                ));

                println!("📊 BRIDGE list_tools: total={} tools", all_tools.len());
                for t in &all_tools {
                    println!("   🔧 {}", t.name);
                }

                if let Some(reply_to) = reply_subject {
                    let response = serde_json::json!({
                        "tools": all_tools,
                        "nextCursor": null
                    });
                    println!("📤 BRIDGE response payload bytes: {}", response.to_string().len());
                    if let Err(e) = nc.publish(reply_to.clone(), response.to_string().into()).await {
                        tracing::error!("❌ Failed to send NATS reply: {}", e);
                    } else {
                        tracing::info!("📤 Sent list_tools reply to {}", reply_to);
                    }
                }
            } else {
                if let Ok(dispatch) = serde_json::from_slice::<DispatchPayload>(&payload_bytes) {
                    let name = &dispatch.tool_name;
                    // read_skill is bridge-handled (like discover_agent_services), not gateway-handled
                    if name != "read_skill" && (
                       name.starts_with("claw_") || name.starts_with("skill_") || 
                       name.starts_with("google_calendar_") || name.starts_with("stripe_") || 
                       name.starts_with("shopify_")) {
                        tracing::info!("Ignoring tool '{}', handled by trust_gateway", name);
                        return;
                    }


                }

                let result = process_dispatch(mcp_client, &payload_bytes, nc.clone(), http_client, connector_mcp_url, policy).await;
                
                if let Some(reply_to) = reply_subject {
                    let response = match result {
                        Ok(res) => res,
                        Err(e) => serde_json::json!({
                            "error": format!("Bridge error: {}", e)
                        }).to_string(),
                    };
                    
                    if let Err(e) = nc.publish(reply_to.clone(), response.into()).await {
                        tracing::error!("❌ Failed to send NATS reply: {}", e);
                    } else {
                        tracing::info!("📤 Sent reply to {}", reply_to);
                    }
                }
            }
        });
    }

    Ok(())
}

/// Timeout for waiting for user escalation decision (seconds).
const ESCALATION_TIMEOUT_SECS: u64 = 120;

async fn process_dispatch(
    mcp_client: Arc<ssi_mcp_runtime::mcp_client::transport::McpClient>,
    payload_bytes: &[u8],
    nc: Arc<async_nats::Client>,
    http_client: Arc<reqwest::Client>,
    connector_mcp_url: String,
    policy: Arc<EscalationPolicy>,
) -> Result<String> {
    let payload_str = String::from_utf8_lossy(payload_bytes);
    tracing::debug!("📥 Received dispatch: {}", payload_str);

    let dispatch: DispatchPayload = serde_json::from_slice(payload_bytes)
        .context("Failed to parse dispatch payload")?;

    tracing::info!("🔧 Executing tool '{}' for DID: {}", dispatch.tool_name, dispatch.verified_did);

    // Build CallToolRequestParam with _meta stripped
    let mut args_map = dispatch.arguments.as_object().cloned().unwrap_or_default();
    tracing::debug!("📦 Raw arguments (before _meta removal): {:?}", args_map);
    
    // Extract tenant_id and JWT from _meta (if present) to pass to connector and other tools
    let mut tenant_id = "".to_string();
    let mut session_jwt = "".to_string();
    if let Some(meta) = args_map.remove("_meta") {
        if let Some(jwt) = meta.get("X-Session-JWT").and_then(|v| v.as_str()) {
            session_jwt = jwt.to_string();
        }
        // Prefer the explicit tenant_id field
        if let Some(tid) = meta.get("X-Tenant-ID").and_then(|v| v.as_str()) {
            tenant_id = tid.to_string();
        }
        // Fallback: try to extract from JWT
        if tenant_id.is_empty() && !session_jwt.is_empty() {
            if let Some(tid) = ssi_mcp_runtime::audit::extract_tenant_id_from_jwt(&session_jwt) {
                tenant_id = tid;
            }
        }
    }
    
    tracing::debug!("🔧 Calling tool '{}' with args: {:?}", dispatch.tool_name, args_map);
    
    // Phase 2.2: read_skill meta-tool — fetch documentation from Native Skill Executor
    if dispatch.tool_name == "read_skill" {
        tracing::info!("📖 Routing read_skill request via Native Skill Executor");
        let skill_name = args_map.get("skill_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        
        let executor_url = std::env::var("SKILL_EXECUTOR_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:3070".to_string());
        
        match http_client.get(format!("{}/skills/{}/docs", executor_url, skill_name))
            .send().await
        {
            Ok(resp) if resp.status().is_success() => {
                let docs = resp.text().await.unwrap_or_default();
                let tool_result = CallToolResult::success(vec![rmcp::model::Content::text(docs)]);
                let result_json = serde_json::json!({
                    "tool_name": dispatch.tool_name,
                    "result": tool_result,
                    "verified_did": dispatch.verified_did,
                });
                return Ok(serde_json::to_string(&result_json)?);
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                let tool_result = CallToolResult::error(vec![rmcp::model::Content::text(
                    format!("Skill '{}' not found or documentation unavailable (HTTP {}): {}", skill_name, status, body)
                )]);
                let result_json = serde_json::json!({
                    "tool_name": dispatch.tool_name,
                    "result": tool_result,
                    "verified_did": dispatch.verified_did,
                });
                return Ok(serde_json::to_string(&result_json)?);
            }
            Err(e) => {
                let tool_result = CallToolResult::error(vec![rmcp::model::Content::text(
                    format!("Failed to connect to Native Skill Executor: {}", e)
                )]);
                let result_json = serde_json::json!({
                    "tool_name": dispatch.tool_name,
                    "result": tool_result,
                    "verified_did": dispatch.verified_did,
                });
                return Ok(serde_json::to_string(&result_json)?);
            }
        }
    }

    // Custom built-in tool routing: discover_agent_services
    // Sends a discovery request to the local Host via a dedicated NATS subject.
    // The Host handles DID resolution, message packing, and dispatching.
    if dispatch.tool_name == "discover_agent_services" {
        tracing::info!("Routing tool '{}' via NATS discovery channel", dispatch.tool_name);
        if let Some(target_did) = args_map.get("target_did").and_then(|v| v.as_str()) {
            
            // Extract requester DID from the JWT's `iss` claim (dispatch.verified_did is a placeholder)
            let requester_did = if !session_jwt.is_empty() {
                // Decode JWT payload (second part, base64url) to get `iss` claim
                let parts: Vec<&str> = session_jwt.split('.').collect();
                if parts.len() >= 2 {
                    use base64::Engine;
                    let decoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
                    decoder.decode(parts[1]).ok()
                        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                        .and_then(|claims| claims["iss"].as_str().map(|s| s.to_string()))
                        .unwrap_or_else(|| dispatch.verified_did.clone())
                } else {
                    dispatch.verified_did.clone()
                }
            } else {
                dispatch.verified_did.clone()
            };

            tracing::info!("🔍 Discovery: requester_did={}, target_did={}", requester_did, target_did);

            let query_thid = uuid::Uuid::new_v4().to_string();

            let request_payload = serde_json::json!({
                "target_did": target_did,
                "requester_did": requester_did,
                "query_thid": query_thid,
            });

            let payload_bytes = serde_json::to_vec(&request_payload)
                .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

            // 1. Subscribe to the expected reply subject before sending the request
            let reply_subject = format!("mcp.v1.discovery.reply.{}", query_thid);
            let mut reply_sub = nc.subscribe(reply_subject.clone()).await
                .map_err(|e| anyhow::anyhow!("Could not subscribe to reply topic: {}", e))?;

            // 2. Send the request to the Host
            match nc.request("host.v1.discovery.request".to_string(), payload_bytes.into()).await {
                Ok(reply) => {
                    let reply_json: serde_json::Value = serde_json::from_slice(&reply.payload)
                        .unwrap_or(serde_json::json!({"status": "error"}));
                    
                    if let Some(error) = reply_json.get("error").and_then(|e| e.as_str()) {
                        let tool_result = CallToolResult::error(vec![rmcp::model::Content::text(format!("Discovery failed: {}", error))]);
                        let result_json = serde_json::json!({ "tool_name": dispatch.tool_name, "result": tool_result, "verified_did": dispatch.verified_did });
                        return Ok(serde_json::to_string(&result_json)?);
                    }
                    
                    tracing::info!("⏳ Waiting for inline DIDComm reply on {}", reply_subject);
                    
                    // 3. Wait up to 25 seconds for the actual DIDComm disclose message
                    match tokio::time::timeout(std::time::Duration::from_secs(25), reply_sub.next()).await {
                        Ok(Some(disclose_msg)) => {
                            let payload_str = String::from_utf8_lossy(&disclose_msg.payload).to_string();
                            tracing::info!("✅ Received inline disclose via NATS: {}", payload_str);
                            
                            // Clean up the JSON to be readable
                            let readable_result = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&payload_str) {
                                // Assume DIDComm structure: the body contains the tools
                                if let Some(body) = parsed.get("body").and_then(|b| b.as_str()) {
                                    if let Ok(body_parsed) = serde_json::from_str::<serde_json::Value>(body) {
                                        serde_json::to_string_pretty(&body_parsed).unwrap_or(body.to_string())
                                    } else {
                                        body.to_string()
                                    }
                                } else {
                                    serde_json::to_string_pretty(&parsed).unwrap_or(payload_str)
                                }
                            } else {
                                payload_str
                            };

                            let tool_result = CallToolResult::success(vec![rmcp::model::Content::text(format!("Successfully discovered services from {}:\n\n{}", target_did, readable_result))]);
                            let result_json = serde_json::json!({ "tool_name": dispatch.tool_name, "result": tool_result, "verified_did": dispatch.verified_did });
                            return Ok(serde_json::to_string(&result_json)?);
                        }
                        Ok(None) => {
                            return Err(anyhow::anyhow!("Discovery subscription closed unexpectedly"));
                        }
                        Err(_) => {
                            // Timeout
                            let tool_result = CallToolResult::success(vec![rmcp::model::Content::text(format!("Service discovery request sent to {}, but timed out waiting for an inline reply. The response may arrive later as a separate message.", target_did))]);
                            let result_json = serde_json::json!({ "tool_name": dispatch.tool_name, "result": tool_result, "verified_did": dispatch.verified_did });
                            return Ok(serde_json::to_string(&result_json)?);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("NATS request to host.v1.discovery.request failed: {}", e);
                    return Err(anyhow::anyhow!("Discovery request failed: {}", e));
                }
            }
        } else {
            return Err(anyhow::anyhow!("Missing target_did argument for discover_agent_services"));
        }
    }

    // Default routing: native MCP Server (vp_mcp_server) via SSE
    let result = mcp_client
        .call_tool(CallToolRequestParams::new(dispatch.tool_name.clone())
            .with_arguments(args_map.clone()))
        .await;

    match result {
        Ok(tool_result) => {
            tracing::info!("✅ Tool '{}' executed successfully", dispatch.tool_name);
            let result_json = serde_json::json!({
                "tool_name": dispatch.tool_name,
                "result": tool_result,
                "verified_did": dispatch.verified_did,
            });
            Ok(serde_json::to_string(&result_json)?)
        }
        Err(e) => {
            let err_str = format!("{}", e);
            
            // Detect ESCALATION_REQUIRED from vp_mcp_server (returned as -32003 JSON-RPC error)
            if err_str.contains("ESCALATION_REQUIRED") || err_str.contains("-32003") {
                tracing::warn!(
                    "🔒 Tool '{}' requires escalation. Requesting user approval...",
                    dispatch.tool_name
                );
                return handle_escalation(
                    &dispatch,
                    Some(args_map),
                    &session_jwt,
                    mcp_client,
                    nc,
                ).await;
            }
            
            // Propagate other errors normally
            Err(e.into())
        }
    }
}

/// Result of the escalation decision process.
enum EscalationDecision {
    Approved { elevated_jwt: String },
    Denied { message: String },
    Timeout,
}

/// Core escalation logic: publishes an escalation request to the Host,
/// waits for user approval/denial via the portal UI, and returns the decision.
///
/// This is used by both the VP MCP server retry flow and the connector tool flow.
async fn wait_for_escalation_decision(
    dispatch: &DispatchPayload,
    session_jwt: &str,
    nc: Arc<async_nats::Client>,
) -> Result<EscalationDecision> {
    let correlation_id = uuid::Uuid::new_v4().to_string();

    let mut owner_did = dispatch.verified_did.clone();
    let mut requester_did = dispatch.verified_did.clone();
    
    if !session_jwt.is_empty() {
        let parts: Vec<&str> = session_jwt.split('.').collect();
        if parts.len() >= 2 {
            use base64::Engine;
            let decoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            if let Ok(bytes) = decoder.decode(parts[1]) {
                if let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    if let Some(iss) = claims.get("iss").and_then(|v| v.as_str()) {
                        owner_did = iss.to_string();
                    }
                    if let Some(sub) = claims.get("sub").and_then(|v| v.as_str()) {
                        requester_did = sub.to_string();
                    }
                }
            }
        }
    }

    // 1. Publish escalation request to Host
    let escalation_payload = serde_json::json!({
        "tool_name": dispatch.tool_name,
        "user_did": owner_did,
        "requester_did": requester_did,
        "correlation_id": correlation_id,
        "original_arguments": dispatch.arguments,
    });

    // Use NATS request-reply to get the reply subject back from the Host
    let response = nc.request(
        "host.v1.escalation.request".to_string(),
        serde_json::to_string(&escalation_payload)?.into(),
    ).await.context("Failed to publish escalation request to Host")?;

    // Parse the Host's acknowledgement to get the reply subject
    let ack: serde_json::Value = serde_json::from_slice(&response.payload)
        .context("Failed to parse escalation acknowledgement")?;
    
    let reply_subject = ack["reply_subject"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing reply_subject in escalation acknowledgement"))?
        .to_string();

    tracing::info!(
        "📩 Escalation published (correlation: {}). Waiting for user decision on {}...",
        correlation_id, reply_subject
    );

    // 2. Subscribe to the reply subject and wait for user decision
    let mut reply_sub = nc.subscribe(reply_subject.clone()).await
        .context("Failed to subscribe to escalation reply")?;

    let decision = tokio::time::timeout(
        std::time::Duration::from_secs(ESCALATION_TIMEOUT_SECS),
        reply_sub.next(),
    ).await;

    match decision {
        Ok(Some(reply_msg)) => {
            let reply: serde_json::Value = serde_json::from_slice(&reply_msg.payload)
                .context("Failed to parse escalation decision")?;

            let status = reply["status"].as_str().unwrap_or("UNKNOWN");

            match status {
                "APPROVED" => {
                    let elevated_jwt = reply["elevated_jwt"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    // WS-A1: Defensive check — an approval without a valid JWT
                    // is a security degradation. Treat as denied.
                    if elevated_jwt.is_empty() {
                        tracing::error!("🚨 Approval received with empty elevated_jwt — treating as denied");
                        return Ok(EscalationDecision::Denied {
                            message: "Approval failed: no elevated JWT was provided".to_string(),
                        });
                    }
                    Ok(EscalationDecision::Approved { elevated_jwt })
                }
                "DENIED" => {
                    let message = reply["message"]
                        .as_str()
                        .unwrap_or("User denied permission")
                        .to_string();
                    Ok(EscalationDecision::Denied { message })
                }
                _ => {
                    Err(anyhow::anyhow!("Unknown escalation status: {}", status))
                }
            }
        }
        Ok(None) => {
            Err(anyhow::anyhow!("Escalation reply stream ended unexpectedly"))
        }
        Err(_) => {
            tracing::warn!(
                "⏰ Escalation timeout ({}s) for tool '{}'. User did not respond.",
                ESCALATION_TIMEOUT_SECS, dispatch.tool_name
            );
            Ok(EscalationDecision::Timeout)
        }
    }
}

/// Handles the escalation flow for VP MCP server tools:
/// 1. Calls wait_for_escalation_decision to get user approval
/// 2. If approved, retries the tool call with the elevated JWT
async fn handle_escalation(
    dispatch: &DispatchPayload,
    args_map: Option<serde_json::Map<String, serde_json::Value>>,
    session_jwt: &str,
    mcp_client: Arc<ssi_mcp_runtime::mcp_client::transport::McpClient>,
    nc: Arc<async_nats::Client>,
) -> Result<String> {
    let decision = wait_for_escalation_decision(dispatch, session_jwt, nc).await?;

    match decision {
        EscalationDecision::Approved { elevated_jwt } => {
            tracing::info!(
                "✅ Escalation APPROVED for tool '{}'. Retrying with elevated JWT...",
                dispatch.tool_name
            );

            // Re-inject the elevated JWT into _meta for the retry
            let mut retry_args = args_map.unwrap_or_default();
            let meta = serde_json::json!({
                "X-Session-JWT": elevated_jwt,
            });
            retry_args.insert("_meta".to_string(), meta);

            // Retry the tool call via the VP MCP server
            let retry_result: CallToolResult = mcp_client
                .call_tool(CallToolRequestParams::new(dispatch.tool_name.clone())
                    .with_arguments(retry_args))
                .await
                .context("Elevated tool execution failed")?;

            tracing::info!("✅ Elevated tool '{}' executed successfully", dispatch.tool_name);

            let result_json = serde_json::json!({
                "tool_name": dispatch.tool_name,
                "result": retry_result,
                "verified_did": dispatch.verified_did,
                "escalation": "approved",
            });
            Ok(serde_json::to_string(&result_json)?)
        }
        EscalationDecision::Denied { message } => {
            tracing::warn!("🚫 Escalation DENIED for tool '{}': {}", dispatch.tool_name, message);
            let result_json = serde_json::json!({
                "tool_name": dispatch.tool_name,
                "error": message,
                "escalation": "denied",
            });
            Ok(serde_json::to_string(&result_json)?)
        }
        EscalationDecision::Timeout => {
            let result_json = serde_json::json!({
                "tool_name": dispatch.tool_name,
                "error": format!(
                    "Escalation timeout: user did not respond within {}s for tool '{}'",
                    ESCALATION_TIMEOUT_SECS, dispatch.tool_name
                ),
                "escalation": "timeout",
            });
            Ok(serde_json::to_string(&result_json)?)
        }
    }
}
