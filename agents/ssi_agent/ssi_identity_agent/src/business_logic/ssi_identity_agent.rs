use async_trait::async_trait;
use uuid::Uuid;
use configuration::AgentConfig;

#[allow(unused)]
use anyhow::{Context, bail, Result};

use agent_core::business_logic::mcp_runtime::McpRuntimeDetails;

use llm_api::chat::{ChatLlmInteraction};
use std::sync::Arc;
use tokio::sync::Mutex;

use tracing::debug;

use serde_json::Map;
use serde_json::Value;

use futures_util::{StreamExt, SinkExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage, tungstenite::client::IntoClientRequest};



// todo : change the prompt of mcp runtime , so that he tries to use internal knowledge if possible
// todo: see if the method of delegation to mcp_runtime is optimal
use ssi_mcp_runtime::mcp_agent_logic::agent::McpAgent;

use llm_api::chat::Message as LlmMessage;

use agent_core::business_logic::agent::{Agent};
use agent_core::business_logic::services::{EvaluationService, MemoryService, DiscoveryService};


use agent_models::execution::execution_result::{ExecutionResult};

use agent_core::business_logic::services::WorkflowServiceApi;

#[derive(Clone, Debug, serde::Deserialize)]
pub struct PicoClawConfig {
    pub picoclaw_target_id: String,
    pub picoclaw_endpoint: String,
    pub picoclaw_publish_subject: String,
    #[serde(default)]
    pub trust_gateway_url: Option<String>,
    #[serde(default)]
    pub picoclaw_ws_endpoint: Option<String>,
    #[serde(default)]
    pub picoclaw_token: Option<String>,
}

#[derive(Clone, serde::Deserialize)]
struct LocalConfig {
    picoclaw: Option<PicoClawConfig>,
}

/// Modern A2A server setup 
#[derive(Clone)]
pub struct SsiIdentityAgent {
    llm_interaction: ChatLlmInteraction,
    mcp_agent:Option<Arc<Mutex<McpAgent>>>,
    picoclaw_config: Option<PicoClawConfig>,
    system_message: String, // Store the specific prompt
}

use ssi_mcp_runtime::SsiAuthenticationData;

#[async_trait]
impl Agent for SsiIdentityAgent {

    /// Creation of a new identity agent
    async fn new(
        agent_config: AgentConfig,
        agent_api_key:String,
        mcp_runtime_details: Option<McpRuntimeDetails>,
        _evaluation_service: Option<Arc<dyn EvaluationService>>,
        _memory_service: Option<Arc<dyn MemoryService>>,
        _discovery_service: Option<Arc<dyn DiscoveryService>>,
        _workflow_service: Option<Arc<dyn WorkflowServiceApi>>,
    ) -> anyhow::Result<Self> {

               // Set model to be used
        let model_id = agent_config.agent_model_id();

        // Set system message to be used, ensuring it's present in the config
        let system_message = agent_config.agent_system_prompt().expect("agent_system_prompt not found in config");

        // Set API key for LLM
        let llm_a2a_api_key =agent_api_key;

        let llm_interaction= ChatLlmInteraction::new(
            agent_config.agent_llm_url(),
            model_id,
            llm_a2a_api_key,
        );

        let mcp_agent = if let Some(details) = mcp_runtime_details {
            // Case 1: McpRuntimeDetails struct provided directly
            Some(Arc::new(Mutex::new(McpAgent::new(details.config, Some(details.api_key), None).await?)))
        } else if let Some(path) = agent_config.agent_mcp_config_path() {
            // Case 2: MCP config path specified in AgentConfig (API key from environment)
            let agent_mcp_config = configuration::McpRuntimeConfig::load_agent_config(path.as_str())
                .context("Error loading MCP config for identity agent from agent_config.agent_mcp_config_path")?;
            let mcp_agent = McpAgent::new(agent_mcp_config, None, None).await?; // Pass None for API key and NATS client to use defaults
            Some(Arc::new(Mutex::new(mcp_agent)))
        } else {
            // Case 3: No MCP config provided in any way
            None
        };

        // Parse PicoClawConfig locally
        let picoclaw_config = std::fs::read_to_string("configuration/agent_identity_config.toml")
            .ok()
            .and_then(|content| toml::from_str::<LocalConfig>(&content).ok())
            .and_then(|loc| loc.picoclaw);

          Ok(Self {
            llm_interaction,
            mcp_agent,
            picoclaw_config,
            system_message,
          })
    }


    

        /// business logic for handling user request with authentication
        async fn handle_request(&self, request: LlmMessage,metadata:Option<Map<String, Value>>) ->anyhow::Result<ExecutionResult> {
       
         let request_id = uuid::Uuid::new_v4().to_string();
         let thread_id = metadata.as_ref()
             .and_then(|m| m.get("thread_id").or_else(|| m.get("conversation_id")))
             .and_then(|v| v.as_str())
             .map(|s| s.to_string())
             .unwrap_or_else(|| Uuid::new_v4().to_string());
             
         let conversation_id = thread_id.clone();
         let session_id = format!("ssi:{}", thread_id);

         let ssi_authentication_data = self.extract_authentication_metadata(&metadata)?;
         
         // JWT extraction for authentication logic
         let _jwt_token_opt = ssi_authentication_data.jwt.clone();

         // Scenario Routing Logic:
         // 1. If PicoClaw config exists and matches, forward it.
         // 2. If mcp_agent exists, run it (which now should use NATS multiplexing internally)
         // 3. Fallback to raw LLM interaction
         let response = if let Some(ref config) = self.picoclaw_config {
             tracing::info!("PicoClaw bypass active. Forwarding to external PicoClaw WebSocket API");

             let prompt_text = request.content.clone().unwrap_or_default();
             
             let default_ws_url = "ws://127.0.0.1:18790/pico/ws";
             let base_ws_url = config.picoclaw_ws_endpoint.as_deref().unwrap_or(default_ws_url);
             let url_with_session = if base_ws_url.contains('?') {
                 format!("{}&session_id={}", base_ws_url, session_id)
             } else {
                 format!("{}?session_id={}", base_ws_url, session_id)
             };
             
             let mut ws_request = url_with_session.into_client_request()
                 .map_err(|e| anyhow::anyhow!("Invalid WebSocket URL for PicoClaw: {}", e))?;
                 
             if let Some(token) = &config.picoclaw_token {
                 ws_request.headers_mut().insert(
                     "Authorization",
                     tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&format!("Bearer {}", token))
                         .map_err(|e| anyhow::anyhow!("Invalid PicoClaw token format: {}", e))?
                 );
             }

             let (ws_stream, _) = connect_async(ws_request).await
                 .map_err(|e| anyhow::anyhow!("Failed to connect to PicoClaw WebSocket: {}", e))?;
                 
             let (mut write, mut read) = ws_stream.split();
             
             let turn_msg_id = format!("req-{}", request_id);
             let payload = serde_json::json!({
                 "type": "message.send",
                 "id": turn_msg_id,
                 "session_id": session_id,
                 "timestamp": chrono::Utc::now().timestamp_millis(),
                 "payload": {
                     "content": prompt_text
                 }
             });
             
             write.send(WsMessage::Text(payload.to_string())).await
                 .map_err(|e| anyhow::anyhow!("Failed to send message over WebSocket: {}", e))?;
                 
             let mut accumulated_response = String::new();
             let mut stopped_typing = false;
             
             loop {
                 let wait_time = if stopped_typing { std::time::Duration::from_millis(5000) } else { std::time::Duration::from_secs(120) };
                 match tokio::time::timeout(wait_time, read.next()).await {
                     Ok(Some(msg)) => {
                         match msg {
                             Ok(WsMessage::Text(text)) => {
                                 tracing::info!("PicoClaw WS RECV: {}", text);
                                 let body: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
                                 let msg_type = body.get("type").and_then(|t| t.as_str()).unwrap_or("");
                                 
                                 match msg_type {
                                     "message.create" | "message.update" => {
                                         if let Some(content) = body.get("payload").and_then(|p| p.get("content")).and_then(|c| c.as_str()) {
                                             if let Some(delta) = body.get("payload").and_then(|p| p.get("delta")).and_then(|d| d.as_str()) {
                                                 accumulated_response.push_str(delta);
                                             } else {
                                                 accumulated_response = content.to_string();
                                             }
                                         }
                                     }
                                     "error" => {
                                         let err_msg = body.get("payload").and_then(|p| p.get("message")).and_then(|m| m.as_str()).unwrap_or("Unknown PicoClaw error");
                                         tracing::error!("PicoClaw protocol error: {}", err_msg);
                                         return Err(anyhow::anyhow!("PicoClaw error: {}", err_msg));
                                     }
                                     "typing.stop" => {
                                         tracing::info!("PicoClaw sent typing.stop - starting 5000ms termination window.");
                                         stopped_typing = true;
                                     }
                                     "pong" | "typing.start" => {}
                                     _ => {}
                                 }
                             }
                             Ok(WsMessage::Close(_)) => {
                                 tracing::warn!("PicoClaw WebSocket closed unexpectedly.");
                                 break;
                             }
                             Err(e) => {
                                 tracing::error!("WebSocket read error: {}", e);
                                 return Err(anyhow::anyhow!("WebSocket error: {}", e));
                             }
                             _ => {}
                         }
                     }
                     Ok(None) => break, // stream closed naturally
                     Err(_) => {
                         // Timeout occurred
                         if stopped_typing {
                             break;
                         } else {
                             tracing::warn!("Timeout waiting for PicoClaw response");
                             return Err(anyhow::anyhow!("Timeout waiting for PicoClaw response"));
                         }
                     }
                 }
             }

             Ok(Some(llm_api::chat::Message {
                 role: "assistant".to_string(),
                 content: Some(accumulated_response),
                 tool_call_id: None,
                 tool_calls: None,
             }))
         } else if let Some(ref agent) = self.mcp_agent {
             let mut locked_mcp_agent = agent.lock().await;
             locked_mcp_agent.run_agent_internal(request.clone(), Some(ssi_authentication_data)).await
         } else {
             let messages = vec![
                 LlmMessage {
                     role: "system".to_string(),
                     content: Some(self.system_message.clone()),
                     tool_call_id: None,
                     tool_calls: None,
                 },
                 request.clone(),
             ];
             self.llm_interaction.call_api(messages, None, None).await
         };

         let response_msg = response
             .map_err(|e| anyhow::anyhow!("Execution layer error: {}", e))?
             .ok_or_else(|| anyhow::anyhow!("Received None from execution layer"))?;
         let llm_content = response_msg.content.unwrap_or_else(|| "Empty result from tool/LLM".to_string());

         let output_value = match serde_json::from_str::<Value>(&llm_content) {
             Ok(json_val) => json_val,
             Err(_) => Value::String(llm_content),
         };

         debug!("Output Value from Identity Agent: {:?}", output_value);

         Ok(ExecutionResult {
             request_id,
             conversation_id,
             success: true,
             output: output_value,
         })
         }
        
        }

        impl SsiIdentityAgent {


        fn extract_authentication_metadata(&self, metadata: &Option<Map<String, Value>>) -> Result<SsiAuthenticationData> {
            let meta = match metadata {
                Some(m) => m,
                None => {
                    return Ok(SsiAuthenticationData {
                        x_envelope: None,
                        x_instruction: None,
                        jwt: None,
                        tenant_id: None,
                    });
                }
            };

            let x_envelope = meta.get("x_envelope").and_then(|v| v.as_str()).map(|s| s.to_string());
            let x_instruction = meta.get("x_instruction").and_then(|v| v.as_str()).map(|s| s.to_string());
            
            // Handle multiple possible JWT field names from different clients
            let jwt = meta.get("agent_jwt")
                .or_else(|| meta.get("session_jwt"))
                .or_else(|| meta.get("authorization"))
                .and_then(|v| v.as_str())
                .map(|s| s.replace("Bearer ", ""))
                .map(|s| s.to_string());

            let tenant_id = meta.get("tenant_id")
                .or_else(|| meta.get("tenant"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            Ok(SsiAuthenticationData {
                x_envelope,
                x_instruction,
                jwt,
                tenant_id,
            })
        }


    }