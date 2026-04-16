use anyhow::{Result, Context};
use llm_api::chat::Message;
use tracing::{info, error, warn, debug};
use std::env;
use serde_json::json;
use std::sync::Arc;

use crate::audit;

use crate::mcp_client::transport::McpClient;

use llm_api::chat::{ChatLlmInteraction, ChatCompletionRequest, ChatCompletionResponse, Choice, ToolChoice};
use llm_api::tools::Tool;
use configuration::McpRuntimeConfig;
use crate::mcp_client::mcp_client::execute_tool_call_v2;
use crate::mcp_client::mcp_client::get_tools_list_v2;
use crate::mcp_client::mcp_client::initialize_mcp_client_v2;
use crate::mcp_tools::tools::define_all_tools;

/// Represents the discrete states of the agent's execution loop.
///
/// The agent transitions between these states in a state-machine pattern:
/// `Thinking` → `Executing` → `Evaluating` → [`Correcting`] → `Thinking` → ... → `Finished`
#[derive(Clone, Debug)]
enum AgentState {
    /// Agent is calling the LLM to decide on the next action.
    Thinking,
    /// Agent is executing tool calls returned by the LLM.
    Executing(Choice),
    /// Agent is evaluating whether tool execution results are satisfactory.
    Evaluating(Choice, Vec<Message>),
    /// Agent is injecting a correction prompt after unsatisfactory results.
    Correcting(String),
    /// Agent has completed its task.
    Finished,
}

/// The `McpAgent` struct encapsulates the state and logic for the MCP agent.
///
/// Uses a state-machine pattern for the execution loop, providing clean
/// separation of concerns and support for self-correcting tool execution.
#[derive(Clone)]
pub struct McpAgent {
    llm_interaction: ChatLlmInteraction,
    pub nats_client: Arc<async_nats::Client>,
    pub dispatch_subject: String,
    messages: Vec<Message>,
    llm_all_tool: Vec<Tool>,
    agent_mcp_config: McpRuntimeConfig,
    state: AgentState,
    /// JWT session ID for audit trail correlation
    audit_jti: Option<String>,
    /// Delegating user's DID for audit trail
    audit_user_did: Option<String>,
    /// Tenant ID for tenant-scoped audit trail
    audit_tenant_id: Option<String>,
}

impl McpAgent {
    pub async fn new(agent_mcp_config: McpRuntimeConfig, mcp_runtime_api_key: Option<String>) -> anyhow::Result<Self> {
        let model_id = agent_mcp_config.agent_mcp_model_id.clone();
        let system_message = agent_mcp_config.agent_mcp_system_prompt.clone();

        let llm_mcp_api_key = if let Some(api_key) = mcp_runtime_api_key {
            api_key
        } else if let Some(env_var_name) = &agent_mcp_config.agent_mcp_llm_api_key_env_var {
            env::var(env_var_name)
                .context(format!("Environment variable '{}' for LLM API key must be set", env_var_name))?
        } else {
            env::var("LLM_MCP_API_KEY")
                .context("LLM_MCP_API_KEY environment variable must be set")?
        };

        let local_nats_config = std::fs::read_to_string("configuration/mcp_runtime_config.toml")
            .ok()
            .and_then(|c| toml::from_str::<serde_json::Value>(&c).ok());
        
        let nats_url = local_nats_config.as_ref()
            .and_then(|c| c.get("agent_mcp_nats_url").and_then(|v| v.as_str()))
            .unwrap_or("nats://127.0.0.1:4222")
            .to_string();
            
        let dispatch_subject = local_nats_config.as_ref()
            .and_then(|c| c.get("agent_mcp_nats_dispatch_subject").and_then(|v| v.as_str()))
            .unwrap_or("mcp.v1.dispatch")
            .to_string();

        let nats_options = async_nats::ConnectOptions::new()
            .request_timeout(Some(std::time::Duration::from_secs(25)));
        let nats_client = Arc::new(async_nats::connect_with_options(&nats_url, nats_options)
            .await
            .context("Failed to connect to NATS in McpAgent")?);

        // Retrieve tools over NATS bridging (fallback to empty if bridge isn't up yet - will refresh later)
        let list_tools = match crate::mcp_client::mcp_client::get_tools_list_over_nats(nats_client.clone(), &dispatch_subject).await {
            Ok(tools) => tools,
            Err(e) => {
                warn!("⚠️ Could not retrieve tools at startup (is mcp_nats_bridge running?): {}", e);
                vec![]
            }
        };

        let llm_all_tool = define_all_tools(list_tools)
            .unwrap_or_else(|e| {
                warn!("⚠️ Failed to define tools from retrieved list: {}", e);
                vec![]
            });
        
        println!("🛠️ Agent initialized with {} tools", llm_all_tool.len());
        for tool in &llm_all_tool {
            println!("   📌 Tool: {}", tool.function.name);
        }

        let init_messages = vec![Message {
            role: "system".to_string(),
            content: Some(system_message),
            tool_call_id: None,
            tool_calls: None,
        }];

        Ok(Self {
            llm_interaction: ChatLlmInteraction::new(
                agent_mcp_config.agent_mcp_llm_url.clone(),
                model_id,
                llm_mcp_api_key,
            ),
            nats_client,
            dispatch_subject,
            messages: init_messages,
            llm_all_tool,
            agent_mcp_config,
            state: AgentState::Thinking,
            audit_jti: None,
            audit_user_did: None,
            audit_tenant_id: None,
        })
    }

    pub fn get_available_tools(&self) -> Vec<Tool> {
        self.llm_all_tool.clone()
    }

    /// Re-fetch tools from the NATS bridge so newly connected integrations
    /// (e.g. Google Calendar via OAuth) are available without a restart.
    pub async fn refresh_tools(&mut self) {
        match crate::mcp_client::mcp_client::get_tools_list_over_nats(
            self.nats_client.clone(),
            &self.dispatch_subject,
        ).await {
            Ok(tools) => {
                match define_all_tools(tools) {
                    Ok(new_tools) => {
                        let old_count = self.llm_all_tool.len();
                        self.llm_all_tool = new_tools;
                        let new_count = self.llm_all_tool.len();
                        if new_count != old_count {
                            info!("🔄 Tools refreshed: {} → {} tools", old_count, new_count);
                        }
                    }
                    Err(e) => warn!("⚠️ Failed to define refreshed tools: {}", e),
                }
            }
            Err(e) => warn!("⚠️ Failed to refresh tools over NATS: {}", e),
        }
    }

    pub fn push_message(&mut self, user_message: Message) {
        self.messages.push(user_message);
    }

    pub fn reset_messages(&mut self) -> anyhow::Result<()> {
        let system_message = self.agent_mcp_config.agent_mcp_system_prompt.clone();
        self.messages = vec![Message {
            role: "system".to_string(),
            content: Some(system_message),
            tool_call_id: None,
            tool_calls: None,
        }];
        Ok(())
    }

    async fn call_api_v2(
        &self,
        request_payload: &ChatCompletionRequest,
    ) -> anyhow::Result<ChatCompletionResponse> {
        debug!("Calling LLM API with payload: {:?}", request_payload);
        let response = self.llm_interaction.call_chat_completions_v2(request_payload).await
            .context("LLM chat completion API call failed")?;
        debug!("LLM API Response: {:?}", response);
        Ok(response)
    }

    // ──────────────────────────────────────────────────────────────
    // State Machine Steps
    // ──────────────────────────────────────────────────────────────

    /// Thinking: Call the LLM with the current message history and tools.
    /// Returns `Executing` if the LLM requests tool calls, or `Finished` otherwise.
    async fn thinking_step(&mut self) -> anyhow::Result<AgentState> {
        info!("--- Thinking ---");

        let has_tools = !self.llm_all_tool.is_empty();
        let request_payload = ChatCompletionRequest {
            model: self.llm_interaction.model_id.clone(),
            messages: self.messages.clone(),
            temperature: Some(0.0),
            max_tokens: Some(1024),
            top_p: Some(1.0),
            stop: None,
            stream: Some(false),
            tools: if has_tools { Some(self.llm_all_tool.clone()) } else { None },
            tool_choice: if has_tools {
                Some(ToolChoice::String(self.agent_mcp_config.agent_mcp_tool_choice_auto.clone()))
            } else {
                None
            },
        };

        let response = self.call_api_v2(&request_payload).await?;

        if response.choices.is_empty() {
            error!("LLM response contained no choices.");
            anyhow::bail!("LLM response contained no choices.");
        }

        let mut choice = response.choices[0].clone();

        // Clean <think> tags from the response content
        if let Some(content) = choice.message.content.as_mut() {
            *content = self.llm_interaction.remove_think_tags(content.clone()).await?;
        }

        // === AUDIT: llm_call ===
        if let Some(ref jti) = self.audit_jti {
            let has_tool_calls = choice.message.tool_calls.is_some();
            audit::publish_audit(
                &self.nats_client, jti,
                self.audit_user_did.as_deref().unwrap_or("unknown"),
                "llm_call", "ssi_agent",
                json!({
                    "model": self.llm_interaction.model_id,
                    "tool_calls_requested": has_tool_calls,
                }),
                self.audit_tenant_id.as_deref(),
            ).await;
        }

        // Commit the assistant's response to message history
        self.messages.push(Message {
            role: choice.message.role.clone(),
            content: choice.message.content.clone(),
            tool_calls: choice.message.tool_calls.clone(),
            tool_call_id: None,
        });

        if choice.finish_reason == self.agent_mcp_config.agent_mcp_finish_reason_tool_calls {
            Ok(AgentState::Executing(choice))
        } else {
            info!("Agent finished thinking.");
            Ok(AgentState::Finished)
        }
    }

    /// Executing: Run all tool calls from the LLM's response.
    /// Returns `Evaluating` with the tool results, preserving SSI auth_data injection.
    async fn executing_step(
        &mut self,
        choice: &Choice,
        auth_data: Option<crate::SsiAuthenticationData>,
    ) -> anyhow::Result<AgentState> {
        info!("--- Executing ---");

        if let Some(tool_calls) = &choice.message.tool_calls {
            let mut tool_results: Vec<Message> = Vec::new();

            for tool_call in tool_calls {
                info!("Executing tool call: {}", tool_call.id);
                let tool_name = tool_call.function.name.clone();

                match execute_tool_call_v2(self.nats_client.clone(), &self.dispatch_subject, tool_call.clone(), auth_data.clone()).await {
                    Ok(result) => {
                        // Parse the result content to extract just the raw text instead of a stringified JSON array
                        let mut parsed_texts = Vec::new();
                        if let Ok(json_arr) = serde_json::to_value(&result.content) {
                            if let Some(arr) = json_arr.as_array() {
                                for item in arr {
                                    if item.get("type").and_then(|v| v.as_str()) == Some("text") {
                                        if let Some(text) = item.get("text").and_then(|v| v.as_str()) {
                                            parsed_texts.push(text.to_string());
                                        }
                                    }
                                }
                            }
                        }
                        
                        let mut result_content_str = if !parsed_texts.is_empty() {
                            parsed_texts.join("\n")
                        } else {
                            serde_json::to_string(&result.content)
                                .unwrap_or_else(|_| "[]".to_string())
                        };

                        let original_len = result_content_str.chars().count();
                        let mut is_sanitized = false;

                        info!("Tool '{}' returned {} chars. Sanitizer configured: {:?}", 
                            tool_name, original_len, self.agent_mcp_config.agent_mcp_sanitizer_model_id);

                        if original_len > 8000 {
                            if let Some(sanitizer_model) = &self.agent_mcp_config.agent_mcp_sanitizer_model_id {
                                let user_query = self.messages.iter()
                                    .rev()
                                    .find(|m| m.role == "user")
                                    .and_then(|m| m.content.clone())
                                    .unwrap_or_default();
                                
                                let sys_prompt = format!("The user wants to: {}. Below is a long tool output. Provide a comprehensive distillation of this data, keeping only the information relevant to the user's request. Preserve all specific IDs, dates, and URLs. Output only the summarized facts without mentioning truncation or original length.", user_query);
                                
                                let request_payload = ChatCompletionRequest {
                                    model: sanitizer_model.clone(),
                                    messages: vec![
                                        Message {
                                            role: "system".to_string(),
                                            content: Some(sys_prompt),
                                            tool_call_id: None,
                                            tool_calls: None,
                                        },
                                        Message {
                                            role: "user".to_string(),
                                            content: Some(if result_content_str.len() > 15000 {
                                                result_content_str[..15000].to_string()
                                            } else {
                                                result_content_str.clone()
                                            }),
                                            tool_call_id: None,
                                            tool_calls: None,
                                        }
                                    ],
                                    temperature: Some(0.0),
                                    max_tokens: Some(4096),
                                    top_p: Some(1.0),
                                    stop: None,
                                    stream: Some(false),
                                    tools: None,
                                    tool_choice: None,
                                };
                                
                                info!("Payload too large ({} chars). Running Janitor (model: {})...", original_len, sanitizer_model);
                                match self.call_api_v2(&request_payload).await {
                                    Ok(resp) => {
                                        if let Some(choice) = resp.choices.first() {
                                            if let Some(ref sanitized_txt) = choice.message.content {
                                                let cleaned_txt = self.llm_interaction.remove_think_tags(sanitized_txt.clone()).await.unwrap_or(sanitized_txt.clone());
                                                info!("Janitor distillation successful. Reduced from {} to {} chars.", original_len, cleaned_txt.chars().count());
                                                result_content_str = cleaned_txt;
                                                is_sanitized = true;
                                            }
                                        }
                                    },
                                    Err(e) => {
                                        warn!("Janitor sanitization failed: {}. Proceeding with original payload.", e);
                                    }
                                }
                            }
                        }

                        // === AUDIT: tool_executed (success) ===
                        if let Some(ref jti) = self.audit_jti {
                            audit::publish_audit(
                                &self.nats_client, jti,
                                self.audit_user_did.as_deref().unwrap_or("unknown"),
                                "tool_executed", "ssi_agent",
                                json!({
                                    "tool": tool_name,
                                    "result": "success",
                                    "sanitized": is_sanitized,
                                    "original_length": original_len,
                                    "sanitized_length": result_content_str.chars().count(),
                                }),
                                self.audit_tenant_id.as_deref(),
                            ).await;
                        }

                        tool_results.push(Message {
                            role: self.agent_mcp_config.agent_mcp_role_tool.clone(),
                            content: Some(result_content_str.clone()),
                            tool_call_id: Some(tool_call.id.clone()),
                            tool_calls: None,
                        });
                    }
                    Err(e) => {
                        error!("Error executing tool {}: {}", tool_call.id, e);

                        // === AUDIT: tool_executed (error) ===
                        if let Some(ref jti) = self.audit_jti {
                            audit::publish_audit(
                                &self.nats_client, jti,
                                self.audit_user_did.as_deref().unwrap_or("unknown"),
                                "tool_executed", "ssi_agent",
                                json!({
                                    "tool": tool_name,
                                    "result": "error",
                                    "error": format!("{}", e),
                                }),
                                self.audit_tenant_id.as_deref(),
                            ).await;
                        }

                        let error_content = json!({
                            "error": format!("Error executing tool '{}': {}", tool_call.id, e),
                            "tool_call_id": tool_call.id
                        });
                        tool_results.push(Message {
                            role: self.agent_mcp_config.agent_mcp_role_tool.clone(),
                            content: Some(error_content.to_string()),
                            tool_call_id: Some(tool_call.id.clone()),
                            tool_calls: None,
                        });
                    }
                }
            }
            self.messages.extend(tool_results);
            Ok(AgentState::Thinking)
        } else {
            // No tool calls found — go back to thinking
            Ok(AgentState::Thinking)
        }
    }

    /// Evaluating: Send tool results + evaluation prompt to LLM.
    /// Returns `Correcting` if results are unsatisfactory, or `Thinking` to continue.
    async fn evaluating_step(
        &mut self,
        choice: &Choice,
        tool_results: Vec<Message>,
    ) -> anyhow::Result<AgentState> {
        info!("--- Evaluating ---");

        // Build evaluation context: original messages + assistant tool request + tool results + evaluation prompt
        let mut evaluation_messages = self.messages.clone();
        evaluation_messages.push(Message {
            role: choice.message.role.clone(),
            content: Some(choice.message.content.clone().unwrap_or_else(|| "".to_string())),
            tool_calls: choice.message.tool_calls.clone(),
            tool_call_id: None,
        });
        evaluation_messages.extend(tool_results.clone());
        evaluation_messages.push(Message {
            role: "system".to_string(),
            content: Some(self.agent_mcp_config.agent_mcp_evaluation_prompt.clone()),
            tool_call_id: None,
            tool_calls: None,
        });

        let request_payload = ChatCompletionRequest {
            model: self.llm_interaction.model_id.clone(),
            messages: evaluation_messages,
            temperature: Some(0.0),
            max_tokens: Some(1024),
            top_p: Some(1.0),
            stop: None,
            stream: Some(false),
            tools: Some(self.llm_all_tool.clone()),
            tool_choice: Some(ToolChoice::String("none".to_string())),
        };

        let response = self.call_api_v2(&request_payload).await?;

        if let Some(first_choice) = response.choices.get(0) {
            if let Some(content) = &first_choice.message.content {
                if content.contains("unsatisfactory") {
                    warn!("Tool execution unsatisfactory. Entering correction state.");
                    return Ok(AgentState::Correcting(content.clone()));
                }
            }
        }

        // Satisfactory — commit the tool request + results to message history and continue
        info!("Tool execution satisfactory.");
        self.messages.push(Message {
            role: choice.message.role.clone(),
            content: Some(choice.message.content.clone().unwrap_or_else(|| "".to_string())),
            tool_calls: choice.message.tool_calls.clone(),
            tool_call_id: None,
        });
        self.messages.extend(tool_results);
        Ok(AgentState::Thinking)
    }

    /// Correcting: Inject correction prompt with the issue description.
    /// Returns `Thinking` to retry the task.
    async fn correcting_step(&mut self, issue: String) -> anyhow::Result<AgentState> {
        info!("--- Correcting ---");
        self.messages.push(Message {
            role: "system".to_string(),
            content: Some(format!(
                "{}\n The issue was: {}",
                self.agent_mcp_config.agent_mcp_correction_prompt, issue
            )),
            tool_call_id: None,
            tool_calls: None,
        });
        Ok(AgentState::Thinking)
    }

    // ──────────────────────────────────────────────────────────────
    // Main Execution Loop
    // ──────────────────────────────────────────────────────────────

    pub async fn execute_loop(&mut self, auth_data: Option<crate::SsiAuthenticationData>) -> anyhow::Result<Option<Message>> {
        let mut final_message: Option<Message> = None;

        for loop_count in 0..self.agent_mcp_config.agent_mcp_max_loops {
            info!(
                "Agent Loop Iteration: {}/{} - State: {:?}",
                loop_count + 1,
                self.agent_mcp_config.agent_mcp_max_loops,
                self.state
            );

            let next_state = match self.state.clone() {
                AgentState::Thinking => self.thinking_step().await?,
                AgentState::Executing(choice) => self.executing_step(&choice, auth_data.clone()).await?,
                AgentState::Evaluating(choice, tool_results) => self.evaluating_step(&choice, tool_results).await?,
                AgentState::Correcting(issue) => self.correcting_step(issue).await?,
                AgentState::Finished => break,
            };
            self.state = next_state;
        }

        if let Some(last_message) = self.messages.last() {
            if last_message.role == self.agent_mcp_config.agent_mcp_role_assistant {
                final_message = Some(last_message.clone());
            }
        }

        if final_message.is_none() {
            warn!("Agent finished without a definitive final message.");
            return Err(anyhow::anyhow!(
                "Agent reached maximum loops ({}) without returning a final answer (likely an infinite tool calling loop).",
                self.agent_mcp_config.agent_mcp_max_loops
            ));
        }

        Ok(final_message)
    }

    pub async fn run_agent_internal(
        &mut self,
        user_message: Message,
        auth_data: Option<crate::SsiAuthenticationData>,
    ) -> anyhow::Result<Option<Message>> {
        // Refresh tools dynamically (picks up newly connected OAuth integrations)
        // [User Request]: Skipped retrieving list_tools on every call to avoid NATS timeout issues
        // However, if we started with 0 tools (race condition), we should attempt to load them.
        if self.llm_all_tool.is_empty() {
            info!("No tools loaded yet. Attempting to retrieve tools over NATS...");
            self.refresh_tools().await;
        }

        // Extract jti and user_did from JWT for audit trail
        if let Some(ref auth) = auth_data {
            if let Some(ref jwt) = auth.jwt {
                if let Some((jti, user_did)) = audit::extract_jti_from_jwt(jwt) {
                    self.audit_jti = Some(jti);
                    self.audit_user_did = Some(user_did);
                }
                self.audit_tenant_id = audit::extract_tenant_id_from_jwt(jwt);
            }
        }

        self.reset_messages()?;
        self.push_message(user_message);
        self.state = AgentState::Thinking;
        self.execute_loop(auth_data).await
    }

    pub async fn submit_user_text(&self, user_text: String) -> Result<String> {
        info!("MCP Agent received user text: {}", user_text);
        Ok(format!("MCP agent processed: {}", user_text))
    }
}
