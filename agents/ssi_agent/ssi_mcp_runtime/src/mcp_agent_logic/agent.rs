use anyhow::Context;
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
// NOTE: Clone intentionally not derived — McpAgent owns mutable execution state
// (messages, AgentState). Cloning a mid-execution agent would snapshot state,
// which is almost never the desired behavior. Callers use Arc<Mutex<McpAgent>>.
pub struct McpAgent {
    llm_interaction: ChatLlmInteraction,
    pub nats_client: Arc<async_nats::Client>,
    pub dispatch_subject: String,
    messages: Vec<Message>,
    llm_all_tool: Vec<Tool>,
    agent_mcp_config: McpRuntimeConfig,
    original_system_prompt: String,
    state: AgentState,
    /// JWT session ID for audit trail correlation
    audit_jti: Option<String>,
    /// Delegating user's DID for audit trail
    audit_user_did: Option<String>,
    /// Tenant ID for tenant-scoped audit trail
    audit_tenant_id: Option<String>,
}

impl McpAgent {
    /// Dynamically overrides the system prompt for the agent runtime.
    /// This is used for B2B semantic filtering, where external DIDs get specific DLP prompts.
    pub fn override_system_prompt(&mut self, prompt: String) {
        self.agent_mcp_config.agent_mcp_system_prompt = prompt;
    }

    /// Resets the overridden system prompt to the original system prompt configured at startup.
    pub fn reset_system_prompt(&mut self) {
        self.agent_mcp_config.agent_mcp_system_prompt = self.original_system_prompt.clone();
    }

    pub async fn new(
        agent_mcp_config: McpRuntimeConfig,
        mcp_runtime_api_key: Option<String>,
        nats_client: Option<Arc<async_nats::Client>>,
    ) -> anyhow::Result<Self> {
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

        let nats_url = env::var("NATS_URL")
            .ok()
            .or_else(|| agent_mcp_config.agent_mcp_nats_url.clone())
            .unwrap_or_else(|| "nats://127.0.0.1:4222".to_string());

        let dispatch_subject = agent_mcp_config.agent_mcp_nats_dispatch_subject
            .clone()
            .unwrap_or_else(|| "trust.v1".to_string());

        // Use injected NATS client or create one (fallback for standalone usage)
        let nats_client = if let Some(client) = nats_client {
            client
        } else {
            let mut nats_options = if let Ok(seed) = env::var("NATS_NKEY_SEED") {
                async_nats::ConnectOptions::with_nkey(seed)
            } else {
                async_nats::ConnectOptions::new()
            };
            let timeout_secs = env::var("NATS_REQUEST_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(25);
            nats_options = nats_options.request_timeout(Some(std::time::Duration::from_secs(timeout_secs)));
            Arc::new(async_nats::connect_with_options(&nats_url, nats_options)
                .await
                .context("Failed to connect to NATS in McpAgent")?)
        };

        // Retrieve tools over NATS bridging (fallback to empty if bridge isn't up yet - will refresh later)
        let list_tools = match crate::mcp_client::mcp_client::get_tools_list_over_nats(nats_client.clone(), &dispatch_subject, "").await {
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
            content: Some(system_message.clone()),
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
            original_system_prompt: system_message,
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

    /// Re-fetch tools from the Trust Gateway so the tool list reflects
    /// the current active bundle (after switch_context).
    ///
    /// This calls the gateway's NATS `tools.list` endpoint
    /// (which is bundle-filtered by session).
    pub async fn refresh_tools(&mut self) {
        let session_jti = self.audit_jti.clone().unwrap_or_default();

        match crate::mcp_client::mcp_client::get_tools_list_over_nats(
            self.nats_client.clone(),
            &self.dispatch_subject,
            &session_jti,
        ).await {
            Ok(tools) => {
                match define_all_tools(tools) {
                    Ok(new_tools) => {
                        let old_count = self.llm_all_tool.len();
                        self.llm_all_tool = new_tools;
                        let new_count = self.llm_all_tool.len();
                        if new_count != old_count {
                            info!("🔄 Tools refreshed (NATS): {} → {} tools", old_count, new_count);
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
        
        let max_retries = 3;
        let mut delay = std::time::Duration::from_millis(1000);
        
        for attempt in 1..=max_retries {
            match self.llm_interaction.call_chat_completions_v2(request_payload).await {
                Ok(response) => {
                    debug!("LLM API Response (attempt {}): {:?}", attempt, response);
                    return Ok(response);
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    let is_rate_limit = err_msg.contains("429") || err_msg.contains("rate_limit") || err_msg.contains("Rate limit");
                    let is_validation = err_msg.contains("validation") || err_msg.contains("request.tools") || err_msg.contains("validation failed");
                    
                    if is_validation {
                        // Do not retry validation errors; propagate immediately so the recovery flow can handle it
                        return Err(e).context("LLM chat completion API call failed");
                    }
                    
                    if attempt == max_retries {
                        error!("❌ LLM API call failed after {} attempts: {}", max_retries, e);
                        return Err(e).context("LLM chat completion API call failed after max retries");
                    }
                    
                    let status_msg = if is_rate_limit { "Rate limit (429)" } else { "Temporary error" };
                    warn!("⚠️ LLM API call failed: {}. {} on attempt {}/{}. Retrying in {:?}...", err_msg, status_msg, attempt, max_retries, delay);
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
            }
        }
        
        anyhow::bail!("LLM API call failed after max retries")
    }

    // ──────────────────────────────────────────────────────────────
    // State Machine Steps
    // ──────────────────────────────────────────────────────────────

    /// Thinking: Call the LLM with the current message history and tools.
    /// Returns `Executing` if the LLM requests tool calls, or `Finished` otherwise.
    async fn thinking_step(&mut self) -> anyhow::Result<AgentState> {
        info!("--- Thinking ---");

        let has_tools = !self.llm_all_tool.is_empty();

        // 1. Scan for excessive consecutive search_skills or list_bundles calls to prevent infinite loops
        let mut consecutive_searches = 0;
        for msg in self.messages.iter().rev() {
            if msg.role == "assistant" {
                if let Some(tool_calls) = &msg.tool_calls {
                    let has_search = tool_calls.iter().any(|tc| tc.function.name == "search_skills" || tc.function.name == "list_bundles" || tc.function.name == "vp_search");
                    if has_search {
                        consecutive_searches += 1;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else if msg.role == "user" {
                break;
            }
        }

        let mut active_messages = self.messages.clone();
        if consecutive_searches >= 2 {
            tracing::warn!("⚠️ Detected consecutive search_skills/list_bundles calls ({}). Injecting loop-breaking system prompt...", consecutive_searches);
            let loop_breaker = "System Notice: You have repeatedly searched for skills or listed bundles without taking a progress action. If the required tool is in another bundle, call `switch_context(bundle_name: \"<bundle>\")` immediately. If you have already switched or the tool is not found, explain to the user what bundle context or permissions are required and stop.";
            active_messages.push(Message {
                role: "system".to_string(),
                content: Some(loop_breaker.to_string()),
                tool_call_id: None,
                tool_calls: None,
            });
        }

        let request_payload = ChatCompletionRequest {
            model: self.llm_interaction.model_id.clone(),
            messages: active_messages,
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

        let response = match self.call_api_v2(&request_payload).await {
            Ok(resp) => resp,
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("Tool call validation failed") || err_msg.contains("not in request.tools") || err_msg.contains("which was not in request.tools") {
                    // Try to extract the tool name
                    let mut extracted_tool = None;
                    if let Some(start) = err_msg.find("attempted to call tool '") {
                        let rest = &err_msg[start + "attempted to call tool '".len()..];
                        if let Some(end) = rest.find("'") {
                            extracted_tool = Some(rest[..end].to_string());
                        }
                    } else if let Some(start) = err_msg.find("tool '") {
                        let rest = &err_msg[start + "tool '".len()..];
                        if let Some(end) = rest.find("'") {
                            extracted_tool = Some(rest[..end].to_string());
                        }
                    } else if err_msg.contains("tool_use_failed") {
                        if err_msg.contains("discover_agent_services") {
                            extracted_tool = Some("discover_agent_services".to_string());
                        } else if err_msg.contains("claw_weather") {
                            extracted_tool = Some("claw_weather".to_string());
                        } else if err_msg.contains("inspect_schema") {
                            extracted_tool = Some("inspect_schema".to_string());
                        }
                    }

                    if let Some(tool_name) = extracted_tool {
                        tracing::warn!("⚠️ LLM attempted to call restricted/inactive tool '{}' which was not in request.tools. Recovering...", tool_name);
                        
                        let recovery_prompt = format!(
                            "System Warning: You attempted to call the tool '{}' directly, but it is NOT in your active bundle context! \n\
                            To use '{}', you must first call `switch_context(bundle_name: \"<bundle>\")` to activate the bundle containing that tool. \n\
                            Use `search_skills(query: \"{}\")` or `list_bundles()` to find which bundle contains '{}', then call `switch_context`.",
                            tool_name, tool_name, tool_name, tool_name
                        );
                        
                        self.messages.push(Message {
                            role: "system".to_string(),
                            content: Some(recovery_prompt),
                            tool_call_id: None,
                            tool_calls: None,
                        });
                        
                        // Recurse/retry thinking step after adding the correction prompt to context
                        return Box::pin(self.thinking_step()).await;
                    }
                }
                
                // If it's not a tool validation error, propagate
                return Err(e);
            }
        };

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

        let has_tool_calls = choice.message.tool_calls.is_some() && !choice.message.tool_calls.as_ref().unwrap().is_empty();

        if has_tool_calls {
            info!("LLM requested {} tool call(s).", choice.message.tool_calls.as_ref().unwrap().len());
            Ok(AgentState::Executing(choice))
        } else if choice.finish_reason == self.agent_mcp_config.agent_mcp_finish_reason_tool_calls {
            // Fallback for providers that set the finish_reason but might have an empty tool_calls (unlikely but safe)
            Ok(AgentState::Executing(choice))
        } else {
            info!("Agent finished thinking (reason: {:?}).", choice.finish_reason);
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

                        // If the agent successfully switched context, its available tools have changed.
                        // We must fetch the new tool list immediately so the next thinking step has them.
                        if tool_name == "switch_context" {
                            tracing::info!("🔄 Agent executed switch_context. Refreshing tools for next thinking step...");
                            self.refresh_tools().await;
                        }
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
            // Evaluate tool execution results if evaluation is enabled in configuration.
            // When disabled (default behavior for stability), we skip the Evaluating
            // and Correcting states entirely, proceeding directly back to Thinking.
            if self.agent_mcp_config.agent_mcp_enable_evaluation.unwrap_or(false) {
                Ok(AgentState::Evaluating(choice.clone(), tool_results))
            } else {
                // TODO: Stabilize evaluation logic and enable by default in production.
                self.messages.extend(tool_results);
                Ok(AgentState::Thinking)
            }
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
            content: Some(format!(
                "{}\n\nRespond with ONLY a JSON object: {{\"satisfactory\": true/false, \"reason\": \"...\"}}",
                self.agent_mcp_config.agent_mcp_evaluation_prompt
            )),
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
                // Parse structured evaluation response
                #[derive(serde::Deserialize)]
                struct EvalResult {
                    satisfactory: bool,
                    reason: String,
                }

                let (is_unsatisfactory, reason) = match serde_json::from_str::<EvalResult>(content) {
                    Ok(eval) => (!eval.satisfactory, eval.reason),
                    Err(e) => {
                        tracing::warn!("⚠️ Failed to parse EvalResult JSON: {} - Raw: {}", e, content);
                        // Fallback: If it's not valid JSON, treat it as unsatisfactory to force a retry
                        (true, format!("Evaluation failed to produce valid JSON: {}", content))
                    }
                };

                if is_unsatisfactory {
                    warn!("Tool execution unsatisfactory: {}", reason);
                    return Ok(AgentState::Correcting(reason));
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
            warn!("Agent finished without a definitive final message. Generating fallback response.");
            let fallback_message = Message {
                role: self.agent_mcp_config.agent_mcp_role_assistant.clone(),
                content: Some("I apologize, but I encountered an execution issue while trying to process your request (maximum reasoning steps exceeded). This often happens if an external service is unavailable or rate-limited. Please try again in a few moments.".to_string()),
                tool_calls: None,
                tool_call_id: None,
            };
            final_message = Some(fallback_message);
        }

        Ok(final_message)
    }

    pub async fn run_agent_internal(
        &mut self,
        user_message: Message,
        auth_data: Option<crate::SsiAuthenticationData>,
    ) -> anyhow::Result<Option<Message>> {
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

        // Always refresh tools dynamically at the start of every request so the
        // cached list is in sync with the active session bundle for this session JTI.
        self.refresh_tools().await;

        self.reset_messages()?;
        self.push_message(user_message);
        self.state = AgentState::Thinking;
        self.execute_loop(auth_data).await
    }


}
