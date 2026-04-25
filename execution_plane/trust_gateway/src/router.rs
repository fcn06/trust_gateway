// ─────────────────────────────────────────────────────────────
// Connector router — dispatches actions to the correct backend
//
// Phase 6: Registry-driven routing.
// Phase 7: Retry with exponential backoff (WS1.1).
//
// First checks the cached ToolRegistry for executor_type metadata,
// then falls back to tool name prefix matching (backward compat).
// All dispatch calls are wrapped in retry logic for resilience.
// ─────────────────────────────────────────────────────────────

use std::collections::HashMap;
use anyhow::Result;
use tokio::sync::RwLock;
use trust_core::action::{ActionRequest, ActionResult, ActionStatus};
use trust_core::grant::SignedGrant;

use crate::gateway::GatewayState;

// ─── Retry Configuration (WS1.1) ───────────────────────────

/// Maximum number of retry attempts before giving up.
const MAX_RETRIES: u32 = 3;

/// Base delay for exponential backoff (milliseconds).
const RETRY_BASE_MS: u64 = 200;

/// Multiplier for exponential backoff (delay = base * factor^attempt).
const RETRY_FACTOR: u64 = 4;

/// Which executor backend to dispatch to.
#[derive(Debug, Clone, Copy)]
enum ExecutorTarget {
    ConnectorMcp,
    ClawExecutor,
    VpMcp,
    RestaurantService,
}

/// Check if an error is transient and worth retrying.
/// Only retries on transport errors — never on 4xx or business logic errors.
fn is_retryable_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("connection refused")
        || msg.contains("timeout")
        || msg.contains("timed out")
        || msg.contains("connect error")
        || msg.contains("connection error")
        || msg.contains("connection reset")
        || msg.contains("broken pipe")
        || msg.contains("502")
        || msg.contains("503")
        || msg.contains("504")
        || msg.contains("handshake failed")
}

// ─── Circuit Breaker (WS1.2) ────────────────────────────────

/// Circuit breaker states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitState {
    /// Normal operation — requests pass through.
    Closed,
    /// Connector is considered down — requests are rejected immediately.
    Open { opened_at: std::time::Instant },
    /// Allowing a single probe request to test if the connector has recovered.
    HalfOpen,
}

/// Per-connector circuit breaker for resilience.
///
/// Three states: Closed (normal) → Open (reject for N seconds) → HalfOpen (one probe).
/// Tracks consecutive failures per connector in shared state.
pub struct CircuitBreaker {
    state: RwLock<CircuitState>,
    consecutive_failures: RwLock<u32>,
    failure_threshold: u32,
    recovery_timeout: std::time::Duration,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with default thresholds.
    pub fn new(failure_threshold: u32, recovery_timeout: std::time::Duration) -> Self {
        Self {
            state: RwLock::new(CircuitState::Closed),
            consecutive_failures: RwLock::new(0),
            failure_threshold,
            recovery_timeout,
        }
    }

    /// Check if the circuit allows a request through.
    /// Returns Ok(()) if allowed, Err with reason if blocked.
    pub async fn check_allowed(&self) -> Result<()> {
        let state = *self.state.read().await;
        match state {
            CircuitState::Closed => Ok(()),
            CircuitState::HalfOpen => Ok(()), // Allow probe
            CircuitState::Open { opened_at } => {
                if opened_at.elapsed() >= self.recovery_timeout {
                    // Transition to half-open: allow one probe
                    *self.state.write().await = CircuitState::HalfOpen;
                    tracing::info!("🔌 Circuit breaker transitioning to HalfOpen (recovery probe)");
                    Ok(())
                } else {
                    let remaining = self.recovery_timeout - opened_at.elapsed();
                    Err(anyhow::anyhow!(
                        "ConnectorUnavailable: circuit breaker open, retry in {:.0}s",
                        remaining.as_secs_f64()
                    ))
                }
            }
        }
    }

    /// Record a successful dispatch — resets the circuit to Closed.
    pub async fn record_success(&self) {
        *self.consecutive_failures.write().await = 0;
        let prev = *self.state.read().await;
        if prev != CircuitState::Closed {
            *self.state.write().await = CircuitState::Closed;
            tracing::info!("✅ Circuit breaker closed (connector recovered)");
        }
    }

    /// Record a failed dispatch — may trip the circuit to Open.
    pub async fn record_failure(&self) {
        let mut failures = self.consecutive_failures.write().await;
        *failures += 1;
        if *failures >= self.failure_threshold {
            let mut state = self.state.write().await;
            if *state != CircuitState::Closed {
                return; // Already open
            }
            *state = CircuitState::Open {
                opened_at: std::time::Instant::now(),
            };
            tracing::warn!(
                "🔴 Circuit breaker OPEN after {} consecutive failures (rejecting for {:?})",
                *failures, self.recovery_timeout
            );
        }
    }
}

// ─── Tool Registry (Phase 6) ────────────────────────────────

/// Cached tool metadata fetched from Host skills.json and VP MCP servers.
#[derive(Debug, Clone)]
pub struct ToolRegistryEntry {
    pub executor_type: String,  // "mcp" or "claw"
    pub category: Option<String>,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// In-memory cache of the tool registry with a TTL.
pub struct ToolRegistry {
    entries: RwLock<HashMap<String, ToolRegistryEntry>>,
    last_refresh: RwLock<Option<std::time::Instant>>,
    ttl: std::time::Duration,
}

impl ToolRegistry {
    /// Create a new empty registry with the given refresh TTL.
    pub fn new(ttl: std::time::Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(None),
            ttl,
        }
    }

    /// Look up a tool's executor_type from the registry.
    /// Returns None if the tool is not in the registry.
    pub async fn lookup(&self, tool_name: &str) -> Option<ToolRegistryEntry> {
        let entries = self.entries.read().await;
        entries.get(tool_name).cloned()
    }

    /// Return all cached tools for API discovery.
    pub async fn all_tools(&self) -> Vec<(String, ToolRegistryEntry)> {
        let entries = self.entries.read().await;
        entries.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Force an immediate registry refresh regardless of TTL (WS1.5).
    pub async fn force_refresh(&self, client: &reqwest::Client, host_url: &str, vp_mcp_url: &str) {
        // Reset last_refresh to force the stale check to pass
        *self.last_refresh.write().await = None;
        self.refresh_if_stale(client, host_url, vp_mcp_url).await;
    }

    /// Refresh the registry from the Host's /.well-known/skills.json
    /// and the VP MCP Server if the cache has expired.
    pub async fn refresh_if_stale(&self, client: &reqwest::Client, host_url: &str, vp_mcp_url: &str) {
        // Check if refresh is needed
        {
            let last = self.last_refresh.read().await;
            if let Some(instant) = *last {
                if instant.elapsed() < self.ttl {
                    return;
                }
            }
        }

        // Fetch Host skills
        let url = format!("{}/.well-known/skills.json", host_url);
        let skills = match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                resp.json::<serde_json::Value>().await.unwrap_or_default()
            }
            _ => serde_json::json!({}),
        };

        let mut new_entries = HashMap::new();

        // 1. Discovery from Host's skills.json (Static)
        if let Some(mcp_tools) = skills.get("mcp_tools").and_then(|v| v.as_array()) {
            for tool in mcp_tools {
                if let Some(name) = tool.get("name").and_then(|v| v.as_str()) {
                    new_entries.insert(name.to_string(), ToolRegistryEntry {
                        executor_type: "mcp".to_string(),
                        category: tool.get("category").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        description: tool.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        input_schema: tool.get("inputSchema").cloned().unwrap_or(serde_json::json!({})),
                    });
                }
            }
        }

        if let Some(claw_skills) = skills.get("claw_skills").and_then(|v| v.as_array()) {
            for skill in claw_skills {
                if let Some(name) = skill.get("name").and_then(|v| v.as_str()) {
                    new_entries.insert(name.to_string(), ToolRegistryEntry {
                        executor_type: "claw".to_string(),
                        category: skill.get("category").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        description: skill.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        input_schema: skill.get("input_schema").cloned().unwrap_or(serde_json::json!({})),
                    });
                }
            }
        }

        // 2. Discovery from VP MCP Server (Dynamic - Safe timeout)
        if let Ok(vp_tools) = discover_vp_mcp_tools(vp_mcp_url, client.clone()).await {
            for tool in vp_tools {
                new_entries.insert(tool.name.to_string(), ToolRegistryEntry {
                    executor_type: "vp_mcp".to_string(),
                    category: Some("vp".to_string()),
                    description: tool.description.as_ref().map(|s| s.to_string()).unwrap_or_default(),
                    input_schema: serde_json::to_value(tool.input_schema).unwrap_or(serde_json::json!({})),
                });
            }
        }

        let count = new_entries.len();
        *self.entries.write().await = new_entries;
        *self.last_refresh.write().await = Some(std::time::Instant::now());
        tracing::info!("📋 Tool registry refreshed: {} entries cached", count);
    }
}

/// Discover tools from a standard MCP SSE server.
pub async fn discover_vp_mcp_tools(uri: &str, client: reqwest::Client) -> Result<Vec<rmcp::model::Tool>> {
    let mut sse_uri = uri.trim_end_matches('/').to_string();
    if !sse_uri.ends_with("/sse") {
        sse_uri = format!("{}/sse", sse_uri);
    }

    let transport = ssi_mcp_runtime::mcp_client::transport::create_transport(sse_uri, None, client);

    let client_info = rmcp::model::InitializeRequestParams::new(
        rmcp::model::ClientCapabilities::default(),
        rmcp::model::Implementation::new("trust-gateway-discovery", "0.1.0"),
    );

    let mcp_client = rmcp::serve_client(client_info, transport).await
        .map_err(|e| anyhow::anyhow!("VP Discovery handshake failed: {}", e))?;

    let list_tools = mcp_client.list_tools(Default::default()).await?;
    Ok(list_tools.tools)
}

// ─── Dispatch Logic ─────────────────────────────────────────

/// Determine which executor backend should handle a given tool.
async fn determine_executor_target(state: &GatewayState, tool_name: &str) -> ExecutorTarget {
    // Phase 6: Registry-first lookup
    if let Some(ref registry) = state.tool_registry {
        registry.refresh_if_stale(&state.http_client, &state.connectors.host_url, &state.connectors.vp_mcp_url).await;

        if let Some(entry) = registry.lookup(tool_name).await {
            tracing::info!("📋 Registry-driven routing: '{}' → executor='{}'", tool_name, entry.executor_type);
            return match entry.executor_type.as_str() {
                "claw" => ExecutorTarget::ClawExecutor,
                "vp_mcp" => ExecutorTarget::VpMcp,
                "restaurant" => ExecutorTarget::RestaurantService,
                _ => ExecutorTarget::ConnectorMcp,
            };
        }
    }

    // Resilience: If registry missed, check prefix before defaulting to connector
    if tool_name.starts_with("claw_") {
        return ExecutorTarget::ClawExecutor;
    }
    if tool_name.starts_with("restaurant_") {
        return ExecutorTarget::RestaurantService;
    }
    if tool_name.starts_with("vp_") || tool_name == "discover_agent_services" {
        return ExecutorTarget::VpMcp;
    }

    // Default: connector_mcp_server
    ExecutorTarget::ConnectorMcp
}

/// Dispatch an authorized action to the appropriate executor.
///
/// WS1.1: All dispatches are wrapped in `dispatch_with_retry()` which
/// retries up to 3 times with exponential backoff on transient errors.
///
/// WS1.2: Integrated circuit breaker checks — if the target connector's
/// circuit is open, returns fast-fail without attempting dispatch.
pub async fn dispatch_to_connector(
    state: &GatewayState,
    req: &ActionRequest,
    grant: &SignedGrant,
) -> Result<ActionResult> {
    let target = determine_executor_target(state, &req.action.name).await;
    let connector_key = match target {
        ExecutorTarget::ConnectorMcp => "connector_mcp",
        ExecutorTarget::ClawExecutor => "claw_executor",
        ExecutorTarget::VpMcp => "vp_mcp",
        ExecutorTarget::RestaurantService => "restaurant_service",
    };

    // WS1.2: Check circuit breaker before dispatching
    if let Some(cb) = state.circuit_breakers.get(connector_key) {
        if let Err(e) = cb.check_allowed().await {
            tracing::warn!("🔴 Circuit breaker blocked dispatch for '{}': {}", req.action.name, e);
            return Ok(ActionResult {
                action_id: req.action_id.clone(),
                status: ActionStatus::Failed,
                connector: connector_key.to_string(),
                external_reference: None,
                output: serde_json::json!([{
                    "type": "text",
                    "text": format!("Service temporarily unavailable: {}. Please try again shortly.", e)
                }]),
            });
        }
    }

    let result = dispatch_with_retry(state, req, grant, target, MAX_RETRIES).await;

    // WS1.2: Update circuit breaker based on result
    if let Some(cb) = state.circuit_breakers.get(connector_key) {
        match &result {
            Ok(_) => cb.record_success().await,
            Err(_) => cb.record_failure().await,
        }
    }

    result
}

/// WS1.1 — Retry wrapper with exponential backoff.
///
/// Retries on transient transport errors only:
/// - Connection refused / timeout / reset
/// - HTTP 502 / 503 / 504
///
/// Never retries on 4xx or business logic errors (fail-closed).
/// Emits `AuditEventType::ActionRetried` on each retry for Trust Replay.
async fn dispatch_with_retry(
    state: &GatewayState,
    req: &ActionRequest,
    grant: &SignedGrant,
    target: ExecutorTarget,
    max_retries: u32,
) -> Result<ActionResult> {
    let mut last_err = None;

    for attempt in 0..=max_retries {
        let result = match target {
            ExecutorTarget::ConnectorMcp => dispatch_to_connector_mcp(state, req, grant).await,
            ExecutorTarget::ClawExecutor => dispatch_to_claw_executor(state, req, grant).await,
            ExecutorTarget::VpMcp => dispatch_to_vp_mcp(state, req, grant).await,
            ExecutorTarget::RestaurantService => dispatch_to_restaurant_service(state, req, grant).await,
        };

        match result {
            Ok(action_result) => return Ok(action_result),
            Err(e) if attempt < max_retries && is_retryable_error(&e) => {
                let delay_ms = RETRY_BASE_MS * RETRY_FACTOR.pow(attempt);
                let delay = std::time::Duration::from_millis(delay_ms);

                tracing::warn!(
                    "⚠️ Dispatch attempt {}/{} for '{}' failed (retrying in {:?}): {}",
                    attempt + 1, max_retries + 1, req.action.name, delay, e
                );

                // Emit ActionRetried audit event so Trust Replay shows retries
                crate::gateway::publish_audit(
                    &state.jetstream,
                    &state.nats,
                    &req.tenant_id,
                    trust_core::audit::AuditEventType::ActionRetried,
                    "trust_gateway",
                    &req.action_id,
                    serde_json::json!({
                        "attempt": attempt + 1,
                        "max_retries": max_retries,
                        "delay_ms": delay_ms,
                        "error": format!("{}", e),
                        "target": format!("{:?}", target),
                    }),
                ).await;

                tokio::time::sleep(delay).await;
                last_err = Some(e);
            }
            Err(e) => {
                // Non-retryable error — fail immediately (fail-closed)
                return Err(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!(
        "All {} retries exhausted for action '{}'",
        max_retries, req.action.name
    )))
}

/// Dispatch to the existing connector_mcp_server via HTTP.
async fn dispatch_to_connector_mcp(
    state: &GatewayState,
    req: &ActionRequest,
    grant: &SignedGrant,
) -> Result<ActionResult> {
    tracing::info!("🔧 Routing action '{}' to connector_mcp_server", req.action.name);

    let req_body = serde_json::json!({
        "tenant_id": req.tenant_id,
        "tool_name": req.action.name,
        "arguments": req.action.arguments,
        "execution_grant": grant.token,
    });

    let resp = state.http_client
        .post(format!("{}/tools/execute", state.connectors.connector_mcp_url))
        .json(&req_body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Connector connection error: {}", e))?;

    if resp.status().is_success() {
        let exec_result: serde_json::Value = resp.json().await.unwrap_or_default();
        let success = exec_result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

        let raw_output = if !success && exec_result.get("error").is_some() {
            exec_result.get("error").cloned().unwrap()
        } else {
            exec_result.get("content").cloned().unwrap_or(exec_result.clone())
        };

        // Standardize: Wrap JSON into a single MCP text block for the Agent
        let output = serde_json::json!([{
            "type": "text",
            "text": if raw_output.is_string() {
                raw_output.as_str().unwrap_or_default().to_string()
            } else {
                serde_json::to_string_pretty(&raw_output).unwrap_or_default()
            }
        }]);

        Ok(ActionResult {
            action_id: req.action_id.clone(),
            status: if success { ActionStatus::Succeeded } else { ActionStatus::Failed },
            connector: "connector_mcp_server".to_string(),
            external_reference: exec_result.get("external_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
            output,
        })
    } else {
        let status = resp.status();
        let err_text = resp.text().await.unwrap_or_default();
        Err(anyhow::anyhow!("Connector HTTP error {}: {}", status.as_u16(), err_text))
    }
}

/// Dispatch to the Native Skill Executor (Claw backend).
async fn dispatch_to_claw_executor(
    state: &GatewayState,
    req: &ActionRequest,
    grant: &SignedGrant,
) -> Result<ActionResult> {
    tracing::info!("🦞 Routing action '{}' to Native Skill Executor (Claw)", req.action.name);

    let req_body = serde_json::json!({
        "action_id": req.action_id,
        "skill_name": req.action.name,
        "arguments": req.action.arguments,
        "tenant_id": req.tenant_id,
        "execution_grant": grant.token,
    });

    let resp = state.http_client
        .post(format!("{}/invoke", state.connectors.skill_executor_url))
        .json(&req_body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Skill executor connection error: {}", e))?;

    if resp.status().is_success() {
        let exec_result: serde_json::Value = resp.json().await.unwrap_or_default();

        // Standardize: Wrap JSON into a single MCP text block for the Agent
        let output = serde_json::json!([{
            "type": "text",
            "text": if exec_result.is_string() {
                exec_result.as_str().unwrap_or_default().to_string()
            } else {
                serde_json::to_string_pretty(&exec_result).unwrap_or_default()
            }
        }]);

        Ok(ActionResult {
            action_id: req.action_id.clone(),
            status: ActionStatus::Succeeded,
            connector: "native_skill_executor".to_string(),
            external_reference: None,
            output,
        })
    } else {
        let status = resp.status();
        let err_text = resp.text().await.unwrap_or_default();
        Err(anyhow::anyhow!("Skill executor HTTP error {}: {}", status.as_u16(), err_text))
    }
}

/// Dispatch directly to the VP MCP Server via SSE.
async fn dispatch_to_vp_mcp(
    state: &GatewayState,
    req: &ActionRequest,
    grant: &SignedGrant,
) -> Result<ActionResult> {
    use rmcp::model::CallToolRequestParams;

    tracing::info!("📡 Routing action '{}' directly to VP MCP Server", req.action.name);

    // Ensure the URI has /sse path
    let mut sse_uri = state.connectors.vp_mcp_url.trim_end_matches('/').to_string();
    if !sse_uri.ends_with("/sse") {
        sse_uri = format!("{}/sse", sse_uri);
    }

    // 1. Create transport to VP server
    let transport = ssi_mcp_runtime::mcp_client::transport::create_transport(sse_uri, None, state.http_client.clone());

    // 2. Handshake
    let client_info = rmcp::model::InitializeRequestParams::default();
    let mcp_client = rmcp::serve_client(client_info, transport).await
        .map_err(|e| anyhow::anyhow!("VP handshake failed: {}", e))?;

    // 3. Inject execution grant into arguments so VP server can verify it
    let mut args = req.action.arguments.clone();
    if let Some(obj) = args.as_object_mut() {
        let meta = obj.entry("_meta").or_insert(serde_json::json!({}));
        if let Some(meta_obj) = meta.as_object_mut() {
            meta_obj.insert("X-Execution-Grant".to_string(), serde_json::json!(grant.token));
        }
    }

    // 4. Call tool
    let result = mcp_client.call_tool(
        CallToolRequestParams::new(req.action.name.clone())
            .with_arguments(args.as_object().cloned().unwrap_or_default())
    ).await.map_err(|e| anyhow::anyhow!("VP tool execution failed: {}", e))?;

    Ok(ActionResult {
        action_id: req.action_id.clone(),
        status: ActionStatus::Succeeded,
        connector: "vp_mcp_server".to_string(),
        external_reference: None,
        output: serde_json::to_value(result.content).unwrap_or(serde_json::json!([])),
    })
}

/// Dispatch to the Restaurant State Service.
/// Mirrors the Claw executor pattern — POST /invoke with standard payload.
async fn dispatch_to_restaurant_service(
    state: &GatewayState,
    req: &ActionRequest,
    grant: &SignedGrant,
) -> Result<ActionResult> {
    tracing::info!("🍽️ Routing action '{}' to Restaurant State Service", req.action.name);

    let req_body = serde_json::json!({
        "action_id": req.action_id,
        "skill_name": req.action.name,
        "arguments": req.action.arguments,
        "tenant_id": req.tenant_id,
        "execution_grant": grant.token,
    });

    let resp = state.http_client
        .post(format!("{}/invoke", state.connectors.restaurant_service_url))
        .json(&req_body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Restaurant service connection error: {}", e))?;

    if resp.status().is_success() {
        let exec_result: serde_json::Value = resp.json().await.unwrap_or_default();
        let success = exec_result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

        // Standardize: Wrap JSON into a single MCP text block for the Agent
        let output = serde_json::json!([{
            "type": "text",
            "text": if exec_result.is_string() {
                exec_result.as_str().unwrap_or_default().to_string()
            } else {
                serde_json::to_string_pretty(&exec_result).unwrap_or_default()
            }
        }]);

        Ok(ActionResult {
            action_id: req.action_id.clone(),
            status: if success { ActionStatus::Succeeded } else { ActionStatus::Failed },
            connector: "restaurant_state_service".to_string(),
            external_reference: None,
            output,
        })
    } else {
        let status = resp.status();
        let err_text = resp.text().await.unwrap_or_default();
        Err(anyhow::anyhow!("Restaurant service HTTP error {}: {}", status.as_u16(), err_text))
    }
}
