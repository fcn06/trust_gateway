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

use anyhow::{Context, Result};
use futures::StreamExt;
use rmcp::model::CallToolRequestParams;
use std::collections::HashMap;
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

#[derive(Debug, Clone, Copy)]
enum ExecutorTarget {
    ConnectorMcp,
    ClawExecutor,
    SandboxedSkill,
    VpMcp,
    InternalMeta,
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
        || msg.contains("transport closed")
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

/// Interior state for the circuit breaker, protected by a single lock.
///
/// P2/M2 fix: Previously `state` and `consecutive_failures` lived behind
/// two separate `RwLock`s. Between acquiring `consecutive_failures`
/// (increment) and `state` (trip) in `record_failure()`, another task
/// could read `state` as Closed and proceed — a classic TOCTOU race.
/// Now both fields are behind a single `RwLock`, ensuring atomic reads
/// and writes of the full circuit breaker state.
struct CircuitBreakerInner {
    state: CircuitState,
    consecutive_failures: u32,
}

/// Per-connector circuit breaker for resilience.
///
/// Three states: Closed (normal) → Open (reject for N seconds) → HalfOpen (one probe).
/// Tracks consecutive failures per connector in shared state.
pub struct CircuitBreaker {
    inner: RwLock<CircuitBreakerInner>,
    failure_threshold: u32,
    recovery_timeout: std::time::Duration,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with default thresholds.
    pub fn new(failure_threshold: u32, recovery_timeout: std::time::Duration) -> Self {
        Self {
            inner: RwLock::new(CircuitBreakerInner {
                state: CircuitState::Closed,
                consecutive_failures: 0,
            }),
            failure_threshold,
            recovery_timeout,
        }
    }

    /// Check if the circuit allows a request through.
    /// Returns Ok(()) if allowed, Err with reason if blocked.
    pub async fn check_allowed(&self) -> Result<()> {
        // Fast path: read lock only
        {
            let inner = self.inner.read().await;
            match inner.state {
                CircuitState::Closed | CircuitState::HalfOpen => return Ok(()),
                CircuitState::Open { opened_at } => {
                    if opened_at.elapsed() < self.recovery_timeout {
                        let remaining = self.recovery_timeout - opened_at.elapsed();
                        return Err(anyhow::anyhow!(
                            "ConnectorUnavailable: circuit breaker open, retry in {:.0}s",
                            remaining.as_secs_f64()
                        ));
                    }
                    // Fall through to upgrade to write lock for state transition
                }
            }
        }

        // Slow path: transition Open → HalfOpen (needs write lock)
        let mut inner = self.inner.write().await;
        if let CircuitState::Open { opened_at } = inner.state {
            if opened_at.elapsed() >= self.recovery_timeout {
                inner.state = CircuitState::HalfOpen;
                tracing::info!("🔌 Circuit breaker transitioning to HalfOpen (recovery probe)");
                return Ok(());
            }
        }
        // Re-check in case another task already transitioned
        match inner.state {
            CircuitState::Closed | CircuitState::HalfOpen => Ok(()),
            CircuitState::Open { opened_at } => {
                let remaining = self.recovery_timeout - opened_at.elapsed();
                Err(anyhow::anyhow!(
                    "ConnectorUnavailable: circuit breaker open, retry in {:.0}s",
                    remaining.as_secs_f64()
                ))
            }
        }
    }

    /// Record a successful dispatch — resets the circuit to Closed.
    pub async fn record_success(&self) {
        let mut inner = self.inner.write().await;
        let was_open = inner.state != CircuitState::Closed;
        inner.consecutive_failures = 0;
        inner.state = CircuitState::Closed;
        if was_open {
            tracing::info!("✅ Circuit breaker closed (connector recovered)");
        }
    }

    /// Record a failed dispatch — may trip the circuit to Open.
    pub async fn record_failure(&self) {
        let mut inner = self.inner.write().await;
        inner.consecutive_failures += 1;
        if inner.consecutive_failures >= self.failure_threshold
            && inner.state == CircuitState::Closed
        {
            inner.state = CircuitState::Open {
                opened_at: std::time::Instant::now(),
            };
            tracing::warn!(
                "🔴 Circuit breaker OPEN after {} consecutive failures (rejecting for {:?})",
                inner.consecutive_failures,
                self.recovery_timeout
            );
        }
    }
}

// ─── Tool Registry (Phase 6) ────────────────────────────────

/// Cached tool metadata fetched from Host skills.json and VP MCP servers.
#[derive(Debug, Clone)]
pub struct ToolRegistryEntry {
    pub executor_type: String, // "mcp" or "claw"
    pub category: Option<String>,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub cron: Option<String>,
}

/// In-memory cache of the tool registry with a TTL.
pub struct ToolRegistry {
    entries: RwLock<HashMap<String, ToolRegistryEntry>>,
    last_refresh: RwLock<Option<std::time::Instant>>,
    ttl: std::time::Duration,
    refresh_mutex: tokio::sync::Mutex<()>,
}

impl ToolRegistry {
    /// Create a new empty registry with the given refresh TTL.
    pub fn new(ttl: std::time::Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(None),
            ttl,
            refresh_mutex: tokio::sync::Mutex::new(()),
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
        entries
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Force an immediate registry refresh regardless of TTL (WS1.5).
    pub async fn force_refresh(
        &self,
        client: &reqwest::Client,
        host_url: &str,
    ) {
        // Reset last_refresh to force the stale check to pass
        *self.last_refresh.write().await = None;
        self.refresh_if_stale(client, host_url).await;
    }

    /// Refresh the registry from the Host's /.well-known/skills.json
    /// and built-in tool descriptors if the cache has expired.
    pub async fn refresh_if_stale(
        &self,
        client: &reqwest::Client,
        host_url: &str,
    ) {
        // Check if refresh is needed (fast path)
        {
            let last = self.last_refresh.read().await;
            if let Some(instant) = *last {
                if instant.elapsed() < self.ttl {
                    return;
                }
            }
        }

        // Acquire the refresh mutex to ensure only one task runs the refresh (4.2)
        let _guard = self.refresh_mutex.lock().await;

        // Double check if another thread refreshed while we were waiting for the lock
        {
            let last = self.last_refresh.read().await;
            if let Some(instant) = *last {
                if instant.elapsed() < self.ttl {
                    return;
                }
            }
        }

        let mut new_entries = HashMap::new();

        // 1. Discovery from Host's skills.json (Static)
        // We still fetch from the Host because it may define dynamic local skills
        let url = format!("{}/.well-known/skills.json", host_url);
        let mut host_failed = false;
        let skills = match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                resp.json::<serde_json::Value>().await.unwrap_or_default()
            }
            _ => {
                host_failed = true;
                serde_json::json!({})
            }
        };

        if let Some(mcp_tools) = skills.get("mcp_tools").and_then(|v| v.as_array()) {
            for tool in mcp_tools {
                if let Some(name) = tool.get("name").and_then(|v| v.as_str()) {
                    new_entries.insert(
                        name.to_string(),
                        ToolRegistryEntry {
                            executor_type: "mcp".to_string(),
                            category: tool.get("category").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            description: tool.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            input_schema: tool.get("inputSchema").cloned().unwrap_or(serde_json::json!({})),
                            cron: None,
                        },
                    );
                }
            }
        }

        if let Some(claw_skills) = skills.get("claw_skills").and_then(|v| v.as_array()) {
            for skill in claw_skills {
                if let Some(name) = skill.get("name").and_then(|v| v.as_str()) {
                    let executor_type = skill.get("executor_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("claw")
                        .to_string();
                    new_entries.insert(
                        name.to_string(),
                        ToolRegistryEntry {
                            executor_type,
                            category: skill.get("category").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            description: skill.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            input_schema: skill.get("input_schema").cloned().unwrap_or(serde_json::json!({})),
                            cron: skill.get("cron").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        },
                    );
                }
            }
        }

        if host_failed {
            tracing::warn!("⚠️ Host tool discovery failed. Retaining stale cache for Host tools.");
            let old_entries = self.entries.read().await.clone();
            for (k, v) in old_entries {
                let came_from_host = v.executor_type == "mcp";
                if came_from_host {
                    new_entries.entry(k).or_insert(v);
                }
            }
        }

        // 2. Discovery from Built-in Descriptors (Replaces Legacy HTTP NSE/Connector/VP)
        for desc in trust_core::tool_registry::builtin_descriptors() {
            let executor_type = match desc.executor_profile {
                trust_core::tool_registry::ExecutorProfile::Connector => "connector".to_string(),
                trust_core::tool_registry::ExecutorProfile::Vp => "vp".to_string(),
                trust_core::tool_registry::ExecutorProfile::NativeTool => "native-tool".to_string(),
                trust_core::tool_registry::ExecutorProfile::SandboxedTool => "sandboxed-tool".to_string(),
                trust_core::tool_registry::ExecutorProfile::SandboxedSkill => "sandboxed-skill".to_string(),
            };
            
            let category = desc.bundle_membership.first().cloned();
            let existing_cron = new_entries.get(&desc.mcp_name).and_then(|e| e.cron.clone());

            new_entries.insert(
                desc.mcp_name.clone(),
                ToolRegistryEntry {
                    executor_type,
                    category,
                    description: if desc.description.is_empty() { desc.display_name.clone() } else { desc.description.clone() },
                    input_schema: desc.input_schema.clone(),
                    cron: desc.cron.clone().or(existing_cron),
                },
            );
        }

        let count = new_entries.len();
        
        // Phase 10: Strict meta-tool exclusion.
        // We no longer filter these out because we want them to be categorized into bundles
        // (like the 'core' bundle) for list_bundles and switch_context.
        
        let final_count = new_entries.len();
        *self.entries.write().await = new_entries;
        *self.last_refresh.write().await = Some(std::time::Instant::now());
        tracing::info!("📋 Tool registry refreshed: {} entries cached ({} meta-tools filtered)", final_count, count - final_count);
    }

    // ─── Smart Filtering Methods ────────────────────────────

    /// Return tools filtered by category (bundle).
    ///
    /// If `category` is "discovery" or empty, returns an empty vec
    /// (callers should inject default_tools + meta-tools separately).
    pub async fn tools_by_category(&self, category: &str) -> Vec<(String, ToolRegistryEntry)> {
        if category.is_empty() {
            return Vec::new();
        }
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|(_, v)| {
                v.category
                    .as_deref()
                    .map(|c| c.eq_ignore_ascii_case(category))
                    .unwrap_or(false)
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Search tools by keyword match against name and description.
    ///
    /// Returns matching (name, description, category) tuples for the
    /// `search_skills` meta-tool response. Case-insensitive.
    pub async fn search_tools(&self, query: &str) -> Vec<(String, String, String)> {
        let query_lower = query.to_lowercase();
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|(name, entry)| {
                name.to_lowercase().contains(&query_lower)
                    || entry.description.to_lowercase().contains(&query_lower)
            })
            .map(|(name, entry)| {
                (
                    name.clone(),
                    entry.description.clone(),
                    entry
                        .category
                        .clone()
                        .unwrap_or_else(|| "uncategorized".to_string()),
                )
            })
            .collect()
    }

    /// Return all unique categories present in the registry.
    pub async fn all_categories(&self) -> Vec<String> {
        let entries = self.entries.read().await;
        let mut cats: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (_, entry) in entries.iter() {
            if let Some(ref cat) = entry.category {
                cats.insert(cat.clone());
            }
        }
        let mut sorted: Vec<String> = cats.into_iter().collect();
        sorted.sort();
        sorted
    }

    /// Return specific tools by name (for default_tools injection).
    pub async fn tools_by_names(&self, names: &[String]) -> Vec<(String, ToolRegistryEntry)> {
        let entries = self.entries.read().await;
        names
            .iter()
            .filter_map(|name| entries.get(name).map(|e| (name.clone(), e.clone())))
            .collect()
    }
}

/// Discover tools from a standard MCP SSE server.
pub async fn discover_mcp_tools(
    uri: &str,
    client: reqwest::Client,
) -> Result<Vec<rmcp::model::Tool>> {
    let mut sse_uri = uri.trim_end_matches('/').to_string();
    if !sse_uri.ends_with("/sse") {
        sse_uri = format!("{}/sse", sse_uri);
    }

    let transport = ssi_mcp_runtime::mcp_client::transport::create_transport(sse_uri, None, client);

    let client_info = rmcp::model::InitializeRequestParams::new(
        rmcp::model::ClientCapabilities::default(),
        rmcp::model::Implementation::new("trust-gateway-discovery", "0.1.0"),
    );

    let running = rmcp::serve_client(client_info, transport)
        .await
        .map_err(|e| anyhow::anyhow!("VP Discovery handshake failed: {}", e))?;

    let mcp_client = running.clone();
    
    // Drive the transport in a background task, but ensure it is cleaned up.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let _svc = running;
        let _ = rx.await;
    });

    let result = mcp_client.list_tools(Default::default()).await;
    
    // Explicitly shut down the background task after discovery.
    let _ = tx.send(());
    handle.abort();

    let list_tools = result?;
    Ok(list_tools.tools)
}

// ─── Dispatch Logic ─────────────────────────────────────────

/// Determine which executor backend should handle a given tool.
async fn determine_executor_target(state: &GatewayState, tool_name: &str) -> ExecutorTarget {
    // Phase 0: Gateway-Internal Meta Tools (PRIORITY)
    if tool_name == "search_skills"
        || tool_name == "switch_context"
        || tool_name == "list_bundles"
    {
        return ExecutorTarget::InternalMeta;
    }

    // Phase 1: Registry-first lookup
    if let Some(ref registry) = state.tool_registry {
        registry
            .refresh_if_stale(
                &state.http_client,
                &state.connectors.host_url,
            )
            .await;

        if let Some(entry) = registry.lookup(tool_name).await {
            tracing::info!(
                "📋 Registry-driven routing: '{}' → executor='{}'",
                tool_name,
                entry.executor_type
            );
            return match entry.executor_type.as_str() {
                "claw" | "native_tool" | "native-tool" | "native_skill" | "native-skill" => ExecutorTarget::ClawExecutor,
                "sandboxed-skill" | "sandboxed_skill" => ExecutorTarget::SandboxedSkill,
                "vp" | "vp_mcp" => ExecutorTarget::VpMcp,
                _ => ExecutorTarget::ConnectorMcp,
            };
        }
    }

    // Phase 2: Resilience / Prefixes (Fallback)
    if tool_name.starts_with("claw_") || tool_name.starts_with("tool_") || tool_name.starts_with("skill_") {
        return ExecutorTarget::ClawExecutor;
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
        ExecutorTarget::SandboxedSkill => "claw_executor", // map to claw_executor circuit breaker
        ExecutorTarget::VpMcp => "vp_mcp",
        ExecutorTarget::InternalMeta => "internal_meta",
    };

    // WS1.2: Check circuit breaker before dispatching
    if let Some(cb) = state.circuit_breakers.get(connector_key) {
        if let Err(e) = cb.check_allowed().await {
            tracing::warn!(
                "🔴 Circuit breaker blocked dispatch for '{}': {}",
                req.action.name,
                e
            );
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
    // Phase C: Pluggable Professional Governance / Meta-Tool interceptor
    if let Ok(Some(intercepted)) = state
        .tool_listing_overlay
        .intercept_action(&req.actor.session_jti, req)
        .await
    {
        return Ok(intercepted);
    }

    let mut last_err = None;

    for attempt in 0..=max_retries {
        let result = match target {
            ExecutorTarget::ConnectorMcp => dispatch_to_nats_executor(state, req, grant, "connector").await,
            ExecutorTarget::ClawExecutor => dispatch_to_nats_executor(state, req, grant, "native-tool").await,
            ExecutorTarget::SandboxedSkill => dispatch_to_nats_executor(state, req, grant, "sandboxed-skill").await,
            ExecutorTarget::VpMcp => dispatch_to_nats_executor(state, req, grant, "vp").await,
            ExecutorTarget::InternalMeta => dispatch_internal_meta(state, req).await,
        };

        match result {
            Ok(action_result) => return Ok(action_result),
            Err(e) if attempt < max_retries && is_retryable_error(&e) => {
                let delay_ms = RETRY_BASE_MS * RETRY_FACTOR.pow(attempt);
                let delay = std::time::Duration::from_millis(delay_ms);

                tracing::warn!(
                    "⚠️ Dispatch attempt {}/{} for '{}' failed (retrying in {:?}): {}",
                    attempt + 1,
                    max_retries + 1,
                    req.action.name,
                    delay,
                    e
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
                )
                .await;

                tokio::time::sleep(delay).await;
                last_err = Some(e);
            }
            Err(e) => {
                // Non-retryable error — fail immediately (fail-closed)
                return Err(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        anyhow::anyhow!(
            "All {} retries exhausted for action '{}'",
            max_retries,
            req.action.name
        )
    }))
}

/// Unified NATS dispatch for execution_host profiles.
///
/// P2: Uses canonical `TrustEnvelope<GrantedAction>` from trust_core
/// for structured, typed publish/consume boundaries.
async fn dispatch_to_nats_executor(
    state: &GatewayState,
    req: &ActionRequest,
    grant: &SignedGrant,
    profile: &str,
) -> Result<ActionResult> {
    tracing::info!(
        "📡 Routing action '{}' to NATS executor profile: {}",
        req.action.name,
        profile
    );

    let reply_subject = format!("exec.v1.reply.{}", uuid::Uuid::new_v4());
    let mut subscription = state.nats.subscribe(reply_subject.clone()).await?;

    let input_hash = trust_core::canonical_json::canonical_hash(&req.action.arguments);

    // P2: Construct typed GrantedAction payload
    let granted_action = trust_core::envelope::GrantedAction {
        grant_jwt: grant.token.clone(),
        tool_id: req.action.name.clone(),
        tool_version: "1.0.0".to_string(),
        canonical_args: req.action.arguments.clone(),
        input_hash,
        reply_subject: reply_subject.clone(),
    };

    // P2: Wrap in canonical TrustEnvelope — trace_id, auth_context, and
    // policy_fingerprint now flow end-to-end through the NATS boundary.
    let envelope = trust_core::envelope::TrustEnvelope::new(
        &req.tenant_id,
        &req.action_id,
        granted_action,
    )
    .with_auth_context(&req.actor.requester_did)
    .with_policy_fingerprint(state.policy_fingerprint.clone());

    let publish_subject = format!("exec.v1.{}.{}.invoke", req.tenant_id, profile);
    state.nats.publish(publish_subject, serde_json::to_vec(&envelope)?.into()).await?;

    // Wait for response
    let res = match tokio::time::timeout(std::time::Duration::from_secs(45), subscription.next()).await {
        Ok(Some(msg)) => {
            let response: serde_json::Value = serde_json::from_slice(&msg.payload)?;
            let payload = response.get("payload").ok_or_else(|| anyhow::anyhow!("Missing payload in response"))?;
            
            let output = payload.get("output").cloned().unwrap_or(serde_json::Value::Null);
            let error = payload.get("error").and_then(|v| v.as_str()).map(|s| s.to_string());

            Ok(ActionResult {
                action_id: req.action_id.clone(),
                status: if error.is_none() { ActionStatus::Succeeded } else { ActionStatus::Failed },
                connector: format!("executor_host:{}", profile),
                external_reference: None,
                output: if output.is_array() { output } else { 
                    serde_json::json!([{ "type": "text", "text": if output.is_string() { output.as_str().unwrap().to_string() } else { serde_json::to_string_pretty(&output).unwrap_or_default() } }])
                },
            })
        }
        Ok(None) => Err(anyhow::anyhow!("Executor disconnected before replying")),
        Err(_) => Err(anyhow::anyhow!("Executor timed out after 45s")),
    };

    // Explicitly drop subscription to avoid leaks (2.2)
    drop(subscription);

    res
}

// ─── Internal Meta Dispatch ─────────────────────────────────

async fn dispatch_internal_meta(state: &GatewayState, req: &ActionRequest) -> Result<ActionResult> {
    let tool_name = req.action.name.as_str();
    let args = &req.action.arguments;

    let text = match tool_name {
        "list_bundles" => {
            let results = if let Some(ref registry) = state.tool_registry {
                registry
                    .refresh_if_stale(
                            &state.http_client,
                            &state.connectors.host_url,
                    )
                    .await;
                registry.all_tools().await
            } else {
                Vec::new()
            };

            let mut bundle_tools: std::collections::HashMap<String, Vec<(String, String)>> =
                std::collections::HashMap::new();
            for (name, entry) in results {
                if let Some(cat) = entry.category {
                    bundle_tools
                        .entry(cat)
                        .or_insert_with(Vec::new)
                        .push((name, entry.description));
                }
            }

            if bundle_tools.is_empty() {
                "No tool bundles are currently available.".to_string()
            } else {
                let mut lines = vec!["Available tool bundles:".to_string()];
                let mut sorted_bundles: Vec<_> = bundle_tools.into_iter().collect();
                sorted_bundles.sort_by(|a, b| a.0.cmp(&b.0));
                for (bundle, mut tools) in sorted_bundles {
                    lines.push(format!("  • Bundle: {}", bundle));
                    tools.sort_by(|a, b| a.0.cmp(&b.0));
                    for (t_name, t_desc) in tools {
                        // Keep descriptions short to save tokens
                        let short_desc = if t_desc.len() > 80 {
                            format!("{}...", &t_desc[..77])
                        } else {
                            t_desc
                        };
                        lines.push(format!("      - {}: {}", t_name, short_desc));
                    }
                }
                lines.push("\nTo access these tools, directly use: switch_context(bundle_name).".to_string());
                lines.join("\n")
            }
        }
        "search_skills" => {
            let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
            if query.is_empty() {
                "Please provide a search query.".to_string()
            } else {
                let results = if let Some(ref registry) = state.tool_registry {
                    registry
                        .refresh_if_stale(
                            &state.http_client,
                            &state.connectors.host_url,
                        )
                        .await;
                    registry.search_tools(query).await
                } else {
                    Vec::new()
                };

                if results.is_empty() {
                    format!("No skills found matching '{}'.", query)
                } else {
                    let mut lines = vec![format!(
                        "Found {} skill(s) matching '{}':",
                        results.len(),
                        query
                    )];
                    for (name, desc, cat) in results {
                        lines.push(format!("  • {} [{}] — {}", name, cat, desc));
                    }
                    lines.join("\n")
                }
            }
        }
        "switch_context" => {
            let bundle = args
                .get("bundle_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if bundle.is_empty() {
                "Please specify a bundle_name.".to_string()
            } else {
                // In NATS world, session_id is typically the correlation_id or owner_did
                let session_id = &req.actor.session_jti;

                // Persist session state to NATS KV
                if let Ok(store) = state.jetstream.get_key_value("mcp_session_state").await {
                    let val = serde_json::json!({
                        "active_bundle": bundle,
                        "last_updated": chrono::Utc::now().to_rfc3339(),
                    });

                    // Key 1: session_jti (correlation_id or SSE UUID)
                    if !session_id.is_empty() {
                        let key = format!("session_{}", session_id.replace(':', "_").replace('/', "_"));
                        let _ = store.put(&key, val.to_string().into()).await;
                    }

                    // Key 2: requester_did
                    let req_did = &req.actor.requester_did;
                    if !req_did.is_empty() {
                        let key = format!("session_{}", req_did.replace(':', "_").replace('/', "_"));
                        let _ = store.put(&key, val.to_string().into()).await;
                    }

                    // Key 3: owner_did
                    let owner_did = &req.actor.owner_did;
                    if !owner_did.is_empty() {
                        let key = format!("session_{}", owner_did.replace(':', "_").replace('/', "_"));
                        let _ = store.put(&key, val.to_string().into()).await;
                    }
                }

                format!(
                    "Successfully switched to bundle '{}'. Your tool list has been updated.",
                    bundle
                )
            }
        }
        _ => "Unknown meta-tool".to_string(),
    };

    Ok(ActionResult {
        action_id: req.action_id.clone(),
        status: ActionStatus::Succeeded,
        connector: "trust_gateway".to_string(),
        external_reference: None,
        output: serde_json::json!([{
            "type": "text",
            "text": text,
        }]),
    })
}
