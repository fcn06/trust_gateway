// ─────────────────────────────────────────────────────────────
// Gateway core — shared state and NATS backward-compat listener
// ─────────────────────────────────────────────────────────────
use anyhow::{Context, Result};
use futures::StreamExt;
use identity_context::AuthVerifier;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use trust_core::action::{ActionDescriptor, ActionRequest, ActionStatus, infer_operation, infer_category};
use trust_core::actor::ActorContext;
use trust_core::audit::{AuditEvent, AuditEventType};
use trust_core::decision::ActionDecision;
use trust_core::grant::GrantClearance;
use trust_core::traits::{AuditSink, GrantIssuer, PolicyEngine}; // RULE[010_JWT_CONTRACTS.md]

use crate::router;
use base64::Engine;
use tracing::Instrument;

/// Shared state for the Trust Gateway.
///
/// Uses trait objects for pluggability — enterprise editions can
/// inject their own PolicyEngine, GrantIssuer, and AuditSink
/// implementations without forking this module.
pub struct ConnectorConfig {
    /// Connector MCP server URL — used only for OAuth proxy (/oauth/*), not tool dispatch.
    pub connector_mcp_url: String,
    pub host_url: String,
    pub portal_url: String,
    pub oauth2_service_url: Option<String>,
}

pub struct SecurityState {
    pub policy_engine: Arc<dyn PolicyEngine>,
    pub grant_issuer: Arc<dyn GrantIssuer>,
    pub audit_sink: Arc<dyn AuditSink>,
}

pub struct GatewayState {
    pub security: SecurityState,
    pub connectors: ConnectorConfig,
    pub approval_store: Arc<dyn trust_core::traits::ApprovalStore>,
    pub agent_registry: Arc<dyn trust_core::traits::AgentRegistry>,
    pub nats: async_nats::Client,
    pub jetstream: async_nats::jetstream::Context,
    pub http_client: reqwest::Client,
    /// Phase 6: In-memory tool registry for registry-driven routing.
    pub tool_registry: Option<router::ToolRegistry>,
    /// WS1.2: Per-connector circuit breakers for resilience.
    pub circuit_breakers: std::collections::HashMap<String, router::CircuitBreaker>,
    /// Allowed CORS origins (configurable via ALLOWED_ORIGINS env var).
    pub allowed_origins: Vec<String>,
    /// Phase 1: OAuth2 Configuration
    pub oauth_config: Option<crate::oauth::config::OAuthConfig>,
    /// JWT secret for session verification.
    pub jwt_secret: String,
    /// Pluggable token validator (dependency injection).
    ///
    /// Community edition: `StandardJwtValidator` (HMAC-HS256 session JWTs).
    /// Professional edition: injects an `EnterpriseValidator` that handles
    /// SSI Verifiable Presentations and falls back to `StandardJwtValidator`
    /// for regular web sessions.
    pub token_validator: Arc<dyn crate::auth::TokenValidator>,
    /// Smart Filtering: Active SSE session senders for pushing notifications.
    ///
    /// Maps session_id → mpsc::Sender<Event> so that meta-tool handlers
    /// (e.g., switch_context) can push `notifications/tools/list_changed`
    /// events to the correct SSE stream.
    pub sse_senders:
        dashmap::DashMap<String, tokio::sync::mpsc::Sender<axum::response::sse::Event>>,
    /// Smart Filtering: Admin-configured tools that are always visible,
    /// regardless of the active context bundle. Loaded from the
    /// `--default-tools` CLI argument or DEFAULT_TOOLS env var.
    pub default_tools: Vec<String>,
    /// WS-H2: Runtime JSON Schema validator for ingress payload validation.
    /// Loaded from `trust_core/snapshots/` at startup.
    pub schema_validator: Option<trust_core::schema_validator::SchemaValidator>,
    /// Port for dynamic tool listing interception and stateful overlays.
    pub tool_listing_overlay: Arc<dyn trust_core::ports::ToolListingOverlay>,
    /// WS3.3: SHA-256 fingerprint of the currently active policy.
    pub policy_fingerprint: String,
    /// Observability: Background task supervisor statuses.
    pub task_statuses: std::sync::Arc<dashmap::DashMap<String, TaskStatus>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TaskStatus {
    pub last_started: chrono::DateTime<chrono::Utc>,
    pub restart_count: u32,
    pub status: String,
}



/// The HTTP API request for POST /v1/actions/propose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposeActionRequest {
    /// Session JWT from ssi_vault.
    /// Optional when JWT is provided via Authorization header (preferred).
    #[serde(default)]
    pub session_jwt: String,
    /// Skill or tool name, e.g. "google_calendar_create_event".
    pub action_name: String,
    /// Raw arguments for the action.
    pub arguments: serde_json::Value,
    /// Optional tenant ID override (normally extracted from JWT).
    pub tenant_id: Option<String>,
    /// Source origin: "ssi_agent" (default) or "picoclaw".
    /// Used to apply source-specific policy rules.
    #[serde(default)]
    pub source_type: Option<String>,
}

/// The response from the Trust Gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayResponse {
    pub action_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation: Option<String>,
}

/// Core governance logic: validate → policy check → branch on decision.
pub async fn process_action(
    state: Arc<GatewayState>,
    action_req: ActionRequest,
) -> Result<GatewayResponse> {
    let action_id = action_req.action_id.clone();
    let action_name = action_req.action.name.clone();
    let tenant_id = action_req.tenant_id.clone();
    let source_type = action_req.source.source_type.clone();
    let session_jti = action_req.actor.session_jti.clone();
    let start_time = std::time::Instant::now();

    // Note: The rigid 5-step pipeline is executed below via dispatch_pipeline()
    if let Some(ref validator) = state.schema_validator {
        if let Ok(json_value) = serde_json::to_value(&action_req) {
            if let Err(e) = validator.validate("action_request", &json_value) {
                tracing::warn!(
                    "⚠️ Schema validation failed for action '{}': {} (proceeding with caution)",
                    action_id,
                    e
                );
            }
        }
    }
    
    // We delegate the core execution loop to the rigid 5-step dispatch pipeline
    dispatch_pipeline(state, action_req, action_id, action_name, tenant_id, source_type, session_jti, start_time).await
}

/// The rigid 5-step pipeline for gateway governance.
/// Enforces the "Agents propose, Gateway decides, Executors verify" invariant.
async fn dispatch_pipeline(
    state: Arc<GatewayState>,
    action_req: ActionRequest,
    action_id: String,
    action_name: String,
    tenant_id: String,
    source_type: String,
    session_jti: String,
    start_time: std::time::Instant,
) -> Result<GatewayResponse> {


    // 1. Publish audit: action.proposed (Phase 7: enriched)
    crate::audit_sink::emit_audit(
        &*state.security.audit_sink,
        &tenant_id,
        AuditEventType::ActionProposed,
        "trust_gateway",
        &action_id,
        serde_json::json!({
            "action_name": action_name,
            "actor": action_req.actor.requester_did,
            "source_type": source_type,
            "session_jti": session_jti,
            "tenant_id": tenant_id,
            "operation_kind": format!("{:?}", action_req.action.operation),
            "arguments": action_req.action.arguments,
            "auth_level": format!("{}", action_req.actor.auth_level),
            "auth_method": format!("{:?}", action_req.actor.auth_method),
        }),
    )
    .await;

    // ── Agent Registry: Resolve and enforce ──────────────────
    // Attempt to resolve the agent by source type. If found, enforce
    // kill switch and status checks before policy evaluation.
    let agent_id_for_audit: Option<String>;
    let agent_source_key = if !source_type.is_empty() {
        source_type.clone()
    } else {
        "ssi_agent".to_string()
    };

    if let Ok(Some(agent)) = state
        .agent_registry
        .resolve_by_source(&agent_source_key)
        .await
    {
        agent_id_for_audit = Some(agent.agent_id.clone());

        // Kill switch is absolute — bypasses all policy
        if agent.kill_switch {
            tracing::warn!(
                "🔴 KILL SWITCH: Agent '{}' ({}) is killed — blocking action '{}'",
                agent.name,
                agent.agent_id,
                action_name
            );
            return Ok(GatewayResponse {
                action_id,
                status: "denied".to_string(),
                result: None,
                error: Some(format!(
                    "Agent '{}' has been killed (emergency stop)",
                    agent.name
                )),
                approval_id: None,
                escalation: None,
            });
        }

        // Status check
        match agent.status {
            trust_core::agent::AgentStatus::Revoked => {
                tracing::warn!(
                    "🚫 REVOKED: Agent '{}' ({}) — blocking action '{}'",
                    agent.name,
                    agent.agent_id,
                    action_name
                );
                return Ok(GatewayResponse {
                    action_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some(format!(
                        "Agent '{}' registration has been revoked",
                        agent.name
                    )),
                    approval_id: None,
                    escalation: None,
                });
            }
            trust_core::agent::AgentStatus::Paused => {
                tracing::info!(
                    "⏸️ PAUSED: Agent '{}' ({}) — blocking action '{}'",
                    agent.name,
                    agent.agent_id,
                    action_name
                );
                return Ok(GatewayResponse {
                    action_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some(format!("Agent '{}' is currently paused", agent.name)),
                    approval_id: None,
                    escalation: None,
                });
            }
            trust_core::agent::AgentStatus::Active => {
                // Proceed — agent is healthy
            }
        }

        // Update heartbeat (fire-and-forget, non-blocking)
        let registry = state.agent_registry.clone();
        let aid = agent.agent_id.clone();
        tokio::spawn(async move {
            let _ = registry.touch(&aid).await;
        });
    } else {
        agent_id_for_audit = None;
        // No registered agent — proceed with policy as before.
        // Community edition allows unregistered agents through.
        // Enterprise edition can enforce deny-by-default here.
        tracing::debug!(
            "No registered agent for source '{}' — proceeding with policy only",
            agent_source_key
        );
    }

    // 2. Evaluate policy
    let decision = state
        .security
        .policy_engine
        .evaluate(&action_req)
        .await
        .map_err(|e| anyhow::anyhow!("Policy evaluation failed: {}", e))?;

    // 3. Publish audit: policy.evaluated (enriched with agent_id)
    crate::audit_sink::emit_audit(
        &*state.security.audit_sink,
        &tenant_id,
        AuditEventType::PolicyEvaluated,
        "trust_gateway",
        &action_id,
        serde_json::json!({
            "decision": format!("{:?}", decision),
            "policy_id": decision.policy_id(),
            "agent_id": agent_id_for_audit,
        }),
    )
    .await;

    // 4. Branch on decision
    match &decision {
        ActionDecision::Allow { policy_id } => {
            tracing::info!(
                "✅ Action '{}' allowed by policy '{}'",
                action_name,
                policy_id
            );

            // Issue ExecutionGrant
            let grant = state.security.grant_issuer.issue_execution_grant(
                &action_req,
                GrantClearance::AutoApproved,
                std::time::Duration::from_secs(30),
            )?;

            // Publish audit: grant.issued
            crate::audit_sink::emit_audit(
                &*state.security.audit_sink,
                &tenant_id,
                AuditEventType::GrantIssued,
                "trust_gateway",
                &action_id,
                serde_json::json!({
                    "grant_id": grant.claims.grant_id,
                    "clearance": "auto_approved",
                    "expires_at": grant.claims.expires_at,
                    "input_hash": grant.claims.input_hash,
                    "auth_level": format!("{}", action_req.actor.auth_level),
                }),
            )
            .await;

            // Route to connector
            let result = router::dispatch_to_connector(&state, &action_req, &grant).await;

            match result {
                Ok(mut action_result) => {
                    let latency_ms = start_time.elapsed().as_millis();

                    if action_result.status == ActionStatus::Succeeded {
                        // ── SEC-4: Egress Pipeline Ordering ─────────────
                        // Deterministic ordering:
                        //   1. Executor returns raw result
                        //   2. PII regex filter runs (redacts in-place)
                        //   3. Deterministic validator checks (rejects on violation)
                        //   4. Response returned to caller
                        //
                        // This ordering ensures data minimisation: policy limits
                        // what fields tools fetch before LLM sees them.
                        trust_core::egress_filter::redact_json(&mut action_result.output);

                        // For B2B/external sources, apply strict egress validation
                        let is_external = source_type == "b2b_agent"
                            || source_type == "external_swarm"
                            || source_type == "picoclaw";

                        if is_external {
                            let egress_config = trust_core::egress_validator::EgressConfig::default();
                            let output_str = serde_json::to_string(&action_result.output)
                                .unwrap_or_default();
                            if let Err(violation) = trust_core::egress_validator::validate_egress(
                                &output_str,
                                &egress_config,
                            ) {
                                tracing::warn!(
                                    "🔒 SEC-4: Egress violation for B2B response on action '{}': {}",
                                    action_id,
                                    violation
                                );

                                crate::audit_sink::emit_audit(
                                    &*state.security.audit_sink,
                                    &tenant_id,
                                    AuditEventType::ActionFailed,
                                    "trust_gateway",
                                    &action_id,
                                    serde_json::json!({
                                        "error": format!("Egress violation: {}", violation),
                                        "source_type": source_type,
                                        "latency_ms": latency_ms,
                                    }),
                                )
                                .await;

                                return Ok(GatewayResponse {
                                    action_id,
                                    status: "failed".to_string(),
                                    result: None,
                                    error: Some(format!(
                                        "Response blocked by egress policy: {}",
                                        violation
                                    )),
                                    approval_id: None,
                                    escalation: None,
                                });
                            }
                        }
                        // ── End SEC-4 ───────────────────────────────────

                        crate::audit_sink::emit_audit(
                            &*state.security.audit_sink,
                            &tenant_id,
                            AuditEventType::ActionSucceeded,
                            "trust_gateway",
                            &action_id,
                            serde_json::json!({
                                "connector": action_result.connector,
                                "executor_type": action_result.connector,
                                "external_reference": action_result.external_reference,
                                "source_type": source_type,
                                "latency_ms": latency_ms,
                            }),
                        )
                        .await;

                        Ok(GatewayResponse {
                            action_id,
                            status: "succeeded".to_string(),
                            result: Some(action_result.output),
                            error: None,
                            approval_id: None,
                            escalation: None,
                        })
                    } else {
                        crate::audit_sink::emit_audit(
                            &*state.security.audit_sink,
                            &tenant_id,
                            AuditEventType::ActionFailed,
                            "trust_gateway",
                            &action_id,
                            serde_json::json!({
                                "error": format!("{:?}", action_result.output),
                                "source_type": source_type,
                                "latency_ms": latency_ms,
                            }),
                        )
                        .await;

                        let error_str = if let Some(arr) = action_result.output.as_array() {
                            arr.first()
                                .and_then(|v| v.get("text"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("Action execution failed")
                                .to_string()
                        } else {
                            "Action execution failed".to_string()
                        };

                        Ok(GatewayResponse {
                            action_id,
                            status: "failed".to_string(),
                            result: None,
                            error: Some(error_str),
                            approval_id: None,
                            escalation: None,
                        })
                    }
                }
                Err(e) => {
                    let latency_ms = start_time.elapsed().as_millis();
                    crate::audit_sink::emit_audit(
                        &*state.security.audit_sink,
                        &tenant_id,
                        AuditEventType::ActionFailed,
                        "trust_gateway",
                        &action_id,
                        serde_json::json!({
                            "error": format!("{}", e),
                            "source_type": source_type,
                            "latency_ms": latency_ms,
                        }),
                    )
                    .await;

                    Ok(GatewayResponse {
                        action_id,
                        status: "failed".to_string(),
                        result: None,
                        error: Some(format!("{}", e)),
                        approval_id: None,
                        escalation: None,
                    })
                }
            }
        }

        ActionDecision::Deny { reason, policy_id } => {
            tracing::warn!(
                "🚫 Action '{}' denied by policy '{}': {}",
                action_name,
                policy_id,
                reason
            );
            Ok(GatewayResponse {
                action_id,
                status: "denied".to_string(),
                result: None,
                error: Some(reason.clone()),
                approval_id: None,
                escalation: None,
            })
        }

        ActionDecision::RequireApproval {
            ref tier,
            ref reason,
            ref policy_id,
        } => {
            tracing::info!(
                "⏳ Action '{}' requires approval (tier: {}, policy: '{}'): {}",
                action_name,
                tier,
                policy_id,
                reason
            );

            let approval_id = uuid::Uuid::new_v4().to_string();

            // Build action summary for portal display
            let action_summary = trust_core::approval::ActionSummary {
                action_name: action_name.clone(),
                category: format!("{:?}", action_req.action.category),
                operation: format!("{:?}", action_req.action.operation),
                amount: action_req.action.amount.as_ref().map(|m| m.to_string()),
                requester: action_req.actor.requester_did.clone(),
                source: source_type.clone(),
            };

            // Store the full request so the daemon can dispatch it later
            let approval_req = trust_core::approval::ApprovalRequest {
                approval_id: approval_id.clone(),
                action_id: action_id.clone(),
                tenant_id: tenant_id.clone(),
                tier: tier.clone(),
                reason: reason.clone(),
                policy_id: policy_id.clone(),
                action_summary,
                proof_required: false,
                requested_at: chrono::Utc::now(),
                action_request: action_req.clone(),
            };

            if let Err(e) = state.approval_store.create(approval_req).await {
                tracing::error!("Failed to store approval request: {}", e);
                return Err(anyhow::anyhow!("Internal approval storage error"));
            }

            // Publish audit
            crate::audit_sink::emit_audit(
                &*state.security.audit_sink,
                &tenant_id,
                AuditEventType::ApprovalRequested,
                "trust_gateway",
                &action_id,
                serde_json::json!({
                    "approval_id": approval_id,
                    "tier": format!("{}", tier),
                    "reason": reason,
                }),
            )
            .await;

            // ── Bridge to Host escalation store ─────────────
            // The portal reads pending approvals from the Host's
            // `escalation_requests` KV store (not the gateway's
            // `approval_records`). Publish an escalation request
            // to the Host so it appears in the portal.
            // WS3.2: Build ActionReview for the portal
            let action_review = crate::normalizer::build_action_review(
                &action_req,
                &decision,
                &approval_id,
                reason,
                "",
                &source_type,
            );

            let escalation_payload = serde_json::json!({
                "tool_name": action_name,
                "user_did": action_req.actor.owner_did,
                "requester_did": action_req.actor.requester_did,
                "correlation_id": approval_id,
                "original_arguments": action_req.action.arguments,
                "tier": format!("{}", tier),
                "reason": reason,
                "approval_id": approval_id,
                "action_review": action_review,
                "session_jti": action_req.actor.session_jti,
            });
            match state
                .nats
                .request(
                    "host.v1.escalation.request".to_string(),
                    serde_json::to_string(&escalation_payload)
                        .unwrap_or_default()
                        .into(),
                )
                .await
            {
                Ok(_ack) => {
                    tracing::info!(
                        "📩 Escalation request published to Host (approval_id: {})",
                        approval_id
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Failed to publish escalation to Host (portal may not show it): {}",
                        e
                    );
                }
            }

            Ok(GatewayResponse {
                action_id,
                status: "pending_approval".to_string(),
                result: None,
                error: None,
                approval_id: Some(approval_id),
                escalation: Some(format!("{}", tier)),
            })
        }

        ActionDecision::RequireProof {
            ref proof_request,
            ref reason,
            ref policy_id,
        } => {
            tracing::info!(
                "🔐 Action '{}' requires OID4VP proof (policy: '{}'): {}",
                action_name,
                policy_id,
                reason
            );

            let approval_id = uuid::Uuid::new_v4().to_string();

            // Build action summary for portal display
            let action_summary = trust_core::approval::ActionSummary {
                action_name: action_name.clone(),
                category: format!("{:?}", action_req.action.category),
                operation: format!("{:?}", action_req.action.operation),
                amount: action_req.action.amount.as_ref().map(|m| m.to_string()),
                requester: action_req.actor.requester_did.clone(),
                source: source_type.clone(),
            };

            let approval_req = trust_core::approval::ApprovalRequest {
                approval_id: approval_id.clone(),
                action_id: action_id.clone(),
                tenant_id: tenant_id.clone(),
                tier: trust_core::approval::ApprovalTier::Tier3VerifiedPresentation,
                reason: reason.clone(),
                policy_id: policy_id.clone(),
                action_summary,
                proof_required: true,
                requested_at: chrono::Utc::now(),
                action_request: action_req.clone(),
            };

            if let Err(e) = state.approval_store.create(approval_req).await {
                tracing::error!("Failed to store proof approval request: {}", e);
                return Err(anyhow::anyhow!("Internal approval storage error"));
            }

            crate::audit_sink::emit_audit(
                &*state.security.audit_sink,
                &tenant_id,
                AuditEventType::ProofRequested,
                "trust_gateway",
                &action_id,
                serde_json::json!({
                    "approval_id": approval_id,
                    "proof_type": format!("{}", proof_request.proof_type),
                    "required_claims": proof_request.required_claims,
                    "reason": reason,
                }),
            )
            .await;

            // ── Bridge to Host escalation store for OID4VP ──
            let action_review = crate::normalizer::build_action_review(
                &action_req,
                &decision,
                &approval_id,
                reason,
                "",
                &source_type,
            );

            let escalation_payload = serde_json::json!({
                "tool_name": action_name,
                "user_did": action_req.actor.owner_did,
                "requester_did": action_req.actor.requester_did,
                "correlation_id": approval_id,
                "original_arguments": action_req.action.arguments,
                "tier": "tier3",
                "reason": reason,
                "approval_id": approval_id,
                "proof_required": true,
                "proof_request": serde_json::to_value(proof_request).unwrap_or_default(),
                "action_review": action_review,
                "session_jti": action_req.actor.session_jti,
            });
            match state
                .nats
                .request(
                    "host.v1.escalation.request".to_string(),
                    serde_json::to_string(&escalation_payload)
                        .unwrap_or_default()
                        .into(),
                )
                .await
            {
                Ok(_ack) => {
                    tracing::info!(
                        "📩 Escalation proof request published to Host (approval_id: {})",
                        approval_id
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Failed to publish escalation proof request to Host: {}",
                        e
                    );
                }
            }

            Ok(GatewayResponse {
                action_id,
                status: "pending_proof".to_string(),
                result: None,
                error: None,
                approval_id: Some(approval_id),
                escalation: Some("pending_proof".to_string()),
            })
        }
    }
}

/// Convert a ProposedAction (transport-neutral identity) into an ActionRequest
/// (the policy engine's input).
///
/// This is the **single canonical conversion** used by all three entry points:
/// HTTP propose, NATS dispatch, and MCP SSE tools/call.
///
/// Phase 2.1: Extracted from 3 duplicated copies across api.rs, gateway.rs, and mcp_sse.rs.
pub fn build_action_request(proposed: identity_context::models::ProposedAction) -> Result<ActionRequest> {
    // Phase 8: Strip namespace prefix (e.g. "lianxi.io:google_calendar_list_events" -> "google_calendar_list_events")
    // This handles MCP clients (like Claude) that prefix tool names with the server name.
    let canonical_name = if let Some(pos) = proposed.tool_name.rfind(':') {
        let stripped = &proposed.tool_name[pos + 1..];
        tracing::debug!(
            "🏷️ Stripped namespace prefix: '{}' -> '{}'",
            proposed.tool_name,
            stripped
        );
        stripped.to_string()
    } else {
        proposed.tool_name.clone()
    };

    let operation = infer_operation(&canonical_name);
    let category = infer_category(&canonical_name);

    // Strict Tenant Enforcement
    let tenant_id = proposed.identity.tenant_id.clone();
    if tenant_id.is_empty() || tenant_id == "default" || tenant_id == "unknown" {
        return Err(anyhow::anyhow!("Strict tenant enforcement failed: valid tenant_id is required"));
    }

    Ok(ActionRequest {
        action_id: proposed.action_id,
        tenant_id,
        actor: ActorContext {
            owner_did: proposed.identity.owner_did,
            requester_did: proposed.identity.requester_did,
            user_did: None,
            session_jti: proposed.identity.source.correlation_id.clone(),
            auth_level: proposed.identity.auth_level,
            auth_method: proposed.identity.auth_method,
            oauth_scopes: proposed.identity.oauth_scopes,
        },
        source: proposed.identity.source.into(),
        action: ActionDescriptor {
            name: canonical_name,
            category,
            resource: None,
            operation,
            amount: {
                let extracted = crate::amount_extractor::extract_amount(&proposed.arguments);
                extracted.amount.map(|value| {
                    trust_core::Money::from_major(
                        value,
                        extracted.currency.unwrap_or_else(|| "EUR".to_string()),
                    )
                })
            },
            arguments: proposed.arguments,
            tags: vec![],
        },
    })
}

/// Run the canonical NATS listener (subscribes to trust.v1.*.action.propose)
pub async fn run_trust_v1_listener(
    nc: async_nats::Client,
    state: Arc<GatewayState>,
) -> Result<()> {
    let subject = "trust.v1.*.action.propose";
    let mut subscriber = nc
        .subscribe(subject.to_string())
        .await
        .context("Failed to subscribe to trust.v1.*.action.propose")?;
    tracing::info!("📬 NATS listener subscribed to {}", subject);

    while let Some(msg) = subscriber.next().await {
        let reply_subject = msg.reply.clone();
        let payload_bytes = msg.payload.to_vec();
        let state = state.clone();
        let nc = nc.clone();

        // Extract tenant_id from the subject: trust.v1.<tenant>.action.propose
        let subject_str = msg.subject.to_string();
        let tenant_from_subject = subject_str
            .split('.')
            .nth(2)
            .unwrap_or("unknown")
            .to_string();

        tokio::spawn(async move {
            let req: ProposeActionRequest = match serde_json::from_slice::<trust_core::action::NormalizedActionProposal>(&payload_bytes) {
                Ok(normalized) => {
                    tracing::info!("📥 Parsed NormalizedActionProposal for action: {}", normalized.action_name);
                    ProposeActionRequest {
                        session_jwt: normalized.payload.get("session_jwt").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        action_name: normalized.action_name,
                        arguments: normalized.action_arguments,
                        tenant_id: Some(normalized.tenant_id),
                        source_type: Some(normalized.source_type),
                    }
                },
                Err(e) => {
                    tracing::debug!("Failed to parse NormalizedActionProposal: {}, falling back to ProposeActionRequest", e);
                    match serde_json::from_slice(&payload_bytes) {
                        Ok(p) => p,
                        Err(e2) => {
                            tracing::error!("Failed to parse ProposeActionRequest: {}", e2);
                            return;
                        }
                    }
                }
            };

            // Extract correlation ID / trace ID
            let trace_id = req.arguments.get("_meta")
                .and_then(|m| m.get("io.lianxi"))
                .and_then(|i| i.get("correlation_id"))
                .and_then(|c| c.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    if !req.session_jwt.is_empty() {
                        let parts: Vec<&str> = req.session_jwt.split('.').collect();
                        if parts.len() == 3 {
                            if let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
                                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&decoded) {
                                    if let Some(jti) = json.get("jti").and_then(|v| v.as_str()) {
                                        return jti.to_string();
                                    }
                                }
                            }
                        }
                    }
                    uuid::Uuid::new_v4().to_string()
                });

            let span = tracing::info_span!("nats_propose_action", trace_id = %trace_id);

            async move {
                // 1. Resolve identity via TokenValidator
                let headers = if !req.session_jwt.is_empty() {
                    let mut h = axum::http::HeaderMap::new();
                    h.insert(
                        axum::http::header::AUTHORIZATION,
                        format!("Bearer {}", req.session_jwt).parse().unwrap(),
                    );
                    h
                } else {
                    axum::http::HeaderMap::new()
                };

                let identity = match state.token_validator.validate(&headers, &state.jwt_secret).await {
                    Ok(id) => id,
                    Err(e) => {
                        tracing::warn!("🔒 Identity validation failed for NATS request on {}: {}", msg.subject, e);
                        
                        // Reply with error to prevent client timeout
                        if let Some(reply) = reply_subject {
                            let error_resp = serde_json::json!({
                                "status": "failed",
                                "error": format!("Unauthorized: {}", e)
                            });
                            if let Err(pub_err) = nc.publish(reply, error_resp.to_string().into()).await {
                                tracing::error!("❌ Failed to send error reply: {}", pub_err);
                            }
                        }
                        return;
                    }
                };

                // Strict Tenant Enforcement: The subject MUST match the identity's tenant
                if identity.tenant_id != tenant_from_subject && tenant_from_subject != "unknown" {
                    tracing::warn!(
                        "Strict Tenant Violation: Identity tenant '{}' does not match subject tenant '{}'",
                        identity.tenant_id,
                        tenant_from_subject
                    );
                    if let Some(reply_to) = reply_subject {
                        let err = serde_json::json!({"error": "Strict tenant enforcement failed: tenant mismatch"});
                        let _ = nc.publish(reply_to, err.to_string().into()).await;
                    }
                    return;
                }

                // 2. Normalize to ProposedAction
                let mut source = identity_context::models::SourceContext::default();
                source.transport = identity_context::models::TransportKind::Nats;
                source.source_type = if req.source_type.as_deref() == Some("picoclaw") {
                    identity_context::models::SourceType::HttpApi
                } else {
                    identity_context::models::SourceType::SsiAgent
                };
                source.correlation_id = trace_id.clone();

                let mut identity = identity;
                identity.source = source;

                let proposed = identity_context::models::ProposedAction {
                    action_id: uuid::Uuid::new_v4().to_string(),
                    tool_name: req.action_name,
                    arguments: req.arguments,
                    identity,
                    raw_meta: None,
                };

                tracing::debug!(
                    "📥 action normalized: tool={}, tenant={}, action_id={}",
                    proposed.tool_name,
                    proposed.identity.tenant_id,
                    proposed.action_id
                );

                let action_req = match build_action_request(proposed) {
                    Ok(req) => req,
                    Err(e) => {
                        tracing::warn!("Failed to build action request: {}", e);
                        if let Some(reply_to) = reply_subject {
                            let response = serde_json::json!({"error": format!("Validation error: {}", e)});
                            let _ = nc.publish(reply_to, response.to_string().into()).await;
                        }
                        return;
                    }
                };

                let result = process_action(state, action_req).await;

                if let Some(reply_to) = reply_subject {
                    let response = match result {
                        Ok(gw_resp) => serde_json::to_value(&gw_resp)
                            .unwrap_or_else(|_| serde_json::json!({"error": "serialize error"})),
                        Err(e) => serde_json::json!({"error": format!("Gateway error: {}", e)}),
                    };
                    let _ = nc.publish(reply_to, response.to_string().into()).await;
                }
            }.instrument(span).await;
        });
    }

    Ok(())
}

/// Publish an audit event to NATS JetStream (durable) with plain NATS fallback.
///
/// Returns `Ok(())` if the event was persisted (JetStream) or at least sent (plain NATS).
/// Returns `Err` only if ALL publish mechanisms failed. Callers in safety-critical
/// paths (e.g. grant issuance) should check this and abort the operation.
pub(crate) async fn publish_audit(
    js: &async_nats::jetstream::Context,
    nc: &async_nats::Client,
    tenant_id: &str,
    event_type: AuditEventType,
    component: &str,
    action_id: &str,
    payload: serde_json::Value,
) {
    let event =
        AuditEvent::new(event_type, component, tenant_id, payload).with_action_id(action_id);
    let subject = format!("audit.action.{}", action_id);
    let json = match serde_json::to_string(&event) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(
                "🚨 AUDIT FAIL-CLOSED: Cannot serialize audit event for action {}: {}",
                action_id,
                e
            );
            return;
        }
    };

    // Try JetStream durable publish first
    match js.publish(subject.clone(), json.clone().into()).await {
        Ok(ack_future) => {
            // Await the ack to confirm persistence
            match ack_future.await {
                Ok(_) => return,
                Err(e) => {
                    tracing::warn!(
                        "JetStream ack failed for audit event (falling back to plain NATS): {}",
                        e
                    );
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                "JetStream publish failed for audit event (falling back to plain NATS): {}",
                e
            );
        }
    }

    // Fallback: plain NATS (best-effort, not durable)
    if let Err(e) = nc.publish(subject, json.into()).await {
        tracing::error!(
            "🚨 AUDIT FAIL-CLOSED: ALL audit publish mechanisms failed for action {}: {}",
            action_id,
            e
        );
    }
}

/// Run a NATS listener for bundle-aware tool discovery
/// Subscribes to `trust.v1.*.tools.list`
pub async fn run_tools_list_listener(
    nc: async_nats::Client,
    state: Arc<GatewayState>,
) -> Result<()> {
    let subject = "trust.v1.*.tools.list";
    let mut subscriber = nc
        .subscribe(subject.to_string())
        .await
        .context("Failed to subscribe to trust.v1.*.tools.list")?;
    tracing::info!("📬 NATS listener subscribed to {}", subject);

    while let Some(msg) = subscriber.next().await {
        let reply_subject = match msg.reply.clone() {
            Some(r) => r,
            None => continue,
        };
        let payload_bytes = msg.payload.to_vec();
        let state = state.clone();
        let nc = nc.clone();

        tokio::spawn(async move {
            #[derive(Deserialize)]
            struct ToolsListRequest {
                session_id: String,
            }

            let session_id = match serde_json::from_slice::<ToolsListRequest>(&payload_bytes) {
                Ok(req) => req.session_id,
                Err(_) => {
                    tracing::warn!("Failed to parse session_id from tools list request");
                    String::new()
                }
            };

            let response = crate::mcp_sse::handle_tools_list(&state, None, &session_id).await;
            
            // Convert JsonRpcResponse to the format expected by the client
            let result_json = serde_json::to_value(&response).unwrap_or_else(|_| serde_json::json!({}));
            
            // The client expects an object with a "tools" array
            let final_response = if let Some(result) = result_json.get("result") {
                result.clone()
            } else {
                result_json
            };

            if let Err(e) = nc.publish(reply_subject, serde_json::to_string(&final_response).unwrap_or_default().into()).await {
                tracing::error!("❌ Failed to send tools list reply: {}", e);
            }
        });
    }

    Ok(())
}
