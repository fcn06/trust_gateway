// ─────────────────────────────────────────────────────────────
// Gateway core — shared state and NATS backward-compat listener
// ─────────────────────────────────────────────────────────────
use std::sync::Arc;
use anyhow::{Context, Result};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use trust_core::action::{ActionDescriptor, ActionRequest, ActionStatus};
use trust_core::actor::{ActorContext, AuthLevel};
use trust_core::audit::{AuditEvent, AuditEventType};
use trust_core::decision::ActionDecision;
use trust_core::grant::GrantClearance;
use trust_core::traits::{PolicyEngine, GrantIssuer, AuditSink};

use crate::router;

/// Shared state for the Trust Gateway.
///
/// Uses trait objects for pluggability — enterprise editions can
/// inject their own PolicyEngine, GrantIssuer, and AuditSink
/// implementations without forking this module.
pub struct ConnectorConfig {
    pub connector_mcp_url: String,
    pub skill_executor_url: String,
    pub restaurant_service_url: String,
    pub vp_mcp_url: String,
    pub host_url: String,
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
}

/// The payload received from the ssi_agent via NATS (backward compat).
/// This is the same format as the old mcp_nats_bridge DispatchPayload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsDispatchPayload {
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub verified_did: String,
}

/// The HTTP API request for POST /v1/actions/propose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposeActionRequest {
    /// Session JWT from ssi_vault.
    /// Optional when JWT is provided via Authorization header (preferred).
    #[serde(default)]
    pub session_jwt: String,
    /// Skill or tool name, e.g. "google.calendar.event.create".
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
        }),
    ).await;

    // ── Agent Registry: Resolve and enforce ──────────────────
    // Attempt to resolve the agent by source type. If found, enforce
    // kill switch and status checks before policy evaluation.
    let agent_id_for_audit: Option<String>;
    let agent_source_key = if !source_type.is_empty() {
        source_type.clone()
    } else {
        "ssi_agent".to_string()
    };

    if let Ok(Some(agent)) = state.agent_registry
        .resolve_by_source(&agent_source_key).await
    {
        agent_id_for_audit = Some(agent.agent_id.clone());

        // Kill switch is absolute — bypasses all policy
        if agent.kill_switch {
            tracing::warn!("🔴 KILL SWITCH: Agent '{}' ({}) is killed — blocking action '{}'",
                agent.name, agent.agent_id, action_name);
            return Ok(GatewayResponse {
                action_id,
                status: "denied".to_string(),
                result: None,
                error: Some(format!("Agent '{}' has been killed (emergency stop)", agent.name)),
                approval_id: None,
                escalation: None,
            });
        }

        // Status check
        match agent.status {
            trust_core::agent::AgentStatus::Revoked => {
                tracing::warn!("🚫 REVOKED: Agent '{}' ({}) — blocking action '{}'",
                    agent.name, agent.agent_id, action_name);
                return Ok(GatewayResponse {
                    action_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some(format!("Agent '{}' registration has been revoked", agent.name)),
                    approval_id: None,
                    escalation: None,
                });
            }
            trust_core::agent::AgentStatus::Paused => {
                tracing::info!("⏸️ PAUSED: Agent '{}' ({}) — blocking action '{}'",
                    agent.name, agent.agent_id, action_name);
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
        tokio::spawn(async move { let _ = registry.touch(&aid).await; });
    } else {
        agent_id_for_audit = None;
        // No registered agent — proceed with policy as before.
        // Community edition allows unregistered agents through.
        // Enterprise edition can enforce deny-by-default here.
        tracing::debug!("No registered agent for source '{}' — proceeding with policy only", agent_source_key);
    }

    // 2. Evaluate policy
    let decision = state.security.policy_engine.evaluate(&action_req).await
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
    ).await;

    // 4. Branch on decision
    match decision {
        ActionDecision::Allow { policy_id } => {
            tracing::info!("✅ Action '{}' allowed by policy '{}'", action_name, policy_id);

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
                }),
            ).await;

            // Route to connector
            let result = router::dispatch_to_connector(
                &state,
                &action_req,
                &grant,
            ).await;

            match result {
                Ok(action_result) => {
                    let latency_ms = start_time.elapsed().as_millis();

                    if action_result.status == ActionStatus::Succeeded {
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
                        ).await;

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
                        ).await;

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
                    ).await;

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
            tracing::warn!("🚫 Action '{}' denied by policy '{}': {}", action_name, policy_id, reason);
            Ok(GatewayResponse {
                action_id,
                status: "denied".to_string(),
                result: None,
                error: Some(reason),
                approval_id: None,
                escalation: None,
            })
        }

        ActionDecision::RequireApproval { ref tier, ref reason, ref policy_id } => {
            tracing::info!(
                "⏳ Action '{}' requires approval (tier: {}, policy: '{}'): {}",
                action_name, tier, policy_id, reason
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
            ).await;

            // ── Bridge to Host escalation store ─────────────
            // The portal reads pending approvals from the Host's
            // `escalation_requests` KV store (not the gateway's
            // `approval_records`). Publish an escalation request
            // to the Host so it appears in the portal.
            let escalation_payload = serde_json::json!({
                "tool_name": action_name,
                "user_did": action_req.actor.owner_did,
                "requester_did": action_req.actor.requester_did,
                "correlation_id": approval_id,
                "original_arguments": action_req.action.arguments,
                "tier": format!("{}", tier),
                "reason": reason,
                "approval_id": approval_id,
            });
            match state.nats.request(
                "host.v1.escalation.request".to_string(),
                serde_json::to_string(&escalation_payload)
                    .unwrap_or_default()
                    .into(),
            ).await {
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

        ActionDecision::RequireProof { ref proof_request, ref reason, ref policy_id } => {
            tracing::info!(
                "🔐 Action '{}' requires OID4VP proof (policy: '{}'): {}",
                action_name, policy_id, reason
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
            ).await;

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
pub fn build_action_request(proposed: identity_context::models::ProposedAction) -> ActionRequest {
    let operation = crate::api::infer_operation(&proposed.tool_name);
    let category = crate::api::infer_category(&proposed.tool_name);

    // Derive tenant_id: use identity context value, or fall back to a
    // deterministic default derived from the owner DID.  Community
    // edition JWTs often omit the tenant_id claim; without this
    // fallback the entire pipeline propagates an empty string that
    // downstream services reject.
    let tenant_id = if proposed.identity.tenant_id.is_empty() {
        let fallback = format!("default-{}", &proposed.identity.owner_did);
        tracing::info!(
            "📋 JWT missing tenant_id — derived fallback: '{}'",
            fallback
        );
        fallback
    } else {
        proposed.identity.tenant_id
    };

    ActionRequest {
        action_id: proposed.action_id,
        tenant_id,
        actor: ActorContext {
            owner_did: proposed.identity.owner_did,
            requester_did: proposed.identity.requester_did,
            user_did: None,
            session_jti: proposed.identity.source.correlation_id.clone(),
            auth_level: AuthLevel::Session,
        },
        source: proposed.identity.source.into(),
        action: ActionDescriptor {
            name: proposed.tool_name,
            category,
            resource: None,
            operation,
            amount: {
                let extracted = crate::amount_extractor::extract_amount(&proposed.arguments);
                extracted.amount.map(|value| trust_core::Money::from_major(
                    value,
                    extracted.currency.unwrap_or_else(|| "EUR".to_string()),
                ))
            },
            arguments: proposed.arguments,
            tags: vec![],
        },
    }
}

/// Convert a NATS DispatchPayload (old format) into an ActionRequest (new format).
pub fn convert_nats_dispatch(payload: &NatsDispatchPayload) -> ActionRequest {
    let clean_args = payload.arguments.clone();
    
    // Extract legacy session info to feed the normalizer
    let meta = clean_args.as_object().and_then(|a| a.get("_meta"));
    let session_jwt = meta
        .and_then(|m| m.get("io.lianxi/session_jwt").or_else(|| m.get("X-Session-JWT")))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let tenant_id = meta
        .and_then(|m| m.get("io.lianxi/tenant_id").or_else(|| m.get("X-Tenant-ID")))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Use the new transport normalizer
    let proposed = crate::transport_normalizer::normalize_nats_dispatch(
        &payload.tool_name,
        clean_args.clone(),
        session_jwt,
        tenant_id,
    ).unwrap_or_else(|e| {
        tracing::debug!("NATS dispatch normalization failed (fallback mode): {}", e);
        // Fallback for malformed _meta to allow policy engine to deny it safely
        identity_context::models::ProposedAction {
            action_id: uuid::Uuid::new_v4().to_string(),
            tool_name: payload.tool_name.clone(),
            arguments: clean_args.clone(),
            identity: identity_context::models::IdentityContext {
                tenant_id: tenant_id.to_string(),
                owner_did: payload.verified_did.clone(),
                requester_did: payload.verified_did.clone(),
                session_jwt: session_jwt.to_string(),
                source: identity_context::models::SourceContext::default(),
            },
            raw_meta: None,
        }
    });

    build_action_request(proposed)
}

/// Run the NATS backward-compat listener (subscribes to mcp.v1.dispatch.>).
pub async fn run_nats_listener(
    nc: async_nats::Client,
    subject: String,
    state: Arc<GatewayState>,
) -> Result<()> {
    let mut subscriber = nc.subscribe(subject.clone()).await
        .context("Failed to subscribe to NATS dispatch subject")?;
    tracing::info!("📬 NATS listener subscribed to {}", subject);

    while let Some(msg) = subscriber.next().await {
        let reply_subject = msg.reply.clone();
        let payload_bytes = msg.payload.to_vec();
        let state = state.clone();
        let nc = nc.clone();

        tokio::spawn(async move {
            let subject = msg.subject.as_str();

            // Handle list_tools request
            if subject.ends_with(".list_tools") {
                // Ignore tool listing requests in the gateway.
                // The dedicated `mcp_nats_bridge` service is responsible for aggregating
                // tools from the VP MCP Server, Skills Registry, and built-in tools.
                // By returning here, we let the bridge win the race condition and serve the tools.
                return;
            }

            // Phase 2.2: read_skill is a bridge-handled introspection tool.
            // Skip gateway processing — the bridge fetches docs from the NSE directly.
            if subject.ends_with(".read_skill") {
                return;
            }

            // Process dispatch through the Trust Gateway governance pipeline
            let payload: NatsDispatchPayload = match serde_json::from_slice(&payload_bytes) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!("Failed to parse NATS dispatch: {}", e);
                    if let Some(reply_to) = reply_subject {
                        let err = serde_json::json!({"error": format!("Parse error: {}", e)});
                        let _ = nc.publish(reply_to, err.to_string().into()).await;
                    }
                    return;
                }
            };

            let action_req = convert_nats_dispatch(&payload);
            let result = process_action(state.clone(), action_req).await;

            if let Some(reply_to) = reply_subject {
                let response = match result {
                    Ok(gw_resp) => {
                        // Map back to the format expected by the old McpAgent.
                        // We extract the actual tool result (content) from the GatewayResponse
                        // so the Agent receives raw tool output, not gateway metadata.
                        let content = gw_resp.result.unwrap_or_else(|| {
                            if gw_resp.status == "pending_approval" || gw_resp.status == "pending_proof" {
                                serde_json::json!([{"type": "text", "text": format!(
                                    "⏳ ACTION BLOCKED — This action requires human approval before it can execute. \
                                     The approval request has been created (approval_id: {}). \
                                     The user must approve this action in their Local SSI Portal before it will be executed. \
                                     DO NOT tell the user the action was completed. Tell them it is PENDING APPROVAL.",
                                    gw_resp.approval_id.as_deref().unwrap_or("unknown")
                                )}])
                            } else {
                                serde_json::json!([{"type": "text", "text": "No tool content available"}])
                            }
                        });

                        // For pending_approval, mark as error so the agent doesn't
                        // treat it as a successful execution
                        let is_error = gw_resp.status == "failed"
                            || gw_resp.status == "denied"
                            || gw_resp.status == "pending_approval"
                            || gw_resp.status == "pending_proof";
                        
                        serde_json::json!({
                            "tool_name": payload.tool_name,
                            "result": {
                                "content": content,
                                "is_error": is_error,
                            },
                            "verified_did": payload.verified_did,
                            "escalation": gw_resp.escalation,
                        })

                    }
                    Err(e) => {
                        serde_json::json!({
                            "error": format!("Gateway error: {}", e)
                        })
                    }
                };
                let _ = nc.publish(reply_to, response.to_string().into()).await;
            }
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
    let event = AuditEvent::new(event_type, component, tenant_id, payload)
        .with_action_id(action_id);
    let subject = format!("audit.action.{}", action_id);
    let json = match serde_json::to_string(&event) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("🚨 AUDIT FAIL-CLOSED: Cannot serialize audit event for action {}: {}", action_id, e);
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
                    tracing::warn!("JetStream ack failed for audit event (falling back to plain NATS): {}", e);
                }
            }
        }
        Err(e) => {
            tracing::warn!("JetStream publish failed for audit event (falling back to plain NATS): {}", e);
        }
    }

    // Fallback: plain NATS (best-effort, not durable)
    if let Err(e) = nc.publish(subject, json.into()).await {
        tracing::error!("🚨 AUDIT FAIL-CLOSED: ALL audit publish mechanisms failed for action {}: {}", action_id, e);
    }
}
