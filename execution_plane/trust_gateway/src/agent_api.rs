// ─────────────────────────────────────────────────────────────
// Agent Registry HTTP API
//
// CRUD + kill switch for the agent registry.
// Mounted under /v1/agents/* on the Trust Gateway.
//
// Endpoints:
//   GET    /v1/agents                — List all agents
//   POST   /v1/agents                — Register a new agent
//   GET    /v1/agents/:agent_id      — Get agent details
//   PATCH  /v1/agents/:agent_id      — Update agent fields
//   DELETE /v1/agents/:agent_id      — Revoke agent (sets status=revoked)
//   POST   /v1/agents/:agent_id/kill — Activate kill switch
//   POST   /v1/agents/:agent_id/revive — Deactivate kill switch
// ─────────────────────────────────────────────────────────────

use std::sync::Arc;
use axum::{
    extract::{State, Path, Query},
    Json,
};
use crate::gateway::GatewayState;
use trust_core::agent::*;

#[derive(serde::Deserialize)]
pub struct ListAgentsQuery {
    #[serde(default)]
    pub status: Option<String>,
}

/// GET /v1/agents — List all registered agents.
pub async fn list_agents_handler(
    State(state): State<Arc<GatewayState>>,
    Query(query): Query<ListAgentsQuery>,
) -> Json<serde_json::Value> {
    let status_filter = query.status.and_then(|s| match s.as_str() {
        "active" => Some(AgentStatus::Active),
        "paused" => Some(AgentStatus::Paused),
        "revoked" => Some(AgentStatus::Revoked),
        _ => None,
    });

    match state.agent_registry.list(status_filter).await {
        Ok(agents) => {
            let total = agents.len();
            Json(serde_json::json!({
                "agents": agents,
                "total": total,
            }))
        }
        Err(e) => Json(serde_json::json!({
            "error": format!("{}", e),
            "agents": [],
            "total": 0,
        })),
    }
}

/// POST /v1/agents — Register a new agent.
pub async fn register_agent_handler(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<RegisterAgentRequest>,
) -> Json<serde_json::Value> {
    tracing::info!("📋 Registering new agent: {} (type: {})", req.name, req.agent_type);

    match state.agent_registry.register(req).await {
        Ok(record) => {
            // Emit audit event for agent registration
            crate::audit_sink::emit_audit(
                &*state.security.audit_sink,
                "system",
                trust_core::audit::AuditEventType::ActionProposed,
                "agent_registry",
                &record.agent_id,
                serde_json::json!({
                    "event": "agent.registered",
                    "agent_id": record.agent_id,
                    "agent_name": record.name,
                    "agent_type": format!("{}", record.agent_type),
                    "owner": record.owner,
                    "environment": format!("{}", record.environment),
                    "policy_profile": record.policy_profile,
                }),
            ).await;

            Json(serde_json::json!({
                "status": "registered",
                "agent": record,
            }))
        }
        Err(e) => Json(serde_json::json!({
            "error": format!("Registration failed: {}", e),
        })),
    }
}

/// GET /v1/agents/:agent_id — Get agent details.
pub async fn get_agent_handler(
    State(state): State<Arc<GatewayState>>,
    Path(agent_id): Path<String>,
) -> Json<serde_json::Value> {
    match state.agent_registry.get(&agent_id).await {
        Ok(Some(agent)) => Json(serde_json::to_value(agent).unwrap_or_default()),
        Ok(None) => Json(serde_json::json!({ "error": "Agent not found" })),
        Err(e) => Json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// PATCH /v1/agents/:agent_id — Update agent fields.
pub async fn update_agent_handler(
    State(state): State<Arc<GatewayState>>,
    Path(agent_id): Path<String>,
    Json(req): Json<UpdateAgentRequest>,
) -> Json<serde_json::Value> {
    tracing::info!("📋 Updating agent: {}", agent_id);

    match state.agent_registry.update(&agent_id, req).await {
        Ok(updated) => Json(serde_json::json!({
            "status": "updated",
            "agent": updated,
        })),
        Err(e) => Json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// DELETE /v1/agents/:agent_id — Revoke an agent (sets status to revoked).
///
/// This is a soft-delete: the record remains for audit purposes, but
/// the agent is permanently blocked from execution.
pub async fn revoke_agent_handler(
    State(state): State<Arc<GatewayState>>,
    Path(agent_id): Path<String>,
) -> Json<serde_json::Value> {
    tracing::warn!("🚫 Revoking agent: {}", agent_id);

    let req = UpdateAgentRequest {
        name: None,
        owner: None,
        environment: None,
        policy_profile: None,
        allowed_tools: None,
        delegated_identity: None,
        status: Some(AgentStatus::Revoked),
        kill_switch: Some(true),
        metadata: None,
    };

    match state.agent_registry.update(&agent_id, req).await {
        Ok(updated) => {
            // Emit audit event
            crate::audit_sink::emit_audit(
                &*state.security.audit_sink,
                "system",
                trust_core::audit::AuditEventType::ActionFailed,
                "agent_registry",
                &agent_id,
                serde_json::json!({
                    "event": "agent.revoked",
                    "agent_id": agent_id,
                    "agent_name": updated.name,
                }),
            ).await;

            Json(serde_json::json!({
                "status": "revoked",
                "agent": updated,
            }))
        }
        Err(e) => Json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /v1/agents/:agent_id/kill — Emergency kill switch.
///
/// Immediately blocks the agent from all execution, regardless
/// of policy evaluation. This is the highest-priority override.
pub async fn kill_agent_handler(
    State(state): State<Arc<GatewayState>>,
    Path(agent_id): Path<String>,
) -> Json<serde_json::Value> {
    match state.agent_registry.kill(&agent_id).await {
        Ok(()) => {
            // Emit audit event
            crate::audit_sink::emit_audit(
                &*state.security.audit_sink,
                "system",
                trust_core::audit::AuditEventType::ActionFailed,
                "agent_registry",
                &agent_id,
                serde_json::json!({
                    "event": "agent.killed",
                    "agent_id": agent_id,
                }),
            ).await;

            Json(serde_json::json!({
                "status": "killed",
                "agent_id": agent_id,
            }))
        }
        Err(e) => Json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /v1/agents/:agent_id/revive — Deactivate kill switch.
///
/// Re-enables the agent. Agent must still have status == Active
/// to actually execute actions.
pub async fn revive_agent_handler(
    State(state): State<Arc<GatewayState>>,
    Path(agent_id): Path<String>,
) -> Json<serde_json::Value> {
    match state.agent_registry.revive(&agent_id).await {
        Ok(()) => {
            tracing::info!("🟢 Agent revived: {}", agent_id);
            Json(serde_json::json!({
                "status": "revived",
                "agent_id": agent_id,
            }))
        }
        Err(e) => Json(serde_json::json!({ "error": format!("{}", e) })),
    }
}
