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

use crate::gateway::GatewayState;
use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use trust_core::agent::*;

#[derive(serde::Deserialize)]
pub struct ListAgentsQuery {
    #[serde(default)]
    pub status: Option<String>,
}

/// GET /v1/agents — List all registered agents.
pub async fn list_agents_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<ListAgentsQuery>,
) -> impl IntoResponse {
    // Enforce Authentication
    if let Err(status) = state
        .token_validator
        .validate(&headers, &state.jwt_secret)
        .await
    {
        tracing::warn!(
            "🚫 /v1/agents list rejected: Authentication failed ({})",
            status
        );
        let mut response = status.into_response();
        if status == axum::http::StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer realm=\"trust_gateway\""),
            );
        }
        return response;
    }

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
            .into_response()
        }
        Err(e) => Json(serde_json::json!({
            "error": format!("{}", e),
            "agents": [],
            "total": 0,
        }))
        .into_response(),
    }
}

/// POST /v1/agents — Register a new agent.
pub async fn register_agent_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterAgentRequest>,
) -> impl IntoResponse {
    // Enforce Authentication
    if let Err(status) = state
        .token_validator
        .validate(&headers, &state.jwt_secret)
        .await
    {
        tracing::warn!(
            "🚫 /v1/agents register rejected: Authentication failed ({})",
            status
        );
        let mut response = status.into_response();
        if status == axum::http::StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer realm=\"trust_gateway\""),
            );
        }
        return response;
    }

    tracing::info!(
        "📋 Registering new agent: {} (type: {})",
        req.name,
        req.agent_type
    );

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
            )
            .await;

            Json(serde_json::json!({
                "status": "registered",
                "agent": record,
            }))
            .into_response()
        }
        Err(e) => Json(serde_json::json!({
            "error": format!("Registration failed: {}", e),
        }))
        .into_response(),
    }
}

/// GET /v1/agents/:agent_id — Get agent details.
pub async fn get_agent_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    // Enforce Authentication
    if let Err(status) = state
        .token_validator
        .validate(&headers, &state.jwt_secret)
        .await
    {
        tracing::warn!(
            "🚫 /v1/agents get rejected: Authentication failed ({})",
            status
        );
        let mut response = status.into_response();
        if status == axum::http::StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer realm=\"trust_gateway\""),
            );
        }
        return response;
    }

    match state.agent_registry.get(&agent_id).await {
        Ok(Some(agent)) => Json(serde_json::to_value(agent).unwrap_or_default()).into_response(),
        Ok(None) => Json(serde_json::json!({ "error": "Agent not found" })).into_response(),
        Err(e) => Json(serde_json::json!({ "error": format!("{}", e) })).into_response(),
    }
}

/// PATCH /v1/agents/:agent_id — Update agent fields.
pub async fn update_agent_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Path(agent_id): Path<String>,
    Json(req): Json<UpdateAgentRequest>,
) -> impl IntoResponse {
    // Enforce Authentication
    if let Err(status) = state
        .token_validator
        .validate(&headers, &state.jwt_secret)
        .await
    {
        tracing::warn!(
            "🚫 /v1/agents update rejected: Authentication failed ({})",
            status
        );
        let mut response = status.into_response();
        if status == axum::http::StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer realm=\"trust_gateway\""),
            );
        }
        return response;
    }

    tracing::info!("📋 Updating agent: {}", agent_id);

    match state.agent_registry.update(&agent_id, req).await {
        Ok(updated) => Json(serde_json::json!({
            "status": "updated",
            "agent": updated,
        }))
        .into_response(),
        Err(e) => Json(serde_json::json!({ "error": format!("{}", e) })).into_response(),
    }
}

/// DELETE /v1/agents/:agent_id — Revoke an agent (sets status to revoked).
///
/// This is a soft-delete: the record remains for audit purposes, but
/// the agent is permanently blocked from execution.
pub async fn revoke_agent_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    // Enforce Authentication
    if let Err(status) = state
        .token_validator
        .validate(&headers, &state.jwt_secret)
        .await
    {
        tracing::warn!(
            "🚫 /v1/agents revoke rejected: Authentication failed ({})",
            status
        );
        let mut response = status.into_response();
        if status == axum::http::StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer realm=\"trust_gateway\""),
            );
        }
        return response;
    }

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
            )
            .await;

            Json(serde_json::json!({
                "status": "revoked",
                "agent": updated,
            }))
            .into_response()
        }
        Err(e) => Json(serde_json::json!({ "error": format!("{}", e) })).into_response(),
    }
}

/// POST /v1/agents/:agent_id/kill — Emergency kill switch.
///
/// Immediately blocks the agent from all execution, regardless
/// of policy evaluation. This is the highest-priority override.
pub async fn kill_agent_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    // Enforce Authentication
    if let Err(status) = state
        .token_validator
        .validate(&headers, &state.jwt_secret)
        .await
    {
        tracing::warn!(
            "🚫 /v1/agents kill rejected: Authentication failed ({})",
            status
        );
        let mut response = status.into_response();
        if status == axum::http::StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer realm=\"trust_gateway\""),
            );
        }
        return response;
    }

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
            )
            .await;

            Json(serde_json::json!({
                "status": "killed",
                "agent_id": agent_id,
            }))
            .into_response()
        }
        Err(e) => Json(serde_json::json!({ "error": format!("{}", e) })).into_response(),
    }
}

/// POST /v1/agents/:agent_id/revive — Deactivate kill switch.
///
/// Re-enables the agent. Agent must still have status == Active
/// to actually execute actions.
pub async fn revive_agent_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    // Enforce Authentication
    if let Err(status) = state
        .token_validator
        .validate(&headers, &state.jwt_secret)
        .await
    {
        tracing::warn!(
            "🚫 /v1/agents revive rejected: Authentication failed ({})",
            status
        );
        let mut response = status.into_response();
        if status == axum::http::StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer realm=\"trust_gateway\""),
            );
        }
        return response;
    }

    match state.agent_registry.revive(&agent_id).await {
        Ok(()) => {
            tracing::info!("🟢 Agent revived: {}", agent_id);
            Json(serde_json::json!({
                "status": "revived",
                "agent_id": agent_id,
            }))
            .into_response()
        }
        Err(e) => Json(serde_json::json!({ "error": format!("{}", e) })).into_response(),
    }
}

/// Upstream agent definition payload as emitted by agent_core discovery helper
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscoveryAgentDefinition {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub agent_endpoint: Option<String>,
    #[serde(default)]
    pub skills: Vec<DiscoverySkillDefinition>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscoverySkillDefinition {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub parameters: serde_json::Value,
    #[serde(default)]
    pub output: serde_json::Value,
}

/// POST /v1/discovery/agents — Register an upstream agent from agent_core DiscoveryService.
pub async fn discovery_register_handler(
    State(state): State<Arc<GatewayState>>,
    Json(def): Json<DiscoveryAgentDefinition>,
) -> impl IntoResponse {
    let allowed_tools: Vec<String> = def.skills.into_iter().map(|s| s.name).collect();
    let reg_req = RegisterAgentRequest {
        name: def.name.clone(),
        owner: "external_swarm".to_string(),
        agent_type: AgentType::ExternalSwarm,
        environment: AgentEnvironment::Prod,
        policy_profile: "external_restricted".to_string(),
        allowed_tools,
        delegated_identity: def.agent_endpoint.unwrap_or_else(|| "external".to_string()),
        metadata: serde_json::json!({
            "discovery_id": def.id,
            "description": def.description,
        }),
    };

    match state.agent_registry.register(reg_req).await {
        Ok(record) => {
            tracing::info!(
                "📡 Registered upstream discovery agent: {} ({})",
                record.name,
                record.agent_id
            );
            (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({
                    "status": "registered",
                    "agent_id": record.agent_id,
                    "agent": record,
                })),
            )
                .into_response()
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to register discovery agent: {e}"),
            })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_agent_definition_deserialization() {
        let json_payload = serde_json::json!({
            "id": "agent-123",
            "name": "Supplier Agent",
            "description": "Handles B2B negotiation",
            "agent_endpoint": "http://127.0.0.1:9090",
            "skills": [
                {
                    "name": "catalog_query",
                    "description": "Queries product catalog",
                    "parameters": null,
                    "output": null
                }
            ]
        });

        let def: DiscoveryAgentDefinition = serde_json::from_value(json_payload)
            .expect("should deserialize DiscoveryAgentDefinition from agent_core");

        assert_eq!(def.id, Some("agent-123".to_string()));
        assert_eq!(def.name, "Supplier Agent");
        assert_eq!(
            def.agent_endpoint,
            Some("http://127.0.0.1:9090".to_string())
        );
        assert_eq!(def.skills.len(), 1);
        assert_eq!(def.skills[0].name, "catalog_query");
    }
}
