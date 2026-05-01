// ─────────────────────────────────────────────────────────────
// Webhook Handler — Inbound event-driven skills
//
// Intercepts external webhooks (e.g., Stripe, GitHub), validates
// their signatures, evaluates them against the Trust Policy, and
// if allowed, routes them to the agent as an actionable event.
// ─────────────────────────────────────────────────────────────

use std::sync::Arc;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use axum::body::Bytes;
use trust_core::audit::AuditEventType;
use trust_core::action::{ActionRequest, ActionDescriptor, OperationKind};
use trust_core::actor::{ActorContext, SourceContext, AuthLevel};
use trust_core::traits::PolicyEngine;

use crate::gateway::GatewayState;

#[derive(serde::Serialize)]
pub struct WebhookResponse {
    pub status: String,
    pub event_id: String,
}

/// POST /v1/webhooks/:provider
pub async fn webhook_post_handler(
    State(state): State<Arc<GatewayState>>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<WebhookResponse>, StatusCode> {
    let event_id = uuid::Uuid::new_v4().to_string();
    tracing::info!("📥 Received webhook from provider: {} (Event: {})", provider, event_id);

    // 1. Signature Validation (Mocked/Generic for now)
    // In a production scenario, we would use provider-specific secrets
    // to validate HMACs (e.g., X-Hub-Signature-256 for GitHub).
    let is_valid = validate_webhook_signature(&provider, &headers, &body);
    if !is_valid {
        tracing::warn!("❌ Webhook signature validation failed for provider: {}", provider);
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Parse the JSON payload
    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(json) => json,
        Err(e) => {
            tracing::error!("❌ Failed to parse webhook JSON: {}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // 2. Build Policy Evaluation Context (ActionRequest)
    let tenant_id = "system".to_string(); // Webhooks generally operate at a system/tenant level
    let action_name = format!("webhook.{}", provider);
    
    let action_req = ActionRequest {
        action_id: event_id.clone(),
        tenant_id: tenant_id.clone(),
        actor: ActorContext {
            owner_did: "system".to_string(),
            requester_did: format!("webhook:{}", provider),
            user_did: None,
            session_jti: event_id.clone(),
            auth_level: AuthLevel::Session,
        },
        source: SourceContext::webhook(provider.clone()),
        action: ActionDescriptor {
            name: action_name.clone(),
            category: provider.clone(),
            resource: None,
            operation: OperationKind::Create,
            amount: None,
            arguments: payload.clone(),
            tags: vec![provider.clone(), "webhook".to_string()],
        },
    };

    // 3. Evaluate Policy
    let policy_decision = state.security.policy_engine.evaluate(&action_req).await.unwrap_or_else(|e| {
        tracing::error!("Policy evaluation error: {}", e);
        trust_core::decision::ActionDecision::Deny {
            reason: "Policy engine error".to_string(),
            policy_id: "error".to_string(),
        }
    });

    tracing::info!("🛡️ Webhook policy decision for {}: {:?}", action_name, policy_decision);

    if !policy_decision.is_allowed() {
        // Log rejection
        let state_clone = state.clone();
        let event_id_clone = event_id.clone();
        tokio::spawn(async move {
            crate::audit_sink::emit_audit(
                &*state_clone.security.audit_sink,
                &tenant_id,
                AuditEventType::ActionFailed,
                "trust_gateway.webhook",
                &event_id_clone,
                serde_json::json!({
                    "reason": format!("Policy evaluation resulted in denial: {:?}", policy_decision),
                    "provider": provider,
                })
            ).await;
        });

        return Err(StatusCode::FORBIDDEN);
    }

    // 4. Dispatch to Agent
    // Since it's allowed, we push the event to NATS so the agent can react to it.
    let subject = format!("mcp.v1.webhook.{}", provider);
    let message = serde_json::json!({
        "event_id": event_id,
        "provider": provider,
        "payload": payload,
        "policy_rule": policy_decision.policy_id(),
    });

    match state.nats.publish(subject, serde_json::to_vec(&message).unwrap().into()).await {
        Ok(_) => {
            tracing::info!("✅ Successfully dispatched webhook event to agent bus");
            Ok(Json(WebhookResponse {
                status: "accepted".to_string(),
                event_id,
            }))
        }
        Err(e) => {
            tracing::error!("❌ Failed to publish webhook to NATS: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Helper to validate webhook signatures.
fn validate_webhook_signature(provider: &str, headers: &HeaderMap, body: &[u8]) -> bool {
    // Phase 1: Simple passthrough.
    // In production, this checks `X-Hub-Signature-256`, `Stripe-Signature`, etc.
    // against configured env vars like `GITHUB_WEBHOOK_SECRET`.
    true
}
