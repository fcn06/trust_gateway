//! WhatsApp webhook — receives inbound WhatsApp messages (via Twilio/Meta API).

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::json;

use super::shadow_identity::generate_shadow_did;
use crate::GatewayAppState;

/// WhatsApp inbound message payload.
#[derive(Debug, Deserialize)]
pub struct WhatsAppInbound {
    pub from: String,
    pub to: String,
    pub body: String,
    pub message_id: Option<String>,
    /// Tenant ID (resolved from webhook URL path or config).
    pub tenant_id: Option<String>,
}

/// POST /webhooks/whatsapp — Receive inbound WhatsApp message.
pub async fn whatsapp_webhook(
    State(state): State<GatewayAppState>,
    Json(msg): Json<WhatsAppInbound>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    tracing::info!(
        "💬 [WhatsApp] Inbound from {} to {}: {}",
        msg.from,
        msg.to,
        &msg.body[..msg.body.len().min(50)]
    );

    let tenant_id = msg
        .tenant_id
        .clone()
        .or_else(|| state.phone_to_tenant.get(&msg.to).cloned())
        .unwrap_or_else(|| "default".to_string());

    let shadow_did = generate_shadow_did(
        &state.gateway_seed,
        &tenant_id,
        &msg.from,
        "whatsapp",
    );

    let didcomm_msg = json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "type": "https://didcomm.org/basicmessage/2.0/message",
        "from": shadow_did,
        "body": {
            "content": msg.body,
            "channel": "whatsapp",
            "original_sender": msg.from,
        },
        "created_time": chrono::Utc::now().timestamp()
    });

    let subject = state.tenant_router.resolve_subject(
        &tenant_id,
        "gateway",
        &shadow_did,
    ).map_err(|e| (StatusCode::FORBIDDEN, e))?;

    state.rate_limiter.check_tenant(&tenant_id)
        .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;

    state
        .nats
        .publish(subject, serde_json::to_vec(&didcomm_msg).unwrap().into())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("NATS publish failed: {}", e)))?;

    Ok(Json(json!({"status": "received"})))
}
