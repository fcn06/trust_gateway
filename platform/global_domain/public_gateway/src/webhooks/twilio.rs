//! Twilio SMS webhook — receives inbound SMS and wraps into DIDComm.

use axum::{extract::State, http::StatusCode, Form};
use serde::Deserialize;
use serde_json::json;

use super::shadow_identity::generate_shadow_did;
use crate::GatewayAppState;

/// Twilio webhook payload (subset of fields).
#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
pub struct TwilioInboundSms {
    pub From: String,
    pub To: String,
    pub Body: String,
    pub MessageSid: Option<String>,
}

/// POST /webhooks/twilio — Receive inbound SMS from Twilio.
///
/// 1. Identify the tenant from the `To` number (lookup in config)
/// 2. Generate a shadow DID for the sender
/// 3. Wrap the SMS body into a DIDComm v2 chat message
/// 4. Route through tenant NATS namespace
pub async fn twilio_webhook(
    State(state): State<GatewayAppState>,
    Form(sms): Form<TwilioInboundSms>,
) -> Result<String, (StatusCode, String)> {
    tracing::info!(
        "📱 [SMS] Inbound from {} to {}: {}",
        sms.From,
        sms.To,
        &sms.Body[..sms.Body.len().min(50)]
    );

    // Resolve tenant from phone number mapping
    let tenant_id = state
        .phone_to_tenant
        .get(&sms.To)
        .cloned()
        .unwrap_or_else(|| "default".to_string());

    // Generate shadow DID
    let shadow_did = generate_shadow_did(
        &state.gateway_seed,
        &tenant_id,
        &sms.From,
        "sms",
    );

    // Wrap into DIDComm-like message
    let didcomm_msg = json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "type": "https://didcomm.org/basicmessage/2.0/message",
        "from": shadow_did,
        "body": {
            "content": sms.Body,
            "channel": "sms",
            "original_sender": sms.From,
        },
        "created_time": chrono::Utc::now().timestamp()
    });

    // Route via tenant NATS
    let subject = state.tenant_router.resolve_subject(
        &tenant_id,
        "gateway",
        &shadow_did,
    ).map_err(|e| (StatusCode::FORBIDDEN, e))?;

    // Rate check
    state.rate_limiter.check_tenant(&tenant_id)
        .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;
    state.rate_limiter.check_sender(&shadow_did)
        .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;

    state
        .nats
        .publish(subject, serde_json::to_vec(&didcomm_msg).unwrap().into())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("NATS publish failed: {}", e)))?;

    // Return TwiML empty response (acknowledge receipt)
    Ok("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response></Response>".to_string())
}
