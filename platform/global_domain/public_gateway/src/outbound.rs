//! Outbound channel dispatcher — converts DIDComm replies to Web2 API calls.
//!
//! When the host replies to a shadow DID via DIDComm, this module detects
//! the channel metadata and dispatches the reply through the appropriate
//! Web2 API (Twilio SMS, WhatsApp Business API, email).

use serde::{Deserialize, Serialize};

/// Outbound message to be dispatched via a Web2 channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundMessage {
    pub tenant_id: String,
    /// The original sender's external identifier (phone, email).
    pub recipient: String,
    /// The channel to dispatch through.
    pub channel: String,
    /// The message body to send.
    pub body: String,
    /// Thread ID for conversation tracking.
    pub thread_id: Option<String>,
}

/// Delivery status for an outbound message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryStatus {
    pub message_id: String,
    pub channel: String,
    pub status: DeliveryState,
    pub external_id: Option<String>,
    pub error: Option<String>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeliveryState {
    Queued,
    Sent,
    Delivered,
    Failed,
}

/// Outbound channel dispatcher.
///
/// In V1, this is a stub that logs outbound messages. Full implementation
/// will integrate with Twilio REST API, WhatsApp Business API, and SMTP.
pub struct OutboundDispatcher {
    pub twilio_account_sid: Option<String>,
    pub twilio_auth_token: Option<String>,
    pub twilio_from_number: Option<String>,
}

impl OutboundDispatcher {
    pub fn new() -> Self {
        Self {
            twilio_account_sid: std::env::var("TWILIO_ACCOUNT_SID").ok(),
            twilio_auth_token: std::env::var("TWILIO_AUTH_TOKEN").ok(),
            twilio_from_number: std::env::var("TWILIO_FROM_NUMBER").ok(),
        }
    }

    /// Dispatch an outbound message through the appropriate channel.
    pub async fn dispatch(&self, msg: &OutboundMessage) -> DeliveryStatus {
        tracing::info!(
            "📤 [{}] Dispatching to {}: {}",
            msg.channel,
            msg.recipient,
            &msg.body[..msg.body.len().min(50)]
        );

        match msg.channel.as_str() {
            "sms" => self.dispatch_sms(msg).await,
            "whatsapp" => self.dispatch_whatsapp(msg).await,
            "email" => self.dispatch_email(msg).await,
            _ => DeliveryStatus {
                message_id: uuid::Uuid::new_v4().to_string(),
                channel: msg.channel.clone(),
                status: DeliveryState::Failed,
                external_id: None,
                error: Some(format!("Unknown channel: {}", msg.channel)),
                timestamp: chrono::Utc::now().timestamp(),
            },
        }
    }

    async fn dispatch_sms(&self, msg: &OutboundMessage) -> DeliveryStatus {
        // V1: Log and return success stub
        // Full impl: POST to https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json
        tracing::info!(
            "📱 [SMS] Would send to {}: {}",
            msg.recipient,
            &msg.body[..msg.body.len().min(50)]
        );
        DeliveryStatus {
            message_id: uuid::Uuid::new_v4().to_string(),
            channel: "sms".to_string(),
            status: DeliveryState::Queued,
            external_id: None,
            error: None,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    async fn dispatch_whatsapp(&self, msg: &OutboundMessage) -> DeliveryStatus {
        tracing::info!(
            "💬 [WhatsApp] Would send to {}: {}",
            msg.recipient,
            &msg.body[..msg.body.len().min(50)]
        );
        DeliveryStatus {
            message_id: uuid::Uuid::new_v4().to_string(),
            channel: "whatsapp".to_string(),
            status: DeliveryState::Queued,
            external_id: None,
            error: None,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    async fn dispatch_email(&self, msg: &OutboundMessage) -> DeliveryStatus {
        tracing::info!(
            "📧 [Email] Would send to {}: {}",
            msg.recipient,
            &msg.body[..msg.body.len().min(50)]
        );
        DeliveryStatus {
            message_id: uuid::Uuid::new_v4().to_string(),
            channel: "email".to_string(),
            status: DeliveryState::Queued,
            external_id: None,
            error: None,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    /// Web2 fallback for users who don't have a Sovereign Wallet connected.
    ///
    /// When an ActionRequest cannot be delivered because the user has no active
    /// WebSocket session, this method sends a Web2 message (SMS or WhatsApp)
    /// with a link to onboard to the Sovereign Web Wallet.
    pub async fn dispatch_wallet_fallback(
        &self,
        recipient: &str,
        channel: &str,
        action_summary: &str,
        onboarding_url: &str,
    ) -> DeliveryStatus {
        let body = format!(
            "🔐 Action Required: {}\n\n\
             Your approval is needed but you don't have a Sovereign Wallet connected. \
             Upgrade to take control of your data:\n{}\n\n\
             This approval request will expire in 5 minutes.",
            action_summary, onboarding_url
        );

        let msg = OutboundMessage {
            tenant_id: "system".to_string(),
            recipient: recipient.to_string(),
            channel: channel.to_string(),
            body,
            thread_id: None,
        };

        tracing::info!(
            "📲 [Wallet Fallback] Sending upgrade prompt via {} to {}",
            channel, recipient
        );

        self.dispatch(&msg).await
    }
}
