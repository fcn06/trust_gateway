//! Blind Mailbox — JetStream-backed offline message storage for wallet DIDs.
//!
//! Messages are stored keyed by a blind pointer (HMAC of pairwise DID)
//! so the gateway never sees the actual DID in storage keys.

use async_nats::jetstream::{self, Context as JsContext};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};

type HmacSha256 = Hmac<Sha256>;

/// Name of the JetStream stream for blind mailbox storage.
pub const STREAM_NAME: &str = "BLIND_MAILBOX";

/// Default TTL for messages in seconds (7 days).
pub const DEFAULT_TTL_SECS: u64 = 7 * 24 * 3600;

/// A stored mailbox message (envelope only — gateway never decrypts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxMessage {
    /// Unique message ID
    pub id: String,
    /// The encrypted DIDComm envelope (opaque to gateway)
    pub encrypted_payload: String,
    /// Unix timestamp when stored
    pub stored_at: i64,
    /// TTL in seconds from stored_at
    pub ttl_secs: u64,
}

/// Generate a blind pointer from a pairwise DID using HMAC-SHA256.
/// The gateway_seed ensures the pointer is gateway-specific and unlinkable.
pub fn blind_pointer(pairwise_did: &str, gateway_seed: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(gateway_seed)
        .expect("HMAC key length is valid");
    mac.update(b"blind-mailbox:");
    mac.update(pairwise_did.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Initialize the BLIND_MAILBOX JetStream stream if it doesn't exist.
pub async fn init_stream(js: &JsContext) -> Result<(), async_nats::Error> {
    let config = jetstream::stream::Config {
        name: STREAM_NAME.to_string(),
        subjects: vec!["mailbox.>".to_string()],
        max_age: std::time::Duration::from_secs(DEFAULT_TTL_SECS),
        storage: jetstream::stream::StorageType::File,
        ..Default::default()
    };

    match js.get_or_create_stream(config).await {
        Ok(stream) => {
            tracing::info!("📬 Blind Mailbox stream ready: {} ({} messages)", 
                STREAM_NAME, 
                stream.cached_info().state.messages);
            Ok(())
        }
        Err(e) => {
            tracing::error!("❌ Failed to create Blind Mailbox stream: {}", e);
            Err(e.into())
        }
    }
}

/// Store an encrypted message in the blind mailbox for a given pairwise DID.
pub async fn store_message(
    js: &JsContext,
    pairwise_did: &str,
    encrypted_payload: &str,
    gateway_seed: &[u8],
) -> Result<String, String> {
    let pointer = blind_pointer(pairwise_did, gateway_seed);
    let msg_id = uuid::Uuid::new_v4().to_string();
    
    let msg = MailboxMessage {
        id: msg_id.clone(),
        encrypted_payload: encrypted_payload.to_string(),
        stored_at: Utc::now().timestamp(),
        ttl_secs: DEFAULT_TTL_SECS,
    };

    let payload = serde_json::to_vec(&msg)
        .map_err(|e| format!("Serialization failed: {}", e))?;

    let subject = format!("mailbox.{}", pointer);
    
    js.publish(subject, payload.into())
        .await
        .map_err(|e| format!("JetStream publish failed: {}", e))?
        .await
        .map_err(|e| format!("JetStream ack failed: {}", e))?;

    tracing::info!("📬 Stored message {} in blind mailbox (pointer: {}…)", 
        msg_id, &pointer[..12]);
    
    Ok(msg_id)
}

/// Drain all pending messages from a wallet's blind mailbox.
/// Returns messages and creates a consumer that reads all then deletes.
pub async fn drain_mailbox(
    js: &JsContext,
    pairwise_did: &str,
    gateway_seed: &[u8],
) -> Result<Vec<MailboxMessage>, String> {
    let pointer = blind_pointer(pairwise_did, gateway_seed);
    let filter_subject = format!("mailbox.{}", pointer);
    
    let stream = js.get_stream(STREAM_NAME)
        .await
        .map_err(|e| format!("Stream not found: {}", e))?;

    // Create an ephemeral consumer filtered to this DID's messages
    let consumer_config = jetstream::consumer::pull::Config {
        filter_subject: filter_subject.clone(),
        deliver_policy: jetstream::consumer::DeliverPolicy::All,
        ack_policy: jetstream::consumer::AckPolicy::Explicit,
        ..Default::default()
    };

    let consumer = stream
        .create_consumer(consumer_config)
        .await
        .map_err(|e| format!("Consumer creation failed: {}", e))?;

    let mut messages = Vec::new();
    
    // Fetch up to 100 messages with a short timeout
    let mut batch = consumer
        .fetch()
        .max_messages(100)
        .expires(std::time::Duration::from_secs(1))
        .messages()
        .await
        .map_err(|e| format!("Fetch failed: {}", e))?;

    use futures::StreamExt;
    while let Some(Ok(msg)) = batch.next().await {
        if let Ok(mailbox_msg) = serde_json::from_slice::<MailboxMessage>(&msg.payload) {
            messages.push(mailbox_msg);
        }
        // Acknowledge (removes from stream)
        let _ = msg.ack().await;
    }

    tracing::info!("📬 Drained {} messages from blind mailbox (pointer: {}…)", 
        messages.len(), &pointer[..12]);

    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_pointer_deterministic() {
        let seed = b"test-gateway-seed-32-bytes-long!!";
        let p1 = blind_pointer("did:twin:zABC123", seed);
        let p2 = blind_pointer("did:twin:zABC123", seed);
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_blind_pointer_different_dids() {
        let seed = b"test-gateway-seed-32-bytes-long!!";
        let p1 = blind_pointer("did:twin:zABC123", seed);
        let p2 = blind_pointer("did:twin:zDEF456", seed);
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_blind_pointer_different_seeds() {
        let seed1 = b"gateway-seed-1-32-bytes-long!!!!";
        let seed2 = b"gateway-seed-2-32-bytes-long!!!!";
        let p1 = blind_pointer("did:twin:zABC123", seed1);
        let p2 = blind_pointer("did:twin:zABC123", seed2);
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_mailbox_message_serialization() {
        let msg = MailboxMessage {
            id: "test-123".to_string(),
            encrypted_payload: "{\"protected\":\"...\"}".to_string(),
            stored_at: 1709913600,
            ttl_secs: DEFAULT_TTL_SECS,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: MailboxMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "test-123");
        assert_eq!(deserialized.ttl_secs, DEFAULT_TTL_SECS);
    }
}
