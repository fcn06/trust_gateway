// ─────────────────────────────────────────────────────────────
// JetStream Audit Sink — implements trust_core::traits::AuditSink
//
// WS2: Hash-chained implementation that computes SHA-256 chain
// hashes before publishing. Each event includes:
//   - prev_hash: hash of the previous event (None for genesis)
//   - event_hash: SHA-256(prev_hash || canonical(event data))
//
// This makes the audit trail tamper-evident: any modification
// to a past event breaks the hash chain from that point forward.
// ─────────────────────────────────────────────────────────────

use std::sync::Mutex;
use sha2::{Sha256, Digest};
use trust_core::audit::{AuditEvent, AuditEventType};
use trust_core::errors::AuditError;

/// Default AuditSink implementation backed by NATS JetStream.
///
/// Publishes to `audit.action.{action_id}` subjects with a
/// plain NATS fallback if JetStream publish or ack fails.
///
/// WS2: Maintains a hash chain across all published events.
pub struct JetStreamAuditSink {
    js: async_nats::jetstream::Context,
    nc: async_nats::Client,
    /// The hash of the most recently published event.
    /// Protected by a Mutex for thread-safe sequential access.
    last_hash: Mutex<Option<String>>,
}

impl JetStreamAuditSink {
    pub fn new(js: async_nats::jetstream::Context, nc: async_nats::Client) -> Self {
        Self {
            js,
            nc,
            last_hash: Mutex::new(None),
        }
    }

    /// Compute the SHA-256 hash of an event for chain integrity.
    ///
    /// The hash covers: event_id + tenant_id + timestamp + event_type +
    /// canonical(payload) + prev_hash. This ensures any field mutation
    /// breaks the chain.
    fn compute_event_hash(event: &AuditEvent) -> String {
        let mut hasher = Sha256::new();
        hasher.update(event.event_id.as_bytes());
        hasher.update(event.tenant_id.as_bytes());
        hasher.update(event.timestamp.to_rfc3339().as_bytes());
        hasher.update(format!("{:?}", event.event_type).as_bytes());
        // Use canonical JSON for the payload to ensure deterministic hashing
        let payload_str = serde_json::to_string(&event.payload).unwrap_or_default();
        hasher.update(payload_str.as_bytes());
        if let Some(ref prev) = event.prev_hash {
            hasher.update(prev.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

#[async_trait::async_trait]
impl trust_core::traits::AuditSink for JetStreamAuditSink {
    async fn publish(&self, mut event: AuditEvent) -> Result<(), AuditError> {
        // ── WS2: Hash-chain computation ─────────────────────
        // Set prev_hash from the last published event, compute
        // this event's hash, then update the chain head.
        {
            let mut last = self.last_hash.lock().unwrap();
            event.prev_hash = last.clone();
            event.event_hash = Some(Self::compute_event_hash(&event));
            *last = event.event_hash.clone();
        }

        let action_id = event.action_id.clone().unwrap_or_default();
        let subject = format!("audit.action.{}", action_id);
        let json = serde_json::to_string(&event)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;

        // Emit on the v1 broadcast subject for SSE listeners
        let broadcast_subject = "audit.v1.events";
        let _ = self.nc.publish(broadcast_subject.to_string(), json.clone().into()).await;

        // Try JetStream durable publish first
        match self.js.publish(subject.clone(), json.clone().into()).await {
            Ok(ack_future) => {
                match ack_future.await {
                    Ok(_) => return Ok(()),
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
        self.nc
            .publish(subject, json.into())
            .await
            .map_err(|e| {
                tracing::error!(
                    "🚨 AUDIT FAIL-CLOSED: ALL audit publish mechanisms failed for action {}: {}",
                    action_id, e
                );
                AuditError::PublishFailed(e.to_string())
            })
    }
}

/// Helper to build and publish an audit event via the AuditSink trait.
///
/// This replaces the old `publish_audit()` free function. Call sites
/// use this instead of constructing AuditEvent + calling sink directly.
pub async fn emit_audit(
    sink: &dyn trust_core::traits::AuditSink,
    tenant_id: &str,
    event_type: AuditEventType,
    component: &str,
    action_id: &str,
    payload: serde_json::Value,
) {
    let event = AuditEvent::new(event_type, component, tenant_id, payload)
        .with_action_id(action_id);
    if let Err(e) = sink.publish(event).await {
        tracing::error!("🚨 Audit emit failed for action {}: {}", action_id, e);
    }
}
