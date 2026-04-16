// ─────────────────────────────────────────────────────────────
// JetStream Audit Sink — implements trust_core::traits::AuditSink
//
// Default community implementation that publishes audit events
// to NATS JetStream with a plain NATS fallback.
// ─────────────────────────────────────────────────────────────

use trust_core::audit::{AuditEvent, AuditEventType};
use trust_core::errors::AuditError;

/// Default AuditSink implementation backed by NATS JetStream.
///
/// Publishes to `audit.action.{action_id}` subjects with a
/// plain NATS fallback if JetStream publish or ack fails.
pub struct JetStreamAuditSink {
    js: async_nats::jetstream::Context,
    nc: async_nats::Client,
}

impl JetStreamAuditSink {
    pub fn new(js: async_nats::jetstream::Context, nc: async_nats::Client) -> Self {
        Self { js, nc }
    }
}

#[async_trait::async_trait]
impl trust_core::traits::AuditSink for JetStreamAuditSink {
    async fn publish(&self, event: AuditEvent) -> Result<(), AuditError> {
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
