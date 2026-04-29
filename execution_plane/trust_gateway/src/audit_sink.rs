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
//
// P3/H2 fix: Hash chain is now per-action-id (not global) and
// persisted to NATS KV so restarts don't break the chain.
//
// P3/M3 fix: Uses tokio::sync::Mutex instead of std::sync::Mutex
// so we don't block the Tokio thread under high audit throughput.
// ─────────────────────────────────────────────────────────────

use std::collections::HashMap;
use tokio::sync::Mutex;
use sha2::{Sha256, Digest};
use trust_core::audit::{AuditEvent, AuditEventType};
use trust_core::errors::AuditError;

/// NATS KV bucket name for persisting hash chain heads.
const CHAIN_HEAD_BUCKET: &str = "audit_chain_heads";

/// Default AuditSink implementation backed by NATS JetStream.
///
/// Publishes to `audit.action.{action_id}` subjects with a
/// plain NATS fallback if JetStream publish or ack fails.
///
/// WS2: Maintains a hash chain across all published events.
///
/// P3/H2 fix: The hash chain is now per-action-id. Each action
/// has its own independent chain, and the chain head is persisted
/// to the `audit_chain_heads` NATS KV bucket on every publish.
/// On startup, the chain is lazily loaded from KV on first access
/// for each action_id.
///
/// P3/M3 fix: Uses `tokio::sync::Mutex` instead of `std::sync::Mutex`
/// for async-safe locking that doesn't block the Tokio runtime.
pub struct JetStreamAuditSink {
    js: async_nats::jetstream::Context,
    nc: async_nats::Client,
    /// Per-action-id hash chain heads.
    /// Lazily populated from KV on first access per action_id.
    chain_heads: Mutex<HashMap<String, Option<String>>>,
}

impl JetStreamAuditSink {
    pub fn new(js: async_nats::jetstream::Context, nc: async_nats::Client) -> Self {
        Self {
            js,
            nc,
            chain_heads: Mutex::new(HashMap::new()),
        }
    }

    /// Load the persisted chain head for an action_id from NATS KV.
    /// Returns None if no prior chain exists (genesis event).
    async fn load_chain_head(&self, action_id: &str) -> Option<String> {
        match self.js.get_key_value(CHAIN_HEAD_BUCKET).await {
            Ok(store) => {
                match store.get(action_id).await {
                    Ok(Some(entry)) => {
                        String::from_utf8(entry.to_vec()).ok()
                    }
                    _ => None,
                }
            }
            Err(_) => None,
        }
    }

    /// Persist the chain head for an action_id to NATS KV.
    /// Best-effort — if KV write fails, we log and continue.
    async fn persist_chain_head(&self, action_id: &str, hash: &str) {
        let hash_owned = hash.as_bytes().to_vec();
        match self.js.get_key_value(CHAIN_HEAD_BUCKET).await {
            Ok(store) => {
                if let Err(e) = store.put(action_id, hash_owned.into()).await {
                    tracing::warn!(
                        "⚠️ Failed to persist audit chain head for action {}: {} (chain may break on restart)",
                        action_id, e
                    );
                }
            }
            Err(e) => {
                tracing::debug!(
                    "Cannot access {} KV bucket: {} (chain heads not persisted)",
                    CHAIN_HEAD_BUCKET, e
                );
            }
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
        let action_id = event.action_id.clone().unwrap_or_default();

        // ── P3/H2 + M3: Per-action-id hash chain with async mutex ──
        // Lazily load chain head from KV on first access for this action_id,
        // then compute hash and update in-memory + persisted state.
        {
            let mut heads = self.chain_heads.lock().await;

            // Lazy load from KV if we haven't seen this action_id yet
            if !heads.contains_key(&action_id) {
                let persisted = self.load_chain_head(&action_id).await;
                heads.insert(action_id.clone(), persisted);
            }

            let prev_hash = heads.get(&action_id).and_then(|h| h.clone());
            event.prev_hash = prev_hash;
            event.event_hash = Some(Self::compute_event_hash(&event));
            heads.insert(action_id.clone(), event.event_hash.clone());
        }

        // Persist the updated chain head (fire-and-forget, best-effort)
        if let Some(ref hash) = event.event_hash {
            self.persist_chain_head(&action_id, hash).await;
        }

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

    async fn flush(&self) {
        let _ = self.nc.flush().await;
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
