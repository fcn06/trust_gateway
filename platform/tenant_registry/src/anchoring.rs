//! Audit anchoring — daily hash computation for compliance tamper-evidence.
//!
//! Computes a SHA256 hash of all audit events in a tenant's audit stream
//! for a given day, forming a verifiable anchor chain. Each day's anchor
//! includes the previous day's hash for chain integrity.

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use crate::AppState;

/// A single day's audit anchor record.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditAnchor {
    pub tenant_id: String,
    /// ISO 8601 date (e.g., "2026-03-02")
    pub date: String,
    /// SHA256 hash of all audit events for the day.
    pub hash: String,
    /// Hash of the previous day's anchor (chain link).
    pub previous_hash: String,
    /// Number of events included in the hash.
    pub event_count: u64,
    /// Timestamp when this anchor was computed.
    pub computed_at: i64,
}

/// Compute a daily audit anchor for a tenant.
///
/// Reads all audit events for the given date from the tenant's audit KV bucket,
/// hashes them in order, and stores the anchor record.
pub async fn compute_daily_anchor(
    state: &Arc<AppState>,
    tenant_id: &str,
    date: &str,
) -> anyhow::Result<AuditAnchor> {
    let bucket_name = format!("tenant_{}_agent_audit", tenant_id);
    let audit_kv = state.js.get_key_value(&bucket_name).await?;

    let mut hasher = Sha256::new();
    let mut event_count: u64 = 0;

    // Iterate all keys and hash their values
    let mut keys = audit_kv.keys().await?;
    use futures::StreamExt;
    while let Some(Ok(key)) = keys.next().await {
        if let Ok(Some(entry)) = audit_kv.get(&key).await {
            // Filter by date if the event has a `ts` field
            if let Ok(event) = serde_json::from_slice::<serde_json::Value>(&entry.to_vec()) {
                if let Some(ts) = event.get("ts").and_then(|v| v.as_u64()) {
                    let event_date = chrono::DateTime::from_timestamp(ts as i64, 0)
                        .map(|dt| dt.format("%Y-%m-%d").to_string())
                        .unwrap_or_default();
                    if event_date != date {
                        continue;
                    }
                }
            }
            hasher.update(&entry.to_vec());
            event_count += 1;
        }
    }

    // Get previous day's anchor hash (chain link)
    let anchor_bucket_name = format!("tenant_{}_audit_anchors", tenant_id);
    let anchor_kv = state.js.create_key_value(async_nats::jetstream::kv::Config {
        bucket: anchor_bucket_name.clone(),
        description: format!("Audit anchors for tenant {}", tenant_id),
        history: 1,
        ..Default::default()
    }).await?;

    // Compute previous date
    let prev_date = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d")?
        .pred_opt()
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default();

    let previous_hash = match anchor_kv.get(&prev_date).await {
        Ok(Some(entry)) => {
            if let Ok(prev_anchor) = serde_json::from_slice::<AuditAnchor>(&entry) {
                prev_anchor.hash
            } else {
                "genesis".to_string()
            }
        }
        _ => "genesis".to_string(),
    };

    // Include previous hash in the chain
    hasher.update(previous_hash.as_bytes());

    let hash = format!("{:x}", hasher.finalize());
    let now = chrono::Utc::now().timestamp();

    let anchor = AuditAnchor {
        tenant_id: tenant_id.to_string(),
        date: date.to_string(),
        hash,
        previous_hash,
        event_count,
        computed_at: now,
    };

    // Store the anchor
    let anchor_bytes = serde_json::to_vec(&anchor)?;
    anchor_kv.put(date, anchor_bytes.into()).await?;

    tracing::info!(
        "🔗 Computed audit anchor for tenant {} date {}: {} events, hash: {}",
        tenant_id,
        date,
        event_count,
        &anchor.hash[..16]
    );

    Ok(anchor)
}
