// ─────────────────────────────────────────────────────────────
// Audit Timeline Projector
//
// Background task that subscribes to the JetStream AUDIT_EVENTS
// stream and builds ActionTimeline read models in the
// `action_timelines` KV bucket.
// ─────────────────────────────────────────────────────────────

use async_nats::jetstream::{self, consumer::pull::Config as ConsumerConfig, kv};
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;

/// A projected action timeline stored in the `action_timelines` KV bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionTimeline {
    pub action_id: String,
    pub tenant_id: String,
    #[serde(default)]
    pub approval_id: Option<String>,
    pub summary: ActionTimelineSummary,
    pub timeline: Vec<TimelineEvent>,
    pub last_updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionTimelineSummary {
    pub title: String,
    pub action_name: String,
    pub source_type: String,
    pub status: String,
    pub risk_level: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub seq: u64,
    pub event_type: String,
    pub at: String,
    pub component: String,
    pub label: String,
    pub details: serde_json::Value,
}

/// Map audit event types to human-readable labels.
fn event_label(event_type: &str) -> &'static str {
    match event_type {
        "action_proposed" => "Action proposed",
        "policy_evaluated" => "Policy matched",
        "approval_requested" => "Approval requested",
        "approval_approved" => "Approved by human",
        "approval_denied" => "Denied",
        "proof_requested" => "Role proof requested",
        "proof_verified" => "Role proof verified",
        "grant_issued" => "One-time grant issued",
        "action_succeeded" => "Action executed",
        "action_failed" => "Action failed",
        "action_retried" => "Dispatch retried",
        _ => "Unknown event",
    }
}

/// Derive the projected status from the latest event.
fn projected_status(event_type: &str, details: &serde_json::Value) -> String {
    match event_type {
        "action_proposed" => "pending".to_string(),
        "policy_evaluated" => "pending".to_string(),
        "approval_requested" => "waiting_approval".to_string(),
        "proof_requested" => "waiting_proof".to_string(),
        "approval_approved" => "approved".to_string(),
        "approval_denied" => "denied".to_string(),
        "proof_verified" => {
            if details.get("verified").and_then(|v| v.as_bool()).unwrap_or(false) {
                "approved".to_string()
            } else {
                "denied".to_string()
            }
        }
        "grant_issued" => "approved".to_string(),
        "action_succeeded" => "executed".to_string(),
        "action_failed" => "failed".to_string(),
        // WS1.1: Retry events don't change the projected status
        "action_retried" => "retrying".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Spawn the audit projector background task.
///
/// This subscribes to the `AUDIT_EVENTS` JetStream stream with a
/// durable pull consumer and updates the `action_timelines` KV bucket.
pub async fn spawn_projector(
    js: jetstream::Context,
    audit_stream_name: &str,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    // Get or create the action_timelines KV store
    let kv_store = match js.get_key_value("action_timelines").await {
        Ok(store) => store,
        Err(e) => {
            tracing::warn!("⚠️ Cannot access action_timelines KV bucket (projector disabled): {}", e);
            return Ok(tokio::spawn(async {}));
        }
    };

    // Create a durable pull consumer for the projector
    let stream = match js.get_stream(audit_stream_name).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("⚠️ Cannot access AUDIT_EVENTS stream (projector disabled): {}", e);
            return Ok(tokio::spawn(async {}));
        }
    };

    let consumer = stream.get_or_create_consumer("timeline_projector", ConsumerConfig {
        durable_name: Some("timeline_projector".to_string()),
        ack_policy: jetstream::consumer::AckPolicy::Explicit,
        ..Default::default()
    }).await?;

    tracing::info!("✅ Audit timeline projector started (durable consumer: timeline_projector)");

    let handle = tokio::spawn(async move {
        loop {
            match consumer.messages().await {
                Ok(mut messages) => {
                    while let Some(Ok(msg)) = messages.next().await {
                        if let Err(e) = process_audit_message(&kv_store, &msg).await {
                            tracing::warn!("⚠️ Projector failed to process audit event: {}", e);
                        }
                        let _ = msg.ack().await;
                    }
                }
                Err(e) => {
                    tracing::error!("❌ Projector consumer error: {} — retrying in 5s", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    });

    Ok(handle)
}

/// Process a single audit event message and upsert into the timeline KV.
///
/// WS1.4: Idempotent — uses JetStream stream_sequence to deduplicate.
/// If a message with the same stream_sequence was already processed for
/// this action_id, it is silently skipped.
async fn process_audit_message(
    kv_store: &kv::Store,
    msg: &async_nats::jetstream::Message,
) -> anyhow::Result<()> {
    let event: serde_json::Value = serde_json::from_slice(&msg.payload)?;

    let action_id = event.get("action_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if action_id.is_empty() {
        return Ok(()); // Skip events without action_id
    }

    // WS1.4: Extract JetStream stream_sequence for idempotency
    let stream_seq = msg.info()
        .map(|info| info.stream_sequence)
        .unwrap_or(0);

    let event_type_str = event.get("event_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let tenant_id = event.get("tenant_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let component = event.get("component")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let timestamp = event.get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let details = event.get("payload")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    // Try to get existing timeline or create a new one
    let mut timeline = match kv_store.get(&action_id).await {
        Ok(Some(entry)) => {
            serde_json::from_slice::<ActionTimeline>(&entry)
                .unwrap_or_else(|_| new_timeline(&action_id, &tenant_id, &event_type_str, &details))
        }
        _ => new_timeline(&action_id, &tenant_id, &event_type_str, &details),
    };

    // WS1.4: Idempotency check — skip if we already have this stream sequence
    if stream_seq > 0 && timeline.timeline.iter().any(|e| e.seq == stream_seq) {
        tracing::debug!(
            "⏭️ Skipping duplicate event for action {} (stream_seq={})",
            action_id, stream_seq
        );
        return Ok(());
    }

    // Add the new event with the JetStream stream_sequence as its seq
    let timeline_event = TimelineEvent {
        seq: stream_seq,
        event_type: event_type_str.clone(),
        at: timestamp.clone(),
        component,
        label: event_label(&event_type_str).to_string(),
        details: details.clone(),
    };
    timeline.timeline.push(timeline_event);

    // Update status from latest event (skip retries — they shouldn't change status)
    if event_type_str != "action_retried" {
        timeline.summary.status = projected_status(&event_type_str, &details);
    }
    timeline.last_updated_at = timestamp;

    // Update title from action_name if available (from action_proposed event)
    if event_type_str == "action_proposed" {
        if let Some(name) = details.get("action_name").and_then(|v| v.as_str()) {
            timeline.summary.action_name = name.to_string();
            // Use the normalizer to generate a title
            let normalized = crate::normalizer::normalize_action(name, &details);
            timeline.summary.title = normalized.title;
        }
        if let Some(source) = details.get("source_type").and_then(|v| v.as_str()) {
            timeline.summary.source_type = source.to_string();
        }
    }

    // Extract approval_id from relevant events
    if let Some(aid) = details.get("approval_id").and_then(|v| v.as_str()) {
        timeline.approval_id = Some(aid.to_string());
    }

    // Persist back to KV
    let bytes = serde_json::to_vec(&timeline)?;
    kv_store.put(&action_id, bytes.into()).await?;

    tracing::debug!("📝 Timeline updated for action {} (event: {}, seq: {}, status: {})",
        action_id, event_type_str, stream_seq, timeline.summary.status);

    Ok(())
}

fn new_timeline(action_id: &str, tenant_id: &str, event_type: &str, details: &serde_json::Value) -> ActionTimeline {
    let now = chrono::Utc::now().to_rfc3339();
    ActionTimeline {
        action_id: action_id.to_string(),
        tenant_id: tenant_id.to_string(),
        approval_id: None,
        summary: ActionTimelineSummary {
            title: format!("Action {}", action_id),
            action_name: String::new(),
            source_type: String::new(),
            status: projected_status(event_type, details),
            risk_level: None,
            created_at: now.clone(),
        },
        timeline: vec![],
        last_updated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_labels() {
        assert_eq!(event_label("action_proposed"), "Action proposed");
        assert_eq!(event_label("approval_approved"), "Approved by human");
        assert_eq!(event_label("action_succeeded"), "Action executed");
        assert_eq!(event_label("action_retried"), "Dispatch retried");
        assert_eq!(event_label("unknown"), "Unknown event");
    }

    #[test]
    fn test_projected_status() {
        assert_eq!(projected_status("action_proposed", &serde_json::json!({})), "pending");
        assert_eq!(projected_status("approval_requested", &serde_json::json!({})), "waiting_approval");
        assert_eq!(projected_status("approval_approved", &serde_json::json!({})), "approved");
        assert_eq!(projected_status("approval_denied", &serde_json::json!({})), "denied");
        assert_eq!(projected_status("action_succeeded", &serde_json::json!({})), "executed");
        assert_eq!(projected_status("action_retried", &serde_json::json!({})), "retrying");
        assert_eq!(projected_status("proof_verified", &serde_json::json!({"verified": true})), "approved");
        assert_eq!(projected_status("proof_verified", &serde_json::json!({"verified": false})), "denied");
    }
}
