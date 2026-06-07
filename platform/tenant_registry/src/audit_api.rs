//! Audit export API — customer-accessible audit trail and usage metrics.
//!
//! Added as routes to the Tenant Registry for centralized access.

use std::sync::Arc;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// Query parameters for audit export.
#[derive(Debug, Deserialize)]
pub struct AuditExportParams {
    /// Start timestamp (Unix epoch seconds).
    pub from: Option<i64>,
    /// End timestamp (Unix epoch seconds).
    pub to: Option<i64>,
    /// Filter by user DID.
    pub user_did: Option<String>,
    /// Max number of events to return.
    pub limit: Option<usize>,
}

/// A single audit event record.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub jti: String,
    pub tenant_id: String,
    pub user_did: String,
    pub ts: u64,
    pub component: String,
    pub action: String,
    pub detail: serde_json::Value,
}

/// Response for audit export.
#[derive(Debug, Serialize)]
pub struct AuditExportResponse {
    pub tenant_id: String,
    pub events: Vec<AuditEvent>,
    pub total: usize,
    pub has_more: bool,
}

/// Usage metrics for a tenant.
#[derive(Debug, Serialize)]
pub struct TenantMetrics {
    pub tenant_id: String,
    pub period: String,
    pub llm_tokens_used: u64,
    pub tool_calls: u64,
    pub escalations: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub audit_events: u64,
}

/// GET /api/tenant/:id/audit/export — Export audit events for a tenant.
///
/// Reads from the tenant-scoped audit KV bucket and filters by parameters.
pub async fn export_audit(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
    Query(params): Query<AuditExportParams>,
) -> Result<Json<AuditExportResponse>, (StatusCode, String)> {
    // Verify tenant exists
    let _tenant = state
        .store
        .get(&tenant_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Store error: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Tenant not found".to_string()))?;

    // Read from tenant-scoped audit bucket
    let bucket_name = format!("tenant_{}_agent_audit", tenant_id);
    let audit_kv = state
        .js
        .get_key_value(&bucket_name)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Cannot access audit bucket '{}': {}", bucket_name, e),
            )
        })?;

    let mut events = Vec::new();
    let limit = params.limit.unwrap_or(100).min(1000);

    let mut keys = audit_kv.keys().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Cannot list audit keys: {}", e),
        )
    })?;

    use futures::StreamExt;
    while let Some(Ok(key)) = keys.next().await {
        if let Ok(Some(entry)) = audit_kv.get(&key).await {
            if let Ok(event) = serde_json::from_slice::<AuditEvent>(&entry) {
                // Apply filters
                if let Some(from) = params.from {
                    if (event.ts as i64) < from {
                        continue;
                    }
                }
                if let Some(to) = params.to {
                    if (event.ts as i64) > to {
                        continue;
                    }
                }
                if let Some(ref did_filter) = params.user_did {
                    if &event.user_did != did_filter {
                        continue;
                    }
                }
                events.push(event);
            }
        }
    }

    events.sort_by_key(|e| std::cmp::Reverse(e.ts));

    let total = events.len();
    let has_more = total > limit;
    if events.len() > limit {
        events.truncate(limit);
    }

    Ok(Json(AuditExportResponse {
        tenant_id,
        events,
        total,
        has_more,
    }))
}

/// GET /api/tenant/:id/metrics — Usage metrics for a tenant.
///
/// Returns aggregated usage statistics. In V1, this reads from KV counters
/// that are updated by the publish_audit functions.
pub async fn get_metrics(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<TenantMetrics>, (StatusCode, String)> {
    // Verify tenant exists
    let _tenant = state
        .store
        .get(&tenant_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Store error: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Tenant not found".to_string()))?;

    // Read metrics from tenant-scoped KV (future: dedicated metrics bucket)
    let bucket_name = format!("tenant_{}_agent_audit", tenant_id);
    let event_count = match state.js.get_key_value(&bucket_name).await {
        Ok(kv) => {
            match kv.keys().await {
                Ok(keys) => {
                    use futures::StreamExt;
                    keys.count().await as u64
                }
                Err(_) => 0,
            }
        }
        Err(_) => 0,
    };

    Ok(Json(TenantMetrics {
        tenant_id,
        period: "current_month".to_string(),
        llm_tokens_used: 0,     // TODO: Aggregate from metering module
        tool_calls: 0,           // TODO: Aggregate from metering events
        escalations: 0,          // TODO: Count escalation events
        messages_sent: 0,        // TODO: Count from sovereign_kv
        messages_received: 0,    // TODO: Count from sovereign_kv
        audit_events: event_count,
    }))
}
