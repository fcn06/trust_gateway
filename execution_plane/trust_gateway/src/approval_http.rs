// ─────────────────────────────────────────────────────────────
// Standalone Approval API (spec §20)
//
// Allows approval decisions without Host dependency.
// When the Host is absent, pending approvals can be completed
// via these HTTP endpoints directly.
// ─────────────────────────────────────────────────────────────

use std::sync::Arc;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::Deserialize;

use trust_core::approval::{ApprovalRecord, ApprovalResult, ApprovalStatus};
use crate::gateway::GatewayState;

/// Decision request body for `POST /v1/approvals/{id}/decision`.
#[derive(Debug, Deserialize)]
pub struct DecisionRequest {
    /// "approved" or "denied".
    pub decision: String,
    /// DID of the approver.
    pub actor_did: Option<String>,
    /// Reason for the decision.
    pub reason: Option<String>,
    /// Correlation ID for tracing.
    pub correlation_id: Option<String>,
}

/// Query params for listing approvals.
#[derive(Debug, Deserialize)]
pub struct ApprovalQuery {
    pub tenant_id: Option<String>,
}

// ─── Handlers ───────────────────────────────────────────────

/// `GET /v1/approvals/{approval_id}` — Fetch approval status.
pub async fn get_approval_handler(
    State(state): State<Arc<GatewayState>>,
    Path(approval_id): Path<String>,
) -> Result<Json<ApprovalRecord>, StatusCode> {
    match state.approval_store.get(&approval_id).await {
        Ok(Some(record)) => Ok(Json(record)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("ApprovalStore get failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// `POST /v1/approvals/{approval_id}/decision` — Submit decision.
pub async fn submit_decision_handler(
    State(state): State<Arc<GatewayState>>,
    Path(approval_id): Path<String>,
    Json(body): Json<DecisionRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Fetch existing record
    let record = match state.approval_store.get(&approval_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Idempotency check 
    match record.status {
        ApprovalStatus::Approved | ApprovalStatus::Denied => {
            let existing_decision = if record.status == ApprovalStatus::Approved {
                "approved"
            } else {
                "denied"
            };

            if body.decision == existing_decision {
                return Ok(Json(serde_json::json!({
                    "status": "already_decided",
                    "approval_id": approval_id,
                    "decision": existing_decision,
                })));
            } else {
                return Err(StatusCode::CONFLICT);
            }
        }
        ApprovalStatus::Expired => {
            return Err(StatusCode::GONE);
        }
        _ => {}
    }

    let result = ApprovalResult {
        resolved_by: body.actor_did.clone().unwrap_or_else(|| "unknown".to_string()),
        resolution_method: "portal_click".to_string(), // In reality we'd pull from token claims
        notes: body.reason.clone(),
        resolved_at: chrono::Utc::now(),
    };

    let (new_status, result_action) = match body.decision.as_str() {
        "approved" | "approve" => {
            (ApprovalStatus::Approved, state.approval_store.mark_approved(&approval_id, result).await)
        }
        "denied" | "deny" => {
            (ApprovalStatus::Denied, state.approval_store.mark_denied(&approval_id, result).await)
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    if let Err(e) = result_action {
        tracing::error!("Failed to update approval status: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    tracing::info!(
        "✅ Standalone approval decision: {} → {:?} (by: {:?})",
        approval_id,
        new_status,
        body.actor_did,
    );

    Ok(Json(serde_json::json!({
        "status": "decided",
        "approval_id": approval_id,
        "decision": body.decision,
    })))
}

/// `GET /v1/approvals` — List pending approvals (optionally filtered by tenant).
pub async fn list_approvals_handler(
    State(state): State<Arc<GatewayState>>,
    Query(params): Query<ApprovalQuery>,
) -> Result<Json<Vec<ApprovalRecord>>, StatusCode> {
    
    // We only support tenant_id queries via trait to encourage multi-tenant hygiene
    if let Some(tenant_id) = params.tenant_id {
        match state.approval_store.list_pending(&tenant_id).await {
            Ok(records) => Ok(Json(records)),
            Err(e) => {
                tracing::error!("ApprovalStore list failed: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        // Must provide tenant ID
        Err(StatusCode::BAD_REQUEST)
    }
}

/// `GET /v1/actions/status/{action_id}` — Poll for action execution result.
///
/// After receiving a `pending_approval` response from `/v1/actions/propose`,
/// callers poll this endpoint to check if the approval was resolved and if
/// the action was executed by the background daemon.
pub async fn action_status_handler(
    State(state): State<Arc<GatewayState>>,
    Path(action_id): Path<String>,
) -> Json<serde_json::Value> {
    // Check timeline KV first — that's where the daemon logs execution results
    if let Ok(kv) = state.jetstream.get_key_value("action_timelines").await {
        if let Ok(Some(entry)) = kv.get(&action_id).await {
            if let Ok(timeline) = serde_json::from_slice::<serde_json::Value>(&entry) {
                let status = timeline.get("summary")
                    .and_then(|s| s.get("status"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");

                return Json(serde_json::json!({
                    "action_id": action_id,
                    "status": status,
                    "timeline": timeline,
                }));
            }
        }
    }

    // Fall back: scan approval_records for an approval tied to this action_id
    if let Ok(kv) = state.jetstream.get_key_value("approval_records").await {
        use futures::StreamExt;
        if let Ok(mut keys) = kv.keys().await {
            while let Some(Ok(key)) = keys.next().await {
                if let Ok(Some(entry)) = kv.get(&key).await {
                    if let Ok(record) = serde_json::from_slice::<ApprovalRecord>(&entry) {
                        if record.action_id == action_id {
                            let status = match record.status {
                                ApprovalStatus::Pending | ApprovalStatus::PendingProof => "pending_approval",
                                ApprovalStatus::Approved => "approved_executing",
                                ApprovalStatus::Denied => "denied",
                                ApprovalStatus::Expired => "expired",
                                ApprovalStatus::Executed => "succeeded",
                                ApprovalStatus::ExecutionFailed => "execution_failed",
                            };
                            return Json(serde_json::json!({
                                "action_id": action_id,
                                "status": status,
                                "approval_id": record.approval_id,
                                "tier": format!("{}", record.tier),
                                "reason": record.reason,
                            }));
                        }
                    }
                }
            }
        }
    }

    Json(serde_json::json!({
        "action_id": action_id,
        "status": "not_found",
        "error": "No action or approval record found for this action_id",
    }))
}

