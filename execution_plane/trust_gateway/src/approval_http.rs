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

use axum::http::HeaderMap;
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

// ─── Portal Compatibility DTOs (Spec §20.1) ─────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct EscalationRequest {
    pub id: String,
    pub user_did: String,
    pub tool_name: String,
    pub status: String,
    pub created_at: String,
    pub nats_reply_subject: String,
    pub requester_did: String,
    #[serde(default)]
    pub owner_user_id: Option<String>,
    #[serde(default)]
    pub arguments: Option<serde_json::Value>,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub proof_required: bool,
    #[serde(default)]
    pub proof_request: Option<serde_json::Value>,
    #[serde(default)]
    pub approved_by: Option<String>,
    #[serde(default)]
    pub action_review: Option<serde_json::Value>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EscalationRequestsResponse {
    pub requests: Vec<EscalationRequest>,
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

/// `GET /api/escalation_requests` — Portal-compatible list handler.
pub async fn list_escalations_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<EscalationRequestsResponse>, StatusCode> {
    // Phase 2: Mandatory authentication
    let verified = state.token_validator.validate(&headers, &state.jwt_secret).await
        .map_err(|e| e)?;
    let claims = verified.claims();
    
    let tenant_id = if claims.tenant_id.is_empty() {
        "default"
    } else {
        &claims.tenant_id
    };

    match state.approval_store.list_pending(tenant_id).await {
        Ok(records) => {
            let requests = records.into_iter().map(|r| {
                EscalationRequest {
                    id: r.approval_id.clone(),
                    user_did: r.action_request.actor.owner_did.clone(),
                    tool_name: r.action_request.action.name.clone(),
                    status: match r.status {
                        ApprovalStatus::Pending => "PENDING",
                        ApprovalStatus::PendingProof => "PENDING_PROOF",
                        ApprovalStatus::Approved => "APPROVED",
                        ApprovalStatus::Denied => "DENIED",
                        ApprovalStatus::Expired => "TIMEOUT",
                        ApprovalStatus::Executed => "EXECUTED",
                        ApprovalStatus::ExecutionFailed => "FAILED",
                    }.to_string(),
                    created_at: r.requested_at.to_rfc3339(),
                    nats_reply_subject: format!("host.v1.escalation.reply.{}", r.action_id),
                    requester_did: r.action_request.actor.requester_did.clone(),
                    owner_user_id: claims.user_did.clone(),
                    arguments: Some(r.action_request.action.arguments.clone()),
                    tier: Some(format!("{}", r.tier)),
                    reason: Some(r.reason.clone()),
                    proof_required: r.status == ApprovalStatus::PendingProof,
                    proof_request: None, // could be enriched from record
                    approved_by: r.resolved_by.clone(),
                    action_review: None, // could be enriched from record
                }
            }).collect();
            Ok(Json(EscalationRequestsResponse { requests }))
        },
        Err(e) => {
            tracing::error!("ApprovalStore list failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// `POST /api/escalation_requests/{id}/approve` — Portal-compatible approve handler.
pub async fn approve_escalation_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let verified = state.token_validator.validate(&headers, &state.jwt_secret).await
        .map_err(|e| e)?;
    let claims = verified.claims();

    let decision = DecisionRequest {
        decision: "approved".to_string(),
        actor_did: Some(claims.user_did.clone().unwrap_or_else(|| claims.sub.clone())),
        reason: None,
        correlation_id: None,
    };

    process_decision(state, id, decision).await
}

/// `POST /api/escalation_requests/{id}/deny` — Portal-compatible deny handler.
pub async fn deny_escalation_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let verified = state.token_validator.validate(&headers, &state.jwt_secret).await
        .map_err(|e| e)?;
    let claims = verified.claims();

    let decision = DecisionRequest {
        decision: "denied".to_string(),
        actor_did: Some(claims.user_did.clone().unwrap_or_else(|| claims.sub.clone())),
        reason: None,
        correlation_id: None,
    };

    process_decision(state, id, decision).await
}

/// Common logic for processing a decision and notifying the Host.
async fn process_decision(
    state: Arc<GatewayState>,
    approval_id: String,
    body: DecisionRequest,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Fetch existing record
    let record = match state.approval_store.get(&approval_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Idempotency check 
    if record.status == ApprovalStatus::Approved || record.status == ApprovalStatus::Denied {
         return Ok(Json(serde_json::json!({ "status": "already_processed" })));
    }

    let result = ApprovalResult {
        resolved_by: body.actor_did.clone().unwrap_or_else(|| "unknown".to_string()),
        resolution_method: "portal_direct".to_string(),
        notes: body.reason.clone(),
        resolved_at: chrono::Utc::now(),
    };

    let new_status = match body.decision.as_str() {
        "approved" | "approve" => {
            state.approval_store.mark_approved(&approval_id, result).await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            ApprovalStatus::Approved
        }
        "denied" | "deny" => {
            state.approval_store.mark_denied(&approval_id, result).await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            ApprovalStatus::Denied
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    // ── Notify the Host via NATS to keep chat/audit in sync ────────
    // This subject is watched by Host's loops/escalation.rs
    let result_subject = "host.v1.escalation.result";
    let payload = serde_json::json!({
        "approval_id": approval_id,
        "action_id": record.action_id,
        "tool_name": record.action_request.action.name,
        "status": if new_status == ApprovalStatus::Approved { "APPROVED" } else { "DENIED" },
        "resolved_by": body.actor_did,
        "owner_did": record.action_request.actor.owner_did,
        "resolution_method": "portal_direct",
    });


    if let Err(e) = state.nats.publish(result_subject.to_string(), payload.to_string().into()).await {
        tracing::error!("❌ Failed to publish escalation result to Host: {}", e);
    }

    tracing::info!(
        "✅ Processed approval decision: {} → {:?} (notified Host)",
        approval_id,
        new_status
    );

    Ok(Json(serde_json::json!({
        "status": "decided",
        "approval_id": approval_id,
        "decision": body.decision,
    })))
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

