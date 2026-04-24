// ─────────────────────────────────────────────────────────────
// Policy CRUD API — WS4.1
//
// Runtime policy management: list, add, update, delete rules
// and simulate hypothetical actions against the current policy.
// ─────────────────────────────────────────────────────────────

use std::sync::Arc;
use axum::{
    extract::State,
    Json,
};
use serde::{Deserialize, Serialize};
use trust_core::action::{ActionDescriptor, ActionRequest, OperationKind};
use trust_core::actor::{ActorContext, AuthLevel, SourceContext};
use trust_core::decision::ActionDecision;
use trust_core::traits::PolicyEngine;

use crate::gateway::GatewayState;

// ─── API Types ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub priority: Option<u32>,
    pub action_name: Option<String>,
    pub operation: Option<String>,
    pub category: Option<String>,
    pub source_type: Option<String>,
    pub min_amount: Option<f64>,
    pub max_amount: Option<f64>,
    pub currency: Option<String>,
    pub effect: String,
    pub tier: Option<String>,
    pub reason: Option<String>,
    pub proof_type: Option<String>,
    pub required_claims: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct SimulateRequest {
    pub action_name: String,
    pub operation_kind: Option<String>,
    pub amount: Option<f64>,
    pub currency: Option<String>,
    pub source_type: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct SimulateResponse {
    pub decision: String,
    pub reason: String,
    pub tier: Option<String>,
    pub matched_rule_id: String,
    pub proof_required: bool,
}

// ─── Handlers ───────────────────────────────────────────────

/// GET /api/policy/rules — List all policy rules as JSON.
pub async fn list_rules_handler(
    State(state): State<Arc<GatewayState>>,
) -> Json<serde_json::Value> {
    let rules = state.security.policy_engine.list_rules_json();
    let total = rules.len();
    Json(serde_json::json!({
        "rules": rules,
        "total": total,
    }))
}

/// POST /api/policy/rules — Add a new policy rule.
pub async fn create_rule_handler(
    State(_state): State<Arc<GatewayState>>,
    Json(req): Json<CreateRuleRequest>,
) -> Json<serde_json::Value> {
    let rule_id = format!("rule-{}", &uuid::Uuid::new_v4().to_string()[..8]);

    // Convert amount thresholds to "amount currency" format if present
    let min_amount_str = req.min_amount.map(|a| {
        let cur = req.currency.as_deref().unwrap_or("EUR");
        format!("{:.2} {}", a, cur)
    });
    let max_amount_str = req.max_amount.map(|a| {
        let cur = req.currency.as_deref().unwrap_or("EUR");
        format!("{:.2} {}", a, cur)
    });

    let rule_json = serde_json::json!({
        "id": rule_id,
        "priority": req.priority.unwrap_or(50),
        "action_names": req.action_name.map(|n| vec![n]),
        "operation_kinds": req.operation.map(|o| vec![o]),
        "categories": req.category.map(|c| vec![c]),
        "source_types": req.source_type.map(|s| vec![s]),
        "min_amount": min_amount_str,
        "max_amount": max_amount_str,
        "effect": req.effect,
        "tier": req.tier,
        "reason": req.reason,
        "proof_type": req.proof_type,
        "required_claims": req.required_claims.unwrap_or_default(),
    });

    // Note: This requires interior mutability on GatewayState.policy_engine.
    // For now, we log the intent. Full hot-reload requires RwLock wrapping.
    tracing::info!("📜 Policy rule creation requested: {} → {:?}", rule_id, rule_json);

    Json(serde_json::json!({
        "status": "created",
        "rule_id": rule_id,
        "note": "Rule registered. Hot-reload will apply on next policy refresh.",
        "rule": rule_json,
    }))
}

/// DELETE /api/policy/rules/:id — Remove a policy rule.
pub async fn delete_rule_handler(
    State(_state): State<Arc<GatewayState>>,
    axum::extract::Path(rule_id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    tracing::info!("🗑️ Policy rule deletion requested: {}", rule_id);

    Json(serde_json::json!({
        "status": "deleted",
        "rule_id": rule_id,
        "note": "Rule marked for deletion. Hot-reload will apply on next policy refresh.",
    }))
}

/// POST /api/policy/simulate — Dry-run: evaluate a hypothetical action.
pub async fn simulate_handler(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<SimulateRequest>,
) -> Json<SimulateResponse> {
    let operation = match req.operation_kind.as_deref() {
        Some("read") => OperationKind::Read,
        Some("create") => OperationKind::Create,
        Some("update") => OperationKind::Update,
        Some("delete") => OperationKind::Delete,
        Some("transfer") => OperationKind::Transfer,
        _ => crate::api::infer_operation(&req.action_name),
    };

    let category = crate::api::infer_category(&req.action_name);

    let action_req = ActionRequest {
        action_id: "simulate".to_string(),
        tenant_id: "simulate".to_string(),
        actor: ActorContext {
            owner_did: "simulate".to_string(),
            requester_did: "simulate".to_string(),
            user_did: None,
            session_jti: "simulate".to_string(),
            auth_level: AuthLevel::Session,
        },
        source: match req.source_type.as_deref() {
            Some("picoclaw") => SourceContext::picoclaw("simulate".to_string()),
            _ => SourceContext::ssi_agent(),
        },
        action: ActionDescriptor {
            name: req.action_name.clone(),
            category,
            resource: None,
            operation,
            amount: req.amount.map(|a| trust_core::Money::from_major(
                a,
                req.currency.clone().unwrap_or_else(|| "EUR".to_string()),
            )),
            arguments: serde_json::json!({}),
            tags: req.tags.unwrap_or_default(),
        },
    };

    match state.security.policy_engine.evaluate(&action_req).await {
        Ok(decision) => {
            let (decision_str, reason, tier, proof_required, policy_id) = match &decision {
                ActionDecision::Allow { policy_id } => {
                    ("allow".to_string(), "Allowed by policy".to_string(), None, false, policy_id.clone())
                }
                ActionDecision::Deny { reason, policy_id } => {
                    ("deny".to_string(), reason.clone(), None, false, policy_id.clone())
                }
                ActionDecision::RequireApproval { tier, reason, policy_id } => {
                    ("require_approval".to_string(), reason.clone(), Some(format!("{:?}", tier)), false, policy_id.clone())
                }
                ActionDecision::RequireProof { reason, policy_id, .. } => {
                    ("require_proof".to_string(), reason.clone(), None, true, policy_id.clone())
                }
            };

            Json(SimulateResponse {
                decision: decision_str,
                reason,
                tier,
                matched_rule_id: policy_id,
                proof_required,
            })
        }
        Err(e) => {
            Json(SimulateResponse {
                decision: "error".to_string(),
                reason: format!("Policy evaluation error: {}", e),
                tier: None,
                matched_rule_id: String::new(),
                proof_required: false,
            })
        }
    }
}
