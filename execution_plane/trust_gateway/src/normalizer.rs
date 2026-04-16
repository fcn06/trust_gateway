// ─────────────────────────────────────────────────────────────
// Action Normalizer — converts raw tool arguments into
// human-readable business diffs for the Approval Center.
//
// Contains adapter functions for known integrations (Shopify,
// Google Calendar) plus a generic fallback.
// ─────────────────────────────────────────────────────────────

use trust_core::{
    ActionDecision, ActionRequest, BusinessDiffField, NormalizedAction,
    PolicyEvaluationDisplay, RiskLevel, ActionReview,
};

/// Normalize a raw ActionRequest into a human-readable NormalizedAction.
///
/// Dispatches to known adapters by action name prefix, falling back
/// to a generic adapter that surfaces all raw argument keys.
pub fn normalize_action(action_name: &str, args: &serde_json::Value) -> NormalizedAction {
    // Match on known action name prefixes
    if action_name.starts_with("shopify_order_refund") || action_name.starts_with("shopify.order.refund") {
        normalize_shopify_refund(action_name, args)
    } else if action_name.starts_with("shopify_order") || action_name.starts_with("shopify.order") {
        normalize_shopify_order(action_name, args)
    } else if action_name.starts_with("google_calendar") || action_name.starts_with("google.calendar") {
        normalize_google_calendar(action_name, args)
    } else {
        normalize_generic(action_name, args)
    }
}

/// Compute risk level from the policy decision.
pub fn compute_risk_level(decision: &ActionDecision) -> RiskLevel {
    match decision {
        ActionDecision::Allow { .. } => RiskLevel::Low,
        ActionDecision::Deny { .. } => RiskLevel::Critical,
        ActionDecision::RequireApproval { tier, .. } => {
            match tier {
                trust_core::ApprovalTier::Tier0AutoAllow => RiskLevel::Low,
                trust_core::ApprovalTier::Tier1PortalClick => RiskLevel::Medium,
                trust_core::ApprovalTier::Tier2ReAuthenticate => RiskLevel::High,
                trust_core::ApprovalTier::Tier3VerifiedPresentation => RiskLevel::High,
            }
        }
        ActionDecision::RequireProof { .. } => RiskLevel::High,
    }
}

/// Build the human-readable policy evaluation display.
pub fn build_policy_display(
    decision: &ActionDecision,
    reason: &str,
) -> PolicyEvaluationDisplay {
    match decision {
        ActionDecision::Allow { policy_id } => PolicyEvaluationDisplay {
            decision: "allow".to_string(),
            effect: "Action will proceed immediately".to_string(),
            tier: None,
            policy_rule_id: policy_id.clone(),
            reason: reason.to_string(),
            proof_type: None,
            required_claims: vec![],
        },
        ActionDecision::Deny { policy_id, reason: deny_reason } => PolicyEvaluationDisplay {
            decision: "deny".to_string(),
            effect: "Action is blocked by policy".to_string(),
            tier: None,
            policy_rule_id: policy_id.clone(),
            reason: deny_reason.clone(),
            proof_type: None,
            required_claims: vec![],
        },
        ActionDecision::RequireApproval { tier, policy_id, reason: tier_reason } => {
            let tier_str = format!("{}", tier);
            let effect = match tier {
                trust_core::ApprovalTier::Tier0AutoAllow => "Auto-approved by policy".to_string(),
                trust_core::ApprovalTier::Tier1PortalClick => "Requires a single click approval in the portal".to_string(),
                trust_core::ApprovalTier::Tier2ReAuthenticate => "Requires re-authentication before approval".to_string(),
                trust_core::ApprovalTier::Tier3VerifiedPresentation => "Requires a verified credential presentation".to_string(),
            };
            PolicyEvaluationDisplay {
                decision: "require_approval".to_string(),
                effect,
                tier: Some(tier_str),
                policy_rule_id: policy_id.clone(),
                reason: tier_reason.clone(),
                proof_type: None,
                required_claims: vec![],
            }
        }
        ActionDecision::RequireProof { proof_request, policy_id, reason: proof_reason } => {
            PolicyEvaluationDisplay {
                decision: "require_proof".to_string(),
                effect: "Requires a verified credential presentation".to_string(),
                tier: Some("tier3".to_string()),
                policy_rule_id: policy_id.clone(),
                reason: proof_reason.clone(),
                proof_type: Some(format!("{}", proof_request.proof_type)),
                required_claims: proof_request.required_claims.clone(),
            }
        }
    }
}

/// Build a full ActionReview from the action request and policy decision.
pub fn build_action_review(
    action_req: &ActionRequest,
    decision: &ActionDecision,
    approval_id: &str,
    reason: &str,
    reply_subject: &str,
    source_type: &str,
) -> ActionReview {
    let action_name = &action_req.action.name;
    let normalized = normalize_action(action_name, &action_req.action.arguments);
    let risk_level = compute_risk_level(decision);
    let policy_display = build_policy_display(decision, reason);

    let status = match decision {
        ActionDecision::RequireApproval { .. } => "pending_approval",
        ActionDecision::RequireProof { .. } => "pending_proof",
        _ => "pending",
    };

    ActionReview {
        approval_id: approval_id.to_string(),
        action_id: action_req.action_id.clone(),
        tenant_id: action_req.tenant_id.clone(),
        source_type: source_type.to_string(),
        owner_did: action_req.actor.owner_did.clone(),
        requester_did: action_req.actor.requester_did.clone(),
        action_name: action_name.clone(),
        operation_kind: format!("{}", action_req.action.operation),
        tool_args: action_req.action.arguments.clone(),
        normalized_action: normalized,
        policy_evaluation: policy_display,
        risk_level,
        status: status.to_string(),
        reply_subject: reply_subject.to_string(),
        timeout_seconds: 120,
        execution_preview: "If approved, a one-time execution grant valid for 30 seconds will be issued".to_string(),
        proof_request: None,
        approved_by: None,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: None,
    }
}

// ── Adapter: Shopify Order Refund ──────────────────────

fn normalize_shopify_refund(_action_name: &str, args: &serde_json::Value) -> NormalizedAction {
    let order_id = args.get("order_id")
        .or_else(|| args.get("orderId"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let amount = args.get("amount")
        .or_else(|| args.get("refund_amount"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let currency = args.get("currency")
        .and_then(|v| v.as_str())
        .unwrap_or("EUR");

    let reason = args.get("reason")
        .or_else(|| args.get("note"))
        .and_then(|v| v.as_str())
        .unwrap_or("Not specified");

    let title = format!("Refund {} {:.2} for order #{}", currency, amount, order_id);

    let mut fields = vec![
        BusinessDiffField {
            label: "Order".to_string(),
            before: None,
            after: Some(format!("#{}", order_id)),
            format: None,
        },
        BusinessDiffField {
            label: "Refund Amount".to_string(),
            before: None,
            after: Some(format!("{:.2} {}", amount, currency)),
            format: Some("currency".to_string()),
        },
        BusinessDiffField {
            label: "Reason".to_string(),
            before: None,
            after: Some(reason.to_string()),
            format: None,
        },
    ];

    // Add any additional fields
    if let Some(notify) = args.get("notify_customer").and_then(|v| v.as_bool()) {
        fields.push(BusinessDiffField {
            label: "Notify Customer".to_string(),
            before: None,
            after: Some(if notify { "Yes" } else { "No" }.to_string()),
            format: None,
        });
    }

    NormalizedAction {
        title,
        system_target: "Shopify".to_string(),
        resource_type: "order_refund".to_string(),
        resource_id: Some(order_id.to_string()),
        change_preview: fields,
        sensitive_fields: vec!["Refund Amount".to_string()],
        change_preview_mode: "normalized".to_string(),
    }
}

// ── Adapter: Shopify Order Update ──────────────────────

fn normalize_shopify_order(action_name: &str, args: &serde_json::Value) -> NormalizedAction {
    let order_id = args.get("order_id")
        .or_else(|| args.get("orderId"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let operation = if action_name.contains("cancel") {
        "Cancel"
    } else if action_name.contains("update") {
        "Update"
    } else {
        "Modify"
    };

    let title = format!("{} Shopify order #{}", operation, order_id);

    // Extract changed fields from args
    let fields = extract_fields_from_args(args, &["order_id", "orderId"]);

    NormalizedAction {
        title,
        system_target: "Shopify".to_string(),
        resource_type: "order".to_string(),
        resource_id: Some(order_id.to_string()),
        change_preview: fields,
        sensitive_fields: vec![],
        change_preview_mode: "normalized".to_string(),
    }
}

// ── Adapter: Google Calendar ───────────────────────────

fn normalize_google_calendar(_action_name: &str, args: &serde_json::Value) -> NormalizedAction {
    let summary = args.get("summary")
        .or_else(|| args.get("title"))
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled Event");

    let start = args.get("start")
        .or_else(|| args.get("start_time"))
        .or_else(|| args.get("startTime"))
        .and_then(|v| v.as_str())
        .unwrap_or("TBD");

    let end = args.get("end")
        .or_else(|| args.get("end_time"))
        .or_else(|| args.get("endTime"))
        .and_then(|v| v.as_str())
        .unwrap_or("TBD");

    let location = args.get("location")
        .and_then(|v| v.as_str());

    let calendar_id = args.get("calendar_id")
        .or_else(|| args.get("calendarId"))
        .and_then(|v| v.as_str())
        .unwrap_or("primary");

    let title = format!("Create calendar event: {}", summary);

    let mut fields = vec![
        BusinessDiffField {
            label: "Event Title".to_string(),
            before: None,
            after: Some(summary.to_string()),
            format: None,
        },
        BusinessDiffField {
            label: "Start".to_string(),
            before: None,
            after: Some(start.to_string()),
            format: Some("datetime".to_string()),
        },
        BusinessDiffField {
            label: "End".to_string(),
            before: None,
            after: Some(end.to_string()),
            format: Some("datetime".to_string()),
        },
        BusinessDiffField {
            label: "Calendar".to_string(),
            before: None,
            after: Some(calendar_id.to_string()),
            format: None,
        },
    ];

    if let Some(loc) = location {
        fields.push(BusinessDiffField {
            label: "Location".to_string(),
            before: None,
            after: Some(loc.to_string()),
            format: None,
        });
    }

    NormalizedAction {
        title,
        system_target: "Google Calendar".to_string(),
        resource_type: "calendar_event".to_string(),
        resource_id: None,
        change_preview: fields,
        sensitive_fields: vec![],
        change_preview_mode: "normalized".to_string(),
    }
}

// ── Generic Fallback ───────────────────────────────────

fn normalize_generic(action_name: &str, args: &serde_json::Value) -> NormalizedAction {
    let title = format!("Execute: {}", action_name);
    let fields = extract_fields_from_args(args, &[]);

    NormalizedAction {
        title,
        system_target: "Unknown".to_string(),
        resource_type: "generic".to_string(),
        resource_id: None,
        change_preview: fields,
        sensitive_fields: vec![],
        change_preview_mode: "raw".to_string(),
    }
}

// ── Helpers ────────────────────────────────────────────

/// Extract all top-level args as BusinessDiffFields, excluding specified keys.
fn extract_fields_from_args(args: &serde_json::Value, exclude: &[&str]) -> Vec<BusinessDiffField> {
    let mut fields = Vec::new();
    if let Some(obj) = args.as_object() {
        let mut keys: Vec<&String> = obj.keys().collect();
        keys.sort();
        for key in keys {
            if exclude.contains(&key.as_str()) {
                continue;
            }
            if let Some(val) = obj.get(key) {
                let display_val = match val {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Bool(b) => if *b { "Yes".to_string() } else { "No".to_string() },
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Null => "null".to_string(),
                    other => serde_json::to_string(other).unwrap_or_default(),
                };
                fields.push(BusinessDiffField {
                    label: humanize_key(key),
                    before: None,
                    after: Some(display_val),
                    format: None,
                });
            }
        }
    }
    fields
}

/// Convert snake_case or camelCase keys to human-readable labels.
fn humanize_key(key: &str) -> String {
    let mut result = String::new();
    let mut prev_was_lower = false;
    for (i, ch) in key.chars().enumerate() {
        if ch == '_' {
            result.push(' ');
            prev_was_lower = false;
        } else if ch.is_uppercase() && prev_was_lower {
            result.push(' ');
            result.push(ch);
            prev_was_lower = false;
        } else if i == 0 {
            result.push(ch.to_uppercase().next().unwrap_or(ch));
            prev_was_lower = ch.is_lowercase();
        } else {
            result.push(ch);
            prev_was_lower = ch.is_lowercase();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shopify_refund_normalizer() {
        let args = serde_json::json!({
            "order_id": "1234",
            "amount": 620.0,
            "currency": "EUR",
            "reason": "Customer request",
            "notify_customer": true,
        });
        let result = normalize_action("shopify_order_refund_create", &args);
        assert_eq!(result.title, "Refund EUR 620.00 for order #1234");
        assert_eq!(result.system_target, "Shopify");
        assert_eq!(result.resource_type, "order_refund");
        assert_eq!(result.resource_id, Some("1234".to_string()));
        assert_eq!(result.change_preview.len(), 4);
        assert_eq!(result.change_preview[1].label, "Refund Amount");
        assert_eq!(result.change_preview[1].after, Some("620.00 EUR".to_string()));
        assert_eq!(result.change_preview_mode, "normalized");
    }

    #[test]
    fn test_google_calendar_normalizer() {
        let args = serde_json::json!({
            "summary": "Team standup",
            "start": "2026-03-27T09:00:00",
            "end": "2026-03-27T09:30:00",
            "location": "Room 42",
        });
        let result = normalize_action("google_calendar_create_event", &args);
        assert_eq!(result.title, "Create calendar event: Team standup");
        assert_eq!(result.system_target, "Google Calendar");
        assert_eq!(result.change_preview.len(), 5); // title, start, end, calendar, location
    }

    #[test]
    fn test_generic_normalizer() {
        let args = serde_json::json!({
            "foo": "bar",
            "count": 42,
        });
        let result = normalize_action("unknown_tool", &args);
        assert_eq!(result.title, "Execute: unknown_tool");
        assert_eq!(result.system_target, "Unknown");
        assert_eq!(result.change_preview_mode, "raw");
        assert_eq!(result.change_preview.len(), 2);
    }

    #[test]
    fn test_humanize_key() {
        assert_eq!(humanize_key("order_id"), "Order id");
        assert_eq!(humanize_key("refundAmount"), "Refund Amount");
        assert_eq!(humanize_key("simple"), "Simple");
    }

    #[test]
    fn test_risk_level_from_decision() {
        let allow = ActionDecision::Allow { policy_id: "p1".to_string() };
        assert_eq!(compute_risk_level(&allow), RiskLevel::Low);

        let deny = ActionDecision::Deny { reason: "blocked".to_string(), policy_id: "p1".to_string() };
        assert_eq!(compute_risk_level(&deny), RiskLevel::Critical);
    }
}
