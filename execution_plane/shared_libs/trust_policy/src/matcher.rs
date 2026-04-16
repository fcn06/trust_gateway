// ─────────────────────────────────────────────────────────────
// Policy matcher
//
// Evaluates whether an ActionRequest matches a PolicyRule's
// conditions. All specified conditions must be true (AND logic).
// ─────────────────────────────────────────────────────────────

use trust_core::action::ActionRequest;
use trust_core::Money;
use crate::rules::PolicyMatcher;

impl PolicyMatcher {
    /// Check if an ActionRequest matches all conditions in this matcher.
    ///
    /// Unspecified conditions (None or empty) are treated as wildcards
    /// (always match). All specified conditions must be true for
    /// the overall match to succeed.
    pub fn matches(&self, req: &ActionRequest) -> bool {
        // Match action names
        if let Some(ref names) = self.action_names {
            if !names.is_empty() && !names.iter().any(|n| n == &req.action.name) {
                return false;
            }
        }

        // Match categories
        if let Some(ref categories) = self.categories {
            if !categories.is_empty() && !categories.iter().any(|c| c == &req.action.category) {
                return false;
            }
        }

        // Match operation kinds
        if let Some(ref ops) = self.operation_kinds {
            if !ops.is_empty() {
                let op_str = req.action.operation.to_string();
                if !ops.iter().any(|o| o.eq_ignore_ascii_case(&op_str)) {
                    return false;
                }
            }
        }

        // Match tenant IDs
        if let Some(ref tenants) = self.tenant_ids {
            if !tenants.is_empty() && !tenants.iter().any(|t| t == &req.tenant_id) {
                return false;
            }
        }

        // Match source types
        if let Some(ref sources) = self.source_types {
            if !sources.is_empty() && !sources.iter().any(|s| s == &req.source.source_type) {
                return false;
            }
        }

        // Match tags (any specified tag must be present in the action's tags)
        if let Some(ref tags) = self.tags {
            if !tags.is_empty() && !tags.iter().any(|t| req.action.tags.contains(t)) {
                return false;
            }
        }

        // Match minimum amount
        if let Some(ref min_str) = self.min_amount {
            if let Some(min) = parse_money(min_str) {
                match &req.action.amount {
                    Some(action_amount) => {
                        if action_amount.currency != min.currency
                            || action_amount.amount_minor < min.amount_minor
                        {
                            return false;
                        }
                    }
                    None => return false, // Rule requires an amount but action has none
                }
            }
        }

        // Match maximum amount
        if let Some(ref max_str) = self.max_amount {
            if let Some(max) = parse_money(max_str) {
                match &req.action.amount {
                    Some(action_amount) => {
                        if action_amount.currency != max.currency
                            || action_amount.amount_minor > max.amount_minor
                        {
                            return false;
                        }
                    }
                    None => {} // No amount is fine for max check
                }
            }
        }

        true
    }
}

/// Parse a money string like "100.00 EUR" into a Money value.
fn parse_money(s: &str) -> Option<Money> {
    let parts: Vec<&str> = s.trim().split_whitespace().collect();
    if parts.len() != 2 {
        return None;
    }
    let amount: f64 = parts[0].parse().ok()?;
    let currency = parts[1].to_string();
    Some(Money::from_major(amount, currency))
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_core::action::{ActionDescriptor, ActionRequest, OperationKind};
    use trust_core::actor::{ActorContext, AuthLevel, SourceContext};

    fn make_request(name: &str, op: OperationKind, amount: Option<Money>, tags: Vec<String>) -> ActionRequest {
        ActionRequest {
            action_id: "test-action".to_string(),
            tenant_id: "tenant-1".to_string(),
            actor: ActorContext {
                owner_did: "did:key:owner".to_string(),
                requester_did: "did:key:user".to_string(),
                user_did: None,
                session_jti: "jti-123".to_string(),
                auth_level: AuthLevel::Session,
            },
            source: SourceContext::ssi_agent(),
            action: ActionDescriptor {
                name: name.to_string(),
                category: "test".to_string(),
                resource: None,
                operation: op,
                amount,
                arguments: serde_json::json!({}),
                tags,
            },
        }
    }

    #[test]
    fn test_empty_matcher_matches_everything() {
        let matcher = PolicyMatcher::default();
        let req = make_request("anything", OperationKind::Read, None, vec![]);
        assert!(matcher.matches(&req));
    }

    #[test]
    fn test_action_name_match() {
        let matcher = PolicyMatcher {
            action_names: Some(vec!["google.calendar.event.create".to_string()]),
            ..Default::default()
        };
        let req1 = make_request("google.calendar.event.create", OperationKind::Create, None, vec![]);
        let req2 = make_request("shopify.order.refund", OperationKind::Create, None, vec![]);
        assert!(matcher.matches(&req1));
        assert!(!matcher.matches(&req2));
    }

    #[test]
    fn test_operation_kind_match() {
        let matcher = PolicyMatcher {
            operation_kinds: Some(vec!["read".to_string()]),
            ..Default::default()
        };
        let req1 = make_request("any", OperationKind::Read, None, vec![]);
        let req2 = make_request("any", OperationKind::Create, None, vec![]);
        assert!(matcher.matches(&req1));
        assert!(!matcher.matches(&req2));
    }

    #[test]
    fn test_min_amount_match() {
        let matcher = PolicyMatcher {
            min_amount: Some("100.00 EUR".to_string()),
            ..Default::default()
        };
        let req_above = make_request("any", OperationKind::Create, Some(Money::from_major(200.0, "EUR")), vec![]);
        let req_below = make_request("any", OperationKind::Create, Some(Money::from_major(50.0, "EUR")), vec![]);
        let req_none = make_request("any", OperationKind::Create, None, vec![]);
        assert!(matcher.matches(&req_above));
        assert!(!matcher.matches(&req_below));
        assert!(!matcher.matches(&req_none));
    }

    #[test]
    fn test_tag_match() {
        let matcher = PolicyMatcher {
            tags: Some(vec!["payout_change".to_string()]),
            ..Default::default()
        };
        let req_with = make_request("any", OperationKind::Update, None, vec!["payout_change".to_string()]);
        let req_without = make_request("any", OperationKind::Update, None, vec!["other".to_string()]);
        assert!(matcher.matches(&req_with));
        assert!(!matcher.matches(&req_without));
    }

    #[test]
    fn test_source_type_match() {
        let matcher = PolicyMatcher {
            source_types: Some(vec!["picoclaw".to_string()]),
            ..Default::default()
        };
        // ssi_agent source should NOT match a picoclaw-only rule
        let req_ssi = make_request("any", OperationKind::Read, None, vec![]);
        assert!(!matcher.matches(&req_ssi));

        // picoclaw source should match
        let mut req_pico = make_request("any", OperationKind::Read, None, vec![]);
        req_pico.source = SourceContext::picoclaw("test-instance");
        assert!(matcher.matches(&req_pico));
    }
}
