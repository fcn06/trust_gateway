use sha2::Digest;
use trust_canonical::canonical_hash;
use trust_model::ExecutionGrant;

pub struct GrantIssuer;

impl GrantIssuer {
    pub fn create_grant(
        action_id: &str,
        tenant_id: &str,
        tool_name: &str,
        arguments: &serde_json::Value,
        issuer: &str,
        ttl_seconds: i64,
    ) -> ExecutionGrant {
        Self::create_grant_with_workspace(
            action_id,
            tenant_id,
            "default",
            tool_name,
            arguments,
            issuer,
            ttl_seconds,
        )
    }

    pub fn create_grant_with_workspace(
        action_id: &str,
        tenant_id: &str,
        workspace_id: &str,
        tool_name: &str,
        arguments: &serde_json::Value,
        issuer: &str,
        ttl_seconds: i64,
    ) -> ExecutionGrant {
        let input_hash = canonical_hash(arguments);
        let now = chrono::Utc::now().timestamp();
        let nonce = format!(
            "{:x}",
            sha2::Sha256::digest(format!("{action_id}:{now}").as_bytes())
        );

        ExecutionGrant {
            grant_id: format!("grant_{action_id}"),
            action_id: action_id.to_string(),
            tenant_id: tenant_id.to_string(),
            workspace_id: workspace_id.to_string(),
            tool_name: tool_name.to_string(),
            input_hash,
            issuer: issuer.to_string(),
            expires_at: now + ttl_seconds,
            nonce,
            contract_id: None,
            contract_hash: None,
            economic_claim: None,
            budget: None,
        }
    }

    /// Creates an execution grant bound to an economic claim (payment token, quota).
    pub fn create_grant_with_economic_claim(
        action_id: &str,
        tenant_id: &str,
        tool_name: &str,
        arguments: &serde_json::Value,
        issuer: &str,
        ttl_seconds: i64,
        economic_claim: Option<trust_model::EconomicClaim>,
    ) -> ExecutionGrant {
        Self::create_grant(
            action_id,
            tenant_id,
            tool_name,
            arguments,
            issuer,
            ttl_seconds,
        )
        .with_economic_claim(economic_claim)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_grant_with_economic_claim() {
        let args = serde_json::json!({"query": "SELECT * FROM orders"});
        let claim = trust_model::EconomicClaim {
            currency: "CREDIT".to_string(),
            max_cost_minor: 100,
            payment_token: Some("voucher_abc".to_string()),
            quota_reservation_id: Some("res_999".to_string()),
        };
        let budget = trust_model::ExecutionBudget {
            max_duration_seconds: 15,
            max_external_calls: 1,
        };

        let grant = GrantIssuer::create_grant_with_economic_claim(
            "act_001",
            "tenant_a",
            "db.query",
            &args,
            "gateway_1",
            60,
            Some(claim),
        )
        .with_budget(Some(budget));

        assert_eq!(grant.action_id, "act_001");
        assert_eq!(
            grant
                .economic_claim
                .as_ref()
                .unwrap()
                .payment_token
                .as_deref(),
            Some("voucher_abc")
        );
        assert_eq!(grant.budget.as_ref().unwrap().max_duration_seconds, 15);
    }
}
