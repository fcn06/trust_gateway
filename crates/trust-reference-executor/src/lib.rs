use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use trust_egress::EgressFilter;
use trust_executor_sdk::{verify_input_hash, Executor};
use trust_model::{ExecutionResult, GrantedAction, TransactionOutcomeState};

pub type ToolHandler =
    Arc<dyn Fn(&serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync>;

pub struct ReferenceExecutor {
    handlers: Arc<Mutex<HashMap<String, ToolHandler>>>,
    consumed_grant_ids: Arc<Mutex<HashSet<String>>>,
}

impl Default for ReferenceExecutor {
    fn default() -> Self {
        let mut exec = Self::new();
        exec.register_handler("mock_echo", Arc::new(|args| Ok(args.clone())));
        exec.register_handler(
            "mock_refund",
            Arc::new(|args| {
                let amount = args.get("amount").and_then(|v| v.as_str()).unwrap_or("0");
                Ok(serde_json::json!({
                    "status": "refund_processed",
                    "amount": amount,
                    "account_email": "user@example.com"
                }))
            }),
        );
        exec
    }
}

impl ReferenceExecutor {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(Mutex::new(HashMap::new())),
            consumed_grant_ids: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn register_handler(&mut self, tool_name: &str, handler: ToolHandler) {
        self.handlers
            .lock()
            .unwrap()
            .insert(tool_name.to_string(), handler);
    }
}

#[async_trait]
impl Executor for ReferenceExecutor {
    async fn execute(&self, action: GrantedAction) -> Result<ExecutionResult, anyhow::Error> {
        let start = std::time::Instant::now();

        // 1. Verify input_hash binding
        verify_input_hash(&action.grant.input_hash, &action.action_arguments)?;

        // 2. Single-use grant_id (JTI) nonce replay prevention
        {
            let mut consumed = self.consumed_grant_ids.lock().unwrap();
            if !consumed.insert(action.grant.grant_id.clone()) {
                anyhow::bail!(
                    "Replay attack blocked: grant_id '{}' was already consumed",
                    action.grant.grant_id
                );
            }
        }

        // 3. Lookup registered handler
        let handler = {
            let guard = self.handlers.lock().unwrap();
            guard.get(&action.grant.tool_name).cloned()
        };

        let (raw_output, is_success) = match handler {
            Some(h) => match h(&action.action_arguments) {
                Ok(val) => (val, true),
                Err(err) => (serde_json::json!({ "error": err }), false),
            },
            None => (
                serde_json::json!({ "error": format!("Tool '{}' not found in ReferenceExecutor", action.grant.tool_name) }),
                false,
            ),
        };

        // 4. Apply PII egress filter sanitization
        let serialized = serde_json::to_string(&raw_output)?;
        let sanitized = EgressFilter::sanitize_text(&serialized);
        let sanitized_output: serde_json::Value = serde_json::from_str(&sanitized)?;

        let status = if is_success {
            TransactionOutcomeState::Succeeded
        } else {
            TransactionOutcomeState::Failed
        };

        Ok(ExecutionResult {
            action_id: action.grant.action_id.clone(),
            status,
            connector: "reference_executor".to_string(),
            external_reference: Some(format!("ref_{}", action.grant.grant_id)),
            provider_idempotency_key: Some(action.grant.provider_idempotency_key()),
            reconciled: false,
            output: sanitized_output,
            duration_ms: start.elapsed().as_millis() as u64,
            receipt: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_canonical::canonical_hash;
    use trust_model::ExecutionGrant;

    fn make_grant(grant_id: &str, args: &serde_json::Value) -> ExecutionGrant {
        ExecutionGrant {
            grant_id: grant_id.to_string(),
            action_id: "act-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            workspace_id: "default".to_string(),
            tool_name: "mock_refund".to_string(),
            input_hash: canonical_hash(args),
            issuer: "issuer-1".to_string(),
            expires_at: 9999999999,
            nonce: "nonce-1".to_string(),
            contract_id: None,
            contract_hash: None,
        }
    }

    #[tokio::test]
    async fn test_executor_input_hash_verification_and_tamper_rejection() {
        let executor = ReferenceExecutor::default();
        let original_args = serde_json::json!({ "amount": "50.00" });
        let grant = make_grant("grant-1", &original_args);

        let valid_action = GrantedAction {
            grant: grant.clone(),
            raw_grant_jwt: "mock.jwt".to_string(),
            action_arguments: original_args,
        };

        // Execution with matching args should succeed
        let res = executor.execute(valid_action).await;
        assert!(res.is_ok());

        // Execution with tampered args should fail input hash check
        let tampered_args = serde_json::json!({ "amount": "5000.00" });
        let tampered_action = GrantedAction {
            grant: make_grant("grant-2", &serde_json::json!({ "amount": "50.00" })),
            raw_grant_jwt: "mock.jwt".to_string(),
            action_arguments: tampered_args,
        };

        let err = executor.execute(tampered_action).await.unwrap_err();
        assert!(err.to_string().contains("Input hash mismatch"));
    }

    #[tokio::test]
    async fn test_executor_replay_rejection() {
        let executor = ReferenceExecutor::default();
        let args = serde_json::json!({ "amount": "50.00" });
        let grant = make_grant("grant-replay", &args);

        let action = GrantedAction {
            grant,
            raw_grant_jwt: "mock.jwt".to_string(),
            action_arguments: args,
        };

        // First execution succeeds
        assert!(executor.execute(action.clone()).await.is_ok());

        // Replay attempt with same grant_id fails
        let err = executor.execute(action).await.unwrap_err();
        assert!(err.to_string().contains("Replay attack blocked"));
    }
}
