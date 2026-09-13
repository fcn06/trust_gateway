use async_trait::async_trait;
use trust_canonical::canonical_hash;
use trust_model::{ExecutionResult, GrantedAction, TransactionOutcomeState};

/// Abstract trait that all tool executors implement.
#[async_trait]
pub trait Executor: Send + Sync {
    /// Execute a tool action after verifying cryptographic grant binding.
    async fn execute(&self, action: GrantedAction) -> Result<ExecutionResult, anyhow::Error>;
}

/// Verify input binding between grant `input_hash` and action arguments.
pub fn verify_input_hash(
    grant_hash: &str,
    arguments: &serde_json::Value,
) -> Result<(), anyhow::Error> {
    let computed = canonical_hash(arguments);
    if grant_hash != computed {
        anyhow::bail!("Input hash mismatch: grant claimed {grant_hash}, computed {computed}");
    }
    Ok(())
}

/// Reconcile a timed-out mutation by recording UNKNOWN_OUTCOME state.
pub fn reconcile_timeout(action_id: &str, connector: &str) -> ExecutionResult {
    ExecutionResult {
        action_id: action_id.to_string(),
        status: TransactionOutcomeState::UnknownOutcome,
        connector: connector.to_string(),
        external_reference: None,
        provider_idempotency_key: None,
        reconciled: false,
        output: serde_json::json!({
            "error": "Execution timed out during external SaaS mutation",
            "state": "unknown_outcome",
            "reconciliation_required": true
        }),
        duration_ms: 0,
        receipt: None,
    }
}
