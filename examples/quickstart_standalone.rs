use trust_executor_sdk::Executor;
use trust_grants::GrantIssuer;
use trust_model::{GrantedAction, OperationAttributes, ProposedAction};
use trust_policy::CorePolicyEngine;
use trust_reference_executor::ReferenceExecutor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️ Trust Gateway Standalone Control Flow Quickstart");

    let now = chrono::Utc::now().timestamp();

    // 1. Define a proposed action from an Agent
    let action = ProposedAction {
        action_id: "action-demo-001".to_string(),
        tenant_id: "tenant-demo".to_string(),
        workspace_id: "default".to_string(),
        requester_id: "agent-demo".to_string(),
        tool_name: "mock_refund".to_string(),
        arguments: serde_json::json!({
            "amount": "50.00",
            "reason": "customer dissatisfaction"
        }),
        operation_attributes: OperationAttributes {
            operation_kind: "financial_mutation".to_string(),
            amount: None,
            resource: Some("payment/refund".to_string()),
            beneficiary: None,
        },
        timestamp: now,
        contract_context: None,
        call_chain_context: None,
    };

    println!("📥 1. Received ProposedAction: tool='{}'", action.tool_name);

    // 2. Evaluate Policy
    let decision = CorePolicyEngine::evaluate(&action, 10000);
    println!("⚖️ 2. Policy Decision: approved={}, reason='{}'", decision.approved, decision.reason);

    assert!(decision.approved, "Policy denied action");

    // 3. Issue ExecutionGrant
    let grant = GrantIssuer::create_grant(
        &action.action_id,
        &action.tenant_id,
        &action.tool_name,
        &action.arguments,
        "trust_gateway_prod",
        30,
    );

    println!("🔑 3. Issued ExecutionGrant: id='{}', input_hash='{}'", grant.grant_id, grant.input_hash);

    // 4. Dispatch to ReferenceExecutor
    let executor = ReferenceExecutor::default();
    let granted_action = GrantedAction {
        grant: grant.clone(),
        raw_grant_jwt: "mock.jwt.token".to_string(),
        action_arguments: action.arguments.clone(),
    };

    let result = executor.execute(granted_action).await?;

    println!("⚡ 4. Execution Result: status={:?}, duration={}ms", result.status, result.duration_ms);
    println!("🔒 5. Sanitized Output: {}", serde_json::to_string_pretty(&result.output)?);

    println!("✅ Standalone execution completed successfully!");
    Ok(())
}
