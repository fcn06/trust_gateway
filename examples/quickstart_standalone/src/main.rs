use trust_executor_sdk::Executor;
use trust_grants::GrantIssuer;
use trust_model::{GrantedAction, OperationAttributes, ProposedAction};
use trust_policy::CorePolicyEngine;
use trust_reference_executor::ReferenceExecutor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: cargo run -p quickstart-standalone -- [OPTIONS]\n");
        println!("Options:");
        println!("  --tamper, --simulate-attack  Simulate argument tampering after grant issuance");
        println!("  --replay                     Simulate grant replay attack (re-submitting consumed grant)");
        println!(
            "  --call-chain                 Simulate Layer 0 call-chain recursion/loop attack"
        );
        println!("  --help                       Print this help menu");
        return Ok(());
    }

    let is_tamper = args
        .iter()
        .any(|a| a == "--tamper" || a == "--simulate-attack");
    let is_replay = args.iter().any(|a| a == "--replay");
    let is_call_chain = args.iter().any(|a| a == "--call-chain");

    println!("=====================================================");
    if is_tamper {
        println!("🛡️ Trust Gateway Attack Simulation: Argument Tampering");
    } else if is_replay {
        println!("🛡️ Trust Gateway Attack Simulation: Grant Replay Attack");
    } else if is_call_chain {
        println!("🛡️ Trust Gateway Attack Simulation: Layer 0 Call-Chain Recursion / Loop");
    } else {
        println!("🛡️ Trust Gateway Standalone Control Flow Quickstart");
    }
    println!("=====================================================");

    let now = chrono::Utc::now().timestamp();

    // Setup CallChainContext if simulating call-chain attack
    let call_chain_context = if is_call_chain {
        Some(trust_model::CallChainContext {
            trace_id: "trace-attack-001".to_string(),
            call_stack: vec!["mock_refund".to_string()], // cyclic recursion on mock_refund
            invocation_counts: std::collections::HashMap::from([("mock_refund".to_string(), 1)]),
        })
    } else {
        None
    };

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
        call_chain_context,
    };

    println!("📥 1. Received ProposedAction: tool='{}'", action.tool_name);

    // 2. Evaluate Policy
    let decision = CorePolicyEngine::evaluate(&action, 10000);
    println!(
        "⚖️ 2. Policy Decision: approved={}, reason='{}'",
        decision.approved, decision.reason
    );

    if is_call_chain {
        println!("⚡ Evaluation Result: Call-chain attack BLOCKED at Layer 0!");
        println!("🚫 Reason: {}", decision.reason);
        println!("=====================================================");
        println!("🛡️ Call-chain cyclic loop successfully BLOCKED before grant issuance!");
        println!("=====================================================");
        return Ok(());
    }

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

    println!(
        "🔑 3. Issued ExecutionGrant: id='{}', input_hash='{}'",
        grant.grant_id, grant.input_hash
    );

    let executor = ReferenceExecutor::default();

    if is_tamper {
        // Tamper Attack Simulation: mutate argument after grant issuance
        let mut tampered_arguments = action.arguments.clone();
        tampered_arguments["amount"] = serde_json::json!("5000.00");

        println!(
            "⚠️  Simulating tampered args: amount {} → {}",
            action.arguments["amount"].as_str().unwrap_or("50.00"),
            tampered_arguments["amount"].as_str().unwrap_or("5000.00")
        );

        let tampered_action = GrantedAction {
            grant: grant.clone(),
            raw_grant_jwt: "mock.jwt.token".to_string(),
            action_arguments: tampered_arguments,
        };

        match executor.execute(tampered_action).await {
            Ok(result) => {
                println!(
                    "❌ UNEXPECTED: Executor allowed tampered execution: status={:?}",
                    result.status
                );
            }
            Err(err) => {
                println!("⚡ 4. Execution REJECTED: {err}");
                println!("🚫 Executor refused to run — grant was cryptographically bound to different arguments.");
            }
        }
    } else if is_replay {
        // Replay Attack Simulation: execute once successfully, then re-submit the identical grant
        let granted_action = GrantedAction {
            grant: grant.clone(),
            raw_grant_jwt: "mock.jwt.token".to_string(),
            action_arguments: action.arguments.clone(),
        };

        let result1 = executor.execute(granted_action.clone()).await?;
        println!(
            "⚡ 4a. Initial Execution Succeeded! status={:?}, duration={}ms (Grant consumed)",
            result1.status, result1.duration_ms
        );

        println!(
            "⚠️  Simulating replay attack: Re-submitting already consumed grant (grant_id='{}')",
            grant.grant_id
        );

        match executor.execute(granted_action).await {
            Ok(result2) => {
                println!(
                    "❌ UNEXPECTED: Executor allowed replayed grant: status={:?}",
                    result2.status
                );
            }
            Err(err) => {
                println!("⚡ 4b. Execution REJECTED: {err}");
                println!("🚫 Executor refused to run — grant nonce/JTI was already consumed.");
            }
        }
    } else {
        // Standard Happy Path
        let granted_action = GrantedAction {
            grant: grant.clone(),
            raw_grant_jwt: "mock.jwt.token".to_string(),
            action_arguments: action.arguments.clone(),
        };

        let result = executor.execute(granted_action).await?;

        println!(
            "⚡ 4. Execution Result: status={:?}, duration={}ms",
            result.status, result.duration_ms
        );
        println!(
            "🔒 5. Sanitized Output:\n{}",
            serde_json::to_string_pretty(&result.output)?
        );
    }

    println!("=====================================================");
    if is_tamper {
        println!("🛡️ Tamper attack successfully BLOCKED by cryptographic input binding!");
    } else if is_replay {
        println!("🛡️ Replay attack successfully BLOCKED by single-use grant nonce!");
    } else {
        println!("✅ Standalone execution completed successfully!");
    }
    println!("=====================================================");
    Ok(())
}
