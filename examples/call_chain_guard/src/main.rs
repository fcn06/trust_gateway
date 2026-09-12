use trust_model::CallChainContext;
use trust_policy::call_chain::{evaluate_and_advance, validate_context_integrity, CallChainPolicy};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("============================================================");
    println!("🛡️ Trust Gateway Example: Layer 0 Call-Chain Guard");
    println!("============================================================");

    let policy = CallChainPolicy::default();
    println!("Active Policy Invariants:");
    println!("  - Max Execution Depth: {}", policy.max_depth);
    println!(
        "  - Max Frequency per Tool: {}",
        policy.max_frequency_per_tool
    );
    println!("  - Allow Cycles: {}\n", policy.allow_cycles);

    // -------------------------------------------------------------
    // Scenario 1: Healthy Nested Multi-Agent Delegation
    // -------------------------------------------------------------
    println!("--- Scenario 1: Valid Multi-Agent Delegation ---");
    let mut session_ctx = CallChainContext::new("orchestrator-agent");

    println!("Step 1: Orchestrator delegates to research_agent");
    evaluate_and_advance(&mut session_ctx, "research_agent", &policy)?;
    println!("  ✅ Stack: {:?}", session_ctx.call_stack);

    println!("Step 2: Research agent queries data_fetcher");
    evaluate_and_advance(&mut session_ctx, "data_fetcher", &policy)?;
    println!("  ✅ Stack: {:?}", session_ctx.call_stack);

    println!("Step 3: Data fetcher queries weather_service");
    evaluate_and_advance(&mut session_ctx, "weather_service", &policy)?;
    println!("  ✅ Stack: {:?}", session_ctx.call_stack);
    println!("  🎯 Outcome: Multi-agent chain executed cleanly within all bounds.\n");

    // -------------------------------------------------------------
    // Scenario 2: Agent Recursion Loop / Cycle Attack
    // -------------------------------------------------------------
    println!("--- Scenario 2: Loop / Cycle Detection Attack ---");
    let mut loop_ctx = CallChainContext::new("orchestrator-agent");
    evaluate_and_advance(&mut loop_ctx, "agent_alpha", &policy)?;
    evaluate_and_advance(&mut loop_ctx, "agent_beta", &policy)?;
    println!("Current Stack: {:?}", loop_ctx.call_stack);
    println!("Simulating loop: agent_beta attempts to call back into agent_alpha...");

    match evaluate_and_advance(&mut loop_ctx, "agent_alpha", &policy) {
        Ok(_) => println!("❌ UNEXPECTED: Loop was allowed!"),
        Err(err) => {
            println!("🛑 1. Cycle Rejected: {err}");
            println!("  ✅ Guard stopped cyclic ping-pong cascade.\n");
        }
    }

    // -------------------------------------------------------------
    // Scenario 3: Plan Runaway Recursion Depth Limit
    // -------------------------------------------------------------
    println!("--- Scenario 3: Runaway Recursion Depth Attack ---");
    let mut deep_ctx = CallChainContext::new("orchestrator-agent");
    for i in 1..=10 {
        let tool = format!("tool_step_{i}");
        evaluate_and_advance(&mut deep_ctx, &tool, &policy)?;
    }
    println!(
        "Stack depth reached maximum allowed: {}",
        deep_ctx.call_stack.len()
    );
    println!("Simulating step 11 (exceeding depth limit 10)...");

    match evaluate_and_advance(&mut deep_ctx, "tool_step_11", &policy) {
        Ok(_) => println!("❌ UNEXPECTED: Over-depth execution allowed!"),
        Err(err) => {
            println!("🛑 2. Depth Limit Rejected: {err}");
            println!("  ✅ Guard prevented infinite plan runaway.\n");
        }
    }

    // -------------------------------------------------------------
    // Scenario 4: Frequency Cap Attack (Tool Thrashing)
    // -------------------------------------------------------------
    println!("--- Scenario 4: Frequency Capping Attack ---");
    let freq_policy = CallChainPolicy {
        max_depth: 20,
        max_frequency_per_tool: 3,
        allow_cycles: true,
    };
    let mut freq_ctx = CallChainContext::new("agent-batch-worker");

    for i in 1..=3 {
        evaluate_and_advance(&mut freq_ctx, "send_email", &freq_policy)?;
        println!("Invocation {i}/3 of 'send_email' allowed.");
    }
    println!("Simulating 4th invocation of 'send_email' (exceeding max frequency 3)...");

    match evaluate_and_advance(&mut freq_ctx, "send_email", &freq_policy) {
        Ok(_) => println!("❌ UNEXPECTED: Over-frequency execution allowed!"),
        Err(err) => {
            println!("🛑 3. Frequency Bound Rejected: {err}");
            println!("  ✅ Guard prevented tool spam / budget burn.\n");
        }
    }

    // -------------------------------------------------------------
    // Scenario 5: Context Tampering / History Reset Attack
    // -------------------------------------------------------------
    println!("--- Scenario 5: Client Context Tampering Detection ---");
    let mut tracked_server_state = CallChainContext::new("client-agent");
    evaluate_and_advance(&mut tracked_server_state, "tool_a", &policy)?;
    evaluate_and_advance(&mut tracked_server_state, "tool_b", &policy)?;
    evaluate_and_advance(&mut tracked_server_state, "tool_c", &policy)?;

    println!(
        "Authoritative Gateway Session History: {:?}",
        tracked_server_state.call_stack
    );
    println!("Compromised client attempts to submit a forged context resetting call history:");

    let mut forged_client_context = CallChainContext::new("client-agent");
    forged_client_context.call_stack = vec!["tool_a".to_string()]; // reset history to evade limits

    match validate_context_integrity(Some(&forged_client_context), Some(&tracked_server_state)) {
        Ok(_) => println!("❌ UNEXPECTED: Forged client context was accepted!"),
        Err(err) => {
            println!("🛑 4. Context Integrity Rejected: {err}");
            println!("  ✅ Gateway detected call-chain rewind attempt and aborted execution.\n");
        }
    }

    println!("============================================================");
    println!("🎉 All Layer 0 Call-Chain Guard scenarios verified successfully!");
    println!("============================================================");

    Ok(())
}
