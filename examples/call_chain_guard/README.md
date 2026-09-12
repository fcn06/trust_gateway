# Layer 0 Call-Chain Guard Example

This example demonstrates the **Layer 0 Call-Chain Guard** (`crates/trust-policy/src/call_chain.rs`), which protects multi-agent systems and tool delegation workflows from:
1. **Agent Recursion Loops**: Cycles where Agent A calls Agent B, which calls back into Agent A.
2. **Plan Runaway Attacks**: Deep recursive reasoning cascades exceeding maximum execution depth limits.
3. **Tool Thrashing & Budget Burn**: Single tools being invoked repeatedly beyond frequency caps.
4. **Context Integrity Tampering**: Client-side agents attempting to reset or forge their execution stack to evade policy limits.

---

## Running the Example

```bash
cargo run -p call-chain-guard-example
```

---

## What This Demonstrates

| Scenario | Invariant Checked | Outcome |
|---|---|---|
| **1. Valid Delegation** | Nested multi-agent delegation | Allowed (`depth: 3 <= 10`, no cycles) |
| **2. Loop Attack** | Cycle detection (`allow_cycles = false`) | Rejected with `CycleDetected` error |
| **3. Depth Runaway** | Execution depth limit (`max_depth = 10`) | Rejected with `DepthExceeded` error |
| **4. Frequency Capping** | Per-tool frequency limit (`max_frequency = 3`) | Rejected with `FrequencyExceeded` error |
| **5. Context Tampering** | Server-side session integrity tracking | Rejected with `ChainDivergence` error |

---

## Architectural Role in Trust Gateway

The Call-Chain Guard sits at **Layer 0** of the Trust Gateway's decision pipeline:

```text
Inbound ActionProposal
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 0: Call-Chain Guard (crates/trust-policy/call_chain)  │
│  - Depth check: depth <= max_depth                          │
│  - Cycle check: cycle_detected in call_stack?               │
│  - Frequency check: invocation_count <= max_frequency       │
│  - Gateway Session Integrity: tracked vs. submitted stack   │
└─────────────────────────────┬───────────────────────────────┘
                              │
               Pass           ▼           Violation
         ┌─────────────────────────┐   ┌──────────────────────────┐
         │ Layer 1: Policy Rules   │   │ Immediate Deny (Exit 126)│
         │ (policy.toml ABAC)      │   │ "Call-chain limit hit"   │
         └─────────────────────────┘   └──────────────────────────┘
```
