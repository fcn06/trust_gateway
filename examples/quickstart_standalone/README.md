# Standalone Quickstart

Zero-dependency standalone control flow demo. This is the **golden path** — the fastest way to see Trust Gateway in action.

## What It Demonstrates

This example runs the entire Trust Gateway control flow **in-process** without NATS, Docker, or any external dependencies:

1. An AI agent **proposes** a `mock_refund` action
2. The **policy engine** evaluates the action and approves it
3. A cryptographic **ExecutionGrant** JWT is minted with SHA-256 `input_hash` binding
4. The **reference executor** verifies the grant and executes the tool
5. **PII scrubbing** redacts sensitive data (email addresses) from the output

## Prerequisites

- Rust 1.89+ with cargo
- C compiler and OpenSSL dev headers (see [main README](../../README.md#prerequisites))

## Run

### 1. Happy Path Demo
```bash
cargo run -p quickstart-standalone
# or: make quickstart
```

### 2. Argument Tampering Attack Simulation (`--tamper` or `--simulate-attack`)
Demonstrates live rejection by the executor when an attacker tampers with action parameters after grant issuance:
```bash
cargo run -p quickstart-standalone -- --tamper
```

### 3. Grant Replay Attack Simulation (`--replay`)
Demonstrates live single-use grant/nonce rejection when an attacker attempts to re-submit an already consumed grant:
```bash
cargo run -p quickstart-standalone -- --replay
```

### 4. Layer 0 Call-Chain Loop / Recursion Simulation (`--call-chain`)
Demonstrates immediate denial at Layer 0 when an agent attempts recursive invocation or cyclic tool loops:
```bash
cargo run -p quickstart-standalone -- --call-chain
```

## Expected Output

### Happy Path
```
=====================================================
🛡️ Trust Gateway Standalone Control Flow Quickstart
=====================================================
📥 1. Received ProposedAction: tool='mock_refund'
⚖️ 2. Policy Decision: approved=true, reason='Action permitted under default policy'
🔑 3. Issued ExecutionGrant: id='grant_action-demo-001', input_hash='38c23c59...'
⚡ 4. Execution Result: status=Succeeded, duration=5ms
🔒 5. Sanitized Output:
{
  "account_email": "[REDACTED]",
  "amount": "50.00",
  "status": "refund_processed"
}
=====================================================
✅ Standalone execution completed successfully!
=====================================================
```

### Tamper Simulation (`--tamper`)
```
=====================================================
🛡️ Trust Gateway Attack Simulation: Argument Tampering
=====================================================
📥 1. Received ProposedAction: tool='mock_refund'
⚖️ 2. Policy Decision: approved=true, reason='Action permitted under default policy'
🔑 3. Issued ExecutionGrant: id='grant_action-demo-001', input_hash='38c23c59...'
⚠️  Simulating tampered args: amount 50.00 → 5000.00
⚡ 4. Execution REJECTED: Input hash mismatch: grant claimed 38c23c59..., computed a91f2e04...
🚫 Executor refused to run — grant was cryptographically bound to different arguments.
=====================================================
🛡️ Tamper attack successfully BLOCKED by cryptographic input binding!
=====================================================
```

### Replay Simulation (`--replay`)
```
=====================================================
🛡️ Trust Gateway Attack Simulation: Grant Replay Attack
=====================================================
📥 1. Received ProposedAction: tool='mock_refund'
⚖️ 2. Policy Decision: approved=true, reason='Action permitted under default policy'
🔑 3. Issued ExecutionGrant: id='grant_action-demo-001', input_hash='38c23c59...'
⚡ 4a. Initial Execution Succeeded! status=Succeeded, duration=1ms (Grant consumed)
⚠️  Simulating replay attack: Re-submitting already consumed grant (grant_id='grant_action-demo-001')
⚡ 4b. Execution REJECTED: Replay attack blocked: grant_id 'grant_action-demo-001' was already consumed
🚫 Executor refused to run — grant nonce/JTI was already consumed.
=====================================================
🛡️ Replay attack successfully BLOCKED by single-use grant nonce!
=====================================================
```

## Key Concepts Demonstrated

| Output Line | Concept |
|---|---|
| `📥 1. Received ProposedAction` | Agents propose — they never execute directly |
| `⚖️ 2. Policy Decision: approved=true` | Gateway decides — policy engine evaluates rules |
| `🔑 3. Issued ExecutionGrant` | Cryptographic binding — grant includes `input_hash` |
| `⚡ 4. Execution Result` | Executors verify — grant is checked before execution |
| `🔒 5. Sanitized Output: [REDACTED]` | PII scrubbing — sensitive data is automatically removed |
| `⚠️ Simulating tampered args` | Input binding security — tampering invalidates execution |
| `⚠️ Simulating replay attack` | Replay protection — grants cannot be reused |

