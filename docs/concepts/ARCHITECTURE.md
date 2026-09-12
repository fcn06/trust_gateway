# Trust Gateway Architecture

The Trust Gateway enforces the 3-pillar zero-trust value proposition:
**"Agents propose. Gateway decides. Executors verify."**

---

## 🏛️ The 3 Core Pillars & Architectural Planes

### 🤖 Pillar 1: Agents Propose (Reasoning & Intent)
* **Reasoning Plane**: Sovereign agents generate action intents represented as canonical `ProposedAction` payloads (`crates/trust-model`).
* **Zero-Trust Boundary**: Agents hold zero API credentials, database keys, or direct execution capabilities. All action intents must be submitted over NATS or REST endpoints.

---

### 🛡️ Pillar 2: Gateway Decides (Governance & Control)
* **Layer 0 Call-Chain Guard**: Sits at the entrance of the decision pipeline (`crates/trust-policy/src/call_chain.rs`). Enforces call-chain depth bounds (`max_depth = 10`), cycle/recursion loop detection (`allow_cycles = false`), and per-tool frequency caps (`max_frequency_per_tool = 3`) while verifying call-stack integrity against server-tracked session state.
* **Governance Plane**: The Trust Gateway evaluates request attributes against `policy.toml` (`crates/trust-policy`, `policy-sdk`). If required by policy rules, human approval is triggered via the approval daemon, backed by a durable pending-approvals store.
* **Grant Minting Plane**: Upon approval, the Gateway mints a short-lived Ed25519-signed `ExecutionGrant` JWT (`crates/trust-grants`), cryptographically bound to the SHA-256 `input_hash` of canonical arguments (`crates/trust-canonical`).
* **Trust Operations Plane (`trust_ops`)**: Key lifecycle management (JWKS rotation), executor posture attestation, and hash-chained audit log reconciliation (`crates/trust-audit`).
* **CLI Policy Enforcement Point**: Command-line interface adapter (`adapters/surface-cli`) providing dynamic CLI introspection and execution of governed tools via `trustctl tool run`.

---

### ⚡ Pillar 3: Executors Verify (Verification & Execution)
* **Execution & Verification Plane**: Isolated runtimes (`executor_host`, `verifier`, `crates/trust-executor-sdk`) verify the Ed25519 signature, SHA-256 `input_hash` argument binding, and single-use replay nonces before dispatching tool mutations.
* **Egress Scrubbing Plane**: Execution results pass through structural validation and PII/secret scrubbing (`crates/trust-egress`) before returning to the agent.

---

## 🔀 Execution Dispatch Modes

The reference architecture supports two operational execution modes:

### 1. Managed Dispatch (Production Default)
In Managed Dispatch mode, the agent never receives or touches the `ExecutionGrant` JWT:
1. Agent sends `ProposedAction` to Gateway over NATS or REST.
2. Gateway evaluates policy, mints `ExecutionGrant`, and dispatches the `GrantedAction` directly to an isolated Executor Host over NATS (`exec.v1.<tenant>.<profile>.invoke`).
3. Executor verifies grant, executes side-effect, and passes raw output to Gateway for egress filtering.
4. Agent receives only the final sanitized outcome.

### 2. Portable Grant Mode (REST & MCP Clients)
In Portable Grant mode, external agents (such as MCP clients or third-party webhooks) receive the minted `ExecutionGrant`:
1. Client requests authorization from Gateway for a proposed action.
2. Gateway returns short-lived (e.g. 30s TTL), Ed25519-signed `ExecutionGrant` JWT.
3. Client presents `ExecutionGrant` + argument payload to the isolated Executor Host endpoint.
4. Executor validates grant authenticity, parameter hash match, and single-use nonce before executing.

---

## 👤 Human Approval Binding Flow

When a policy evaluates to `action = "require_approval"`, execution authority is bound to an explicit approval workflow:

```text
Proposal (arguments) 
  ──► Canonical Fingerprint (SHA-256)
  ──► Approval Decision (bound to Fingerprint + Approver ID)
  ──► ExecutionGrant Minting (including Fingerprint)
  ──► Executor Verification (validates Fingerprint & Hash match)
```

1. **Fingerprinting**: The proposal's canonical argument digest (`input_hash`) is computed.
2. **Approval Request**: An approval request is recorded with `proposal_fingerprint`, pending approver action.
3. **Grant Minting**: Upon approver authorization, the Gateway mints the `ExecutionGrant` containing the exact `input_hash` and `policy_fingerprint`.
4. **Tamper Rejection**: Any post-approval attempt to tamper with arguments causes `input_hash` verification failure at the Executor boundary.

---

## 💾 State Management & Replay Nonce Store

* **Horizontally Scalable Gateway**: The Gateway process is stateless in runtime logic and externalizes durable state to configured backends (default: NATS JetStream KV).
* **Single-Use Replay Nonce Store**: Executors check and consume grant `jti` identifiers against a shared JetStream KV nonce store.
* **Crash Recovery & Provider Idempotency**: Nonce consumption is recorded prior to side-effect execution. For non-idempotent target APIs, network partitions during execution rely on target SaaS provider-side idempotency keys.

---

## 🧩 Domain Crate Responsibilities

| Pillar | Domain Crate | Responsibility |
| :--- | :--- | :--- |
| **Pillar 1** | [`crates/trust-model`](../../crates/trust-model) | Pure domain model definitions (`ProposedAction`, `ExecutionGrant`, `TransactionOutcomeState`). |
| **Pillar 2** | [`crates/trust-policy`](../../crates/trust-policy) | Attribute-based policy evaluator engine and Layer 0 Call-Chain Guard (`call_chain`). |
| **Pillar 2** | [`crates/trust-canonical`](../../crates/trust-canonical) | RFC 8785 JSON canonicalizer & SHA-256 `input_hash` digest calculation. |
| **Pillar 2** | [`crates/trust-grants`](../../crates/trust-grants) | Ed25519 `ExecutionGrant` issuance and key management. |
| **Pillar 2** | [`crates/trust-audit`](../../crates/trust-audit) | Hash-chained `AuditEvent` ledger and audit sinks. |
| **Pillar 2** | [`adapters/surface-cli`](../../adapters/surface-cli) | Dynamic CLI Policy Enforcement Point (PEP) projecting tool JSON Schemas to typed CLI commands. |
| **Pillar 3** | [`crates/trust-auth`](../../crates/trust-auth) | Strict JWT signature and claims contract verification. |
| **Pillar 3** | [`crates/trust-executor-sdk`](../../crates/trust-executor-sdk) | Abstract Executor trait & outcome state reconciliation. |
| **Pillar 3** | [`crates/trust-egress`](../../crates/trust-egress) | Regex & LLM-powered PII & secret egress scrubbing. |
| **Pillar 3** | [`verifier/`](../../verifier) | Standalone zero-dependency Ed25519 execution grant verifier library. |

