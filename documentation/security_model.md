# Security Model

> **Design principle:** Unauthorized execution is *physically impossible* — not just policy-discouraged.

This document explains the cryptographic invariants, grant lifecycle, policy engine, and audit trail that make the Trust Gateway a hard security boundary rather than a soft guardrail.

---

## Governing Invariants

The "no unauthorized execution" guarantee holds **only if all** of the following are maintained:

- Agents **never** hold SaaS credentials, OAuth tokens, or API keys — only executors do.
- Executors are the **sole** components with outbound egress to provider APIs.
- Agents and the gateway **cannot** reach external SaaS endpoints directly.
- OAuth refresh tokens live exclusively in executor-scoped NATS KV vaults.
- All executor invocations flow through NATS subjects gated by nkey ACLs — no direct bypass.
- Legacy HTTP executor endpoints are firewalled or removed.
- Executor credentials cannot be injected into agent environments (`env_clear()` on spawn).

**Violating any invariant degrades the guarantee to "administratively discouraged."** See the [Known Limitations](#known-limitations) section in the README for current gaps.

---

## Grant Lifecycle

Every tool call follows this cryptographic chain:

```text
Session JWT (minted by ssi_vault WASM, 30s scope)
    ↓
ProposedAction (NATS: trust.v1.<tenant>.action.propose)
    ↓
Policy evaluation (policy.toml — Allow / Require Approval / Require VP / Deny)
    ↓
ExecutionGrant JWT (Ed25519, 30s TTL, bound to tool_name + input_hash)
    ↓
NATS dispatch (exec.v1.<tenant>.<profile>.invoke)
    ↓
Executor: verify signature → check JTI nonce → recompute input_hash → execute
    ↓
Durable result (exec.v1.<tenant>.<action_id>.result)
```

### Signing Algorithm

Ed25519 is the production signing algorithm. HMAC is available in development mode only (`LIANXI_ENV=development`) and the gateway **panics on startup** if a production environment lacks an Ed25519 key.

### Grant Binding

Every grant carries:

- **`tool_name` binding** — re-targeting to a different tool is rejected
- **`input_hash`** — SHA-256 of canonical JSON args; argument tampering between issuance and execution is rejected
- **`JTI` nonce** — replayed grants are rejected even within their TTL window, logged as `GrantReplayBlocked`

---

## Policy Engine

Policies are priority-ordered TOML rules evaluated deterministically. No model is involved in the policy decision. The LLM proposes; the gateway decides.

```toml
# Auto-allow read-only operations
[[rules]]
match_operation = ["read"]
effect = "allow"

# Human approval required for mutations
[[rules]]
match_operation = ["create", "update", "delete", "transfer"]
effect = "require_approval"
tier = "tier1"

# Step-up VP proof for high-value transactions
[[rules]]
match_tool = ["stripe_refund"]
match_amount_gt = 500
effect = "require_proof"
```

Policies are SHA-256 fingerprinted at startup. The fingerprint is recorded in a `policy.loaded` audit event, creating an immutable record of which policy version governed each grant.

For a complete policy configuration reference, see [Configuration](configuration.md).

---

## Audit Trail

Every action produces a hash-chained audit sequence:

```text
action.proposed → policy.evaluated → approval.requested → approval.approved → grant.issued → executor.command → execution.result
```

Audit events include:
- **`auth_level`** — how strongly the user authenticated
- **`input_hash`** — cryptographic argument provenance

The chain is tamper-evident within NATS JetStream with 90-day retention. External anchoring (RFC 3161, blockchain) is a future enterprise feature.

A unified **UI Projector** consumes raw audit events, sanitizes sensitive fields (credentials, internal hashes), and publishes them to tenant-scoped `ui.v1.<tenant>.events` subjects for real-time portal display.

---

## Human-in-the-Loop Approvals

High-risk operations are interrupted for manual approval:

1. The agent's execution is **suspended** — it waits.
2. A named human operator reviews a plain-language summary in the portal (or via Telegram in Professional Edition).
3. The operator approves or denies.
4. The approval event is logged with the approver's identity.

This is a first-class primitive, not an afterthought. The approval request appears in real time via WebSocket — no polling.

---

## Real-Time Portal Security

The portal connects to the NATS WebSocket bridge (port 9222) and subscribes to `ui.v1.<tenant>.events`. All audit events are **PII-scrubbed before delivery** — the browser never receives credentials or internal identifiers.

The activity feed and Validation Center update instantly on any system event. Reconnection uses exponential backoff (up to 32s) and auto-fetches missed state on recovery.
