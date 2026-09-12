# Open Execution Authorization Protocol Specification

Version: 1.0.0

## Overview

The **Open Execution Authorization Protocol** provides a vendor-neutral, cryptographically verifiable specification for controlling side-effecting actions in autonomous AI agent systems.

It separates reasoning intelligence from execution authority by requiring agents to obtain a short-lived, cryptographically signed **ExecutionGrant** before mutating external target systems.

---

## Normative Message Contracts

| Contract | Direction | Purpose |
| :--- | :--- | :--- |
| `ProposedAction` | Agent → Gateway | Intent proposal payload submitted for authorization (carries optional `CallChainContext`) |
| `CallChainContext` | Agent → Gateway | Multi-agent execution trace metadata: `depth`, `call_stack`, `invocation_counts`, `initiator_agent_id` |
| `PolicyDecision` | Gateway → Internal | Evaluation outcome (`Allow`, `Deny`, `RequireApproval`) |
| `ExecutionGrant` | Gateway → Executor / Agent | Ed25519-signed authorization token bound to exact input digest |
| `GrantedAction` | Gateway → Executor Host | Dispatched execution envelope containing grant and parameters |
| `ExecutionResult` | Executor → Gateway / Agent | Standardized execution outcome status and sanitized output |

---

## Layer 0: Call-Chain Governance

To protect distributed multi-agent workflows from infinite recursion, cyclic delegation ping-pong, and plan runaway attacks, the protocol defines **Layer 0 Call-Chain Guard** evaluation prior to attribute rule processing:

```json
{
  "call_chain_context": {
    "depth": 2,
    "call_stack": ["lead_orchestrator", "research_worker"],
    "invocation_counts": {
      "lead_orchestrator": 1,
      "research_worker": 2
    },
    "initiator_agent_id": "did:key:z6Mku...lead"
  }
}
```

* **Depth Bounds**: Evaluated against configured maximum call depth (default: 10). Reaching `depth > max_depth` causes an immediate `Deny`.
* **Cycle Detection**: Unless explicitly allowed, duplicate appearances of an agent or tool in the active `call_stack` are detected as execution loops and denied.
* **Frequency Caps**: Invocations per tool are tracked within the trace session; exceeding `max_frequency_per_tool` (default: 3) triggers denial.
* **Session Integrity Tracking**: Gateway maintains an authoritative session state keyed by `trace_id`. Inbound proposals whose reported stack or counts conflict with server-tracked history are rejected to prevent compromised agents from resetting their execution counters.


---

## `ExecutionGrant` Core Claims

An `ExecutionGrant` is a short-lived Ed25519-signed JWT. The protocol requires the following core claims:

```json
{
  "iss": "trust-gateway",
  "aud": "executor-host",
  "sub": "agent-001",
  "iat": 1740000000,
  "nbf": 1740000000,
  "exp": 1740000030,
  "jti": "grant-550e8400-e29b-41d4-a716-446655440000",
  "tenant_id": "tenant_demo",
  "tool_name": "io.example.refund@v1",
  "input_hash": "sha256:<64-hex-character-digest>",
  "policy_fingerprint": "sha256:<64-hex-character-digest>"
}
```

The grant authorizes one execution of one versioned tool with exactly one canonical argument set. Executors must reject expired grants, invalid signatures, reused `jti` values, mismatched tool identities, or mismatched argument hashes.

### Claim Definitions

* `iss`: Issuer identifier (must equal expected Gateway issuer URI).
* `aud`: Audience identifier (must equal target Executor host domain).
* `sub`: Subject identifier (agent or user initiating proposal).
* `iat`: Unix timestamp (seconds) when the grant was issued.
* `nbf`: Unix timestamp before which the grant is invalid.
* `exp`: Unix timestamp defining grant expiration (maximum recommended TTL: 30 seconds).
* `jti`: Unique single-use grant identifier (UUID v4) for replay prevention.
* `tenant_id`: Multi-tenant isolation context.
* `tool_name`: Authorized target tool or action name (populated from `action_name` in HTTP proposal).
* `input_hash`: Hex-encoded SHA-256 digest of RFC 8785 canonicalized input arguments.
* `policy_fingerprint`: Hash of the evaluated policy snapshot for auditing.

### Field Naming Conventions & Transport Mapping

| Layer / Context | Field Name | Purpose & Example |
| :--- | :--- | :--- |
| **HTTP REST Payload** (`POST /v1/actions/propose`) | `action_name` | Ingress action/tool name submitted by agent: `"action_name": "claw_hello_world"` |
| **Internal Domain Model** (`ProposedAction`) | `tool_name` | Internal tool name field in Rust domain model: `tool_name: "claw_hello_world"` |
| **`ExecutionGrant` JWT Claim** | `tool_name` | Signed JWT claim bound to signature: `"tool_name": "claw_hello_world"` |

---

## Canonicalization & Input Hash Protocol (RFC 8785)

To guarantee argument integrity across heterogeneous components, parameter inputs are canonicalized prior to hashing:

1. Keys in JSON objects are sorted lexicographically by UTF-8 code points.
2. Extra whitespace, indentation, and trailing commas are stripped.
3. Floating point numbers follow standard IEEE 754 canonical formatting.
4. The resulting string is UTF-8 encoded and hashed using SHA-256.

$$\text{input}\_\text{hash} = \text{"sha256:"} + \text{Hex}(\text{SHA256}(\text{Canonicalize}_{\text{RFC8785}}(\text{arguments})))$$

---

## Executor Verification Requirements

An Executor **MUST** reject execution if any of the following conditions fail:

1. **Signature Verification**: The Ed25519 signature fails verification against the Gateway public key.
2. **Class Separation**: Token `typ` or `token_class` is not `execution_grant`.
3. **Expiration**: Current UTC time $> \text{exp}$ or $< \text{nbf}$.
4. **Tool Binding**: `tool_name` in grant does not match requested target tool.
5. **Argument Integrity**: SHA-256 digest of canonicalized execution arguments does not equal `input_hash`.
6. **Replay Check**: `jti` exists in the consumed single-use nonce store.

---

## Replay Prevention Semantics

Grants are strictly single-use. Executors perform atomic consumption of the `jti` identifier in a durable nonce store shared by all executor instances.
If an incoming `jti` has already been recorded, execution is rejected immediately with error `GRANT_REPLAY_DETECTED`.

---

## Reference Implementation Artifacts

This repository provides reference components implementing this protocol:
* [`gateway/`](../../gateway): Reference policy decision point and grant issuer.
* [`executor_host/`](../../executor_host): Reference execution worker host.
* [`verifier/`](../../verifier): Zero-dependency Rust reference verifier SDK.
* [`conformance/`](../../conformance): Protocol conformance suite.
* [`test-vectors/`](../../test-vectors): Standard test vectors for multi-language implementations.

> **Transport Agnosticism**: NATS JetStream is the default transport of the reference implementation. The protocol specification can be bound to alternative transports (REST/HTTP, gRPC, WebSocket, MCP) without altering grant semantics.

