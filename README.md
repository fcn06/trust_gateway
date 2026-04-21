# AI Agents Trust Gateway — Community Edition

> **The execution control plane for the agentic era.** 
> Built in Rust. Runs self-hosted. No cloud dependency.

---

## The Problem

Your AI agent just sent an email to the wrong client. Or called a payment API with hallucinated parameters. Or deleted records that a hundred downstream processes depend on.

This isn't a model quality problem. It's an architecture problem.

Existing security frameworks were built for two kinds of actors: **humans** and **static service accounts**. Neither model fits an autonomous agent — an actor with dynamic intent, no fixed permission scope, and the ability to chain dozens of tool calls whose combined effect is invisible from any individual operation.

**Trust Gateway solves this** by inserting a deterministic governance layer between your agents and your business systems. Every agentic intent is treated as a *proposed action* until it clears a cryptographic and policy hurdle. Nothing executes unless the gateway says so.

---

## What Makes This Different

Most "AI gateway" projects are reverse proxies with rate limiting bolted on. Trust Gateway is an **execution control plane** — a fundamentally different architecture:

| Concern | Typical API Gateway | Trust Gateway |
|---|---|---|
| Unit of control | HTTP request | Proposed Action (intent) |
| Trust model | Network perimeter | Cryptographic execution grant |
| Policy | Allow/deny by route | Allow / Require Approval / Deny by identity + operation |
| Human oversight | None | First-class human-in-the-loop primitive |
| Audit | Access logs | Durable, replayable JetStream event trail |
| Identity | API key / token | DID + WebAuthn passkey (FIDO2) |
| Skill runtime | N/A | OS process isolation (Wasm sandboxing in Enterprise) |

---

## Architecture

The gateway decouples **intelligence** (the LLM) from **capability** (the tools) via a governance layer that cannot be bypassed:

```
User Intent
    │
    ▼
Host Orchestrator  ←── WebAuthn / DID identity
    │
    ▼
Execution Orchestrator
    │
    ▼
┌─────────────────────────────────────┐
│          TRUST GATEWAY              │
│                                     │
│  1. Identity Resolution (DID/JWT)   │
│  2. Policy Evaluation (TOML rules)  │
│  3. Execution Grant issuance        │
│     (Ed25519 or HMAC-SHA256 JWT)    │
│  4. Audit event → JetStream         │
│  5. Human approval (if required)    │
└──────────────┬──────────────────────┘
               │  Signed ExecutionGrant
               ▼
     Specialized Executors
     (MCP connectors / Claw skills)
```

### The Host: Wasm Component Model Architecture

The Host is the most technically differentiated component in this project. It is not a conventional service — it is a **WebAssembly Component Model host** (via Wasmtime) that loads cryptographic and identity primitives as sandboxed Wasm modules at runtime.

#### How It Works

Critical modules — `ssi_vault` (key management, DID generation, JWT signing), `acl_store` (connection policy enforcement), `contact_store`, and `messaging_service` — are compiled to `.wasm` binaries and loaded dynamically at startup. Each component is bound through **WIT (WebAssembly Interface Types)** interfaces, which provide:

- **Memory-safe boundaries** — Wasm's linear memory model isolates each component. A vulnerability in one module cannot escape its sandbox.
- **Interface-typed contracts** — WIT defines precise function signatures between the host runtime and its components. No serialization ambiguity, no FFI footguns.
- **Async component execution** — The host uses Wasmtime's async support (`wasm_config.async_support(true)`) and `tokio::sync::RwLock` for all shared state, ensuring non-blocking access patterns across concurrent Wasm component invocations.

#### Compile-Time Feature Gates (Open-Core Boundary)

Enterprise-only components are gated behind Cargo feature flags at compile time — not runtime checks:

```rust
#[cfg(feature = "messaging")]
let (messaging_cmd_tx, messaging_cmd_rx) = mpsc::channel(100);
#[cfg(not(feature = "messaging"))]
let (messaging_cmd_tx, _messaging_cmd_rx) = mpsc::channel::<IncomingMessage>(1);
```

This means the Community Edition binary physically cannot execute enterprise code paths. Zero-overhead separation, zero risk of accidental exposure.

#### Component Registration

Components are registered in `config/components.toml` and loaded per-edition:

```toml
[[components]]
name = "ssi_vault"
path = "target/wasm32-wasip2/release/ssi_vault.wasm"
required = true

[[components]]
name = "acl_store"
path = "target/wasm32-wasip2/release/acl_store.wasm"
required = true
```

The Host validates all required components are present at startup and panics with a clear diagnostic if any are missing — no silent degradation.

This is the same architecture direction the WASI ecosystem is converging on. Trust Gateway is built on it today.

### The Gateway: Policy + Cryptographic Execution Grants

Every proposed action flows through the gateway's governance pipeline:

**1. Policy Engine** — Priority-ordered TOML rules evaluated deterministically. No model involved in the policy decision. The LLM proposes; the gateway decides.

```toml
[[rules]]
name = "protect_financial_ops"
match_source_type = "external_swarm"
match_operation = ["transfer", "delete"]
effect = "require_approval"
tier = "tier1"

[[rules]]
name = "block_bulk_comms"
match_source_type = "internal_agent"
match_operation = ["email.send_bulk"]
effect = "deny"
```

**2. Execution Grants** — When an action is approved, the gateway issues a short-lived (30s), cryptographically signed JWT scoped to that specific action. Executors validate the grant before running anything. No valid grant = no execution, even with direct network access to an executor.

Grant signing supports two modes:
- **Ed25519** (preferred): set `GRANT_SIGNING_KEY_PATH`. Private key stays in the gateway; executors only need the public key.
- **HMAC-SHA256** (fallback): symmetric shared secret via `JWT_SECRET`.

The gateway refuses to start with a known dev secret outside of `LIANXI_ENV=development` — a hard guard against accidental production misconfiguration.

**3. Human-in-the-Loop** — High-risk operations are interrupted for manual approval. The agent waits. A named human operator reviews a plain-language summary and approves or denies. The approval event is logged with the approver's identity. This is a first-class primitive, not an afterthought.

**4. Audit Trail** — Every step — proposal received, policy evaluated, grant issued, execution result, human approval — is written to a durable NATS JetStream stream with 90-day retention. An audit projector builds queryable timelines from the event log. The record answers: *what did the agent try to do, what did the gateway permit, who approved it, and what was the outcome?*

**5. Circuit Breakers** — Per-connector circuit breakers (5-failure threshold, 30s recovery window) prevent a degraded downstream service from cascading into gateway failures.

### Transport Normalizer

The gateway speaks three transports natively:

- **MCP over SSE** at `/v1/mcp/sse` — the recommended integration path for any MCP-compatible agent
- **HTTP REST** at `/v1/actions/propose`
- **NATS** subject `mcp.v1.dispatch.>` for backward compatibility

All three paths flow through the same governance pipeline.

### "The Claw" — Native Skill Execution

The `native_skill_executor` runs operator-deployed scripts as bounded OS subprocesses:

```
TRUST GATEWAY
  └── issues ExecutionGrant JWT
        │
        ▼
NATIVE SKILL EXECUTOR
  1. Validates HMAC ExecutionGrant
  2. Resolves skill_id → script path
     ✓ Interpreter allow-list (bash, python3, node, deno, ruby)
     ✓ Path traversal prevention (canonicalized paths)
  3. env_clear() — no inherited env vars
     Only PATH, HOME + manifest-declared vars injected
  4. Bounded timeout (30s default)
  5. Captures stdout/stderr → JSON result
```

> **Community edition**: OS process isolation. 
> **Enterprise edition**: Wasm sandboxed execution for fully untrusted skill code.

---

## Quick Start

### Prerequisites

- **Rust** 1.75+
- **Wasmtime** 25+ with Component Model support (`cargo install wasmtime-cli`) 
- **target wasm32-wasip2 , to build wasm components** (`rustup target add wasm32-wasip2` )
- **NATS Server** with JetStream: `nats-server -js`
- **Trunk** for the Web UI: `cargo install --locked trunk`

### Run

```bash
git clone https://github.com/fcn06/trust_gateway.git
cd trust_gateway
make build
./start_dev.sh
```

The `start_dev.sh` script auto-generates a random `JWT_SECRET` if one is not set in `.env`.

Once running, open the **Local SSI Portal** at **[http://localhost:8080/](http://localhost:8080/)** — a WebAuthn-authenticated web interface for identity management, messaging, agent interaction, and approval workflows.

### Verify

```bash
# List available tools
curl http://localhost:3060/v1/tools/list

# Propose an action (REST path)
curl -X POST http://localhost:3060/v1/actions/propose \
  -H "Authorization: Bearer <your_session_jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "action_name": "google.calendar.event.create",
    "arguments": { "summary": "Strategy Meeting", "start": "2025-09-01T10:00:00Z" }
  }'

# MCP path — connect your agent to:
# http://localhost:3060/v1/mcp/sse
```

---

## Configuration

### Policy (`config/policy.toml`)

Rules are evaluated in priority order (lowest number = highest priority). Three possible outcomes per rule: `allow`, `require_approval`, `deny`.

```toml
[[rules]]
name = "allow_read_ops"
match_operation = ["read", "list", "search"]
effect = "allow"
priority = 10

[[rules]]
name = "protect_financial_ops"
match_source_type = "external_swarm"
match_operation = ["transfer", "delete", "refund"]
effect = "require_approval"
tier = "tier1"
priority = 20

[[rules]]
name = "deny_bulk_external"
match_operation = ["email.send_bulk", "sms.send_bulk"]
effect = "deny"
priority = 30
```

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `JWT_SECRET` | Yes | Shared HMAC secret for execution grants (dev fallback) |
| `GRANT_SIGNING_KEY_PATH` | No | Path to Ed25519 PEM private key (recommended for production) |
| `GRANT_SIGNING_KEY_ID` | No | Key ID for the Ed25519 key (default: `gateway-ed25519-1`) |
| `NATS_URL` | No | NATS server URL (default: `nats://127.0.0.1:4222`) |
| `LIANXI_ENV` | No | Set to `production` to enforce non-dev secret guard |
| `ALLOWED_ORIGINS` | No | Comma-separated CORS allow-list |
| `ENABLE_HOT_RELOAD` | No | Set to `1` to enable tool registry hot-reload via NATS |

---

## Repository Structure

```
trust_gateway/
├── execution_plane/
│   ├── trust_gateway/          # The gateway — policy engine, grant issuance, audit
│   └── shared_libs/
│       ├── trust_core/         # Shared traits: AuditSink, ApprovalStore, GrantIssuer
│       ├── trust_policy/       # TOML policy engine
│       ├── identity_context/   # JWT + DID identity resolution
│       └── ssi_mcp_runtime/    # MCP transport runtime
├── agent_in_a_box/
│   └── host/                   # Wasm Component Model host — WebAuthn, SSI vault, ACL
├── portals/
│   └── local_ssi_portal/       # Web UI (Trunk/WASM frontend)
└── platform/                   # Connector implementations
```

---

## Technology Stack

| Layer | Technology | Why |
|---|---|---|
| Language | Rust | Memory safety for a security-critical gateway |
| Async runtime | Tokio + `tokio::sync::RwLock` | Non-blocking async I/O; RwLock prevents deadlocks under concurrent load |
| HTTP framework | Axum 0.7 | Ergonomic, tower-compatible |
| HTTP client | reqwest (rustls backend) | Pure-Rust TLS — no OpenSSL/C-library attack surface |
| Messaging | NATS + JetStream | Durable audit, fan-out, KV store — without Kafka overhead |
| Wasm runtime | Wasmtime (Component Model) | Sandboxed identity/crypto primitives via WIT interfaces |
| JWT | jwt-simple (pure-rust) | No OpenSSL dependency |
| Identity | WebAuthn / webauthn-rs | Production FIDO2 — no mock auth |
| MCP | rmcp 1.3 | Native MCP over SSE |
| Shutdown | tokio-util CancellationToken | Deterministic task cancellation and NATS flush on shutdown |

---

## Community vs. Enterprise

| Feature | Community | Enterprise |
|---|---|---|
| Policy engine (Allow/Deny/Approve) | ✅ | ✅ |
| Ed25519 execution grants | ✅ | ✅ |
| Human-in-the-loop approvals | ✅ | ✅ |
| JetStream audit trail (90 days) | ✅ | ✅ |
| WebAuthn / FIDO2 identity | ✅ | ✅ |
| MCP + HTTP + NATS transports | ✅ | ✅ |
| Circuit breakers per connector | ✅ | ✅ |
| OS process isolation (The Claw) | ✅ | ✅ |
| Wasm sandboxed skill execution | ❌ | ✅ |
| Multi-tenancy | ❌ | ✅ |
| Attribute-based policy (ABAC) | ❌ | ✅ |
| Enterprise support | ❌ | ✅ |

---

## Contributing

The project is at an early but technically substantive stage. Contributions are welcome, particularly in these areas:

- **Asymmetric JWT nonce store** — JTI replay prevention within the 30s execution grant window
- **Policy expression language** — attribute-based contextual rules (time-of-day, value thresholds)
- **CI pipeline** — `cargo test` + `cargo clippy` on push
- **Docker Compose** — single-command dev environment including NATS
- **Integration tests** — end-to-end propose → evaluate → execute flow

Please open an issue before starting significant work so we can discuss approach.

---

## License

Apache 2.0 — use it, build on it, contribute back.

---

*Enterprise edition in preparation. Feedback and early enterprise interest welcome via GitHub Issues.*