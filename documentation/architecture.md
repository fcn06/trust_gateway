
## Architecture

The gateway decouples **intelligence** (the LLM) from **capability** (the tools) via a governance layer that cannot be bypassed:

```
User Intent
    │
    ▼
Host Orchestrator  ←── WebAuthn / DID identity
    │
    ▼
Execution Orchestrator (ssi_agent + McpAgent / External Swarm)
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
│  6. JTI replay prevention           │
└──────────────┬──────────────────────┘
               │  Signed ExecutionGrant
               ▼
     Specialized Executors
     (MCP connectors / Claw skills / VP MCP server)
```

The **internal agent** (`ssi_identity_agent`) delegates tool management to `ssi_mcp_runtime::McpAgent`, which runs the full LLM tool loop (Thinking → Executing → Evaluating). McpAgent dispatches **all** tool calls through NATS (`mcp.v1.dispatch.*`), meaning every invocation is intercepted by the Trust Gateway for policy evaluation, grant issuance, and audit — before any executor receives the request.

The **VP MCP server** and **connector MCP server** are **pure executors** — they authenticate requests and run tools but have no governance or escalation logic. All approval decisions happen upstream in the Trust Gateway.

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
- **Ed25519** (preferred): set `GRANT_SIGNING_KEY_PATH`. Private key stays in the gateway; executors only need the public key — they cannot mint grants.
- **HMAC-SHA256** (fallback): symmetric shared secret via `JWT_SECRET`.

Each grant carries a unique `grant_id` (JWT `jti` claim). Executors enforce **consume-once semantics** via a `NonceStore` — a replayed grant is rejected even within its 30s TTL. Replay attempts are logged as `GrantReplayBlocked` audit events.

The gateway refuses to start with a known dev secret outside of `LIANXI_ENV=development` — a hard guard against accidental production misconfiguration.

**3. Human-in-the-Loop** — High-risk operations are interrupted for manual approval. The agent waits. A named human operator reviews a plain-language summary and approves or denies. The approval event is logged with the approver's identity. This is a first-class primitive, not an afterthought.

**4. Audit Trail** — Every step — proposal received, policy evaluated, grant issued, execution result, human approval, replay blocked — is written to a durable NATS JetStream stream with 90-day retention. A unified **UI Projector** consumes these raw events, sanitizes sensitive fields (e.g. credentials, internal hashes), and publishes them directly to tenant-scoped `ui.v1.<tenant>.events` subjects. This flattened architecture eliminates redundant intermediate broadcast subjects and enables "WebSocket-only" data flow in the Portal without HTTP polling fallbacks.

The gateway uses deterministic graceful shutdown (`CancellationToken` + `TaskTracker`) with a final `nc.flush().await` to guarantee audit events are never lost — even during deployments or restarts.

**5. Circuit Breakers** — Per-connector circuit breakers (5-failure threshold, 30s recovery window) prevent a degraded downstream service from cascading into gateway failures.

### Transport Normalizer

The gateway speaks three transports natively:

- **MCP over SSE** at `/v1/mcp/sse` — the recommended integration path for any MCP-compatible agent
- **HTTP REST** at `/v1/actions/propose`
- **NATS** subject `mcp.v1.dispatch.>` for internal orchestration

All three paths flow through the same governance pipeline. No transport gets a shortcut.

### "The Claw" — Native Skill Execution

The `native_skill_executor` runs operator-deployed scripts as bounded OS subprocesses:

```
TRUST GATEWAY
  └── issues ExecutionGrant JWT (Ed25519 or HMAC)
        │
        ▼
NATIVE SKILL EXECUTOR
  1. Validates ExecutionGrant (signature + expiry + JTI nonce)
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

#### Isolation Controls

| Control | Implementation |
| :--- | :--- |
| **Environment isolation** | `env_clear()` — scripts cannot read `JWT_SECRET`, `NATS_URL`, or any service secrets |
| **Process isolation** | `setsid` + `RLIMIT_AS` (512MB memory cap) |
| **Interpreter allow-list** | `bash`, `sh`, `python3`, `node`, `deno`, `ruby` only |
| **Path traversal prevention** | Script paths canonicalized and verified within skill directory |
| **Execution grant** | Every invocation requires a valid ExecutionGrant — no bypass |
| **JTI replay prevention** | JetStream `NonceStore` enforces single-use semantics |
| **Timeout** | Killed after `EXEC_TIMEOUT` seconds (default: 30s) |

Skills can be added or hot-reloaded at runtime. The agent picks them up via `claw.v1.skills.changed` NATS events without a gateway restart.

### Real-Time UI

The portal connects to the NATS WebSocket bridge (port 9222) and subscribes to `ui.v1.<tenant>.events`. All audit events are PII-scrubbed before delivery — the browser never receives credentials or internal identifiers.

The activity feed and Validation Center update instantly on any system event. No polling. Reconnection uses exponential backoff (up to 32s) and auto-fetches missed state on recovery.

### Two-Server Production Topology

The system uses a physical two-server topology in production: a clean public ingress node (no credentials, no user data) peers with a sovereign backend node over NATS Leaf Node on port 7422. All private KV stores (`acl`, `ssi_vault`, `approvals`, `grant_nonces`) reside exclusively on the sovereign node. No cryptographic keys are ever copied between servers during setup.

## Technology Stack

| Layer | Technology | Why |
|---|---|---|
| Language | Rust | Memory safety for a security-critical gateway |
| Async runtime | Tokio + `tokio::sync::RwLock` | Non-blocking async I/O; RwLock prevents deadlocks under concurrent load |
| HTTP framework | Axum 0.7 | Ergonomic, tower-compatible |
| HTTP client | reqwest (rustls backend) | Pure-Rust TLS — no OpenSSL/C-library attack surface |
| Messaging | NATS + JetStream | Durable audit, fan-out, KV store — without Kafka overhead |
| Wasm runtime | Wasmtime (Component Model) | Sandboxed identity/crypto primitives via WIT interfaces |
| JWT | jwt-simple (pure-rust) | Ed25519 + HMAC-SHA256 grant signing, no C dependencies |
| Identity | WebAuthn / webauthn-rs | Production FIDO2 — no mock auth |
| MCP | rmcp 1.3 | Native MCP over SSE |
| Shutdown | tokio-util CancellationToken | Deterministic task cancellation and NATS flush on shutdown |
