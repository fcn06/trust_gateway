# Sovereign AI Governance Infrastructure — Community Edition

### Let AI agents operate business tools without losing control.

Trust Gateway sits between agents and systems like Google Workspace, Stripe, Shopify, internal APIs, and MCP tools. It enforces policy, requests human approval for risky actions, and records every action in a replayable audit trail.

The Trust Gateway is a policy-driven control plane that governs how AI agents interact with the real world. Every tool call flows through a deterministic pipeline:

```
Assess → Decide → Approve → Grant → Route → Audit
```

## Three Pillars

1.  **Control** — least-privilege execution, policy tiers, step-up verification.
2.  **Trust** — human approval for sensitive actions, plain-language diffs, full replay.
3.  **Execution** — works across MCP tools, OAuth apps, native skills, and external swarms.

> “Trust Gateway lets enterprises put AI agents into production safely by enforcing policy, approvals, delegated identity, and replayable audit across MCP tools and business systems.”

## What It Does

- **Policy Engine** — TOML-based rules evaluate every action request against attributes (operation kind, amount, source type, category).
- **Agent Registry** — Maintain a durable record for each agent or swarm source. Every agent is identifiable, attributed to an owner, and can be instantly revoked.
- **Execution Grants** — Narrow, short-lived JWT tokens replace broad session permissions for connector execution, following Zero Trust principles.
- **Human-in-the-Loop** — Seamlessly interrupt risky actions for human approval, with plain-language diffs and the ability to resume or reject actions in real-time.
- **Audit Trail** — Tamper-evident, replayable event stream showing the full lineage from human → agent → action for compliance and forensics.
- **Multi-Transport Normalization** — Uniformly govern actions across MCP, native skills, and custom API connectors.
- **Multi-Tenant** — Full tenant isolation with separate policy configurations, built for enterprise-grade security.

## Why Trust Gateway?

Existing security frameworks do not fully account for autonomous agents. They need explicit oversight, identity, and control mechanisms. Trust Gateway addresses the "Blast Radius" problem by ensuring that while your AI can analyze, it can only act within safe, predefined boundaries. It bridges the gap between agentic autonomy and corporate compliance.

## Architecture

Lianxi.io is designed as an **AI Action Gateway** and execution control plane. It decouples the intelligence (Agent) from the capability (Tools) via a secure governance layer.

```
agent_in_a_box/     — Secure host orchestrator (WebAuthn) + sandboxed WASM runtime
execution_plane/    — Trust Gateway, policy engine, and connectors
  trust_gateway/    — Central policy enforcement and decision point
  shared_libs/      — Core traits (trust_core) and identity context
agents/             — SSI Agent (MCP runtime) providing decentralized identity
```

### Trust Policy Engine (`policy.toml`)

An attribute-based, priority-ordered rules engine evaluated by the Trust Gateway. Rules are evaluated in priority order. With external extensions, `match_source_type` boundaries filter explicit external swarm logic:

```toml
[[rules]]
name = "external_swarm_require_approval"
match_source_type = "external_swarm"
match_operation = ["create", "update", "delete", "transfer"]
effect = "require_approval"
tier = "tier1"
```

### Native Skill Execution Flow ("The Claw Method")

This details how the `native_skill_executor` locally processes requests from the Gateway by spawning bounded, isolated CLI actions:

```text
┌─────────────────────────────────────────────────────┐  
│               TRUST GATEWAY (port 3060)             │  
│  Validates Request & issues ExecutionGrant JWT      │  
└────────────────────┬────────────────────────────────┘  
                     │ HTTP POST /invoke
                     │ Payload: { skill_id, args, token }
┌────────────────────▼────────────────────────────────┐  
│         NATIVE SKILL EXECUTOR (port 3070)           │  
│                                                     │  
│  1. Token Validation: Checks HMAC ExecutionGrant    │  
│  2. Registry Lookup: Matches `skill_id` to path     │  
│  3. Env Setup: Injects bounded environment vars     │  
│                                                     │  
│  ┌─────────────────────────────────────────────────────┐  │  
│  │ Local `/skills/` Configuration Map                  │  │  
│  │                                                     │  │  
│  │ ├── /claw_extract_content_from_url/                 │  │  
│  │ │    ├── manifest.json (LLM schema)                 │  │  
│  │ │    └── run.sh (POST to parsejet.com)              │  │  
│  │ │                                                   │  │  
│  │ └── /claw_weather/                                  │  │  
│  │      ├── manifest.json                              │  │  
│  │      └── run.sh (Bash Script)                       │  │  
│  └───────────────────────┬─────────────────────────────┘  │  
│                          │ `tokio::process::Command`      │  
│  ┌───────────────────────▼─────────────────────────────┐  │  
│  │    ISOLATED OS PROCESS (Subprocess Spawn)           │  │  
│  │  - Receives: `args` via command line/stdin          │  │  
│  │  - Runs: e.g., `bash run.sh <args>`                 │  │  
│  │  - Captures: `stdout` and `stderr`                  │  │  
│  └───────────────────────┬─────────────────────────────┘  │  
└──────────────────────────┼────────────────────────────────┘  
                           │ Raw JSON Output Result returned
                           ▼
```

## Quick Start

```bash
# Prerequisites: Rust 1.75+, wasm32-unknown-unknown target, Trunk, NATS server (nats-server -js)
# cargo install --locked trunk
# rustup target add wasm32-unknown-unknown

make
./start_dev.sh
```

## Building

```bash
# Build all
make build

# Run tests
make test
```

## Configuration

The gateway is configured via environment variables and CLI flags:

| Variable | Default | Description |
|----------|---------|-------------|
| `NATS_URL` | `nats://127.0.0.1:4222` | NATS server URL |
| `GATEWAY_LISTEN` | `0.0.0.0:3060` | HTTP listen address |
| `POLICY_PATH` | `config/policy.toml` | Policy TOML file path |
| `JWT_SECRET` | — | Shared signing secret |
| `CONNECTOR_MCP_URL` | `http://127.0.0.1:3050` | Connector MCP server |
| `SKILL_EXECUTOR_URL` | `http://127.0.0.1:3070` | Native skill executor |

## Example Usage

You can propose an action directly to the Trust Gateway API (e.g., retrieving weather information via `picoclaw`):

```bash
curl -X POST http://127.0.0.1:3060/v1/actions/propose \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_SESSION_JWT>" \
  -d '{
    "action_name": "claw_weather",
    "source_type": "picoclaw",
    "arguments": {
      "location": "Nice"
    }
  }'
```

## Security note: The `JWT_SECRET`

The `JWT_SECRET` is the shared signing secret used by the execution plane to secure operations. Specifically:
- **Minting**: When a tool call request successfully clears the Policy Engine (or is manually approved by a human), the **Trust Gateway** mints an `ExecutionGrant` JWT indicating the action is approved. It signs this grant using HMAC-SHA256 and the `JWT_SECRET`.
- **Validation**: The Trust Gateway passes this token downstream to executors (such as the `connector_mcp_server` and `native_skill_executor`). These executors read the exact same `JWT_SECRET` to verify the HMAC signature before authorizing the actual execution.

This process enables a Zero Trust execution environment where downstream components cryptographically verify that the Trust Gateway explicitly authorized all sensitive operations.

## License

Apache License 2.0.
