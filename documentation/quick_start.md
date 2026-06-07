
## Quick Start Guide

Get the Trust Gateway running and your first agent connected in under 5 minutes.

### Prerequisites

- **Rust** 1.75+ (`rustup` recommended)
- **Wasm targets**: `rustup target add wasm32-wasip2 wasm32-unknown-unknown`
- **Wasm Component Tooling**: `cargo install cargo-component`
- **Wasmtime** — consumed as the `wasmtime` Rust crate (no separate binary install needed)
- **NATS Server** with JetStream: `nats-server -js`
- **Trunk** for the Web UI: `cargo install --locked trunk`

> **Tip:** A single-command Docker Compose setup (NATS included)
> is on the roadmap. Star the repo to be notified.

### Build & Run

```bash
git clone https://github.com/fcn06/trust_gateway.git
cd trust_gateway
make build
./start_dev.sh
```

The `start_dev.sh` script auto-generates a random `JWT_SECRET` if one is not set in `.env`.

Once running, open the **Local SSI Portal** at **[http://localhost:8080/](http://localhost:8080/)** — a WebAuthn-authenticated web interface for identity management, agent interaction, and approval workflows. Once logged in, through developer console, you can get a JWT token, that you can use to interact with the gateway.

### Infrastructure Dashboard

| Service / Interface | Local Address | Purpose |
| :--- | :--- | :--- |
| **Portal (Web UI)** | `http://localhost:8080` | Real-time reactive approval feed |
| **Trust Gateway** | `localhost:3060` | Central policy engine and grant signing service |
| **Agent Host** | `localhost:3000` | Sovereign host managing WebAuthn and identities |
| **NATS JetStream** | `localhost:4222` | Secure asynchronous messaging bus |
| **NATS WebSocket Bridge** | `localhost:9222` | Real-time UI updates bridge |

Point any MCP-compatible agent at: `nats://localhost:4222` or `http://localhost:3060/v1/mcp/sse`

### Verify

```bash
# Check the gateway is up
curl http://localhost:3060/health

# List available tools
curl http://localhost:3060/v1/tools/list

# Propose an action (REST path - non-escalated example)
curl -X POST http://localhost:3060/v1/actions/propose \
  -H "Authorization: Bearer <your_session_jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "action_name": "claw_weather",
    "arguments": { "location": "Paris" }
  }'

# http://localhost:3060/v1/mcp/sse
```

### Production Warning

The gateway **panics at startup** if `LIANXI_ENV` is not `development` and no Ed25519 key is configured. This is intentional — it prevents accidental deployment with insecure symmetric keys.

### Next Steps

- [Interactive Walkthrough](interactive_walkthrough.md) — See the approval flow end-to-end
- [Configuration Reference](configuration.md) — Policy rules and environment variables
- [Telegram Integration Guide](telegram_integration.md) — Mobile push notifications for approvals
