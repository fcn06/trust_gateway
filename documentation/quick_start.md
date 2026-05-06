
## Full Configuration Reference

### Prerequisites

- **Rust** 1.75+ (`rustup` recommended)
- **Wasmtime** — consumed as the `wasmtime` Rust crate (no separate binary install needed)
- **Wasm target**: `rustup target add wasm32-wasip2`
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

# MCP path — connect your agent to:
# http://localhost:3060/v1/mcp/sse
```
