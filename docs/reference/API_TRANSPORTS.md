# 📡 Available API Interfaces & Transports

`trust-gateway` provides multiple standardized API transports for seamless integration with AI agents, governance dashboards, and executor runtimes:

| Interface / Transport | Endpoint / Channel | Protocol & Description |
| :--- | :--- | :--- |
| **🔌 MCP (Model Context Protocol)** | `GET /v1/mcp/sse`<br/>`POST /v1/mcp/messages` | **MCP over HTTP SSE / Streamable**: Enables AI clients (Claude Desktop, Cursor, Custom LLM Agents) to dynamically discover governed tools (`tools/list`) and submit tool calls (`tools/call`). |
| **🌐 REST / HTTP API** | `POST /v1/actions/propose`<br/>`GET /v1/tools/list` | **Standard JSON REST API**: Direct HTTP endpoints for proposing actions, fetching tool definitions, and monitoring service health (`GET /health`). |
| **📨 A2A / NATS Event Protocol** | `trust.v1.*.action.propose`<br/>`trust.v1.*.tools.list` | **Agent-to-Agent Pub/Sub over NATS**: High-performance, decoupled event transport for async agent proposals and real-time JetStream audit streaming. |
| **👤 Human Approval API** | `GET /v1/approvals`<br/>`POST /v1/approvals/:id/decision` | **Human-in-the-Loop Governance**: API endpoints for administrative portals and human reviewers to list pending escalations and submit approval/denial decisions. |
| **🖥️ CLI Surface Adapter** | `trustctl tool list`<br/>`trustctl tool run <tool> [args...]` | **CLI Policy Enforcement Point (PEP)**: Dynamic JSON Schema-driven command-line interface (`adapters/surface-cli`) with automatic argument parsing, input hashing, and standardized exit codes (0, 1, 126, 127, 130). |
| **🔐 OAuth2 & OIDC Discovery** | `/.well-known/openid-configuration`<br/>`/.well-known/oauth-protected-resource` | **Identity & OAuth Proxy**: Standardized OpenID & OAuth2 metadata discovery endpoints for third-party connector authentication workflows. |

## Dispatch Modes

Trust Gateway supports two execution dispatch modes:

### Managed Dispatch (Production Default)

The Gateway dispatches `GrantedAction` payloads directly to the Executor Host via NATS subjects (`exec.v1.<tenant>.<profile>.invoke`). The agent never receives the `ExecutionGrant` JWT.

```
Agent → Gateway → Executor Host → Target API
```

### Portable Grant (REST / MCP Clients)

For REST and MCP integrations, the Gateway returns the `ExecutionGrant` JWT to the caller, who then presents it to the executor for verification and execution.

```
Agent → Gateway → Agent (receives grant) → Executor Host → Target API
```

> **Security Note on Portable Grants**:
> - **Zero SaaS Credentials**: Portable grants contain zero SaaS API keys, DB credentials, or standing authorities.
> - **Parameter Bound**: Grants are cryptographically bound to exact action parameters via SHA-256 `input_hash`. Tampering with any argument invalidates the grant.
> - **Short TTL & Single-Use**: Grants carry a short lifetime (e.g. 30-second TTL) and are strictly single-use (`jti` nonce tracking).
> - **Protected Executor Boundary**: Executors remain network-isolated and protected by their own transport authentication.
> - Managed dispatch remains the recommended default for high-security environments.

