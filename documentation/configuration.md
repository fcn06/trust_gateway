
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
lianxi-community/
├── execution_plane/
│   ├── trust_gateway/            # Policy engine, grant issuance, audit, graceful shutdown
│   ├── native_skill_executor/    # "The Claw" — OS process skill runner + JTI nonce store
│   ├── connector_mcp_server/     # OAuth2 MCP connector (Google, Stripe, Shopify)
│   └── shared_libs/
│       ├── trust_core/           # Domain types: ExecutionGrant, NonceStore, AuditEvent
│       ├── trust_policy/         # TOML policy engine
│       └── identity_context/     # JWT + DID identity resolution
├── agent_in_a_box/
│   └── host/                     # Wasm Component Model host — WebAuthn, SSI vault, ACL
├── agents/
│   └── ssi_agent/                # A2A agent with MCP runtime
├── portals/
│   └── local_ssi_portal/         # Web UI — Trunk/WASM frontend (port 8080)
└── platform/                     # Infrastructure (tenant registry, public gateway)
```
