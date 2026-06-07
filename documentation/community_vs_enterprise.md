
## Community vs. Enterprise

| Feature | Community | Enterprise |
|---|---|---|
| Policy engine (Allow/Deny/Approve) | ✅ | ✅ |
| Ed25519 + HMAC execution grants | ✅ | ✅ |
| JTI replay prevention (NonceStore) | ✅ | ✅ |
| Human-in-the-loop approvals | ✅ | ✅ |
| JetStream audit trail (90 days) | ✅ | ✅ |
| WebAuthn / FIDO2 identity | ✅ | ✅ |
| MCP + HTTP + NATS transports | ✅ | ✅ |
| Telegram Bot & Mobile Approval Flow | ❌ | ✅ |
| Circuit breakers per connector | ✅ | ✅ |
| Cron-based action scheduling | ✅ | ✅ |
| Inbound Webhook Governance | ✅ | ✅ |
| OS process isolation (The Claw) | ✅ | ✅ |
| Wasm sandboxed skill execution | ❌ | ✅ |
| Multi-tenancy | ❌ | ✅ |
| E2EE Group Messaging (OpenMLS) | ❌ | ✅ |
| Managed DID Transit (Mediator) | ❌ | ✅ |
| Attribute-based policy (ABAC) | ❌ | ✅ |
| EntraId / SSO support | ❌ | ✅ |
| Custom Branding & White-labeling | ❌ | ✅ |
| Standalone OAuth2 AS / OIDC Provider | ❌ | ✅ |

---

### Deep Dive: Enterprise Asynchronous & Encrypted Messaging

The Enterprise and Professional editions feature a fully sovereign, secure, and resilient messaging plane:

#### 1. OpenMLS (Messaging Layer Security)
- **Forward Secrecy:** If a session key is compromised, prior communications remain cryptographically secure.
- **Post-Compromise Security:** A compromise of a single node's state is automatically self-healed in subsequent epochs, locking out adversaries.
- **Dynamic Group Orchestration:** Perfect for elastic teams of human operators and autonomous agents negotiating high-stakes execution chains.

#### 2. Managed Twin Mediator & DID Transit
- **DIDComm Peering:** Point-to-point transit nodes route tool proposals and approvals without central third-party brokers.
- **High-Density Console:** Engineered for maximum operational density, resembling a WhatsApp-style UI with compacted bubble padding, minimizing whitespace and metadata lag for operators handling concurrent streams.
