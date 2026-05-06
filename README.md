## **AI Agents Trust Gateway — Community Edition**

**The governance layer between AI reasoning and real-world execution.**

Most AI safety work tries to make models better. Trust Gateway takes a different approach: **separate the intelligence from the capability entirely.**

Your AI agent proposes actions. Trust Gateway decides whether they execute — cryptographically, deterministically, with a human in the loop when the stakes require it. The model cannot bypass this. Even if it hallucinates a dangerous command, it lacks the cryptographic authority to make it happen.

AI Agent → PROPOSES intent → Trust Gateway → evaluates policy → EXECUTES (or blocks)

This matters especially when the AI brain and the business tools come from *different companies*. Trust Gateway lets you expose your tools to the world while retaining complete control over how they're used.

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue)](LICENSE)
[![NATS](https://img.shields.io/badge/NATS-JetStream-green?logo=nats.io)](https://nats.io)
[![MCP](https://img.shields.io/badge/MCP-SSE%20%2B%20Streamable-purple)](https://modelcontextprotocol.io)
[![Quick Start](https://img.shields.io/badge/Quick%20Start-3%20commands-brightgreen)](#zero-to-running--3-commands)

---

**Show your support!**  
If you find this project useful, please consider giving it a ⭐ on GitHub! It helps more developers discover the control plane for the agentic era.

---

### **Zero to Running — 3 commands**

Requires: Rust 1.75+, NATS Server with JetStream, Trunk

bash  
git clone https://github.com/fcn06/trust\_gateway.git  
cd trust\_gateway  
make build && ./start\_dev.sh

Open [http://localhost:8080](http://localhost:8080) — governance portal is live.

| Component | Address |
| ----- | ----- |
| Portal (Web UI) | `localhost:8080` |
| Trust Gateway | `localhost:3060` |
| NATS JetStream | `localhost:4222` |

Point any MCP-compatible agent at: `http://localhost:3060/v1/mcp/sse`

---

### **The Core Problems It Solves**

**1\. Agent actions with real consequences** Your agent just called a payment API with hallucinated parameters. Or deleted records that downstream systems depend on. This isn't a model quality problem — it's an architecture problem. Trust Gateway inserts a deterministic policy layer that no model can bypass.

**2\. Async workflows over MCP** MCP is designed as request/response. Real business processes aren't. Connecting a 3-minute data pipeline or a multi-step approval workflow to an AI agent via MCP requires brittle polling hacks — unless you have a durable messaging backbone. Trust Gateway's NATS JetStream layer handles async natively, without orchestration overhead.

**3\. Identity that scales with your integrations** Trust Gateway uses OAuth2 \+ WebAuthn today — the same standards your stack already relies on. No new infrastructure required to get started.

For B2B tool sharing, this matters beyond convenience: OAuth2 requires Company A to create an account at Company B for every integration — an O(N²) problem as your agent ecosystem grows. Trust Gateway's architecture supports SSI-based identity (DID/WebAuthn) as an upgrade path, collapsing this to O(N): each company maintains one identity, recognized across all integrations seamlessly.

---

### **How It Works**

Think of it as a **Notary Public** for AI actions. An agent can draft a contract (a tool call), but cannot sign it. Only the Gateway has the cryptographic stamp to validate intent and authorize execution.

Every proposed action flows through:

1. **Policy evaluation** — deterministic TOML rules, no model involved in the decision  
2. **Human approval** (when required) — the agent waits; a named human reviews and approves  
3. **Cryptographic execution grant** — short-lived Ed25519 JWT, scoped to the specific action, consume-once (JTI nonce store prevents replay)  
4. **Audit trail** — every step written to durable JetStream, 90-day retention


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

```

---

### **Key Properties**

| Property | Approach |
| ----- | ----- |
| Replay prevention | JTI nonce store — each grant consumed exactly once |
| Identity | WebAuthn/FIDO2 passkeys \+ DID (no mock auth) |
| Audit | Durable NATS JetStream, replayable event trail |
| Async workflows | Native JetStream — no polling, no orchestration hacks |
| Skill isolation | OS process sandboxing (Wasm in Enterprise) |
| No silent failures | Misconfigurations crash at startup, not runtime |

---

### **Documentation**

* [Quick Start](documentation/quick_start.md)
* [Full Architecture](documentation/architecture.md)
* [Configuration Reference](documentation/configuration.md)
* [High Level Flow](documentation/high_level_flow.md)  
* [Interactive Walkthrough](documentation/interactive_walkthrough.md)  
* [Community Vs Entreprise](documentation/community_vs_entreprise.md)  

---

### **Contributing**

Early stage, technically substantive. Most wanted: Docker Compose setup, CI pipeline, policy language extensions, integration tests. Open an issue before significant work.

### **License**

Apache 2.0

---

*Enterprise edition in preparation. Early interest welcome via GitHub Issues.*
