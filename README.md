# **Sovereign AI Governance Infrastructure (Community Edition)**

**Let AI agents operate business tools without losing control.**

The **Trust Gateway** is the execution control plane for the agentic era. It sits between AI agents (internal or external swarms) and your business systems (Google Workspace, Stripe, Shopify, MCP tools). It solves the "Blast Radius" problem by enforcing policy, requiring human approval for risky actions, and maintaining a tamper-evident audit trail.

---

## **🛡️ Why Trust Gateway?**

Existing security frameworks are designed for humans or static service accounts. They don’t account for the **autonomous gap**.

* **The Problem:** LLMs can hallucinate tool parameters or over-reach their authority.  
* **The Solution:** A deterministic pipeline that treats every agentic intent as a **Proposed Action** until it clears a cryptographic hurdle.

---

## **✨ Key Features**

| Feature | Description |
| :---- | :---- |
| **Policy Engine** | Priority-ordered, TOML-based rules (Allow, Require Approval, Deny). |
| **Execution Grants** | Short-lived (30s), scoped JWTs that follow Zero Trust principles. |
| **Human-in-the-Loop** | Interrupts risky calls with **Plain-Language Diffs** for manual approval. |
| **The Claw Method** | High-performance, isolated OS process execution for local scripts. |
| **Transport Normalizer** | Unified handling of HTTP, NATS, and MCP tool calls. |
| **Standalone Registry** | Autonomous tool discovery from connectors and native skills. |

---

## **🏗️ Architecture: The Execution Chain**

The Trust Gateway decouples **intelligence** (the LLM) from **capability** (the Tools) via a secure governance layer.

Plaintext  
User Intent → Host Orchestrator → Execution Orchestrator → TRUST GATEWAY → Specialized Executors

### **1. The Decision Point (Port 3060)**

The Gateway evaluates the policy.toml and extracts identity context from incoming _meta payloads. It doesn't just route; it **validates authority**.

### **2. "The Claw" (Native Skill Execution)**

The native_skill_executor (Port 3070) spawns bounded, isolated sub-processes. It’s a "bring your own script" model for AI capabilities.

---

## **🚀 Quick Start**

### **Prerequisites**

* **Rust** 1.75+  
* **NATS Server** (with JetStream enabled: nats-server -js)  
* **Trunk** (for the Web UI: cargo install --locked trunk)

### **Setup**
```bash
# Clone and build  
git clone https://github.com/fcn06/trust_gateway.git  
cd trust_gateway  
make build

# Start the full stack (Gateway, Host, Executors)  
./start_dev.sh
```
---

## **⚙️ Configuration**

The Gateway is configured via config/policy.toml. Rules are evaluated in priority order (lowest number first).

```toml
[[rules]]  
name = "protect_financial_ops"  
match_source_type = "external_swarm"  
match_operation = ["transfer", "delete"]  
effect = "require_approval"  
tier = "tier1"
```

### **Critical Environment Variables**

* JWT_SECRET: Shared secret used to sign **Execution Grants**. If an executor receives a call without a valid HMAC signature from this secret, it refuses to run.  
* NATS_URL: The backbone for real-time audit logs and approval requests.

---

## **🤝 Community vs. Professional**

This repository contains the **Open-Core Community Edition**. It provides the full execution loop, Trust Gateway, and WebAuthn identity system.

For enterprise-grade messaging (**OpenMLS**), managed P2P transit (**Twin Mediator**), and advanced contact enrichment, check out our [Professional Tier](https://lianxi.io/).

---

## **📜 License**

Licensed under the **Apache License 2.0**. Use it, build on it, and help us make AI execution safe for everyone.

