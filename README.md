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
* **Wasmtime**
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

### **Native Skill Execution Flow ("The Claw Method")**

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


## **🤝 Community vs. Professional**

This repository contains the **Open-Core Community Edition**. It provides the full execution loop, Trust Gateway, and WebAuthn identity system.

Enterprise-grade solution in preparation.

---

## **📜 License**

Licensed under the **Apache License 2.0**. Use it, build on it, and help us make AI execution safe for everyone.

