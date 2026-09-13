# 🛡️ Trust Gateway

<p align="center">
  <img src="docs/illustrations/Trust_Gateway_Overall_1.png" alt="Trust Gateway Overall" width="80%">
</p>

[![Rust](https://img.shields.io/badge/Rust-1.89%2B-orange?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue)](LICENSE)
[![NATS](https://img.shields.io/badge/NATS-JetStream-green?logo=nats.io)](https://nats.io)
[![MCP](https://img.shields.io/badge/MCP-SSE%20%2B%20Streamable-purple)](https://modelcontextprotocol.io)
[![Whitepaper](https://img.shields.io/badge/Whitepaper-NICP%20Architecture-teal?logo=read-the-docs&logoColor=white)](whitepaper/b2b_agent_whitepaper.md)

> **Stop giving AI agents raw API keys. Trust Gateway is an Execution Firewall and Human-in-the-Loop gateway for AI tools.**

AI agents should be able to propose actions without automatically possessing the authority to execute them.

**Trust Gateway** sits between AI agents and the tools they want to call. Agents can request actions, but they never receive the credentials needed to execute them directly. The gateway evaluates each request against policy and, when allowed, issues a short-lived cryptographic grant that the executor verifies before performing the action.

Executors independently verify the grant and never rely on the agent's claim that an action was authorized.

> **"Agents propose. Gateway decides. Executors verify."**

> 📄 **New Reference Architecture (Sept 2026):** Read the whitepaper on [Interaction Contracts & Autonomous Reputation Lifecycle for B2B Agents (NICP)](whitepaper/b2b_agent_whitepaper.md).

---

## Simplified Architecture

```text
┌────────────┐       ProposedAction       ┌───────────────┐
│  AI Agent  │ ─────────────────────────▶ │ Trust Gateway │
└────────────┘                            └───────┬───────┘
                                                │
      No downstream credentials                 │ GrantedAction
                                                │ + ExecutionGrant
                                                ▼
                                        ┌───────────────┐
                                        │   Executor    │
                                        │ owns API keys │
                                        └───────┬───────┘
                                                │
                                                ▼
                                           Tools / Systems
```

The agent never receives the downstream credential. It submits a `ProposedAction` to Trust Gateway. If policy permits the action, the gateway issues an `ExecutionGrant` cryptographically bound to that exact tool and parameter set. The executor verifies the grant before using its own credential to perform the action.



---
## 🚀 Quickstart (Python SDK in \< 2 minutes)

Protect your AI agent's tool calls in 3 simple steps.

### 1. Clone & Start the Gateway

```bash
git clone https://github.com/fcn06/trust_gateway.git  
cd trust_gateway

# Spin up Trust Gateway & dependencies in local development mode  
docker compose -f deploy/docker-compose.yml up -d
```

### 2. Install the Python SDK
```bash
pip install -e sdks/python
```

### 3. Guard Your Tools (`quickstart.py`)

Create a script named `quickstart.py` (or run `python examples/python-agent/quickstart.py`):

```python
import os  
from trust_gateway.client import TrustGatewayClient, guard_tool

# Initialize client (automatically uses local development credentials)  
client = TrustGatewayClient.dev_mode(gateway_url="http://localhost:3060")

# 1. Guard a safe/read-only action (Auto-Allowed by Gateway)  
@guard_tool(client, "claw_hello_world")  
def say_hello(message: str):  
    return {"status": "ok", "message": f"Hello, {message}!"}

# 2. Guard a high-risk financial mutation (Requires Human Approval)
@guard_tool(client, "stripe_refund")  
def process_refund(amount: int, order_id: str):  
    return {"status": "refunded", "amount": amount}

if __name__ == "__main__":  
    print("--- 1. Testing Allowed Action ---")  
    result = say_hello(message="World")  
    print(f"✅ Executed: {result}\n")

    print("--- 2. Testing High-Risk Mutation ---")  
    try:   
        # Gateway intercepts the action because policy requires human confirmation
        process_refund(amount=500, order_id="ord_123")  
    except Exception as e:  
        print(f"🛑 EXECUTION NOT AUTHORIZED: {e}")
```

Run it:

```bash
python quickstart.py
```

```
--- 1. Testing Allowed Action ---  
✅ Executed: {'status': 'ok', 'message': 'Hello, World!'}

--- 2. Testing High-Risk Mutation ---  
⚠️  Decision: require_approval (Financial mutation requires human confirmation)  
🛑 EXECUTION NOT AUTHORIZED: Action 'stripe_refund' requires human approval before an ExecutionGrant is issued.
```

---

## Other Ways to Run Trust Gateway

### Docker Demo (No Rust toolchain required)

Build and run the standalone demonstration locally in Docker:

```bash
# 1. Build local container image (or run: make demo-docker)
docker build -t trust-gateway-demo -f deploy/Dockerfile.demo .

# 2. Run standard execution demo
docker run --rm trust-gateway-demo
```

### Source Build (Rust 1.89+)

Run the standalone quickstart demo directly from source:

```bash
# Prerequisites: Rust 1.89+, build-essential / xcode-select, libssl-dev
cargo run -p quickstart-standalone
```

### Governed CLI Invocation (`trustctl tool run`)

Run governed tools directly from the command line using the dynamic CLI Policy Enforcement Point (`adapters/surface-cli`):

```bash
# 1. List registered governed tools
cargo run -p trustctl -- tool list

# 2. Dynamic schema introspection
cargo run -p trustctl -- tool run claw_hello_world --help

# 3. Execute with dynamic arguments
cargo run -p trustctl -- tool run claw_hello_world --message "Hello from CLI"
```

### Autonomous Reputation & Contract Lifecycle Test (Pure Rust)

Execute the complete end-to-end cryptographic lifecycle in pure Rust without external network dependencies:

```bash
# Runs discovery, cold-start inspection, peer proof validation, proposal amendment,
# 9-step activation ceremony, grant dispatch, and ExecutionReceipt minting:
cargo run --bin agent_reputation_lifecycle
```

### Live Autonomous LLM Multi-Turn A2A Dialogue (Bash Client)

Run a realistic multi-turn Agent-to-Agent dialogue between an external Buyer Agent and a live `b2b_agent` powered by an LLM over HTTP JSON-RPC `tasks/send`:

```bash
# Requires local dev environment running (./start_dev.sh)
./../secure-collaboration-fabric/b2b_agent/examples/real_world_reputation_lifecycle_a2a.sh
```

---

## 📜 Protocol Sketch vs. Implementation

This project defines a working set of authorization contracts, independent in principle of any specific runtime:
* **Normative Schemas**: `ProposedAction` (with optional `CallChainContext`), `PolicyDecision`, `ExecutionGrant`, `GrantedAction`, `ExecutionResult`, `ExecutionReceipt`.
* **Layer 0 Call-Chain Guard**: Evaluated before attribute rules to defend against multi-agent runaway loops, infinite recursion, and frequency spikes (`max_depth = 10`, `allow_cycles = false`, `max_frequency_per_tool = 3`) with authoritative server-side session tracking.
* **Deterministic Contract Kernel (`trust-contract`)**: Pure aggregate enforcing RFC 8785 canonical JSON, SHA-256 fingerprinting, 10-state FSM, and a 9-step activation ceremony over mutual Ed25519 signatures.
* **Autonomous Reputation & Evidence Lifecycle**: Cold-start containment via local NATS KV `reputation_scores`, peer attestation verification against `trusted_peer_roots` anchors, and portable, signed `ExecutionReceipt` proofs returned upon `ActionSucceeded`.
* **Cognitive-to-Cryptographic MCP Tools**: 4 specialized lifecycle tools (`reputation_inspect_counterparty`, `contract_propose_or_amend`, `contract_verify_and_activate`, `receipt_present_and_store`) bridging semantic reasoning to control plane enforcement.
* **Canonicalization & Hashing**: Deterministic canonical JSON serialization with lexicographically sorted object keys followed by SHA-256 hashing (`input_hash`).
* **Verification Rules**: Ed25519 public key signature verification, nonce (`jti`) tracking intended to make grant reuse hard, and strict TTL expiration.
* **CLI Surface Adapter**: Dynamic Policy Enforcement Point (`adapters/surface-cli`) projecting native tool JSON Schemas into typed CLI commands with POSIX exit codes (0, 1, 126, 127, 130).

This repository is the only implementation right now — mine, in Rust — plus a Python SDK. "Protocol" here describes an internal design, not an externally reviewed or adopted specification.

---

## 🌐 The Bigger Picture: The "B2B Agent" Architecture

Trust Gateway was designed as the core enforcement engine of a broader architectural paradigm: **Autonomous B2B Agents**.

As enterprises deploy autonomous agents that interact across corporate boundaries (such as procurement, logistics, dynamic partner integrations, and automated commerce), giving LLM agents direct API credentials or ambient execution authority creates severe prompt-injection, confused-deputy, and liability risks.

The **B2B Agent pattern** solves this by establishing a strict dual-plane separation:
1. **Semantic Plane (Probabilistic)**: External and internal agents communicate over agent protocols (such as A2A, MCP, or DIDComm) to discover capabilities and negotiate mutual terms.
2. **Control Plane (Deterministic)**: The **Trust Gateway** is designed to be the sole path to execution — it holds all downstream credentials and evaluates every proposed action against machine-enforceable **Interaction Contracts** and enterprise policy.

```text
┌────────────────────┐   A2A Protocol   ┌────────────────────┐
│ External B2B Agent │ ◀──────────────▶ │Enterprise B2B Agent│
│ (did:web:buyer...) │                  │  (Cognitive LLM)   │
└────────────────────┘                  └─────────┬──────────┘
                                                  │ 4 MCP Tools
                                                  │ (Inspect, Propose,
                                                  │  Activate, Vault)
                                                  ▼
                                        ┌────────────────────┐
                                        │   Trust Gateway    │
                                        │  (PEP & Contracts) │
                                        └─────────┬──────────┘
                                                  │
                ┌─────────────────────────────────┴──────────────────┐
                │ • Checks RFC 8785 Canonical Interaction Contract   │
                │ • Evaluates policy.toml & Layer 0 Call-Chain Guard │
                │ • Mints short-lived ExecutionGrant JWT             │
                └─────────────────────────────────┬──────────────────┘
                                                  │
                                                  ▼
                                        ┌────────────────────┐
                                        │ Isolated Executor  │ ──▶ APIs / ERP
                                        │ (Verifies Grants)  │
                                        └─────────┬──────────┘
                                                  │
                      ┌───────────────────────────┴────────────────┐
                      │ 1. Atomic count increment in reputation_KV │
                      │ 2. Mint & sign portable ExecutionReceipt   │
                      └───────────────────────────┬────────────────┘
                                                  │
                                                  ▼
                                        Verifiable Proof
                                        returned to Buyer
```

### 📄 Read the Whitepaper

For the full architecture, threat model, and an honest accounting of what's implemented versus still a design goal, read the technical whitepaper:

👉 **[Interaction Contracts for Autonomous B2B Agents: Architecture, Threat Model, and Open Questions](whitepaper/b2b_agent_whitepaper.md)**

Key topics covered in the whitepaper:
- **Negotiated Interaction Contracts (NICP)**: Canonicalization (RFC 8785 JCS), contract lifecycle, and mutual cryptographic attestation.
- **Autonomous Reputation & Evidence Lifecycle**: Cold-start containment, atomic local reputation ledgers (`reputation_scores`), peer attestation proofs, and portable `ExecutionReceipt` evidence (§8.3).
- **The Cognitive-to-Cryptographic Bridge**: The 4 MCP tools bridging reasoning LLMs to deterministic gateway primitives (§8.4).
- **The Effective Authority Invariant**: `effective_authority = contract ∩ enterprise_policy ∩ identity_delegation`.
- **Stateful Authorization & Cumulative Risk**: Sliding-window velocity limits and multi-request exposure guards.
- **Implementation Status Matrix**: Transparent status across all subsystems (§11.1).
- **Audit Trails & Dispute Resolution**: Append-only sealed receipts linking grants, contracts, input/output digests, and signatures.

---
## 📖 Explore the Documentation

| Goal | Resource / Guide |
| :--- | :--- |
| **B2B Agent Whitepaper** | [`whitepaper/b2b_agent_whitepaper.md`](whitepaper/b2b_agent_whitepaper.md) |
| **Reputation Lifecycle Example** | [`examples/agent_reputation_lifecycle/README.md`](examples/agent_reputation_lifecycle/README.md) |
| **Real-World A2A Script Guide** | [`../secure-collaboration-fabric/b2b_agent/examples/README.md`](../secure-collaboration-fabric/b2b_agent/examples/README.md) |
| **Contributor & CLI Quickstart** | [`docs/QUICKSTART.md`](docs/QUICKSTART.md) |
| **Integrate via Python** | [`examples/python-agent/quickstart.py`](examples/python-agent/quickstart.py) |
| **Integrate via MCP** | [`docs/tutorials/mcp-client.md`](docs/tutorials/mcp-client.md) |
| **Integrate via REST** | [`docs/tutorials/rest-curl-agent.md`](docs/tutorials/rest-curl-agent.md) |
| **Architecture Deep Dive** | [`docs/concepts/ARCHITECTURE.md`](docs/concepts/ARCHITECTURE.md) |
| **Protocol Specification** | [`docs/reference/PROTOCOL_SPEC.md`](docs/reference/PROTOCOL_SPEC.md) |
| **Write a Custom Policy** | [`docs/how-to/write-policy.md`](docs/how-to/write-policy.md) |
| **What Trust Gateway is Not** | [`docs/concepts/LIMITATIONS.md`](docs/concepts/LIMITATIONS.md) |
| **Why Trust Gateway** | [`docs/concepts/VISUAL_GUIDE.md`](docs/concepts/VISUAL_GUIDE.md) |
| **Threat Model** | [`threat-model/THREAT_MODEL.md`](threat-model/THREAT_MODEL.md) |


---
## 🧰 Development

```bash
make doctor       # Verify prerequisites
make check        # Check workspace compilation
make test         # Run unit tests
make quickstart   # Run standalone demo
make demo-docker  # Build demo Docker image
make conformance  # Run protocol conformance vectors
make lint         # Run clippy & cargo fmt checks
```

---

Maintained by [lianxi.io](https://lianxi.io). Security disclosures: [`SECURITY.md`](SECURITY.md).
