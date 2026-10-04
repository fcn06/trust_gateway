# 🛡️ Trust Gateway: The Execution Firewall for AI Agents. Agents propose, the gateway decides.

<p align="center">
  <img src="docs/illustrations/Trust_Gateway_Overall_1.png" alt="Trust Gateway Overall" width="80%">
</p>

[![Rust](https://img.shields.io/badge/Rust-1.89%2B-orange?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue)](LICENSE)
[![NATS](https://img.shields.io/badge/NATS-JetStream-green?logo=nats.io)](https://nats.io)
[![MCP](https://img.shields.io/badge/MCP-SSE%20%2B%20Streamable-purple)](https://modelcontextprotocol.io)
[![Whitepaper: NICP Architecture](https://img.shields.io/badge/Whitepaper-NICP%20Architecture-teal?logo=read-the-docs&logoColor=white)](whitepaper/b2b_agent_whitepaper.md)
[![Whitepaper: A New Integration Era](https://img.shields.io/badge/Whitepaper-A%20New%20Integration%20Era-indigo?logo=read-the-docs&logoColor=white)](whitepaper/A_New_Opportunity_for_integration_thanks_to_ai_agents.md)

> **Stop giving AI agents raw API keys.** We stand at the precipice of an autonomous **Agentic Economy**—a multi-trillion-dollar frontier where software agents will not merely assist humans behind screens, but independently discover counterparties, orchestrate global supply chains, negotiate bilateral commercial agreements, and transact capital at machine speed.
>
> For thirty years, enterprise integration has been shackled by handwritten specifications: brittle EDI mappings, bespoke point-to-point APIs, and months of manual partner onboarding. Autonomous agents bring an extraordinary promise: what if counterparty systems could dynamically negotiate their own integration interfaces at runtime?
>
> Yet this revolutionary future cannot be built on **ambient authority**. Handing raw downstream credentials, payment rails, or administrative database access to probabilistic neural networks is an existential hazard. When an LLM reasons probabilistically, giving it ambient execution power is like handing a loaded firearm to a brilliant but unpredictable intern.
>
> **Trust Gateway is the zero-trust execution control plane and integration framework for the agentic era.** It builds the missing architectural bridge: freeing cognitive models to explore, communicate, and negotiate at peak creative velocity across heterogeneous ecosystems (A2A, MCP, LangChain, Swarms), while enforcing mathematical, deterministic certainty before any real-world mutation touches enterprise state.

---

> ### ⚡ The Governing Axiom of Autonomous Systems
> # **"Agents propose. Gateway decides. Executors verify."**

AI agents must be fully empowered to **propose** ambitious intents without possessing the ambient authority to **execute** them.

Trust Gateway sits as an uncompromising cryptographic firewall between reasoning intelligence and downstream capabilities. Agents never hold downstream API keys, OAuth refresh tokens, or database credentials. Instead, proposed actions are continuously verified against hierarchical organizational policies, dynamic counterparty trust telemetry, and execution budgets. When policy permits, the gateway mints short-lived, Ed25519-signed cryptographic grants (`ExecutionGrant`) mathematically bound to the tool name and canonical input hash. Isolated executors verify this grant before touching external state—turning stochastic agent plans into provable, enterprise-grade execution.

---

### 📚 Foundational Whitepapers

This project explores the dual frontiers of autonomous commerce and next-generation systems integration:

1. 📄 **[Can Agents Replace Per-Partner Integration Specs? Notes From One Experiment](whitepaper/A_New_Opportunity_for_integration_thanks_to_ai_agents.md)** *(October 2026)*  
   *How autonomous agents rewrite enterprise integration (EDI, iPaaS) by moving from brittle pair-wise specifications written for every partner to self-descriptions and policies written once, with agreements negotiated dynamically at runtime.*
2. 📄 **[Interaction Contracts for Autonomous B2B Agents: Architecture, Threat Model, and Open Questions (NICP)](whitepaper/b2b_agent_whitepaper.md)** *(September 2026)*  
   *A deep architectural exploration of the Negotiated Interaction Contract Protocol (NICP), cryptographic Execution Grants, cold-start counterparty containment, and verifiable execution receipts for safe Agent-to-Agent (A2A) commerce.*

---

## 📐 The Architecture of Sovereign Trust

To unlock safe autonomy, Trust Gateway replaces the dangerous ambient authority model with a **three-tier sovereign separation**:

```text
  🧠 SEMANTIC PLANE (Intelligence)
  ┌───────────────────────────────┐
  │           AI Agent            │  • Formulates multi-turn plans & reasoning
  │  (Zero downstream credentials)│  • Interacts with users or external swarms
  └───────────────┬───────────────┘
                  │
                  │ 1. Proposes Action (Intent, Parameters, Context)
                  ▼
  ⚖️ CONTROL PLANE (Governance)
  ┌───────────────────────────────┐
  │         Trust Gateway         │  • Evaluates 4-layer policy & bilateral contracts (NICP)
  │   (Deterministic Policy PEP)  │  • Assesses dynamic counterparty trust & economic quotas
  └───────────────┬───────────────┘  • Mints single-use, Ed25519-signed ExecutionGrant
                  │
                  │ 2. Dispatches GrantedAction + Cryptographic Grant
                  ▼
  🛡️ EXECUTION PLANE (Capability)
  ┌───────────────────────────────┐
  │     Isolated Executor Host    │  • Cryptographically verifies grant signature & input hash
  │    (Holds physical API keys)  │  • Enforces nonces, timeout bounds & egress scrubbing
  └───────────────┬───────────────┘
                  │
                  │ 3. Performs Authorized Mutation
                  ▼
         🌐 Production Systems (SaaS, ERP, Databases, Payments)
```

### Decoupling Thought from Power: How It Works

1. **Reasoning Without Danger (The Agent Proposes)**  
   The AI agent plans and reasons at peak creative velocity. It never possesses, requests, or handles downstream credentials, database passwords, or payment tokens. When it identifies a necessary mutation, it submits a `ProposedAction` detailing *what* it intends to do and *with what arguments*.

2. **Governance With Mathematical Rigor (The Gateway Decides)**  
   Trust Gateway intercepts the proposal at the boundary. It evaluates tenant policies, bilateral interaction contracts, historical reputation telemetry, call-chain loop limits, and economic budgets. If authorized, the gateway mints a short-lived (30s) `ExecutionGrant` JWT cryptographically bound to the SHA-256 digest of the canonical inputs (`input_hash`).

3. **Execution With Cryptographic Proof (The Executor Verifies)**  
   The isolated executor holds the physical API keys or SaaS credentials, but it never trusts the agent directly. It verifies the gateway's digital signature, validates that the arguments have not been tampered with, checks that the single-use nonce has not been replayed, and confirms that execution stays within budget. Only then does it execute the mutation—scrubbing sensitive PII before returning the filtered result.

> **The Result:** The enterprise gains complete, deterministic safety and auditability without choking agent intelligence. Prompt injections, hallucinations, and runaway loops are stopped dead at the gateway boundary.



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
cargo run --bin agent-reputation-lifecycle-example
```

---

## 📜 Protocol Sketch vs. Implementation

This project defines a working set of authorization contracts, independent in principle of any specific runtime:
* **Normative Schemas**: `ProposedAction` (with optional `CallChainContext`), `PolicyDecision`, `ExecutionGrant`, `GrantedAction`, `ExecutionResult`, `ExecutionReceipt`.
* **Layer 0 Call-Chain Guard**: Evaluated before attribute rules to defend against multi-agent runaway loops, infinite recursion, and frequency spikes (`max_depth = 10`, `allow_cycles = false`, `max_frequency_per_tool = 3`) with authoritative server-side session tracking.
* **Deterministic Contract Kernel (`trust-contract`)**: Pure aggregate enforcing RFC 8785 canonical JSON, SHA-256 fingerprinting, 10-state FSM, and a 9-step activation ceremony over mutual Ed25519 signatures.
* **Autonomous Reputation & Evidence Lifecycle**: Cold-start containment via local NATS KV `reputation_scores`, peer attestation verification against `trusted_peer_roots` anchors, and portable, signed `ExecutionReceipt` proofs returned upon `ActionSucceeded`.
* **Cognitive-to-Cryptographic MCP Tools**: 4 specialized lifecycle tools (`reputation_inspect_counterparty`, `contract_propose_or_amend`, `contract_verify_and_activate`, `receipt_present_and_store`) bridging semantic reasoning to control plane enforcement.
* **Dynamic Agent Discovery & Service Registration**: Decentralized registration via `POST /v1/discovery/agents`, enabling agents to advertise capabilities and discover registered endpoints dynamically.
* **LLM Gateway Supervisor Integration**: Transparent LLM call proxying and policy supervision via `ENABLE_LLM_GATEWAY_SUPERVISOR` and `LLM_GATEWAY_URL`.
* **Metadata Normalization (`identity_context`)**: RequestContext metadata aliases (`agent_jwt` ↔ `credential`, `tenant` ↔ `tenant_id`, `authorization`, `thread_id`) ensuring unified compatibility across heterogeneous agent frameworks (such as `swarm_commons` 0.2.0).
* **Canonicalization & Hashing**: Deterministic canonical JSON serialization with lexicographically sorted object keys followed by SHA-256 hashing (`input_hash`).
* **Verification Rules**: Ed25519 public key signature verification, nonce (`jti`) tracking intended to make grant reuse hard, and strict TTL expiration.
* **Dynamic Multi-Dimensional Trust Metrics (`policy-sdk`)**: Runtime counterparty evaluation (`DynamicTrustMetrics`: failure rate ceilings, cold-start limits, peer attestation scores) with automatic adaptive downgrade to human approval when trust thresholds or local interaction histories are unmet.
* **Economic Claims & Metered Execution Grants (`ExecutionGrant`)**: Cryptographic binding of `EconomicClaim` (currency, cost ceilings, payment vouchers/tokens, quota reservations) and `ExecutionBudget` (duration caps, call limits) to the grant JWT, enabling trust and budget verification for billable/compute-intensive tools before execution.
* **Semantic IO Mapping Middleware (`b2b_agent`)**: Inbound translation layer mapping foreign A2A and MCP tool call schemas to canonical Lianxi tool definitions with deterministic parameter mapping, default value injection, and argument sanitization.
* **CLI Surface Adapter**: Dynamic Policy Enforcement Point (`adapters/surface-cli`) projecting native tool JSON Schemas into typed CLI commands with POSIX exit codes (0, 1, 126, 127, 130).

This repository is the only implementation right now — mine, in Rust — plus a Python SDK. "Protocol" here describes an internal design, not an externally reviewed or adopted specification.

---

## 🌐 The Bigger Picture: Agent-to-Business (A2B) Commerce

> *"The future of commerce isn't just about showing screens to humans; it is about exposing secure endpoints to their agentic representatives."*

Trust Gateway was designed as the deterministic enforcement engine for an emerging architectural pattern: the **Autonomous Business Envoy (ABE)** and **Agent-to-Business (A2B) commerce**.

### A Possible Shift in the E-Commerce Paradigm

For over three decades, digital commerce has been engineered almost entirely around human attention: visual storefronts, catalogue browsing, shopping carts, and OAuth login popups. 

As users and organizations increasingly rely on personal AI assistants and localized agents to research, procure, book, and reconcile orders, that familiar paradigm may quietly shift:
* **The collapsing marketing funnel**: Buyers may rarely visit individual web portals or click through multi-step shopping carts. Instead, customer-side agents will discover suppliers, compare availability across dynamic parameters, and negotiate directly.
* **The limits of raw P2P delegation**: Allowing an unverified personal agent to talk directly to another user's agent introduces credential sprawl, ephemeral downtime, and ambiguous legal authority.
* **The Autonomous Business Envoy (ABE)**: Rather than exposing raw internal APIs to the public internet, merchants deploy dedicated, policy-guided agent enclaves—business envoys—equipped with verifiable corporate identities (`did:web`) that can negotiate catalog specs, volume pricing curves, and delivery SLAs with client agents in real time.

We view this shift not as an overnight replacement, but as an exploratory evolution toward an **agentic economy** where autonomous agents represent companies and individuals in commercial transactions.

### The Paradox of the Bundled Agent

Most initial agent integrations make a fundamental design compromise: they bundle **probabilistic reasoning** and **deterministic execution** into a single loop. An LLM prompt context is handed raw API keys, database credentials, or shell access.

This creates an uncomfortable trade-off:
* **Over-restrict the prompt**, and the agent becomes brittle, sluggish, and incapable of flexible multi-turn negotiation.
* **Grant ambient execution authority**, and the enterprise faces stochastic hallucinations, runaway loops, indirect prompt injections, and confused-deputy vulnerabilities.

Probabilistic models are extraordinary cognitive planners, but production commerce—payments, inventory allocation, and database writes—demands binary certainty.

### Decoupling Intelligence from Authority

The **Autonomous Business Envoy pattern** resolves this dilemma with a foundational principle:

$$\text{Agents propose.} \quad \mathbf{\longrightarrow} \quad \text{Gateway decides.} \quad \mathbf{\longrightarrow} \quad \text{Executors verify.}$$

By splitting operations across two decoupled planes, agents are freed to reason at peak cognitive velocity while the enterprise retains total, deterministic execution control:

1. **Semantic Plane (Probabilistic)**: Counterparty agents communicate over open protocols (A2A, MCP, DIDComm) to discover capabilities, exchange cryptographically signed **Verifiable Presentations (VPs)**, and negotiate bilateral terms.
2. **Control Plane (Deterministic)**: The **Trust Gateway** acts as the sole gatekeeper to state-changing operations. It evaluates proposed actions against machine-enforceable **Interaction Contracts (NICP)**, velocity constraints, and local enterprise policy—holding all downstream credentials so the LLM never touches them.

```text
┌────────────────────┐   A2A Protocol   ┌──────────────────────────┐
│ Customer Agent     │ ◀──────────────▶ │ Merchant Commerce Envoy  │
│ (did:web:buyer...) │  (Negotiation +  │ (Probabilistic LLM)      │
└────────────────────┘   VP Credential) └────────────┬─────────────┘
                                                     │ Proposes Action
                                                     │ (4 MCP Tools)
                                                     ▼
                                        ┌──────────────────────────┐
                                        │      Trust Gateway       │
                                        │  (Deterministic PEP/PDP) │
                                        └────────────┬─────────────┘
                                                     │
                 ┌───────────────────────────────────┴────────────────────┐
                 │ • Checks RFC 8785 Canonical Interaction Contract       │
                 │ • Layer 0 Call-Chain Guard (depth, cycle, frequency)   │
                 │ • Evaluates policy.toml & tenant boundary invariants   │
                 │ • Mints short-lived (30s) ExecutionGrant JWT (Ed25519) │
                 └───────────────────────────────────┬────────────────────┘
                                                     │
                                                     ▼
                                        ┌──────────────────────────┐
                                        │ Isolated Executor Host   │ ──▶ ERP / Ledger
                                        │ (Cryptographic Verifier) │
                                        └────────────┬─────────────┘
                                                     │
                        ┌────────────────────────────┴─────────────────┐
                        │ 1. Asserts grant signature & input_hash match│
                        │ 2. Increments atomic reputation ledger (KV)  │
                        │ 3. Issues sealed, portable ExecutionReceipt  │
                        └────────────────────────────┬─────────────────┘
                                                     │
                                                     ▼
                                           Verifiable Audit Proof
                                             returned to Buyer
```

### The 4-Stage Governance Pipeline

When an autonomous transaction occurs, intent travels through four strictly isolated stages:

1. **Commercial Negotiation (`Customer Agent ↔ Commerce Envoy`)**: The customer's agent presents its `did:web` identity and verifiable credential passport. The two agents negotiate volume tiers, customized terms, or even pooled demand (such as self-organizing "agentic group buying") across probabilistic natural language.
2. **Governed Action Proposal (`Commerce Envoy → Trust Gateway`)**: The envoy formulates a structured `ProposedAction` containing canonical arguments. Guided by principle, the envoy holds zero downstream credentials and cannot execute directly.
3. **Policy Decision & Grant Minting (`Trust Gateway`)**: The Gateway deterministically validates the proposal against bilateral contracts, tenant scopes, spending ceilings, and Layer 0 call-chain guards. If approved, it mints a short-lived (30s TTL) `ExecutionGrant` bound cryptographically to the SHA-256 digest (`input_hash`) of the canonical arguments.
4. **Verified Execution & Audit Receipt (`Secure Executor`)**: The sandboxed executor verifies that the grant is authentic, unexpired, and strictly bound to the exact payload before invoking production services. Upon completion, it returns a non-repudiable `ExecutionReceipt`.

### A Grounded, Humble Perspective

We do not claim that autonomous B2B commerce is fully solved or that web browsers will disappear tomorrow. Complex edge cases remain active engineering and research questions:
* *Multi-hop dispute resolution* when upstream models misunderstand nuanced contractual terms.
* *Decentralized reputation cold-start* when agents encounter counterparties without established histories.
* *Legal enforceability* of machine-negotiated interaction contracts across differing jurisdictional regimes.

Trust Gateway is our pragmatic, open-source attempt to build the missing enforcement layer: providing the cryptographic guardrails and deterministic isolation required before organizations can responsibly experiment with the next paradigm of digital trade.

### 📄 Read the Whitepaper

For the comprehensive architecture, formal state machines, threat model, and an honest accounting of what is verified in code versus what remains an active design target, read the technical whitepaper:

👉 **[Interaction Contracts for Autonomous B2B Agents: Architecture, Threat Model, and Open Questions](whitepaper/b2b_agent_whitepaper.md)**

Key topics covered in the whitepaper:
- **Negotiated Interaction Contracts (NICP)**: Canonicalization (RFC 8785 JCS), 10-state contract lifecycle FSM, and mutual cryptographic attestation.
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
| **Contributor & CLI Quickstart** | [`docs/QUICKSTART.md`](docs/QUICKSTART.md) |
| **API Transports & Discovery** | [`docs/reference/API_TRANSPORTS.md`](docs/reference/API_TRANSPORTS.md) |
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
