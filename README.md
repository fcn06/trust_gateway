# 🛡️ Trust Gateway: The Execution Firewall for AI Agents

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

## 🛡️ Dual HTTP & MCP Edge

Trust Gateway exposes two unified endpoints designed to serve both cognitive agent frameworks and enterprise service architectures:

* **MCP Endpoint (`/v1/mcp/sse`)**: A native Model Context Protocol (MCP) server operating over Server-Sent Events (SSE). It serves dynamically filtered tool definitions to personal and enterprise AI agents, context bundles (`default_tools`, `ecommerce`, `scheduling`), and structured tool invocation handlers.
* **HTTP Endpoint**: Robust REST APIs providing discovery manifests, session verification, WebAuthn biometric approvals, and server-to-server transaction callbacks.

---

## 🌐 Enabling the Personal Agent Protocol (PAP)

Trust Gateway is a **key component** in enabling the **Personal Agent Protocol (PAP)**—the open standard defining how consumer personal agents securely interact with businesses:

* **Multi-Tier Policy Gating**: Enforces graduated access tiers required by PAP:
  * **Guest Tier (`Level0Guest`)**: Read-only browsing for public catalogs, warranties, and return policies with zero credentials.
  * **Account Tier (`Level2Bearer` / `Level3Session`)**: Agent acts on behalf of an authenticated user to check order status or view quotes.
  * **Step-Up Tier (`Level5WebAuthn`)**: High-consequence mutations require biometric confirmation before execution grants are minted.
* **Zero-Credential Execution**: Personal agents propose checkout intents (`box_shop_checkout`). Once policy gates pass, executors verify the Ed25519 `ExecutionGrant` and transact server-to-server—without agents or LLMs ever touching raw credit card numbers or payment credentials.
* **Capability Discovery & Notifications**: Publishes capability manifests (`/.well-known/personal-agent.json`) and coordinates with mediators for asynchronous notification delivery.

---

## ⚡ Powering the Autonomous Agent Economy

Trust Gateway transforms AI agents from isolated assistants into trusted economic counterparties:

* **Tripartite Decoupling**:
  ```text
  Agent (Proposes) ──> Trust Gateway (Decides) ──> Executor Host (Verifies & Runs)
  ```
  *Agents never interact directly with database credentials or sensitive backend APIs.*
* **Cryptographic Execution Grants**: Every tool invocation requires an Ed25519-signed `ExecutionGrant` JWT bound to canonical parameter hashes and spending limits.
* **Mathematical Receipts & Contracts**: Verifiable cryptographic execution receipts and B2B interaction contracts ensure auditability, dispute resolution, and trustless multi-agent collaboration.

---

## 📐 Architecture

To unlock safe autonomy, Trust Gateway enforces a three-tier sovereign separation:

```text
  🧠 SEMANTIC PLANE (Intelligence)
  ┌───────────────────────────────┐
  │           AI Agent            │  • Formulates multi-turn plans & reasoning
  │  (Zero downstream credentials)│  • Interacts with users or external swarms
  └───────────────┬───────────────┘
                  │ 1. Proposes Action (Intent, Parameters, Context)
                  ▼
  ⚖️ CONTROL PLANE (Governance)
  ┌───────────────────────────────┐
  │         Trust Gateway         │  • Evaluates 4-layer policy & bilateral contracts (NICP)
  │   (Deterministic Policy PEP)  │  • Assesses dynamic counterparty trust & economic quotas
  └───────────────┬───────────────┘  • Mints single-use, Ed25519-signed ExecutionGrant
                  │ 2. Dispatches GrantedAction + Cryptographic Grant
                  ▼
  🛡️ EXECUTION PLANE (Capability)
  ┌───────────────────────────────┐
  │     Isolated Executor Host    │  • Cryptographically verifies grant signature & input hash
  │    (Holds physical API keys)  │  • Enforces nonces, timeout bounds & egress scrubbing
  └───────────────┬───────────────┘
                  │ 3. Performs Authorized Mutation
                  ▼
         🌐 Production Systems (SaaS, ERP, Databases, Payments)
```

---

## 🚀 Quickstart

### Prerequisites

* **Rust 1.89+** via [rustup](https://www.rust-lang.org/tools/install)
* **NATS Server** with JetStream enabled
* **System packages**: `build-essential`, `pkg-config`, `libssl-dev`

### Running the Gateway

```bash
# Build the workspace
cargo build --release

# Run Trust Gateway
cargo run -p gateway

# In a separate terminal, run the Executor Host
cargo run -p executor_host
```

### Testing & Verification

```bash
# Run unit and integration test suites
cargo test --workspace

# Run clippy and format checks
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 📚 Foundational Whitepapers & Documentation

* 📄 **[Interaction Contracts for Autonomous B2B Agents: Architecture, Threat Model, and Open Questions (NICP)](whitepaper/b2b_agent_whitepaper.md)**
* 📄 **[Can Agents Replace Per-Partner Integration Specs? Notes From One Experiment](whitepaper/A_New_Opportunity_for_integration_thanks_to_ai_agents.md)**
* [Architecture Deep Dive](docs/concepts/ARCHITECTURE.md)
* [API Transports & Discovery](docs/reference/API_TRANSPORTS.md)
* [Protocol Specification](docs/reference/PROTOCOL_SPEC.md)
* [Writing Custom Policies](docs/how-to/write-policy.md)
* [Threat Model](threat-model/THREAT_MODEL.md)

---

Maintained by [lianxi.io](https://lianxi.io). Security disclosures: [`SECURITY.md`](SECURITY.md).
