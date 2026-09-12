# Interaction Contracts for Autonomous B2B Agents: Architecture, Threat Model, and Open Questions

**Status:** Working draft, personal project — not peer-reviewed, not a standard, not a finished system  
**Author:** fcn06 (Lianxi / Trust Gateway project, [lianxi.io](https://lianxi.io))  
**Date:** September 2026  
**Where this lives:** GitHub ([fcn06/trust_gateway](https://github.com/fcn06/trust_gateway)) and lianxi.io — this is not submitted anywhere, and I have no current plans to submit it to arXiv or a standards body until there's real implementation and outside review behind every claim in it.  

---

## How to read this document

This is a technical report about an architecture I've been building called the **Negotiated Interaction Contract Protocol (NICP)**, together with the **Trust Gateway** that enforces it. It grew out of a dev.to article (["The Agent Economy: Why Agents Must Negotiate Agreements, and How It Rewrites Integration"](https://dev.to/fcn06/the-agent-economy-needs-a-trust-layer-49c)) and goes into the implementation detail that piece didn't have room for.

A few honesty notes up front, because an earlier draft of this document didn't have enough of them:

- **This is one person's project, not a working group.** I'm not going to pretend otherwise by using "we" or inventing an organizational name. Where I say "I," I mean me; where I say "the project," I mean this codebase.
- **Not everything described here is built, and not everything built is public.** Throughout this document I've tagged each major claim with where it actually stands:
  - 🟢 **Implemented and open source** — you can read the code.
  - 🟡 **Implemented, not yet public** — it exists in my private build, working but not yet released or independently reviewed.
  - ⚪ **Design goal, not yet built** — this is the target behavior, not a claim about what exists today.
- **Nothing here has had independent security review.** The threat model and the "invariants" in Section 7 are things I'm *designing toward*, not things I can claim are proven. I'd genuinely like people who do this for a living to try to break them.
- **The market narrative in Section 1.3 is accurate as far as I can verify**, but I'm one person reading public reporting, not an analyst with inside information — treat it as informed context, not authoritative market analysis.

If you're the kind of reader who wants to poke holes in an architecture, this document is written for you. If you're evaluating whether to trust this in production — please don't yet. It isn't there.

---

## Table of Contents

1. [The Problem](#1-the-problem)
2. [Architecture Overview](#2-architecture-overview)
3. [The Interaction Contract](#3-the-interaction-contract)
4. [Stateful Authorization and Risk](#4-stateful-authorization-and-risk)
5. [The Semantic Verification Pipeline](#5-the-semantic-verification-pipeline)
6. [Cryptographic Attestation and Execution Grants](#6-cryptographic-attestation-and-execution-grants)
7. [Threat Model and Design Invariants](#7-threat-model-and-design-invariants)
8. [Operational Trace and Audit Receipts](#8-operational-trace-and-audit-receipts)
9. [How This Relates to Other Work](#9-how-this-relates-to-other-work)
10. [How This Rewrites Integration](#10-how-this-rewrites-integration)
11. [Where This Goes Next](#11-where-this-goes-next)
12. [References](#12-references)

---

## 1. The Problem

A year ago, "agentic AI" meant an LLM with access to a terminal or a calculator. Today the conversation has shifted to the **agent economy** — autonomous agents from different companies discovering one another, negotiating terms, and settling transactions at machine speed. This paper addresses the architectural gap between that ambition and what's actually safe to build.

### 1.1 Point-to-point integration doesn't scale

Connecting two enterprises today usually means custom API adapters, bespoke schemas, mutual auth, rate limits, webhooks, and SDKs, built and maintained per pair. With more counterparties, the number of bilateral integrations grows roughly with the square of the number of participants — everyone who has worked in enterprise integration has lived this. Global schema standards (EDIFACT, SWIFT, RosettaNet, FHIR) reduce the heterogeneity but take years to adopt and are expensive to implement.

Even when both sides use standard formats like JSON or OpenAPI, their business semantics almost never match — does "cancel order" mean voiding the PO immediately, or submitting a cancellation request subject to supplier review?

Agents change the equation because they can reason about intent. Instead of calling `POST /api/v3/orders` with twenty hardcoded parameters, Company A's agent can say: *"I need 500 industrial bearings delivered to our Lyon warehouse before next Friday. Target budget is under €15,000."* It's tempting to think this means LLMs simply replace APIs. That would be a catastrophe — two probabilistic models chatting freely across company boundaries can hallucinate prices, misinterpret delivery terms, or fall prey to prompt injection. A natural language chat is not a business contract.

### 1.2 Why I don't think agents should get direct execution access

LLM agent frameworks make it tempting to let an external agent talk to an internal agent that itself holds API keys or database credentials. I think that's a bad idea, for reasons that aren't hypothetical:

1. **LLMs can't give you a hard guarantee about their own boundaries.** A slightly unusual phrasing can push a model past a limit it was "told" to respect.
2. **Cross-boundary prompt injection is real.** Content embedded in a partner's proposal, purchase order, or quote metadata can attempt to redirect the receiving agent's behavior.
3. **Free-form negotiation isn't auditable.** Two agents talking in natural language don't produce a record either side can point to later and say "this is exactly what we agreed."
4. **Confused deputy problems are easy to create.** An internal agent with broad system access, acting on behalf of an external, less-trusted counterparty, is a classic setup for that failure mode.

The breakthrough isn't replacing APIs with LLM conversations. The breakthrough is **using agents to negotiate a machine-readable agreement at runtime**, while keeping the underlying APIs as the deterministic execution engine.

### 1.3 What's actually happening in the market right now

This section describes real, checkable events, not my own predictions.

Through 2025 and into 2026, several companies tried to build **centralized agentic-checkout gateways** — Google and Shopify's Universal Commerce Protocol, Microsoft's Copilot Checkout, Perplexity's Instant Buy, Amazon's Buy for Me, and OpenAI's ChatGPT Instant Checkout among them.

OpenAI's version is the clearest data point: it launched in September 2025 and was retired in March 2026, about six months later. Walmart reported conversion rates roughly three times lower for in-chat checkout than for its own site, and reporting at the time pointed to broader issues — inaccurate product data, low merchant participation, and a general reluctance from merchants to hand over the customer relationship, margin, and post-purchase experience to an intermediary. The pattern that emerged: people are comfortable discovering products through AI, much less comfortable completing a purchase inside someone else's chat window.

On September 2, 2026, Anthropic released **Claude Commerce Agents**, an open reference blueprint (Apache 2.0) for building shopping and merchant agents that live inside a merchant's own website, app, and back office, rather than inside a third-party aggregator. Anthropic's own material is explicit that the reference implementation does not place orders or charge cards — those actions stay with the merchant's existing systems, and the agent's role is scoped to recommending, cart-staging, and handing off to normal checkout.

I read this as a useful, independent confirmation of the thesis I'd already been building toward: **merchants and enterprises want the agent to live on their own side of the boundary, not to cede transaction authority to it.** I want to be careful about how I frame this, though — Anthropic didn't design Claude Commerce Agents with a gap in mind for this project to fill, and I have no relationship with them around this work. What I think is true is narrower and more useful: their reference implementation demonstrates real market demand for exactly the kind of thing this project is trying to build — a way to give a merchant-embedded agent actual transactional authority, safely, once it's ready to go further than recommend-and-handoff. That's a complementary relationship I'm claiming, not an endorsed one.

### 1.4 The principle this project is built around

The current debate around autonomous agents is stuck between two poles. On one side, full autonomy — hand the LLM an API key and let it roam (terrifying for any CISO or CFO). On the other, zero autonomy — keep a human in the loop for every action (which destroys the efficiency gains agents promise). Negotiated agreements backed by deterministic gateways offer a third path.

The idea I keep coming back to:

```text
Effective authority = negotiated contract ∩ enterprise policy ∩ identity authority ∩ delegated authority
```

Agents get full flexibility to negotiate, discover, and propose. They get none of the underlying authority to make something happen — that's evaluated separately, deterministically, by something that isn't an LLM.

```text
   Autonomous B2B agent (proposes intent and terms)
                │
                ▼
   Negotiated contract (cryptographically sealed once agreed)
                │
                ▼
   Trust Gateway (checks contract against policy, deterministically)
                │
                ▼
   Execution grant (scoped to one exact action)
                │
                ▼
   Isolated executor (verifies the grant, then acts)
                │
                ▼
   Enterprise systems (ERP, payments, inventory, ...)
```

### 1.5 Agents negotiate meaning, not authority

This is the load-bearing architectural principle that makes the entire model work: **agents negotiate meaning and operational terms; they do NOT decide execution authority.**

An LLM is well suited to reconciling differences. It can negotiate whether payment is in EUR or USD, map Company A's `shipping_address` to Company B's `destination_facility`, or agree on a cancellation window. That is **semantic negotiation** — reconciling meaning across organizational boundaries.

But an agent should never have the power to approve its own authority. If Company A's agent and Company B's agent agree on a €50,000 transaction limit, but Company A's internal corporate policy says automated agents are capped at €10,000, enterprise policy must always win. Negotiation can only **shrink** the permitted operational space. It can never expand beyond what deterministic enterprise policy permits.

---

## 2. Architecture Overview

### 2.1 Two planes, deliberately separated

The system is split into a **semantic plane** (probabilistic, not trusted with authority) and a **control plane** (deterministic, holds all the authority).

**Semantic plane** — the enterprise's own B2B agent plus whatever external agent it's talking to. Talks over agent-to-agent protocols. Discovers capabilities, proposes terms, drafts schema mappings. 🟢 *Has no credentials to internal systems and cannot trigger a mutating call directly — this separation is enforced structurally, not by convention.*

**Control plane** — the Trust Gateway, the contract engine, the policy layer, and isolated executors. No LLM sits anywhere in this decision path. 🟡 *Implemented in my private build in Rust, targeting WebAssembly for the executor sandbox. This part is the most mature piece of the system, but I haven't had it independently reviewed.*

```text
SEMANTIC PLANE (probabilistic, no authority)
  External agent  <──── A2A / DIDComm ────>  Enterprise B2B agent
                                                      │
                                          mutual signing ceremony
                                                      ▼
CONTROL PLANE (deterministic, holds all authority)
  Trust Gateway  ──►  Execution Grant  ──►  Isolated Executor  ──►  ERP / payments / inventory
```

### 2.2 A note on network topology

In my own deployment, the public-facing edge (a stateless ingress that terminates external connections and holds no credentials) is physically separate from the core enclave that houses the Trust Gateway, policy engine, and executor sandboxes. That's a sensible pattern for this kind of system generally, not something specific to this protocol — I mention it here mainly so the diagrams later make sense, not as a claim that this is the only correct topology. 🟡

### 2.3 Why I think the agent should sit inside the enterprise, not in front of it

Given what happened with the centralized checkout gateways (§1.3), I think the more durable model is an enterprise running its own B2B agent as the front door across all its inbound channels — web, app, human sales, partner agents, supplier agents — rather than routing all of that through someone else's aggregator. That keeps customer ownership, pricing, and the relationship inside the enterprise, and it means the reasoning model underneath (Claude, an open-weights model, whatever) is swappable without touching the execution guarantees below it. This is a design preference I hold, not a proven claim about how the market will settle.

---

## 3. The Interaction Contract

At a high level, the negotiation flow looks like this:

```text
┌────────────────┐      Propose Capabilities & Terms       ┌────────────────┐
│   Company A    │ ───────────────────────────────────────> │   Company B    │
│   B2B Agent    │ <─────────────────────────────────────── │   B2B Agent    │
└────────────────┘         Counter-Offer & Agreement        └────────────────┘
                                    │
                                    ▼
                     ┌─────────────────────────────┐
                     │    Interaction Contract     │
                     │  (Signed, Hashed, Versioned)│
                     └─────────────────────────────┘
```

Two agents discover each other's capabilities, propose and counter-propose terms, and converge on a shared contract. The detailed lifecycle and state machine are described in §3.4; the operational trace through the Trust Gateway is in §8.1.

### 3.1 What it actually is

An Interaction Contract is a signed, versioned, machine-readable description of what two organizations have agreed their agents can do together: who the counterparties are, what capabilities are in scope, what constraints apply (money, geography, time), what data can move, what obligations exist, and how the agreement can end. Once signed by both sides it's frozen — a new version is a new contract, referencing the old one, not a silent edit.

One clarification I think matters: this is a **machine-enforceable technical agreement**, not a legal contract. The two may eventually need to intersect once commercial terms are involved, but I'm not conflating them here.

I'm also genuinely unsettled on one modeling question: whether this should be one object, or an envelope over several independently versioned pieces (identity, capability agreement, schema mapping, policy constraints, delegation, obligations, attestations) that can each change on their own timeline — the schema mapping, for instance, plausibly needs to evolve independently of the commercial relationship it sits inside. I haven't picked a final answer. 🟡 *My current implementation treats it as one versioned object; I suspect the envelope model is more correct long-term.*

```rust
pub struct InteractionContract {
    pub contract_id: String,
    pub version: u32,
    pub state: ContractState,
    pub issuer: PartyIdentity,
    pub counterparty: PartyIdentity,
    pub purpose: Purpose,
    pub capabilities: Vec<ContractCapability>,
    pub constraints: ContractConstraints,
    pub data_policy: DataPolicy,
    pub obligations: Vec<Obligation>,
    pub commercial_terms: Option<CommercialTerms>,
    pub validity: ContractValidity,
    pub protocol: ProtocolBinding,
    pub evidence: ContractEvidence,
    pub parent_contract_id: Option<String>,
    pub previous_contract_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```
🟢 *This struct reflects the actual open-source data model.*

To make this concrete, here is what an agreed contract looks like from a human perspective — the kind of agreement two agents converge on:

```yaml
# Simplified human-readable view
purpose: supplier_parts_procurement
counterparties:
  buyer: did:web:company-a.com:agent-procure
  seller: did:web:company-b.com:agent-sales
capabilities:
  - quote
  - create_order
  - track_shipment
  - cancel_order
constraints:
  max_order_value:
    currency: EUR
    amount: 15000
  geography:
    delivery_destination: EU
cancellation:
  allowed_until: dispatch
  penalty: 0
validity:
  expires_at: "2026-10-01T00:00:00Z"
```

Notice what just happened: zero custom glue code was written in advance — the agents dynamically discovered each other's capabilities and negotiated mutually agreeable terms. The relationship is strictly bounded — Company A's agent cannot suddenly execute a €50,000 order or deliver to an unsupported jurisdiction. And it's a bilateral agreement, not a unilateral permission list — unlike a static API token or OAuth scope, an Interaction Contract binds both parties to shared constraints, settlement rules, and validity windows.

And here is the same agreement in its canonical, technically precise serialization:

```yaml
# Example minimal Interaction Contract draft (YAML representation)
contract_id: "ctr_0191c7a4-82a1-7000-84c1-6e792c300001"
version: 1
issuer:
  did: "did:web:buyer.corp.example"
counterparty:
  did: "did:web:supplier.logistics.example"
purpose:
  code: "procure_freight_service"
  description: "Cross-border freight and logistics procurement"
capabilities:
  - capability_id: "io.company.orders@v1"
    operations: ["quote", "create", "status", "cancel"]
constraints:
  max_transaction_value:
    amount_minor: 2500000  # Stored as minor units: €25,000.00
    currency: "EUR"
  allowed_geographies: ["EU"]
validity:
  valid_from: "2026-10-01T00:00:00.000Z"
  valid_until: "2026-10-31T23:59:59.000Z"
protocol:
  protocol_version: "nicp/1.0"
```

A fair objection here: isn't this just OAuth scopes plus a JSON Schema plus a policy engine? What I think makes it a different kind of object is that it binds several dimensions together — counterparties, purpose, capabilities, semantics, constraints, data policy, obligations, validity, and attestation — into one versioned, hashable, jointly-signed artifact, rather than leaving those as separately-managed pieces of infrastructure. Whether that's worth a new name or just a well-organized combination of existing primitives is a fair thing to disagree with me about.

### 3.2 Making the contract byte-identical everywhere

Two parties signing "the same contract" only means something if they're signing the exact same bytes, regardless of platform, language, or key ordering. I use the JSON Canonicalization Scheme (RFC 8785): sort object keys, represent money as integer minor units rather than floats, normalize timestamps to UTC ISO 8601, and strip signature fields and runtime-only metadata before hashing.

```text
Raw contract  →  strip signatures & runtime state  →  sort keys, normalize numbers and timestamps
             →  canonical byte array  →  SHA-256  →  contract_hash
```

🟢 *This canonicalization and hashing step is implemented and is the one piece of the system I'm most confident actually works as described, because it's the simplest part — it's a pure function with no distributed-systems complexity.*

I also support representing the same contract as JSON-LD (for public discovery and W3C Verifiable Credential interop), as CBOR (for low-latency wire transport), and as YAML (for human review and GitOps-style policy repos) — all of which need to produce the identical canonical hash regardless of which format you started from. 🟡

**Casing Normalization Note:** To keep hashes identical across formats, the canonical dictionary is normalized to `snake_case` keys prior to RFC 8785 sorting. When parsing JSON-LD using standard W3C `camelCase` identifiers (e.g., `capabilityId`, `maxTransactionValue`, `notBefore`), the parser deterministically projects property keys onto the canonical dictionary using the bijective `@context` mapping table before computing `contract_hash`. 🟡

### 3.3 Signing options

I support three ways to cryptographically bind a contract, because different enterprises will have different identity infrastructure already in place:

| Option | Trust model | Fits |
|---|---|---|
| UCAN | Trustless, cryptographic capability delegation | Sovereign/decentralized agent setups |
| DIDComm v2 / Verifiable Credentials | Decentralized identity, DID-based | Multi-party B2B where DIDs are already in use |
| X.509 / enterprise PKI | Traditional CA hierarchy | Enterprises already running PKI (most large ones) |

⚪ All three bindings are design targets. I've only exercised the PKI path end-to-end in my own testing so far; the UCAN and DIDComm paths are less proven.

### 3.4 Contract lifecycle

A contract moves through a fixed set of states — draft, proposed, counter-proposed, accepted, attested, active, suspended, and terminal states: revoked, expired, or superseded. Once it reaches a terminal state it's immutable; changes require a new version referencing the old contract via `previous_contract_hash` and `parent_contract_id`. Active negotiations enforce bounded limits (`NegotiationLimits`: maximum 8 rounds, 120-second timeout, 64 KB payload cap); negotiations that exceed limits or are rejected transition to the terminal revoked state. 🟢 *The state machine, lifecycle transitions, and negotiation bounds are implemented.*

---

## 4. Stateful Authorization and Risk

A plain per-request check isn't enough here. An agent with a legitimate €10,000 single-transaction limit could still drain a large amount of money by making that request a hundred times in quick succession. So the Trust Gateway needs to track state across requests, not just evaluate each one in isolation.

### 4.1 Effective authority, again

```text
effective_authority = min(contract_limit, enterprise_policy_limit, identity_delegation_limit)
```

Visually, the intersection works like this:

```text
┌────────────────────────────────────────────────────────┐
│                  EFFECTIVE AUTHORITY                   │
│                           =                            │
│   Negotiated Contract  ∩  Enterprise Policy  ∩  Identity │
└────────────────────────────────────────────────────────┘
```

1. **Negotiated Contract (Bilateral):** What did both agents agree to? (e.g., max €15,000).
2. **Enterprise Policy (Local & Deterministic):** What does your company allow right now? (e.g., max €10,000, EU hours only).
3. **Agent Identity (Cryptographic):** Is the calling agent who it claims to be, backed by a verified `did:web` and active keys?

If the contract allows up to €50,000 but enterprise policy caps autonomous agents at €10,000, the effective limit is €10,000. Straightforward, but worth stating explicitly because it's the thing that stops a negotiated agreement from ever becoming *more* permissive than what the enterprise actually allows.

### 4.2 Velocity and cumulative exposure

I track (a) total value moved in a sliding time window, (b) call frequency against a given capability, and (c) cumulative lifetime value under a specific contract — and reject or escalate once any of these thresholds is crossed, even if each individual request was within its own limit. 🟡 *Implemented against a distributed key-value store with atomic compare-and-swap, to avoid race conditions when the Gateway is running as multiple instances. I haven't load-tested this under real concurrent adversarial conditions.*

### 4.3 Human escalation

High-value, novel-counterparty, or sensitive-data transactions get routed to a human approval step rather than an automatic grant, with a "the agent that proposed it can't be the one that approves it" rule and hardware-backed (WebAuthn/FIDO2) sign-off for anything above a configurable threshold. ⚪ Design goal — the escalation path exists in my implementation, but I haven't yet exercised the multi-party approval quorum logic in anything beyond a single test scenario.

### 4.4 Call-Chain Guard: Recursion and Loop Bounds

In multi-agent collaborative workflows, an autonomous agent can delegate to sub-agents or call partner tools that in turn invoke secondary tools, risking infinite recursion, cyclic delegation ping-pong, and plan runaway attacks. The Trust Gateway enforces **Layer 0 Call-Chain Guard** (`trust_policy::call_chain`, evaluated via `evaluate_and_advance` and `validate_context_integrity`) before evaluating individual attribute rules:
- **Depth bounds**: Maximum call-chain depth (default: 10).
- **Cycle detection**: Traverses the execution graph to detect loops (e.g. `Agent A → Tool X → Agent B → Tool X`); cycles are rejected immediately.
- **Per-tool frequency caps**: Limits repeated invocations of any single tool within a trace (default: 3).
- **Authoritative session integrity**: Because client agents cannot be trusted to self-report honest call stacks, the Gateway tracks session history by `trace_id`. Inbound proposals attempting to reset or forge their execution stack are rejected outright. 🟢 *Implemented and open source.*

### 4.5 One thing I'm not fully solving yet: composition

A person combining several individually-safe grants can still end up somewhere unsafe — read access to a catalog, permission to submit a purchasing recommendation, and permission to send an external message might each be fine alone and risky together. My current effective-authority formula evaluates one action against contract/policy/identity limits; it doesn't yet reason about combinations of actions across a longer transaction history, cumulative risk from unrelated capabilities, or separation-of-duties at that broader scale. I think this eventually pushes the Gateway toward genuinely stateful, history-aware authorization rather than the simpler per-action model I have now, and I don't have that built. ⚪

---

## 5. The Semantic Verification Pipeline

### 5.1 Why I don't let an LLM translate schemas at transaction time

If a model translates `{"order_qty": 500}` into `{"quantity": "500"}`, or reads a date as day/month when it meant month/day, that's a silent, high-stakes error that a protocol-level firewall won't catch — because syntactically nothing looks wrong. Two agents can also convince each other that `cancel_order` means the same thing on both sides ("void the order outright" vs. "file a cancellation request pending approval") when it doesn't. I think this kind of **semantic false agreement** is a harder and more dangerous problem than anything cryptographic in this system, because it fails silently rather than loudly.

### 5.2 What I do instead: propose, verify, freeze

Rather than letting an LLM re-derive a schema mapping at execution time, the idea is to treat mapping generation as a one-time compilation step:

1. **Propose** — an LLM looks at both schemas and proposes a mapping.
2. **Verify** — the mapping goes through automated checks: required fields present, no lossy numeric conversions, round-trip identity for critical identifiers (mapping an ID forward and back returns the same ID), and property-based fuzz testing against a large number of synthetic payloads.
3. **Freeze** — once verified, the mapping is compiled into a small, sandboxed WebAssembly module with no filesystem or network access, hashed, and that hash (`mapping_hash`) is stamped directly into the capability definition within the `InteractionContract`. From that point on, the runtime executor loads the exact compiled Wasm bytecode matching that content hash, completely bypassing any live model inference.

```text
Schema A + Schema B → LLM proposes mapping → automated verification (types, round-trip, fuzzing)
                                                        │
                                                 compiled to sandboxed Wasm, content-hashed
                                                        │
                                          referenced in the contract; runtime uses the compiled artifact, not the LLM
```

⚪ This whole pipeline is a design goal. I've built and tested the "propose" and "freeze into Wasm" steps individually; I haven't yet built the full automated verification gate (the round-trip and fuzzing checks) as a single pipeline that blocks activation on failure. In other words: the idea is sound and partially prototyped, but don't read this section as "solved."

---

## 6. Cryptographic Attestation and Execution Grants

This is the part of the system I have the most actual confidence in, because it's the part that's been running the longest in my own testing.

### 6.1 Mutual attestation

A contract doesn't become active on one party's say-so. Both sides compute the same canonical hash independently, sign it, and exchange signatures; the contract only activates once both signatures verify against the identical hash. If the two computed hashes don't match, activation fails outright — there's no "close enough." 🟢

### 6.2 Execution grants

When an agent wants to actually do something under an active contract, the Trust Gateway checks it against the contract and current policy/velocity state, and if it passes, issues a short-lived, narrowly scoped execution grant (I use a signed JWT) that includes:

- a short time-to-live (tens of seconds, not minutes),
- the exact hash of the canonical arguments (`input_hash`) — the grant is valid for this specific call, with these specific arguments, not "a call like this one,"
- the contract ID and its hash, so every execution traces back to the exact agreement it happened under.

🟢 *This binding — grant valid for one action, argument-hash-locked, short TTL — is implemented and is the core security property of the system.*

Here is the exact claim structure of an issued `ExecutionGrant` JWT payload:

```json
{
  "iss": "did:web:company.example:trust-gateway",
  "sub": "did:key:zAgentProcurementWorker",
  "aud": "did:web:company.example:executor-host",
  "jti": "grant_0191c7b5-22a4-7000-91c2-3e817c200042",
  "iat": 1790870400,
  "exp": 1790870460,
  "tool_name": "io.company.orders.create@v1",
  "input_hash": "sha256:d59b207559e355c70752b047a0640df14541bfd6e3be4ff28e67a48d88e6de02",
  "contract_id": "ctr_0191c7a4-82a1-7000-84c1-6e792c300001",
  "contract_hash": "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
}
```

**One thing I want to be precise about, because it's easy to overstate:** a short TTL and a unique grant ID make replay much harder, and the executor host enforces single-use verification via a JetStream KV nonce store (`grant_nonces`), but I'm not yet claiming airtight, verified single-use enforcement across every distributed executor topology. That would require me to show the replay cache is consistent and race-free across all deployment configurations, and I haven't done that verification work. Treat "short-lived and single-purpose" as accurate; treat "provably replay-proof in all conditions" as not yet earned.

### 6.3 The executor

The executor is deliberately dumb: it verifies the grant's signature, checks it hasn't expired, checks the argument hash matches exactly, checks the tool ID matches, and only then executes. It doesn't call an LLM, doesn't interpret policy, doesn't make judgment calls. 🟢

---

## 7. Threat Model and Design Invariants

I'll use the STRIDE categories loosely rather than trying to make this exhaustive.

| Attack | Where it hits | What's supposed to stop it |
|---|---|---|
| Prompt injection in a negotiation message | Semantic plane | The proposal still has to pass through the deterministic Gateway; an LLM being tricked into proposing an unlimited value doesn't matter if policy still clips it to the real limit |
| Replaying a previously valid signature | Attestation | Signatures bind to the exact contract hash plus a fresh nonce tied to the negotiation session; previously-seen attestations are rejected |
| Silently modifying a stored contract after activation | Storage | The Gateway recomputes the stored contract's hash on every evaluation and compares it to the attested hash; any drift suspends the contract immediately |
| Bypassing the Gateway and hitting the executor directly | Execution | Executors have no ambient credentials and only accept requests carrying a valid, signature-verified grant with a matching argument hash |
| Many small transactions adding up to something large | Cumulative risk | Sliding-window velocity and cumulative-exposure limits, not just per-transaction limits (see §4.2) |
| Agent runaway loops & recursion storms | Execution flow | Layer 0 Call-Chain Guard enforces execution depth bounds, cycle detection, per-tool frequency caps, and server-side session integrity tracking (§4.4) |

### 7.1 Design invariants I'm aiming to hold

I originally labeled these "formal, mathematically proven invariants." That was overclaiming — I haven't proven any of them in the mathematical sense, and nobody outside this project has tried to break them. Here's the honest version: these are the properties the architecture is *designed* to guarantee. I believe the design is sound; I don't yet have evidence beyond my own testing.

1. No agent can mutate an enterprise system without going through a verified execution grant.
2. Agents hold no long-lived operational credentials.
3. A contract can never grant more than enterprise policy independently allows.
4. A contract can't activate without mutual, verified attestation over the identical hash.
5. Every execution grant is bound to the exact argument hash of the action it authorizes.
6. Every grant has a unique ID and a short TTL, intended to make reuse hard (see the honesty note in §6.2 about the limits of this claim).
7. An agent can't negotiate terms beyond what its own delegated authority allows.
8. Capabilities reference a fixed registry, not agent-invented tool names.
9. Executors never run an LLM or evaluate policy themselves.
10. Contracts that are revoked, suspended, or expired can't mint new grants.
11. Schema transformations run through versioned, content-addressed compiled artifacts, not live inference, once frozen (§5.2).
12. Failures return typed error codes without leaking internal state, prompts, or stack traces.
13. Execution plans cannot exceed call-chain recursion depth, cycle, or frequency bounds, and client agents cannot forge or reset call-chain history.


I'd genuinely like feedback from people who do adversarial security work on which of these are actually well-founded and which are wishful thinking.

### 7.2 What this list doesn't cover

Two things I know are missing and haven't solved: **failure and dispute semantics** (what happens when an order is created, inventory reservation fails, payment already cleared, and the network response never arrives — the classic distributed-systems problem of retries, idempotency, partial failure, and reconciliation, which this architecture doesn't make disappear), and **discovery trust** (how does Company A know it actually reached Company B's real agent, rather than an impersonation — which points back to identity infrastructure this document mostly assumes rather than solves).

---

## 8. Operational Trace and Audit Receipts

### 8.1 Operational Trace Sequence

The lifecycle of an interaction contract from capability discovery to execution and audit logging proceeds as follows:

```text
Buyer Agent              Supplier B2B Agent           Trust Gateway              Isolated Executor
     │                           │                          │                            │
     │ 1. Discover Capabilities  │                          │                            │
     ├──────────────────────────►│                          │                            │
     │ 2. Propose Contract Draft │                          │                            │
     ├──────────────────────────►│                          │                            │
     │ 3. Counter / Accept       │                          │                            │
     │◄──────────────────────────┤                          │                            │
     │ 4. Mutual Ed25519 Signing │                          │                            │
     │◄═════════════════════════►│                          │                            │
     │ 5. Activate Contract      │                          │                            │
     ├───────────────────────────┼─────────────────────────►│                            │
     │                           │   Validate signatures,   │                            │
     │                           │   mark state = ACTIVE    │                            │
     │ 6. Propose Action         │                          │                            │
     ├───────────────────────────┼─────────────────────────►│                            │
     │                           │   Check limits & velocity│                            │
     │                           │   Mint ExecutionGrant    │                            │
     │                           │◄─────────────────────────┤                            │
     │ 7. Invoke Action          │                          │                            │
     │    (Grant + Arguments)    │                          │                            │
     ├───────────────────────────┼──────────────────────────┼───────────────────────────►│
     │                           │                          │    Verify Grant signature  │
     │                           │                          │    Verify input_hash match │
     │                           │                          │    Execute side effect     │
     │ 8. Sealed Audit Receipt logged to append-only stream │◄───────────────────────────┤
     │◄─────────────────────────────────────────────────────┼────────────────────────────┤
```

### 8.2 Audit Receipts and Dispute Resolution

Every completed execution produces a signed audit receipt — not a mutable log row, but an append-only record — linking the grant, the contract, the exact input and output hashes, the parties' DIDs, and (where relevant) financial and ERP reconciliation references:

```json
{
  "receipt_id": "rcpt_0191c7be-4010-7000-85f2-9a81e3400088",
  "grant_jti": "grant_0191c7b5-22a4-7000-91c2-3e817c200042",
  "contract_id": "ctr_0191c7a4-82a1-7000-84c1-6e792c300001",
  "contract_hash": "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
  "tool_id": "io.company.orders.create@v1",
  "input_hash": "sha256:d59b207559e355c70752b047a0640df14541bfd6e3be4ff28e67a48d88e6de02",
  "output_hash": "sha256:4a6f20e791b8d23e59048a16db32ec840134f0d2c9498b3f462f7902d2aa86c5",
  "parties": {
    "buyer_did": "did:web:buyer.corp.example",
    "supplier_did": "did:web:supplier.logistics.example"
  },
  "execution_outcome": { "status": "SUCCESS", "duration_ms": 142 },
  "timestamps": {
    "grant_issued_at": "2026-09-30T14:20:00.000Z",
    "executed_at": "2026-09-30T14:20:00.142Z"
  }
}
```

The intended dispute-resolution story: if Company A claims a transaction was unauthorized, or Company B claims goods were never reserved, the chain from receipt → grant → contract → mutual signatures should settle it — each link is a hash comparison, not a matter of anyone's word. 🟡 *The receipt schema and hash chain are implemented; I haven't run this through an actual disputed-transaction scenario end to end.*

---

## 9. How This Relates to Other Work

A quick, honest comparison — this is my own understanding, not something I've verified with the teams involved, and it will likely be out of date by the time you read it.

At a glance, the layers stack like this:

| Layer | Protocol / Concept | Primary Role | Analogy |
| :--- | :--- | :--- | :--- |
| **Tool Interface** | **MCP** (Model Context Protocol) | How an agent talks to its internal tools and data sources | The USB port connecting a computer to peripherals |
| **Communication** | **A2A** (Agent-to-Agent) | How two agents discover each other and exchange messages | The telephone line between two offices |
| **Relationship** | **Interaction Contract** | The negotiated operational agreement defining what the two parties agreed to do | The signed business agreement between two companies |
| **Enforcement** | **Trust Gateway** | The deterministic bouncer ensuring actions strictly match the contract and policy | Legal and compliance with the key to the vault |

You don't have to choose between these — they solve completely different layers of the problem. A2A gives agents the wire protocol to talk. MCP gives them tools to execute. Interaction Contracts define what they are allowed to agree on. Trust Gateways guarantee neither side can break the rules.

In more detail:

- **MCP** is about an agent talking to tools and resources. It's not trying to solve what I'm describing here, and NICP could plausibly sit on top of an MCP-connected agent rather than replace anything about MCP.
- **A2A** is about agent-to-agent discovery, capability exchange, and task handoff. I think of NICP as a layer above A2A: assume A2A handles how two agents talk to each other; NICP is about what relationship they're allowed to establish and what stops either side from acting outside it.
- **Payment-network agent protocols** (Visa/Mastercard agent-payment initiatives) solve credential tokenization and payment authorization specifically — a narrower, adjacent problem to the broader capability-and-constraint negotiation this project is trying to address.
- **Anthropic's Claude Commerce Agents** is the most directly relevant reference point, and I've described how I read it in §1.3: it validates that merchants want the agent on their own side of the boundary, and it deliberately stops short of granting execution authority — which is the gap this project is trying to fill for cases that need to go further than recommend-and-handoff.

I'm not trying to compete with any of these, and I'd rather be wrong about how NICP fits next to them than overstate the fit.

---

## 10. How This Rewrites Integration

Most of this document focuses on security, threat models, and cryptographic guarantees. But I think there's a broader consequence of this architecture that's worth stating explicitly, because it may end up mattering more than any individual protocol detail: **it fundamentally changes how companies integrate with each other.**

### 10.1 The integration boundary moves up

Today, connecting two enterprises means agreeing on endpoints, schemas, authentication scopes, webhooks, rate limits, and error codes — then writing bespoke glue code to bridge the differences. Every new counterparty means a new integration project. Every schema change means a coordinated migration. The cost grows roughly with the square of the number of participants.

Negotiated Interaction Contracts change where the boundary sits:

```text
  TODAY                                              WITH INTERACTION CONTRACTS
  ─────                                              ──────────────────────────
  Company A ──[Custom Code]──> Company B API          Company A Agent ──[Negotiate]──> Company B Agent
  (months of specs, mapping, testing)                 (runtime discovery, semantic mapping, signed contract)
  (per-pair, per-version, per-endpoint)               (per-relationship, versioned, machine-enforced)
```

The underlying APIs don't disappear — your ERP, banking APIs, inventory systems remain deterministic, reliable, and auditable. What changes is that you no longer need to spend months standardizing every endpoint before two organizations can do business. The agent handles the semantic reconciliation; the contract locks down the terms; the gateway enforces the rules.

### 10.2 What this means concretely

1. **Onboarding new partners drops from months to hours.** Instead of a multi-month integration project per counterparty, two agents discover capabilities, negotiate constraints, verify identities, and activate a contract — all at machine speed. The human role shifts from writing glue code to reviewing and approving the negotiated terms.

2. **Schema heterogeneity becomes a negotiation problem, not an engineering problem.** Company A calls it `shipping_address`; Company B calls it `destination_facility`. Today, a developer writes a mapping. In this model, agents propose and verify mappings at contract time, compile them to deterministic artifacts (§5.2), and neither side has to adopt the other's naming conventions.

3. **The long tail of B2B relationships becomes viable.** The reason most small and mid-size enterprises are locked out of automated B2B integration is cost — building and maintaining a custom integration for a partner who sends three orders a month doesn't pencil out. When the integration cost drops to negotiating a contract, even low-volume relationships become automatable.

4. **APIs become the execution engine, not the integration surface.** This is the shift I think matters most. APIs remain exactly what they're good at — deterministic, versioned, testable interfaces to internal systems. But the surface that two companies negotiate over is no longer the API itself; it's a higher-level agreement about capabilities, constraints, and obligations. The API is downstream of the contract, not the contract itself.

### 10.3 What I'm not claiming

I want to be precise about scope:

- I'm not claiming this eliminates the need for well-designed APIs. It depends on them.
- I'm not claiming agents can negotiate arbitrarily complex multi-party supply chain agreements today. The current model is bilateral.
- I'm not claiming the semantic mapping pipeline (§5) is production-ready. It's the least mature piece.
- I am claiming that the architectural pattern — negotiate meaning at the agent layer, enforce terms at the gateway layer, execute through existing APIs at the system layer — is a fundamentally different integration model than what exists today, and one that could reduce the cost and timeline of B2B integration by an order of magnitude for the relationships it applies to.

---

## 11. Where This Goes Next

Concretely, and modestly:

- Keep open-sourcing the pieces that are actually stable — the contract canonicalization/hashing engine and the state machine are the best candidates right now.
- Get real, external scrutiny on the threat model and the invariants list in §7 before making any stronger claims about them.
- Actually build the pieces marked ⚪ in this document before describing them as anything more than intentions.
- If and when there's working code and outside interest behind a specific piece of this (the execution-grant binding pattern seems like the strongest candidate), look at whether an informal write-up to a relevant IETF or OpenID working group mailing list makes sense — as a discussion contribution, not a unilateral draft submission claiming priority.

I'd rather this document age well than sound impressive today.

---

## 12. References

1. RFC 8785 — JSON Canonicalization Scheme (JCS)
2. RFC 8949 — Concise Binary Object Representation (CBOR)
3. W3C Decentralized Identifiers (DIDs) v1.0
4. W3C Verifiable Credentials Data Model v2.0
5. UCAN Specification v0.10
6. RFC 7519 — JSON Web Token (JWT)
7. RFC 8032 — EdDSA
8. Anthropic, "Claude Commerce Agents" reference blueprint, released September 2, 2026
9. Public reporting on OpenAI's ChatGPT Instant Checkout launch (September 2025) and retirement (March 2026) — CNBC, The Information, Forrester
10. fcn06, ["The Agent Economy: Why Agents Must Negotiate Agreements, and How It Rewrites Integration"](https://dev.to/fcn06/the-agent-economy-needs-a-trust-layer-49c), dev.to, September 2026
