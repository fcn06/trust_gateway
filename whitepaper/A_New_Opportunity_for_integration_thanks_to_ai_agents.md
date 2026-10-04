# Can Agents Replace Per-Partner Integration Specs? Notes From One Experiment

**Status:** Working draft, personal project. Not peer-reviewed, not a standard, not a product  
**Author:** fcn06 (Lianxi / Trust Gateway project, [lianxi.io](https://lianxi.io))  
**Date:** October 2026  
**Where this lives:** GitHub ([fcn06/trust_gateway](https://github.com/fcn06/trust_gateway)) and lianxi.io

---

## Summary

- **The question.** When two companies want to exchange information automatically, could AI agents that represent each company negotiate the interface at runtime, instead of people writing a detailed specification upfront for every pair of partners?
- **The claim I'm tentatively making.** The specification probably doesn't disappear. It may **move**: from a document written *per pair of companies* to a self-description and a policy written *once per company*, plus a small, machine-readable agreement negotiated at runtime for each relationship.
- **What the experiment showed.** The *mechanics* can work end to end. Two agents negotiated bounded terms, within limits set in advance by policy. Both sides signed the identical agreement, and deterministic software executed a real action under it.
- **What it did not show.** The idea rests on one assumption: that language models can reliably reconcile the *meaning* of two companies' data. **My experiment didn't test that assumption.** The interface already existed, and the field mapping was written by hand. Until that's tested, the thesis is a hypothesis.
- **What would make me drop it.** Section 9 proposes a small benchmark with pre-committed falsification thresholds: if negotiated mappings still let through more than 5% of seeded semantic traps (about 3 of 50) across repeated runs even with worked examples, or if a single LLM proposing the mapping alone does as well as two negotiating agents, the negotiation thesis fails. Section 9 also lists the questions where practitioners' input would help most.

> **Disclosure.** I'm building a related open-source project (the Trust Gateway, described below). I have an interest in this idea working. I've tried to compensate by stating limits plainly, but you should read this paper knowing that.

---

## How to read this document

This paper is written for people who work in **enterprise integration**: EDI, B2B gateways, iPaaS, API design, partner onboarding. It is self-contained. It doesn't assume familiarity with AI-agent protocols or decentralized identity. Key terms are explained where they first appear, and Appendix B collects them in a glossary.

I try to keep three things apart:

1. **What I actually built and observed.**
2. **What I think it suggests**, stated as hypotheses.
3. **What I don't know**, stated as questions.

Each substantive claim about the implementation carries a tag:

- 🟢 **Implemented and open source.** You can read and run the code (see Appendix A).
- 🟡 **Implemented, not yet public.** It exists in my private build. **You cannot verify these claims today.** Please weigh them accordingly; I'd weigh them that way myself if someone else made them.
- ⚪ **Idea, not built.** A proposal for discussion.

Some honesty notes:

- **One person, few scenarios.** Everything rests on a handful of scenarios (freight booking, parts procurement) that I designed myself. It's an experiment, not a field study.
- **No cost measurements.** I haven't compared this approach with a classic integration in time, cost, or error rate.
- **Integration is a mature field.** EDI, ebXML, RosettaNet, OpenAPI, and decades of integration patterns exist for good reasons, and several earlier efforts tried something close to this (Section 4). I'm not claiming any of that is obsolete.

---

## Table of Contents

1. [Where Integration Effort Goes Today](#1-where-integration-effort-goes-today)
2. [The Hypothesis](#2-the-hypothesis)
3. [The Architecture in Brief](#3-the-architecture-in-brief)
4. [Prior Art: This Has Been Tried Before](#4-prior-art-this-has-been-tried-before)
5. [What Was Built and Observed](#5-what-was-built-and-observed)
6. [What the Experiment Did Not Show](#6-what-the-experiment-did-not-show)
7. [Does the Specification Disappear, or Move?](#7-does-the-specification-disappear-or-move)
8. [Directions Worth Exploring](#8-directions-worth-exploring)
9. [How to Test This, and Where I Need Help](#9-how-to-test-this-and-where-i-need-help)
10. [Risks and Reasons This Might Not Work](#10-risks-and-reasons-this-might-not-work)
11. [Status Matrix](#11-status-matrix)
12. [References](#12-references)
13. [Appendix A: Where to Find the Code](#appendix-a-where-to-find-the-code)
14. [Appendix B: Glossary](#appendix-b-glossary)
15. [Appendix C: Benchmark Protocol and Falsification Design](#appendix-c-benchmark-protocol-and-falsification-design)

---

## 1. Where Integration Effort Goes Today

When two companies connect their systems, a familiar sequence usually follows: discover what the partner supports, agree on a specification, map each side's data onto it, exchange credentials, build and test adapters, go live, then maintain the whole thing as both sides change. Most of the effort happens **before** the first useful message flows.

Based on my own experience (I have no hard data on proportions, and they vary a lot by industry), I'd group the work like this:

| Activity | Mostly about… |
| :--- | :--- |
| Discovering what the partner can do | Semantics |
| Agreeing on operations, payloads, error handling | Semantics |
| Agreeing on commercial and operational terms (limits, cancellation, SLAs) | **Business decisions** |
| Mapping internal data models to the agreed format | Semantics, then mechanics |
| Exchanging credentials, certificates, scopes | Mechanics |
| Building and testing adapters, certification | Mechanics |
| Versioning, migrations, reconciliation, disputes | All three |

I've split what is often lumped together as "agreeing on meaning" into two parts, because they behave very differently:

- **Semantic reconciliation** is a translation problem. Is `qty` the same as `quantity_units`? Is a date day-first or month-first? Does `cancel_order` void the order or request a cancellation? Language models can *plausibly* help here, though as Section 6 explains, I haven't tested how well.
- **Business terms** are decisions, not translations. Who bears cancellation risk? What credit ceiling applies to a new partner? An agent doesn't *discover* these. It can only apply rules someone in the company wrote beforehand.

Two more observations will be familiar to anyone in the field. The number of bilateral relationships grows faster than the number of participants; standards like EDIFACT, Peppol, or FHIR exist largely to tame that, and they take years to adopt. And even with a shared format, semantics drift between partners.

**Open question:** Is my intuition right that semantics and terms make up a large share of integration effort? Or is the real bottleneck usually elsewhere, in procurement, legal review, or internal prioritization, which no agent would touch?

---

## 2. The Hypothesis

> **A company could expose a B2B agent as its external interface. The agent knows the company's capabilities, vocabulary, and policy. When it meets another company's agent, the two negotiate a bounded, machine-readable interaction agreement: what will be exchanged, under what terms, and how fields correspond. Execution under that agreement then goes through deterministic software, not through the agents.**

By **interaction agreement** I mean a machine-readable record of what the two agents agreed: parties, purpose, allowed operations, limits, data rules, and validity period. It is **not a legal contract**, but a technical agreement that software can enforce. (In the code, and in my earlier writing, it's called an *Interaction Contract*. I've switched terms here because "contract" invites a legal reading.)

If that worked, a company would describe itself **once**, to its own agent, instead of once per partner. The part that scales badly, the bilateral part, would be negotiated at runtime.

What I'm **not** proposing:

- **Not "LLMs replace APIs."** Two models chatting freely across company boundaries isn't auditable or repeatable, and it's exposed to manipulation. The APIs and back-office systems stay. Agents sit *in front of* them.
- **Not "no specification at all."** Section 7 argues the specification moves rather than disappears.
- **Not "agents decide what is allowed."** Agents negotiate semantics and propose terms. What a company actually permits is decided by its own written policy, enforced by deterministic software. A negotiated agreement can only narrow that space, never widen it.
- **Not a replacement for top-down Hub-and-Spoke mandates.** In concentrated supply chains (retail, automotive, aerospace), dominant hubs like Walmart, Airbus, or Amazon do not negotiate interfaces at runtime; they hand suppliers an AS2/EDI or REST specification and require byte-for-byte compliance. I am not suggesting agents will change that dynamic. If this architecture has an economic wedge, it is more likely in relationships where neither party can dictate the spec: **the mid-market long tail**, **horizontal SaaS-to-SaaS ad-hoc connections**, or **multi-carrier spot logistics** (see §10.2).

---

## 3. The Architecture in Brief

To understand what the experiment did, you need a rough picture of three layers:

```text
SEMANTIC LAYER   (probabilistic: an LLM is involved)
  Each company's B2B agent: discovers the partner, negotiates, proposes actions
        │
        ▼
AGREEMENT LAYER  (deterministic: signed, hashed, versioned)
  Interaction agreement: the "specification", produced at runtime
        │
        ▼
EXECUTION LAYER  (deterministic: no LLM)
  Trust Gateway checks every proposed action against the agreement and the
  company's policy, issues a one-time execution grant, and only then do the
  existing ERP / inventory / payment systems act
```

The **Trust Gateway** is a deterministic program, with no LLM inside, that sits between a company's agent and its internal systems. The agent can only *propose* actions. The gateway checks each proposal and, if it passes, issues an **execution grant**: a short-lived, signed authorization for that one action with those exact arguments. The back-office system checks the grant before acting. After a successful action, the gateway issues a signed **execution receipt** that can serve as evidence later.

Four properties matter for the integration question:

1. **The agent holds no credentials** to internal systems. It can only propose.
2. **What a company allows is the intersection** of three things: the negotiated agreement, the company's own policy, and the verified identity of the partner. If two agents agree on €50,000 but policy caps new partners at €10,000, €10,000 applies.
3. **The agreement is a signed artifact.** Whatever the agents said to each other, what binds both sides is a document both signed, byte for byte.
4. **Execution grants map to immutable ledger entries.** Enterprise backends (SAP, Oracle NetSuite) rely on rigid master data, strict three-way matching, and batch accounting. A runtime agreement cannot simply bypass those controls. In this design, the execution grant binds the specific, immutable agreement hash and resolved parameters, so that downstream actions remain auditable and can reconcile with existing financial ledgers without silent drift.

In EDI terms, the agent plays roughly the role of the people who negotiate a trading-partner agreement and implementation guide. The agreement plays the role of those documents. The gateway plays the role of the translator and validation layer that rejects non-conforming messages. The difference is that the first two happen at runtime rather than in workshops.

---

## 4. Prior Art: This Has Been Tried Before

Readers from the integration world will rightly ask how this differs from earlier efforts. Here is my understanding. Please correct me where it's incomplete.

- **ebXML CPP/CPA** (OASIS, later ISO 15000-1). In ebXML, each partner publishes a *Collaboration-Protocol Profile* (CPP) describing its capabilities, and two partners form a *Collaboration-Protocol Agreement* (CPA) that both use to configure their systems. This is the closest ancestor of what I describe: "describe yourself once, form an agreement per partner" is exactly the CPP/CPA idea. The CPPA 2.0 specification is explicit that, while its schemas are designed to make composing and negotiating agreements easier, **the negotiation process itself is outside its scope**. It discusses negotiation only in a non-normative appendix. A standardized negotiation protocol was anticipated at the time, but as far as I can tell it never became a widely deployed standard. In practice, CPAs were typically produced by matching profiles with tooling and human review. The CPA also mostly covered messaging parameters (transport, security, reliability, business-process binding). It assumed both sides already shared the business document semantics.
- **RosettaNet PIPs** (Partner Interface Processes) standardized both the business process and the documents for specific interactions in electronics and high-tech supply chains. They reduced ambiguity by agreeing on semantics industry-wide, in advance.
- **FIPA Contract Net and agent communication languages** (from multi-agent systems research, 1980s–2000s) defined how software agents could announce tasks, bid, and award contracts. They had protocols for negotiation, but they relied on shared ontologies that had to be built by hand.
- **Classic schema matching and ontology alignment** is a long research line on automatically finding correspondences between two schemas or vocabularies. It produced useful tools and benchmarks, but fully automated, reliable matching never became routine practice. Humans stayed in the loop.
- **LLM-based schema matching and ontology alignment (2022 onwards).** This is the literature closest to my key assumption, and it is active. Narayan et al. showed that prompted foundation models could perform data-wrangling tasks, including schema matching, without task-specific training. Parciak et al. studied LLM schema matching experimentally and found results depend strongly on how much context (names, descriptions, instances) the prompt includes. They position LLMs mainly as assistants that reduce human verification effort. ReMatch and Magneto combine retrieval or small models with LLMs to make matching scale. In ontology alignment, OLaLa reported that zero- and few-shot prompting can approach supervised systems on evaluation tracks, LLMs4OM proposed a retrieval-augmented pipeline, and Agent-OM used LLM *agents* for matching. OAEI-LLM specifically studies LLM *hallucinations* in matching. Taken together, as I read it, this work suggests LLMs can help substantially with matching, usually on public benchmarks and with a human or a verification step at the end. I haven't found work where two independent agents representing different organizations *negotiate* a mapping and bind it into an enforceable agreement, but I may have missed it.

**What, if anything, is different now?** Tentatively:

1. **The semantic step.** Every earlier industrial approach either required shared semantics in advance (CPA, PIPs, FIPA ontologies) or relied on matching algorithms with limited understanding of context. The LLM literature above suggests that gap may be narrowing. Whether it narrows enough, in a two-party setting with no shared author, is precisely the untested assumption.
2. **Business terms within policy.** A CPA configures *how* to exchange. The interaction agreement also carries *bounded business terms* (limits, validity, data rules), negotiated within each company's policy and enforced per action at runtime.
3. **Per-action enforcement.** Each action under the agreement is checked and authorized individually, with signed evidence afterwards, not just configured once.

It's quite possible these differences are smaller than they look. If the semantic step doesn't work reliably, this approach mostly re-implements CPP/CPA with newer cryptography. **The obvious question is why ebXML CPA saw limited adoption, and whether those reasons apply here too.** My suspicion, discussed in §10.1, is that "describe yourself once" depends on companies keeping that description accurate, which they've historically found hard. I'd especially welcome views from people who deployed it.

---

## 5. What Was Built and Observed

This section describes capabilities, not code. File locations are in Appendix A.

### 5.1 A single agreement object 🟢

The interaction agreement holds, in one versioned object: the two parties (identified by DIDs: W3C-standard identifiers tied to cryptographic keys, such as `did:web:company-b.com`, which play roughly the role of a certificate in AS2 or a partner ID in an EDI trading-partner agreement), a declared purpose, a list of allowed capabilities and operations (e.g. "orders: quote, create, status, cancel"), limits (maximum transaction value in integer cents to avoid rounding issues, allowed geographies, maximum units, cancellation terms), data rules (allowed and prohibited data classes, maximum response size, retention), obligations, settlement terms, and a validity window.

For integration, this is notable mainly because it gathers in one place what is usually spread across an API specification, an SLA, a data-processing agreement, and a commercial annex. Whether that bundling is wise is discussed in §7.3.

### 5.2 Both sides agree on exactly the same bytes 🟢

Before signing, the agreement is written in a canonical form (RFC 8785) and hashed. Each side signs the hash. The agreement only becomes active when both signatures verify against the *identical* hash. If the two sides computed different hashes, activation fails. This turns a negotiation into an artifact that both parties can later point to.

### 5.3 Bounded negotiation and versioning 🟢

Negotiation has hard limits: by default at most 8 rounds, a timeout, and a size cap. An agreement goes through a fixed set of states (draft, proposed, counter-proposed, accepted, attested, active, suspended, revoked, expired, superseded). Changing an active agreement creates a new version linked to the previous one by its hash. That is a primitive form of **interface versioning**, produced by the negotiation itself rather than by a release process.

### 5.4 An agent that negotiates without holding authority 🟢 / 🟡

The B2B agent 🟡 receives requests from external agents, authenticated with OAuth2 or a DID-based token. It reaches the control plane only through four tools 🟢:

| Tool | Integration analogue |
| :--- | :--- |
| Inspect counterparty | Partner vetting: "have we worked with them before?" |
| Propose or amend agreement | Drafting the trading-partner agreement |
| Verify and activate agreement | Both sides signing it |
| Present / store receipts | Exchanging references and evidence of past performance |

New partners start with low limits ("cold start"). They can unlock higher limits by presenting signed execution receipts from companies the host already recognizes.

**Exception-based human escalation ("integration co-pilot"):** Enterprise integration rarely tolerates autonomous black boxes; automation is only acceptable if the blast radius is bounded. In this design, the agent cannot finalize agreements that stray outside pre-configured policy corridors (such as transactions above a conservative limit, unfamiliar cancellation terms, or low-confidence semantic matches). Instead, the negotiation pauses and surfaces an exception to a human review queue. A specialist inspects the structured diff, checks the proposed mapping against the worked examples, and decides whether to approve, amend, or reject activation. The agent acts as a drafting assistant—an integration co-pilot—rather than an unsupervised authority.

### 5.5 A four-turn negotiation that ends in an execution 🟡

With a live LLM on the seller side:

1. The buyer asks to book €15,000 of freight. The seller's agent finds no history and explains that a new partner gets a lower ceiling.
2. The buyer presents a signed receipt from another recognized company and proposes terms. The seller's agent verifies it and **counter-proposes** different terms (ceiling, settlement period, cancellation notice).
3. The buyer signs the agreement's hash, and the agreement becomes active.
4. The buyer requests a specific shipment. The gateway checks it against the agreement, it's executed, and a signed receipt comes back.

A version of the same lifecycle without any LLM, fully deterministic, is open source 🟢.

**What I'd carefully conclude:** within a capability that already existed and a vocabulary both sides shared, the two parties went from "never met" to "executing under signed, bounded terms" **without a new integration project for that specific pair of partners**. It was *not* "without any integration work." The capability, its parameters, and the field mapping were all prepared beforehand (see §6).

### 5.6 A very simple field mapping 🟢

A small translation step maps an agreed operation onto an internal tool and renames fields (e.g. `destination_address → target_addr`). It works and is tested. It is also hand-written, flat (renames only), and, today, not part of the signed agreement.

### 5.7 Data rules enforced on responses 🟢

Outgoing responses are checked against the agreement's data rules: a maximum size, and a small set of prohibited data classes (e.g. email-like personal data, card-number-like financial data). That's a fragment of what a data-processing annex would say, enforced at runtime. The detection is basic pattern matching, not a full classifier.

---

## 6. What the Experiment Did Not Show

I think this section matters more than the previous one.

1. **The core assumption was not tested.** The thesis depends on agents reliably reconciling the semantics of two companies' data. In my scenarios, the agents never had to. The capability already existed with a known identifier and known parameters.
2. **The agents negotiated terms, not the interface.** What they negotiated (ceiling, settlement period, cancellation notice) were *business terms*, chosen within limits that my policy file set in advance. Per §1, those are decisions applied from policy, not semantic reconciliation.
3. **The field mapping was hand-written** and isn't covered by the signatures.
4. **Both sides were mine.** The same person built buyer and seller, with shared assumptions about naming, money representation, and identity. Two independently built agents would be a very different test.
5. **One structured domain.** Freight and procurement are relatively well structured. I have no evidence for domains where semantics are the hard part (insurance claims, customs, healthcare).
6. **No measurements** of time, cost, convergence, or subtle errors.
7. **No partner without an agent.** Most real partners won't have one for a long time.

**Honest summary:** the experiment shows that a runtime-negotiated, cryptographically bound, deterministically enforced agreement can work end to end. It doesn't show that agents can produce the *semantic* content of an integration specification reliably. The second claim is the one that would change integration, and it remains untested.

---

## 7. Does the Specification Disappear, or Move?

### 7.1 What still has to exist before negotiation

In the architecture I built, these must exist before two agents can negotiate:

- a **capability catalogue** per company: stable identifiers (e.g. `orders@v1`) and their parameters;
- an **enterprise policy** per company: what the agent may agree to, for which kind of partner;
- a **thin shared envelope** between companies: how to express identity (DIDs), money (integer minor units plus currency), time (UTC), and the agreement format itself.

None of these is per-partner. That is the potentially interesting shift:

```text
TODAY                                      HYPOTHESIS
─────                                      ──────────
Specification written per PAIR             Catalogue + policy written once per COMPANY
(A↔B, A↔C, B↔C, …)                         + a thin shared envelope
                                           + a negotiated, signed agreement per relationship
```

Separating semantics from terms (§1) sharpens this. **Much of what moves is policy.** The business decisions that today get settled in each partner negotiation would be written once, as rules, and applied to every partner. Only the semantic reconciliation would happen pairwise at runtime. Whether that's a gain depends on how reliable and cheap that reconciliation is, and I don't know.

### 7.2 Is this just a new standard in disguise?

Partly, yes. The shared envelope *is* a specification, and someone has to govern it. My tentative answer is that it could be much **thinner** than a domain standard: identity, money, time, and the agreement format, not what a purchase order looks like.

But to negotiate reliably, agents may well need shared domain vocabularies after all. In that case existing standards (UBL, EDIFACT, FHIR) become *more* valuable, as anchors for negotiation (see §8.3).

### 7.3 One object, or several?

Commercial terms and technical mapping change at different speeds and are owned by different people. My implementation bundles them into one object, and leaves the mapping outside the signed part. I suspect an envelope of separately versioned parts would be more correct, but I haven't settled on a design.

### 7.4 The lifecycle, stage by stage

| Stage | What might change with negotiating agents |
| :--- | :--- |
| Partner discovery | Agent resolves the partner's identity and asks what it can do (no public capability-advertisement mechanism yet ⚪) |
| Trust bootstrapping | Low limits for new partners; signed receipts from known partners unlock more 🟢 |
| Specification | Terms are negotiated 🟢; the shape of the exchange is not ⚪ |
| Data mapping | Hand-written today 🟢; agent-proposed and verified mapping ⚪ |
| Security onboarding | DIDs, mutual signatures, one-time grants 🟢 (this may just move effort into key management) |
| Testing / certification | Signed worked examples and canary transactions ⚪ (see §8.1) |
| Go-live | Agreement becomes active 🟢; exception-based human sign-off above semantic drift or financial risk thresholds ⚪ (partly prototyped) |
| Change management | New version linked by hash 🟢; automatic renegotiation triggers ⚪ |
| Disputes | Signed chain receipt → grant → agreement 🟢; reconciliation logic ⚪ |
| Offboarding | Agreement revoked or expired; no adapter to decommission 🟢 |

My own reading: agents most plausibly change **specification, mapping, and change management**. Onboarding, disputes, and operations benefit more from the deterministic parts (agreements, grants, receipts) than from the agents. I'd like to know whether practitioners see it the same way.

---

## 8. Directions Worth Exploring

All ⚪. I've kept those that most directly address the gaps in §6.

### 8.1 Executable examples as the semantic anchor

The biggest risk is **false agreement**: both sides sign the same bytes but understand them differently. One way to reduce it is for both parties to sign, alongside the terms, a small set of **worked examples**: "this payload, sent under this agreement, produces this outcome on our side." Each side runs the examples against its own systems before activation, and any disagreement blocks activation.

There is a trap here. **If the agents generate the examples, the check can pass vacuously**: two agents that share a misunderstanding will produce examples that encode it, and those examples will "agree." So the examples must come from each side's **real system behavior**, not from an agent's reading of the schema. That means past transactions (suitably anonymized), existing test fixtures, or outputs recorded from a sandbox of the actual back-office system. Each side contributes examples drawn from its own systems, and the other side must reproduce the stated outcome.

Furthermore, these examples must be validated against **actual backend business validation engines**—not merely tested for JSON or XML schema validity. For instance, the backend engine must be capable of flagging that a VAT-inclusive price was supplied without the required statutory tax breakdown, or that an ordered item unit conflicts with the warehouse packaging master.

Combined with a few **low-value canary transactions** before full limits apply, this would act as an automated, per-relationship certification step. It's much like the test cycles EDI partners already run, but checked at runtime against evidence from real systems.

*Question:* How many examples does it take to catch most semantic mismatches in a typical document type? Is there a practical way to choose them?

### 8.2 Agent-proposed, verified, frozen mapping

```text
A's schema + B's schema
        │
        ▼
Agent proposes a mapping ──► Deterministic checks (syntactic + behavioral)
        │
        ▼
Frozen, hashed mapping artifact ──► hash included in the SIGNED agreement
        │
        ▼
Runtime uses the artifact only; no LLM at execution time
```

The **Deterministic checks** evaluate:
- Syntactic / structural validation:
  - required fields covered
  - no lossy numeric or unit conversion
  - identifiers survive a round trip
- Behavioral / business rule validation:
  - generated test payloads + signed worked examples (§8.1)
  - backend business rule execution (tax, packaging, dates)

The first concrete step would be to bring the existing mapping (or its hash) inside the signed part of the agreement.

**The deterministic validation trap.**
Notice the distinction between syntactic checks and behavioral validation in the checks above. Syntactic checks (`required fields covered`, `no lossy numeric conversion`, `identifiers survive a round trip`) are necessary structural guards, but they represent a seductive trap: **the most destructive B2B integration bugs pass all three checks cleanly**. For example:
- Mapping `NetPrice` to `GrossPrice`: both are valid `decimal` types, both survive round-trip conversion without precision loss, and mandatory field requirements are satisfied—yet every invoice generated under this mapping will miscalculate tax and trigger financial reconciliation failure.
- Mapping `RequestedDeliveryDate` to `PromisedShipDate`: identical ISO-8601 timestamps, but contractually opposite meanings (buyer demand vs. supplier commitment).
- Mapping `PackQuantity` to `ItemQuantity` where pack size happens to be 1 in initial synthetic tests, silently failing in production when a 12-pack carton is shipped.

Deterministic syntactic checks cannot catch semantic divergence; they verify structural plumbing, not operational truth. That is why I think syntactic validation alone is insufficient: only **behavioral execution against enterprise business rules** (via backend validation logic and the ground-truth worked examples of §8.1) has a chance of catching these divergences before an agreement is frozen into a signed contract.

*Question:* Which classes of mapping errors can deterministic checks catch, and which (two fields with the same type but different business meaning) fundamentally can't be?

### 8.3 Standards as pivots

Rather than competing with UBL, Peppol, EDIFACT, or FHIR, an agent could map its company's model onto a standard **once**, then negotiate only the deviations with each partner.

*Question:* Would that make standards cheaper to adopt for small companies that can't afford a full implementation today?

### 8.4 Partners without an agent

The same interaction agreement could be produced by a company's agent negotiating with a human through a portal, or with a classic API. The agreement layer would then be useful even when only one side runs an agent, which looks like a more realistic adoption path than waiting for both sides.

*Question:* Is a signed, machine-enforceable agreement valuable on its own, regardless of who negotiated it?

### 8.5 Other directions, briefly

Three further areas seem worth exploring:

1. **Exception-based human approval workflows ("Integration Co-Pilot").** In enterprise integration, automation is accepted only if the blast radius is strictly bounded. When an agent encounters ambiguous schemas, low semantic confidence scores, or counter-proposals that push outside conservative policy envelopes, the negotiation should not proceed autonomously. Instead, it pauses and routes an exception to a human review queue. The human reviews the proposed agreement diff and test results, acting as a supervisor who authorizes the final cryptographic signature.

2. **ERP master data impedance matching and ledger idempotency.** In enterprise systems (SAP, Oracle NetSuite, Microsoft Dynamics), partner configurations are fundamentally static: vendor and customer master records store pre-vetted payment terms (e.g., "net 30"), incoterms, tax jurisdiction codes, and bank accounts. If two runtime agents dynamically negotiate a micro-amendment (such as "net 15 days" for a spot order), downstream financial ledgers, automated three-way matching, and nocturnal batch processing can fail or trigger compliance warnings. The gateway must act as an impedance matcher: execution grants should map cleanly into immutable ledger entries with explicit references to the signed agreement, while enterprise policies strictly demarcate which parameters may float dynamically (e.g., spot freight rates within a collar) versus which must remain locked to static ERP master tables.

3. **Automatic renegotiation triggers and multi-tier supply chains.** Automatic renegotiation when a capability changes and chains of agreements across multi-tier supply chains are plausible extensions. They matter less until §8.1–8.2 show the semantic step can work.

---

## 9. How to Test This, and Where I Need Help

### 9.1 A small experiment I can coordinate

The experiment I'd most like is two independent teams, in a domain neither designed, negotiating a real exchange, compared against a classic integration. I can't run that alone. A smaller benchmark I can coordinate, with two external annotators, compares four conditions on resolving semantic correspondences and avoiding traps:

1. **Two negotiating agents** (models from different vendors on each side).
2. **A single LLM** proposing the mapping alone, given both schemas.
3. **A classic schema-matching tool** from the pre-LLM literature, followed by timed human review.
4. Conditions 1 and 2 again, augmented with **worked examples**.

*(Note on test rigor: in an initial synthetic benchmark, worked examples can be generated from simulated system fixtures, but this tests an optimistic version of §8.1; real-system examples from production backends would be a harder test that must be run before production claims.)*

To avoid memorization from pre-training data, the benchmark tests public UBL against vendor JSON, an obfuscated/restructured variant, and a fully synthetic proprietary invoice schema. 

**Pre-committed falsification conditions:**
The thresholds and equivalence margins are arbitrary, but they are committed in advance:
- With at least **50 seeded semantic traps** across multiple document structures and **N=10 repeated runs** per condition (reporting bootstrap 95% confidence intervals over traps):
  - If the **upper bound of the 95% bootstrap confidence interval** for Condition 4 (negotiating agents with worked examples) exceeds **5% of seeded traps** (> 2.5 errors on average), the semantic step is considered too unreliable for unattended integration.
  - If **Condition 2 (single LLM) matches Condition 1 (two negotiating agents)** on error rate (defined as falling within an equivalence margin of $|\Delta| \le 2.0$ percentage points with overlapping confidence intervals), multi-agent negotiation adds nothing over single-model inference for schema mapping. *(Important caveat: this benchmark isolates mapping negotiation; it does not test bilateral terms or policy negotiation. But for the semantic mapping step specifically, single-model matching would mean multi-agent negotiation adds unnecessary complexity.)*
  - If **Condition 3 (classic tooling) matches Condition 1** on error rate within the equivalence margin at comparable human effort, LLM agents add little over established integration practices.

The full benchmark protocol, anti-contamination schema design, trap taxonomies, annotator logistics, and pre-run hash commitments are detailed in [Appendix C](#appendix-c-benchmark-protocol-and-falsification-design).

### 9.2 Metrics for a fuller study

| Metric | What it would tell us |
| :--- | :--- |
| Time to first valid exchange, vs. a classic integration of the same scope | Whether there's a real speed gain |
| Human interventions per negotiation | Whether "no upfront spec" just means "spec work during negotiation" |
| Effort to describe a company once vs. effort per classic integration | Whether cost moves from per-pair to per-company, or just moves |
| Outcome stability across model versions | Exposure to model drift |

### 9.3 Questions for practitioners

1. What share of integration effort is **semantics**, what share **business terms**, and what share mechanics, organizational alignment, or legal review?
2. If you deployed **ebXML CPP/CPA**, why did (or didn't) it spread? Would the same reasons apply here?
3. Which parts of a B2B relationship could reasonably be **negotiated at runtime**, and which must stay fixed and reviewed upfront?
4. Would a business owner find it easier to review a **negotiated agreement plus worked examples** than a specification?
5. Is the **long tail** of low-volume partners really where unmet integration demand lies?
6. What evidence would convince you this is **not** worth pursuing?

### 9.4 Publication and Dissemination Roadmap

Because this paper tries to bridge established integration engineering with language model experiments, it needs scrutiny from people who have built both. To test whether these ideas hold up beyond my own repository, potential avenues for external feedback include:
- **Applied Systems Venues & Workshops:** Adapting the empirical benchmark protocol (Appendix C) and runtime grant architecture for peer-reviewed discussion in venues focused on web services, distributed systems, and enterprise data (such as IEEE ICWS, ACM DEBS, or enterprise systems tracks at VLDB/SIGMOD).
- **Practitioner & Architectural Forums:** Sharing targeted technical write-ups with enterprise integration architects (e.g., through ACM Queue, Martin Fowler's architecture bliki, or technical essays on Substack / Hacker News) to invite direct critique from practitioners who manage SAP, EDIFACT, and iPaaS systems daily.

---

## 10. Risks and Reasons This Might Not Work

### 10.1 The central risk: the self-description has to be maintained

The whole thesis depends on each company maintaining a **high-quality, machine-readable description of itself**: a capability catalogue with accurate field definitions, units, code lists, and edge-case behavior, plus a policy that reflects what the business actually wants. In other words, a **data dictionary**, kept current as systems change.

Companies have historically been bad at maintaining these. I suspect this is part of why ebXML's "describe yourself once" promise didn't spread as hoped. Writing a profile is a project; keeping it true is a permanent cost that nobody owns. **If maintaining an OpenAPI spec or JSON Schema data dictionary is already neglected by internal teams, asking them to maintain an agentic capability catalogue will fail for the exact same reasons.** If the self-description drifts from reality, agents will negotiate confidently against a fiction, and the cost doesn't disappear. It moves from building integrations to maintaining catalogues, possibly with worse failure modes.

I don't have an answer. The only plausible mitigation is that the catalogue cannot be hand-authored prose: it must be **mechanically derived from working code, database schema constraints, ORM models, and existing contract tests**, and verified continuously against real production transactions. Neither is built ⚪. **If this risk can't be managed, I think the rest of the paper doesn't matter much.**

### 10.2 Other risks

Several of these could, on their own, make the idea impractical.

1. **False semantic agreement.** Signatures guarantee both parties signed the same bytes, not that they understood the same thing. This is the most serious *technical* risk. §8.1 is a partial answer at best.
2. **Power asymmetry and the Hub-and-Spoke reality.** Negotiation assumes roughly comparable parties. In real-world enterprise supply chains (retail, automotive, aerospace, telecom), the **Hub-and-Spoke model** dominates: Walmart, Airbus, or Amazon does not negotiate interfaces or commercial envelopes at runtime. They hand suppliers an AS2/EDI or REST specification and state: *"Comply with this byte-for-byte or you do not trade with us."* I am not suggesting agents will change that reality. If this architecture has a realistic economic wedge, it is not in trying to replace top-down EDI in concentrated supply chains, but where power is distributed and custom bilateral specs are cost-prohibitive:
   - **The mid-market long tail:** Tier-2 and tier-3 suppliers, regional manufacturers, and distributors who lack the leverage to dictate terms and cannot afford custom six-figure bilateral integration projects.
   - **Horizontal SaaS-to-SaaS ad-hoc integrations:** Connecting specialized business platforms (e.g., a niche field-service tool to a regional inventory system) on demand without waiting for centralized integration vendors or pre-built iPaaS connectors.
   - **Multi-carrier logistics brokerage and spot markets:** Dynamic freight booking, spot capacity procurement, and multi-carrier dispatch where market participants change daily and no single hub commands absolute interface hegemony.
3. **Adversarial counterparties.** Negotiation messages come from outside the company. A partner could embed instructions meant to manipulate the other agent, or simply negotiate in bad faith. Deterministic policy limits what the agent can *agree to*, but it doesn't limit what it can be persuaded to *say* or *disclose*.
4. **Model drift.** The same negotiation, or the same interpretation of an existing agreement, might come out differently after a model upgrade. That argues strongly for freezing everything semantic into signed artifacts (§8.1–8.2) and never re-deriving meaning at runtime. It also means agreements negotiated with one model version may need re-validation later.
5. **Accountability.** When a negotiated agreement turns out to be wrong, who is accountable: the deploying company, the model provider, the policy author? I'm not a lawyer. The interaction agreement is a technical artifact and doesn't settle this.
6. **Repeatability.** Two negotiations under the same conditions may produce different agreements, which may be unacceptable for regulated exchanges.
7. **Cost and latency.** For high-volume, stable relationships, a classic integration built once may simply be cheaper than any negotiation.
8. **Two-sided adoption.** The full benefit needs both sides running agents and sharing an envelope. That coordination problem has slowed every previous integration standard, ebXML included.
9. **State drift, ERP master data, and batch processing.** In enterprise backends (SAP, Oracle NetSuite, Microsoft Dynamics), partner configurations are fundamentally static: vendor and customer master records store pre-vetted payment terms (e.g., "net 30"), incoterms, tax jurisdiction codes, and bank accounts. If two runtime agents dynamically agree to micro-amendments on a per-order basis (such as agreeing to "net 15 days" or dynamic early-settlement discounts), downstream financial accounting runs, automated three-way matching (PO vs. receipt vs. invoice), and nocturnal batch processing can reject the posting, throw reconciliation errors, or violate statutory tax reporting rules. An interaction agreement cannot simply float detached from these operational realities: execution grants must map into immutable ledger entries, and enterprise policy must strictly demarcate what can be negotiated dynamically (e.g., spot freight rates within a collar) versus what must remain pinned to master records.

---

## 11. Status Matrix

| Element | Section | Status |
| :--- | :--- | :--- |
| Interaction agreement data model | §5.1 | 🟢 |
| Canonical form, hash, mutual signatures, activation | §5.2 | 🟢 |
| Bounded negotiation, lifecycle states, versioned amendments | §5.3 | 🟢 |
| Four control-plane tools for the agent | §5.4 | 🟢 |
| Cold-start limits and receipt-based trust | §5.4 | 🟢 |
| B2B agent receiving external agent requests | §5.4 | 🟡 (not verifiable today) |
| Live-LLM four-turn negotiation ending in execution | §5.5 | 🟡 (not verifiable today) |
| Same lifecycle, deterministic, without LLM | §5.5 | 🟢 |
| Flat field mapping | §5.6 | 🟢 (hand-written, not signed) |
| Data rules on responses | §5.7 | 🟢 (basic pattern matching) |
| Agent-negotiated interface shape | §6 | ⚪ |
| Signed worked examples and canary transactions | §8.1 | ⚪ |
| Agent-proposed, verified, frozen mapping in the signed agreement | §8.2 | ⚪ |
| Standards as pivots | §8.3 | ⚪ |
| Agreements with partners that have no agent | §8.4 | ⚪ |
| Exception-based human review queue ("Integration Co-Pilot") | §5.4, §8.5 | ⚪ |
| ERP master data impedance matching and immutable ledger mapping | §3, §8.5 | ⚪ |
| Semantic-trap benchmark with baselines and pre-committed falsification thresholds | §9.1 | ⚪ |
| Catalogue generated from maintained artifacts and checked against real transactions | §10.1 | ⚪ |

---

## 12. References

**Integration standards and prior art**

1. OASIS, *Collaboration-Protocol Profile and Agreement Specification* (ebXML CPPA), v2.0, 2002 (stating in section 1 that the composition and negotiation processes themselves are outside the scope of the specification, with negotiation discussed non-normatively in an appendix); ISO 15000-1
2. RosettaNet, *Partner Interface Processes (PIPs)* and the RosettaNet Implementation Framework
3. R. G. Smith, "The Contract Net Protocol: High-Level Communication and Control in a Distributed Problem Solver," *IEEE Transactions on Computers*, 1980
4. FIPA, *Contract Net Interaction Protocol Specification* (SC00029) and *FIPA ACL Message Structure Specification*
5. UN/EDIFACT; OASIS Universal Business Language (UBL) and the Peppol network; HL7 FHIR
6. OpenAPI Specification and AsyncAPI Specification
7. G. Hohpe, B. Woolf, *Enterprise Integration Patterns*, Addison-Wesley, 2003

**Schema matching and ontology alignment: classic**

8. E. Rahm, P. A. Bernstein, "A survey of approaches to automatic schema matching," *The VLDB Journal*, 2001
9. J. Euzenat, P. Shvaiko, *Ontology Matching*, Springer, 2nd ed., 2013
10. C. Koutras et al., "Valentine: Evaluating Matching Techniques for Dataset Discovery," *ICDE*, 2021
11. Ontology Alignment Evaluation Initiative (OAEI), annual evaluation campaigns

**Schema matching and ontology alignment: LLM-based**

12. A. Narayan, I. Chami, L. Orr, S. Arora, C. Ré, "Can Foundation Models Wrangle Your Data?," *PVLDB* 16(4): 738–746, 2022
13. M. Parciak, B. Vandevoort, F. Neven, L. M. Peeters, S. Vansummeren, "Schema Matching with Large Language Models: an Experimental Study," *TaDA workshop at VLDB*, 2024
14. E. Sheetrit et al., "ReMatch: Retrieval Enhanced Schema Matching with LLMs," arXiv, 2024
15. Y. Liu et al., "Magneto: Combining Small and Large Language Models for Schema Matching," *PVLDB*, 2025
16. S. Hertling, H. Paulheim, "OLaLa: Ontology Matching with Large Language Models," *K-CAP*, 2023
17. H. Babaei Giglou et al., "LLMs4OM: Matching Ontologies with Large Language Models," 2024
18. Z. Qiang, W. Wang, K. Taylor, "Agent-OM: Leveraging LLM Agents for Ontology Matching," *PVLDB* 18(3): 516–529, 2024
19. Z. Qiang et al., "OAEI-LLM: A Benchmark Dataset for Understanding Large Language Model Hallucinations in Ontology Matching," arXiv, 2024

*My summaries of refs. 12–19 reflect the findings the authors report in their papers. I have not re-run their code or independently verified their experimental results.*

**Technical building blocks**

20. RFC 8785: JSON Canonicalization Scheme (JCS)
21. RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
22. RFC 7519: JSON Web Token (JWT)
23. W3C Decentralized Identifiers (DIDs) v1.0
24. Model Context Protocol (MCP) specification
25. Agent2Agent (A2A) protocol specification

**Related writing by the author** (not required to read this paper)

26. fcn06, *Interaction Contracts for Autonomous B2B Agents: Architecture, Threat Model, and Open Questions*, September 2026 (security architecture and threat model; uses the term "Interaction Contract" for what this paper calls an interaction agreement): `trust-gateway/whitepaper/b2b_agent_whitepaper.md`
27. fcn06, ["The Agent Economy: Why Agents Must Negotiate Agreements, and How It Rewrites Integration"](https://dev.to/fcn06/the-agent-economy-needs-a-trust-layer-49c), dev.to, 2026

---

## Appendix A: Where to Find the Code

Paths are relative to the root of the repository.

| Capability | Status | Location |
| :--- | :--- | :--- |
| Agreement data model (`InteractionContract`) | 🟢 | `trust-gateway/crates/trust-contract/src/model.rs` |
| Canonicalization and hashing | 🟢 | `trust-gateway/crates/trust-contract/src/canonical.rs`, `hash.rs` |
| Mutual attestation and activation ceremony | 🟢 | `trust-gateway/crates/trust-contract/src/attestation.rs`, `ceremony.rs` |
| Negotiation limits and lifecycle states | 🟢 | `trust-gateway/crates/trust-contract/src/negotiation.rs`, `state_machine.rs` |
| Field mapping (`CapabilityBinding`, `translate_contract_action`) | 🟢 | `trust-gateway/crates/trust-contract/src/adapters.rs` |
| Data rules on responses | 🟢 | `trust-gateway/crates/trust-contract/src/data_policy_eval.rs` |
| Four control-plane tools for the agent | 🟢 | `trust-gateway/executor_host/src/vp.rs` |
| Deterministic lifecycle example (no LLM) | 🟢 | `trust-gateway/examples/agent_reputation_lifecycle/` (`cargo run --bin agent-reputation-lifecycle-example`) |
| Agreement-only example | 🟢 | `trust-gateway/examples/nicp_contract/` (`cargo run -p nicp-contract-example`) |
| B2B agent | 🟡 | `secure-collaboration-fabric/b2b_agent/` |
| Live-LLM four-turn negotiation script | 🟡 | `secure-collaboration-fabric/b2b_agent/examples/real_world_reputation_lifecycle_a2a.sh` |

---

## Appendix B: Glossary

| Term | Meaning in this paper |
| :--- | :--- |
| **Agent** | A software component built around a large language model (LLM) that can read requests, reason, and call tools. Here, each company runs its own agent at its boundary. |
| **B2B agent** | The agent a company exposes to external partners: its "front desk" for automated exchanges. |
| **Interaction agreement** | A machine-readable record of what two companies' agents agreed: parties, purpose, allowed operations, limits (amount, geography, time), data rules, and validity period. **It is not a legal contract.** It's a technical agreement that software can enforce. **Terminology note:** the code (`InteractionContract`) and my earlier whitepaper call this an *Interaction Contract*. It's the same object; I use "agreement" here to avoid a legal reading. |
| **Trust Gateway** | A deterministic program (no LLM inside) that sits between a company's agent and its internal systems. The agent can only *propose* actions. The gateway checks each proposal against the active interaction agreement and the company's own policy, and only then authorizes it. |
| **Execution grant** | A short-lived, signed authorization issued by the gateway for one specific action with specific arguments. The system that performs the action (ERP, payment, inventory) checks the grant before acting. |
| **Execution receipt** | A signed record, issued after an action succeeds, of what was executed under which agreement. It can serve as evidence later. |
| **Enterprise policy** | Rules a company writes in advance about what its agent may agree to, e.g. "never more than €10,000 per transaction with a new partner." |
| **Capability catalogue** | A company's machine-readable description of what it offers to partners: operation identifiers, parameters, units, code lists. In effect, a data dictionary. |
| **DID** (Decentralized Identifier) | A W3C standard identifier for an organization or system, tied to cryptographic keys (e.g. `did:web:company-b.com`). Here it plays roughly the role a certificate plays in AS2 or a partner ID in an EDI trading-partner agreement. |
| **Canonicalization (JCS, RFC 8785)** | A deterministic way to write a JSON document so that both parties produce exactly the same bytes, and therefore the same hash, before signing. |
| **MCP** (Model Context Protocol) | An open protocol for connecting an agent to the tools it may call. |
| **A2A** (Agent-to-Agent) | An open protocol for agents from different systems to discover each other and exchange messages. |

---

## Appendix C: Benchmark Protocol and Falsification Design

This appendix provides the full experimental design for the schema-mapping benchmark described in §9.1.

### C.1 Guarding Against Pre-Training Memorization

Because standard formats like UBL and OASIS XML are widely represented in public pre-training corpora, an LLM might solve a mapping by text recall rather than reasoning across schemas. The benchmark tests three tiers of schema pairs for the same business document (an invoice):

1. **Tier A (Standard Public):** UBL 2.1 XML Invoice mapped to a realistic commercial REST/JSON invoice schema.
2. **Tier B (Obfuscated & Restructured):** The same schemas with field names replaced by pseudo-random tokens (e.g., `f_8192` instead of `TaxExclusiveAmount`) and nested hierarchies flattened or re-grouped. Because official UBL documentation text is public and could be memorized by language models, natural-language annotations in Tier B are strictly paraphrased to strip canonical phrasing, alongside an unannotated sub-variant (**Tier B-bare**) containing only types and structural relations without text descriptions.
3. **Tier C (Synthetic Proprietary):** A freshly authored corporate schema designed specifically for this benchmark, containing novel terminology and business rules not present in any public corpus.

Results will be reported both overall and broken down per tier (Tiers A, B, B-bare, C). A significant performance collapse between Tier A and Tier B/C reveals whether a model relies on memorization.

### C.2 Seeded Trap Taxonomy

The test set incorporates at least **50 seeded semantic traps** across the tiers, categorized as:

- **Type-identical semantic traps:** Fields sharing identical primitive types (e.g., `decimal`) with incompatible business semantics:
  - Line-item net price vs. gross price (inclusive of VAT).
  - Invoice issuance date vs. tax point date (value-added tax determination date).
  - Unit quantity (item count) vs. package/box quantity.
- **Code-list collisions:** Enumerated values that overlap in label but diverge in definition:
  - Unit-of-measure codes (UN/ECE Recommendation 20 vs. proprietary internal units).
  - Geographic codes (ISO 3166-1 alpha-2 country codes vs. custom freight carrier terminal codes).
- **Default-value mismatches:** Optional fields where omission implies conflicting business defaults (e.g., `partial_delivery_allowed` defaulting to `true` on Buyer, `false` on Seller).

### C.3 Ground Truth, Error Modeling, and Annotator Logistics

1. **Pre-Run Gold Standard:** The gold mapping and trap catalog are authored by two independent integration practitioners before running any model. Disagreements are explicitly documented and resolved by consensus.
2. **Cryptographic Commitment:** Prior to executing model runs, a SHA-256 hash of the complete gold dataset is computed and committed to a public repository to prove that ground truth was not retroactively adjusted to fit model outputs.
3. **Evaluation Protocol:**
   - **Sample size:** 50 seeded traps minimum, evaluated across $N = 10$ independent runs per condition.
   - **Unit of analysis and error estimation:** Because the same 50 traps recur across the $N=10$ runs, pooling $10 \times 50$ runs as 500 independent trials would spuriously narrow confidence intervals. Instead, the trap is the unit of analysis: for each trap $i$, we compute its mean acceptance rate $p_i$ across runs. We report the overall mean error rate $\bar{p} = \frac{1}{M}\sum_{i=1}^M p_i$ with a 95% confidence interval computed via non-parametric bootstrap over traps (1,000 resamples).
   - **Convergence rate:** The proportion of negotiations concluding in an `Active` agreement within 8 rounds without timeout.

### C.4 Interpreting Falsification Outcomes

The thresholds and equivalence margins are arbitrary, but they are committed in advance of data collection:

- **Unattended Safety Threshold:** If the **upper bound of the 95% bootstrap confidence interval** for Condition 4 (negotiating agents with worked examples) exceeds $5\%$ of seeded traps ($> 2.5$ traps on average across runs), the semantic step is considered too unreliable for unattended integration.
- **Bilateral Utility:** If Condition 2 (single LLM) matches Condition 1 (two negotiating agents) on error rate within an equivalence margin of $|\Delta| \le 2.0$ percentage points with overlapping intervals, multi-agent negotiation is discarded as unnecessary overhead for semantic reconciliation, limiting the valid role of runtime agents to internal translation tools.
- **Baseline Tooling Parity:** If Condition 3 (classic schema-matching tools + timed human review) matches Condition 1 on error rate within the equivalence margin at comparable human effort, LLM agents add little over established integration practices.

---

*I'd rather this document be useful to someone who disagrees with it than persuasive to someone who already agrees. If you see a flaw in the reasoning, know prior work I've missed, or have data that contradicts the hypothesis, I'd like to hear it, via GitHub issues on [fcn06/trust_gateway](https://github.com/fcn06/trust_gateway) or in the comments of the dev.to article.*

