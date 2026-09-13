# End-to-End Agent Reputation & Negotiation Lifecycle Example

This example demonstrates the complete **discovery → reputation check → contract negotiation → deterministic execution → proof of good execution** cycle between two sovereign B2B agents, enforced by the **Trust Gateway**.

It proves how autonomous agents can establish evidence-backed reputation without centralized SaaS portals, tokens, or heavy blockchain networks.

---

## The 5-Stage Architecture Flow

```text
1. DISCOVERY & COLD START
   Buyer Gateway checks local reputation for Supplier DID:
   [Local History: 0 successful executions] ──► Policy: High-value tier (€15,000) LOCKED.
                                                                │
2. PEER ATTESTATION PRESENTATION                                │
   Supplier presents signed ExecutionReceipt from Peer DID:      │
   [Issuer: did:web:aerospace-leader.corp | Outcome: SUCCESS]   │
   Buyer Gateway verifies Ed25519 signature & Peer Root ────────┴──► Policy: UNLOCKED!
                                                                │
3. BILATERAL CONTRACT NEGOTIATION (PROPOSAL ──► AMENDMENT ──► AGREEMENT) ▼
   • Step 3.1: Buyer proposes initial Draft v1 (Ceiling: €10,000, Net-60, 2h cancel).
   • Step 3.2: Supplier counter-proposes Amended v2 (Ceiling: €15,000, Net-15, 24h notice,
               attaches trusted peer ExecutionReceipt to justify higher credit ceiling).
   • Step 3.3: Buyer accepts amendments; both execute 9-step Activation Ceremony.
   Mutual Attestation: Canonical RFC 8785 Hash computed and signed by both parties.
   Contract marked: ACTIVE 🟢 (Version 2)
                                                                │
4. ACTION PROPOSAL & POLICY GATING                              ▼
   Supplier proposes: io.logistics.freight.book (€12,500).
   Gateway checks contract constraints & Policy SDK ────────────► ExecutionGrant Issued 🎫
                                                                │
5. EXECUTION & PROOF OF GOOD EXECUTION                          ▼
   Executor performs action with argument-hash binding.
   Gateway updates Local Ledger: [Local History: 0 ──► 1]
   Gateway mints & signs fresh ExecutionReceipt ────────────────► Delivered to Supplier 📜
```

---

## What This Example Validates

1. **Cold-Start Protection:** An unknown agent cannot execute high-value actions without prior track record.
2. **Third-Party Evidence Presentation:** A cold-start agent can unlock policy tiers by presenting an unforgeable `ExecutionReceipt` signed by a trusted industry peer (`did:web`).
3. **Deterministic Bilateral Negotiation:** Contracts are canonicalized via RFC 8785 (JCS) and sealed by mutual Ed25519 signatures before any execution is permitted.
4. **Zero-Trust Execution Grants:** The gateway issues single-use, 30s TTL grants locked to the exact SHA-256 hash of the arguments (`input_hash`).
5. **Sealed Proof of Good Execution:** Upon completion, the gateway increments its local reputation counter and issues an Ed25519-signed `ExecutionReceipt` that the agent can add to its vault to vouch for itself in future deals.

---

## How to Run

From the root of the repository or from `trust-gateway/`:

```bash
cargo run -p agent-reputation-lifecycle-example
```

---

## Expected Output Walkthrough

When you run the example, you will see the full interactive trace:

```text
================================================================================
🌟 TRUST GATEWAY: END-TO-END AGENT REPUTATION & NEGOTIATION LIFECYCLE
================================================================================

🔑 Established Cryptographic Roots & Identities:
  - Buyer DID:        did:web:buyer.enterprise.corp
  - Supplier DID:     did:web:precision-logistics.supplier
  - Trusted Peer DID: did:web:aerospace-leader.corp

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 STAGE 1: Discovery & Initial Local Reputation Check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Buyer Gateway queries local counterparty reputation for 'did:web:precision-logistics.supplier':
  - Total Local Successful Transactions: 0
  - Total Local Failed Transactions:     0
  - Trust Assessment: ⚠️ COLD START (Unknown counterparty to this Gateway)

🔒 Policy Gating without reputation evidence:
  Result: DENIED — Organization Policy: Insufficient reputation (requires 3 successful executions or a trusted peer attestation, found 0)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📜 STAGE 2: Presentation & Verification of Peer Execution Attestation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Supplier Agent presents prior proof of good execution signed by 'did:web:aerospace-leader.corp'.
Buyer Gateway verifies presented ExecutionReceipt:
  - Receipt ID:    rcpt_aerospace_prior_9981
  - Issuer:        did:web:aerospace-leader.corp
  - Subject:       did:web:precision-logistics.supplier
  - Capability:    io.logistics.freight@v1
  - Stated Status: SUCCESS
  - Cryptographic Signature: ✅ Valid Ed25519 signature from 'did:web:aerospace-leader.corp'
  - Reputation Evaluation:   ✅ ALLOWED — Unlocked high-value tier (€15,000) via verified peer attestation!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🤝 STAGE 3: Bilateral Contract Negotiation & Mutual Signing Ceremony
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Step 3.1: Buyer Agent initiates Draft Contract Proposal (v1)...
  - Proposal ID:       ctr_buyer_supplier_freight_001
  - Version:           v1 (Draft)
  - Proposed Ceiling:  €10,000.00 EUR
  - Settlement Term:   Net-60
  - Cancellation:      2h prior to pickup
  - Canonical Hash v1: sha256:...

Step 3.2: Supplier Agent evaluates v1 and returns Counter-Proposal (v2)...
  ⚠️  Supplier Policy check: Requested priority freight corridor requires €15,000 cap
  ⚠️  Supplier Commercial check: Net-60 rejected; counter-propose Net-15 & 24h notice
  📎 Supplier attaches verified peer ExecutionReceipt to justify terms.
  - Counter-Proposal:  v2 (Amended)
  - Amended Ceiling:   €15,000.00 EUR (+€5,000)
  - Amended Terms:     Net-15, 24h cancellation notice
  - Linked Parent:     sha256:...
  - Canonical Hash v2: sha256:...

Step 3.3: Buyer reviews amendments and both parties enter Activation Ceremony...
  - Checking amended ceiling (€15,000 <= €50,000 Buyer Policy Max): ✅ In bounds
  - Checking attached peer attestation (did:web:aerospace-leader.corp):       ✅ Verified
  - Buyer decision: ACCEPT AMENDED TERMS 🤝
  - Buyer Ed25519 Signature:    Verified ✅
  - Supplier Ed25519 Signature: Verified ✅
  - Activation Ceremony:        Completed (9 invariants verified) ✅
  - Final Contract State:       ACTIVE 🟢 (Version 2)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚡ STAGE 4: Action Proposal & Deterministic Execution Grant Issuance
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Supplier Agent proposes action:
  - Tool:      io.logistics.freight@v1
  - Arguments: {"amount":{"amount_minor":1250000,"currency":"EUR"},"destination":"Lyon Logistics Hub","shipment_id":"SHP-LYON-2026","units":2}
Trust Gateway evaluates and mints ExecutionGrant:
  - Grant ID:     grant_...
  - Input Hash:   sha256:...
  - TTL:          30 seconds (single-use)
  - Contract ID:  ctr_buyer_supplier_freight_001
  - Authorization: GRANTED 🎫

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 STAGE 5: Execution & Proof of Good Execution Minting
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Isolated Executor verifying grant claims and executing action...
Action Succeeded! Output: {"booking_reference":"FR-LYON-88412","estimated_delivery":"2026-10-02T14:00:00Z","status":"confirmed"}

Updating Buyer Gateway local counterparty ledger...
  - Previous local successful count: 0
  - New local successful count:      1
  - Last Success Timestamp:          Some(1789...)

Minting sealed, Ed25519-signed ExecutionReceipt (Proof of Good Execution)...
Sealed Receipt Minted:
  - Receipt ID:   rcpt_...
  - Grant JTI:    grant_...
  - Issuer:       did:web:buyer.enterprise.corp:trust-gateway
  - Counterparty: did:web:precision-logistics.supplier
  - Outcome:      SUCCESS
  - Signature:    ...

Cryptographic Verification: ✅ Verified against Buyer Gateway public key!
🎉 The Supplier Agent now stores this sealed receipt in its credentials vault
   to present as unforgeable proof of good execution to future enterprise peers!

================================================================================
✅ FULL END-TO-END REPUTATION & NEGOTIATION CYCLE SUCCESSFULLY COMPLETED
================================================================================
```
