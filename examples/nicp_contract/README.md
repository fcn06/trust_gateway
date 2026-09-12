# Negotiated Interaction Contracts (NICP) Example

This example demonstrates the bilateral lifecycle and cryptographic enforcement of **Negotiated Interaction Contracts (NICP)** using `crates/trust-contract`.

---

## What This Demonstrates

1. **Contract Authoring**: Machine-enforceable technical agreements declaring business purpose, counterparties, allowed capabilities, and financial ceilings (e.g. €25,000.00).
2. **Deterministic Canonical Hashing**: Strips non-attested fields and serializes using the RFC 8785 JSON Canonicalization Scheme (JCS) followed by SHA-256 to guarantee byte-identical hashes across platforms.
3. **Mutual Attestation Ceremony**: Bilateral Ed25519 digital signature generation and multi-party key verification advancing contract state: `Draft` → `Accepted` → `Attested` → `Active`.
4. **Contract Constraint Enforcement**: Evaluating proposals against contract bounds:
   - In-bounds request (€15,000.00) is authorized.
   - Out-of-bounds request (€35,000.00) is rejected with `ArgumentConstraintViolation`.
5. **Execution Grant Binding**: Minting an `ExecutionGrant` bound to the active `contract_id` and canonical `contract_hash`.

---

## Running the Example

```bash
cargo run -p nicp-contract-example
```
