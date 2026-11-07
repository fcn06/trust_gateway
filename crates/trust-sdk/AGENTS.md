# Component Agent Instructions

<!-- BEGIN GENERATED:component (meta/bin/build, do not edit inside) -->
## Trust SDK (Kernel Models & Cryptography) (`COMP-trust-sdk`)

Pure cryptographic kernel defining canonical envelopes, Ed25519 verification, and capability contracts with zero async/net/db dependencies.

Inspect any ID with `./meta/bin/ctx show <ID>`. Before editing, run `./meta/bin/ctx impact <files>`.

### Governing Invariants (must remain true)
- `INV-002` [P0, enforced by lint]: Zero Local Subprocess Execution in Workers & Pure SDK Kernel
- `INV-003` [P0, enforced by type]: Canonical Grant & Ed25519 Cryptographic Verification
- `INV-006` [P1, enforced by runtime_assertion]: Single-Use Nonce & JTI Replay Prevention
- `INV-008` [P1, enforced by test]: Strict RFC 8785 JCS Canonicalization

### Forbidden Responsibilities & Shortcuts
- Adding async runtime, web server, network, or database dependencies (INV-002 enforced by deny.toml)
- Deriving Deserialize or Clone on private typestate tokens (INV-003)
- Non-deterministic serialization in signature hashing

### Canonical Implementation Patterns (Golden Exemplars)
- `PAT-002`: Zero-Trust ServiceRequestEnvelope Construction & Signing

### Data & Wire Contracts
- `CTR-001`: TrustEnvelope & ServiceRequestEnvelope Wire Contract
- `CTR-002`: SignedContract & InputConstraints Capability Contract
- `CTR-005`: ExecutionReceipt Synchronous Audit Record Contract

### Fast Verification Commands
- `cargo check --manifest-path marketplace_trust_gateway/public/crates/trust-sdk/Cargo.toml --all-targets`
- `cargo clippy --manifest-path marketplace_trust_gateway/public/crates/trust-sdk/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path marketplace_trust_gateway/public/crates/trust-sdk/Cargo.toml`
<!-- END GENERATED:component -->
