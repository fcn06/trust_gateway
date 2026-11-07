# Component Agent Instructions

<!-- BEGIN GENERATED:component (meta/bin/build, do not edit inside) -->
## Trust Engine (Execution & Policy Pipeline) (`COMP-trust-engine`)

Core gateway engine executing policy evaluation, rate limiting, probation checking, and tool dispatch pipeline.

Inspect any ID with `./meta/bin/ctx show <ID>`. Before editing, run `./meta/bin/ctx impact <files>`.

### Governing Invariants (must remain true)
- `INV-001` [P0, enforced by dependency_rule]: Cognitive Ingress Isolation & Zero Runtime LLM Bypass
- `INV-003` [P0, enforced by type]: Canonical Grant & Ed25519 Cryptographic Verification
- `INV-007` [P1, enforced by test]: Fail-Closed Zero-Trust Execution Default

### Forbidden Responsibilities & Shortcuts
- Bypassing the verification pipeline steps or executing unapproved tools
- Executing tools without sandboxed resource limits

### Canonical Implementation Patterns (Golden Exemplars)
- `PAT-001`: Governed Action Dispatch via Trust Engine

### Data & Wire Contracts
- `CTR-001`: TrustEnvelope & ServiceRequestEnvelope Wire Contract

### Fast Verification Commands
- `cargo check --manifest-path marketplace_trust_gateway/public/crates/trust-engine/Cargo.toml --all-targets`
- `cargo clippy --manifest-path marketplace_trust_gateway/public/crates/trust-engine/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path marketplace_trust_gateway/public/crates/trust-engine/Cargo.toml`
<!-- END GENERATED:component -->
