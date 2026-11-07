# Component Agent Instructions

<!-- BEGIN GENERATED:component (meta/bin/build, do not edit inside) -->
## Trust Mapping (IR, Interpreter & Review Pack) (`COMP-trust-mapping`)

Non-Turing-complete intermediate representation parser, fuel-metered evaluator, and review pack generator.

Inspect any ID with `./meta/bin/ctx show <ID>`. Before editing, run `./meta/bin/ctx impact <files>`.

### Governing Invariants (must remain true)
- `INV-001` [P0, enforced by dependency_rule]: Cognitive Ingress Isolation & Zero Runtime LLM Bypass
- `INV-004` [P0, enforced by runtime_assertion]: Deterministic Fuel-Bounded Mapping Execution

### Forbidden Responsibilities & Shortcuts
- Adding unbounded iteration, arbitrary recursion, or I/O primitives to the Mapping IR
- Executing mapping scripts without fuel exhaustion guards (INV-004)

### Canonical Implementation Patterns (Golden Exemplars)
- `PAT-004`: Declarative Schema Mapping AST Execution

### Data & Wire Contracts
- `CTR-003`: MappingRuleSet Non-Turing-Complete IR Wire Contract

### Past Agent Lessons
- `LES-002`: Unbounded Iteration in Schema Mapping Scripts

### Fast Verification Commands
- `cargo check --manifest-path marketplace_trust_gateway/public/crates/trust-mapping/Cargo.toml --all-targets`
- `cargo clippy --manifest-path marketplace_trust_gateway/public/crates/trust-mapping/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path marketplace_trust_gateway/public/crates/trust-mapping/Cargo.toml`
<!-- END GENERATED:component -->
