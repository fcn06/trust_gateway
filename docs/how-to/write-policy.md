# How-To: Write a Governance Policy

This guide explains how to author `policy.toml` files that control what AI agents are allowed to do through Trust Gateway.

---

## Policy File Structure

A policy file has two sections:

1. **`[governance]`** — global defaults
2. **`[[rules]]`** — ordered evaluation rules

### Minimal Example

```toml
[governance]
policy_version = "1.0.0"
default_action = "deny"

[[rules]]
name = "Allow read-only operations"
operation_kind = "read_only"
action = "allow"
priority = 10
```

This policy **denies everything by default**, then allows any action tagged as `read_only`.

---

## Governance Section

```toml
[governance]
policy_version = "1.0.0"           # Policy format version
default_action = "deny"             # What happens when no rule matches
input_hash_binding_required = true  # Require SHA-256 input binding on grants
max_grant_ttl_seconds = 30          # Maximum grant lifetime
```

### `default_action` Options

| Value | Behavior |
|---|---|
| `"deny"` | Reject the action (recommended — fail-closed) |
| `"allow"` | Allow the action (use with caution) |
| `"require_approval"` | Escalate to a human reviewer |

> **Security best practice:** Always use `default_action = "deny"`. This ensures any unrecognized operation is blocked until you explicitly write a rule for it.

---

## Rules

Rules are evaluated in **priority order** (lowest number = highest priority). The first matching rule wins.

```toml
[[rules]]
name = "Descriptive name for this rule"
operation_kind = "read_only"         # Match actions with this operation kind
action = "allow"                     # What to do when matched
priority = 10                        # Evaluation order (lower = evaluated first)
```

### Rule Fields

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Human-readable description |
| `operation_kind` | Yes | The operation type to match (`read_only`, `financial_mutation`, `destructive`, etc.) |
| `action` | Yes | `"allow"`, `"deny"`, or `"require_approval"` |
| `priority` | Yes | Evaluation order — lower numbers are checked first |
| `min_amount_cents` | No | Conditional threshold for financial operations |

---

## Common Patterns

### Allow reads, require approval for writes

```toml
[governance]
policy_version = "1.0.0"
default_action = "deny"

[[rules]]
name = "Auto-allow read-only operations"
operation_kind = "read_only"
action = "allow"
priority = 10

[[rules]]
name = "Require approval for mutations"
operation_kind = "financial_mutation"
action = "require_approval"
priority = 20
```

### Block destructive operations entirely

```toml
[[rules]]
name = "Block all destructive operations"
operation_kind = "destructive"
action = "deny"
priority = 5
```

### Amount-based thresholds

```toml
[[rules]]
name = "Auto-allow small refunds"
operation_kind = "financial_mutation"
action = "allow"
min_amount_cents = 0
priority = 15

[[rules]]
name = "Require approval for large refunds"
operation_kind = "financial_mutation"
action = "require_approval"
min_amount_cents = 10000
priority = 20
```

---

## Dynamic Reputation & Trust Policies

In hierarchical policy mode (`policy_sdk`), organizations can configure adaptive reputation thresholds under `[organization.reputation]`:

```toml
[organization.reputation]
min_successful_executions = 5             # Cold-start threshold
max_failure_rate = 0.10                   # Block agents with >10% failure rate
min_peer_score_for_auto_approval = 0.80   # Require high peer attestation for large actions
adaptive_downgrade = true                 # Downgrade to human approval instead of hard deny
```

### Adaptive Downgrade
When `adaptive_downgrade = true`:
- Unknown or cold-start counterparties (executions < 5 and lacking trusted peer attestation) are escalated to `RequiresHumanApproval` (`reputation_downgrade_cold_start`) instead of failing immediately.
- High-value operations (> $1,000) from unverified counterparties trigger `RequiresHumanApproval` (`reputation_unverified_high_value`).
- Counterparties exceeding `max_failure_rate` are rejected immediately with `Deny`.

---

## Validating a Policy

Use `trustctl` to lint your policy file:

```bash
cargo run -p trustctl -- policy lint config/policy.standalone.toml
```

---

## Where Policies Are Loaded

- **Standalone quickstart**: `config/policy.standalone.toml`
- **Gateway daemon**: Set via the `POLICY_PATH` environment variable
- **Docker Compose**: Mounted as a volume to `/etc/trust-gateway/policy.toml`

---

## Next Steps

- [Security guarantees](../reference/security-guarantees.md) — understand the cryptographic properties policies rely on
- [Protocol specification](../reference/PROTOCOL_SPEC.md) — how policies interact with the execution protocol
