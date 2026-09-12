# Getting Started — Contributor Guide

This guide walks you through building, testing, and contributing to the Trust Gateway Rust workspace.

If you just want to **see what Trust Gateway does**, run the standalone demo first:

```bash
cargo run -p quickstart-standalone
```

---

## Prerequisites

### 1. Rust Toolchain (Required)

Install Rust 1.89+ via [rustup](https://www.rust-lang.org/tools/install):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

The repository includes a `rust-toolchain.toml` that pins the exact Rust version — `rustup` will automatically install the correct toolchain when you build.

### 2. System Build Dependencies (Required)

A C compiler and OpenSSL development headers are needed for native cryptography:

- **Linux (Ubuntu/Debian)**:
  ```bash
  sudo apt-get install -y build-essential pkg-config libssl-dev
  ```
- **Linux (Fedora/RHEL)**:
  ```bash
  sudo dnf install -y gcc openssl-devel pkg-config
  ```
- **macOS**:
  ```bash
  xcode-select --install
  ```

### 3. NATS Server (Optional)

Only needed if you want to run the full `gateway` or `executor_host` daemons (not required for the standalone demo or unit tests):

```bash
# See: https://docs.nats.io/running-a-nats-service/introduction/installation
nats-server -js
```

### Verify Your Environment

Run the doctor script to check all prerequisites:

```bash
make doctor
```

Expected output (all required checks should show ✅):

```
🩺 Trust Gateway — Environment Doctor
========================================

✅ Rust ................. 1.88.0
✅ Cargo ................ 1.88.0
✅ C compiler ........... found (cc)
✅ OpenSSL headers ...... 3.x.x
...
========================================
✅ All required checks passed. Ready to build!
```

---

## Build the Workspace

```bash
# Check compilation (fast — no codegen)
make check
# or: cargo check --workspace

# Build all crates in release mode
cargo build --workspace --release
```

Expected: compilation succeeds with no errors.

---

## Run Tests

### Unit Tests

```bash
make test
# or: cargo test --workspace --lib
```

Expected: all tests pass.

### Conformance Test Vectors

These verify the execution protocol's cryptographic guarantees against reference test vectors:

```bash
make conformance
# or: cargo run -p conformance -- --vectors-dir test-vectors
```

Expected: all vectors pass validation.

### CLI Audit Verification

```bash
make audit
# or: cargo run -p trustctl -- audit verify test-vectors/valid_grant.json
```

Expected: the CLI confirms the grant's Ed25519 signature and input hash are valid.

---

## Run the Standalone Demo

### 1. Happy Path Demo
```bash
cargo run -p quickstart-standalone
# or: make quickstart
```

### 2. Argument Tampering Attack Simulation (`--tamper`)
Demonstrates live rejection by the executor when an attacker tampers with action parameters after grant issuance:
```bash
cargo run -p quickstart-standalone -- --tamper
```

### 3. Grant Replay Attack Simulation (`--replay`)
Demonstrates live single-use grant/nonce rejection when an attacker attempts to re-submit an already consumed grant:
```bash
cargo run -p quickstart-standalone -- --replay
```

### 4. Layer 0 Call-Chain Loop / Recursion Simulation (`--call-chain`)
Demonstrates immediate denial at Layer 0 when an agent attempts recursive invocation or cyclic tool loops:
```bash
cargo run -p quickstart-standalone -- --call-chain
```

**What this demonstrates:**

| Mode / Step | What Happened |
|---|---|
| 📥 Step 1 | An AI agent proposed a `mock_refund` action with specific arguments |
| ⚖️ Step 2 | The policy engine evaluated the action against policy rules |
| 🔑 Step 3 | A cryptographic `ExecutionGrant` was minted, binding the exact arguments via SHA-256 hash |
| ⚡ Step 4 | The executor verified the grant signature and input hash, then executed |
| 🔒 Step 5 | PII (email addresses) was automatically redacted from the output |
| ⚠️ `--tamper` | Parameter tampering post-approval is rejected by executor due to `input_hash` mismatch |
| ⚠️ `--replay` | Re-submitting an already consumed grant is rejected by executor due to single-use nonce/JTI |
| 🛑 `--call-chain` | Layer 0 call-chain guard detects cyclic loop and denies proposed action before grant issuance |

---

## Governed Tool Execution via CLI (`trustctl`)

The Trust Gateway CLI acts as a dynamic **Policy Enforcement Point (PEP)** via `adapters/surface-cli`, automatically projecting native tool JSON Schemas into typed CLI commands.

### 1. Discover Registered Tools

Inspect all governed tools available in the workspace tool directory:

```bash
cargo run -p trustctl -- tool list
```

Expected output:
```text
Available Governed Tools:
  - claw_hello_world (v1.0.0): Echo a message with greeting
  - inspect_schema (v1.0.0): Inspect tool schema definitions
```

### 2. Dynamic Schema Introspection

Inspect command-line arguments generated dynamically from a tool's JSON Schema:

```bash
cargo run -p trustctl -- tool run claw_hello_world --help
```

Expected output:
```text
Echo a message with greeting

Usage: trustctl tool run claw_hello_world [OPTIONS] --message <MESSAGE>

Options:
  --message <MESSAGE>  Message to display
  -h, --help           Print help
```

### 3. Run Governed Tools

Invoke a tool with dynamic arguments. In standalone/direct mode, `trustctl` computes the canonical RFC 8785 `input_hash`, requests authorization, and verifies execution output:

```bash
cargo run -p trustctl -- tool run claw_hello_world --message "Hello Sovereign Gateway"
```

Expected output:
```json
{
  "greeting": "Hello, Hello Sovereign Gateway!"
}
```

### 4. Standardized Exit Codes

`trustctl tool run` adheres to POSIX/standardized security exit codes:

| Exit Code | Condition | Example Scenario |
|:---:|:---|:---|
| **0** | **Success** | Tool executed and output returned successfully |
| **1** | **Validation Error** | Missing required parameters: `trustctl tool run claw_hello_world` (missing `--message`) |
| **126** | **Policy Denied** | Action rejected by Gateway Policy Decision Point (e.g., unauthorized scope or rate limit exceeded) |
| **127** | **Tool Not Found** | Target tool does not exist in registry: `trustctl tool run unknown_tool` |
| **130** | **Cancelled / Timed Out** | Human approval pending and timed out, or user cancelled operation |

---

## Call-Chain Guard (Layer 0 Execution Safety)

In multi-agent collaborative workflows, autonomous agents can easily trigger infinite ping-pong loops, recursion storms, or runaway execution costs. The Trust Gateway deploys **Layer 0 Call-Chain Guard** (`crates/trust-policy/src/call_chain.rs`) before evaluating any attribute or financial rules.

### How It Works

Every proposed action carries an optional `CallChainContext`:
- `depth`: Current invocation depth in the agent execution graph (default maximum: 10).
- `call_stack`: Sequence of preceding tools called in this trace (e.g. `["agent_plan", "data_fetch", "agent_plan"]`).
- `invocation_counts`: Per-tool invocation tally within the current session (default maximum: 3 per tool).
- `initiator_agent_id`: The root agent responsible for starting the workflow.

```text
Incoming ActionProposal
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 0: Call-Chain Guard (crates/trust-policy/call_chain)  │
│  - Depth Check: depth <= max_depth (10)                     │
│  - Cycle Check: cycle_detected in call_stack?               │
│  - Frequency Check: invocation_count <= max_frequency (3)   │
│  - Gateway Session Integrity: tracked vs. submitted stack   │
└─────────────────────────────┬───────────────────────────────┘
                              │
               Pass           ▼           Violation
         ┌─────────────────────────┐   ┌──────────────────────────┐
         │ Layer 1: Policy Rules   │   │ Immediate Deny (Exit 126)│
         │ (policy.toml ABAC)      │   │ "Call-chain limit hit"   │
         └─────────────────────────┘   └──────────────────────────┘
```

### Security Refinement: Authoritative Session Tracking

If a malicious or compromised agent tampers with its `call_stack` or resets its `invocation_counts` to bypass limits, the Gateway detects it. The Trust Gateway maintains an authoritative session state indexed by `trace_id`. If an inbound proposal reports a call-chain state inconsistent with the recorded session history, the proposal is rejected immediately with `PolicyDecision::Deny`.


## Code Quality

```bash
# Check formatting
cargo fmt --all -- --check

# Run clippy lints
cargo clippy --workspace --all-targets -- -D warnings

# Or both at once:
make lint
```

---

## Troubleshooting

### `error: linker 'cc' not found`

Install a C compiler:
- Linux: `sudo apt-get install -y build-essential`
- macOS: `xcode-select --install`

### `failed to run custom build command for 'openssl-sys'`

Install OpenSSL development headers:
- Linux (Ubuntu/Debian): `sudo apt-get install -y pkg-config libssl-dev`
- Linux (Fedora/RHEL): `sudo dnf install -y openssl-devel pkg-config`
- macOS: `brew install openssl` (usually not needed — Xcode provides it)

### `error: rustc X.Y.Z is not supported` or unexpected compilation errors

The repository pins a specific Rust version in `rust-toolchain.toml`. Ensure `rustup` is up to date:
```bash
rustup update
```

### `Could not connect to NATS`

NATS is only required for the full `gateway` and `executor_host` daemons, not for the standalone quickstart or unit tests. If you need it:
```bash
nats-server -js
```

---

## Where to Go from Here

- **[`docs/concepts/VISUAL_GUIDE.md`](concepts/VISUAL_GUIDE.md)** — 5-minute visual architecture overview
- **[`docs/concepts/ARCHITECTURE.md`](concepts/ARCHITECTURE.md)** — Detailed architectural plane breakdown
- **[`docs/reference/PROTOCOL_SPEC.md`](reference/PROTOCOL_SPEC.md)** — Protocol specification
- **[`docs/reference/security-guarantees.md`](reference/security-guarantees.md)** — Security guarantees matrix
