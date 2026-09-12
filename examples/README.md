# Examples

Runnable examples demonstrating Trust Gateway's core capabilities and integration patterns.

## Example Index

| Example | Description | Requirements |
|---|---|---|
| **[`quickstart_standalone/`](quickstart_standalone/)** | Zero-dependency standalone control flow — the **golden path** demo (happy path, `--tamper`, `--replay`, `--call-chain`) | Rust only |
| **[`call_chain_guard/`](call_chain_guard/)** | Layer 0 call-chain guard: recursion limits, cycle prevention, per-tool caps, and context integrity | Rust only |
| **[`cli_pep/`](cli_pep/)** | Surface CLI PEP: dynamic schema inspection, RFC 8785 input hashing, and exit codes (0, 1, 126, 127) | Bash, trustctl |
| **[`nicp_contract/`](nicp_contract/)** | Negotiated Interaction Contracts (NICP): bilateral terms, Ed25519 signing ceremony, in-bounds vs. out-of-bounds evaluation, and grant binding | Rust only |
| **[`egress_sanitization/`](egress_sanitization/)** | Egress PII & credential redaction: regex scrubbing, recursive JSON tree sanitization, and DLP field classification | Rust only |
| **[`rest-curl/`](rest-curl/)** | REST API integration using `curl` and `bash` | curl, jq, running gateway |
| **[`python-agent/`](python-agent/)** | Python client demonstrating propose → grant → verify flow | Python 3, running gateway |
| **[`python-executor/`](python-executor/)** | Python-based grant verification (verifier-side reference) | Python 3 |
| **[`rust-executor/`](rust-executor/)** | Rust-based custom executor implementation | Rust only |
| **[`kubernetes-deployment/`](kubernetes-deployment/)** | Kubernetes manifests for deploying Trust Gateway | kubectl |

## Quick Start

The fastest way to see Trust Gateway in action:

```bash
make quickstart
# or: cargo run -p quickstart-standalone
```

See the [main README](../README.md) for expected output.

## Writing Your Own Example

Each example should contain:
- `README.md` — prerequisites, usage, and expected output
- A single entry point (binary, script, or manifest)
- No external secrets required
