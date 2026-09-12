# CLI Policy Enforcement Point (PEP) Example

This example demonstrates dynamic CLI tool governance via the **CLI Surface Adapter** (`adapters/surface-cli`) and `trustctl`.

## Overview

Rather than giving operators or shell scripts ambient authority or direct script execution rights, the CLI surface adapter projects registered native tool JSON Schemas dynamically into typed CLI commands. It validates arguments locally, calculates RFC 8785 canonical `input_hash` digests, requests execution authorization from the Trust Gateway, and maps authorization outcomes to standardized POSIX exit codes.

---

## Running the Example

Run the demonstration script:

```bash
chmod +x examples/cli_pep/run.sh
./examples/cli_pep/run.sh
```

Or run commands directly via `cargo`:

```bash
# 1. Discover registered tools
cargo run -p trustctl -- tool list

# 2. Inspect dynamic schema help
cargo run -p trustctl -- tool run claw_hello_world --help

# 3. Execute tool with arguments
cargo run -p trustctl -- tool run claw_hello_world --message "Hello from CLI"

# 4. Observe schema validation failure
cargo run -p trustctl -- tool run claw_hello_world # missing --message
```

---

## Standardized Exit Codes

`trustctl tool run` adheres to standardized security exit codes:

| Exit Code | Meaning | Example Scenario |
|:---:|:---|:---|
| **0** | **Success** | Tool executed and output returned successfully |
| **1** | **Validation Error** | Missing required parameters: `trustctl tool run claw_hello_world` (missing `--message`) |
| **126** | **Policy Denied** | Action rejected by Gateway Policy Decision Point (e.g. rate limit exceeded or unauthorized scope) |
| **127** | **Tool Not Found** | Target tool does not exist in registry: `trustctl tool run unknown_tool` |
| **130** | **Cancelled / Timed Out** | User cancelled or human approval expired |
