#!/usr/bin/env bash
# ==============================================================================
# CLI Policy Enforcement Point (PEP) Example Demonstration
#
# This script exercises the dynamic CLI Surface Adapter (`adapters/surface-cli`)
# via `trustctl tool run / list`.
# ==============================================================================

set -e

# Resolve repository root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TRUST_DIR="$REPO_ROOT/trust-gateway"

echo "============================================================"
echo "🖥️ Trust Gateway Example: Dynamic CLI Policy Enforcement Point"
echo "============================================================"

# 1. Discover Registered Tools
echo -e "\n--- 1. Discover Registered Tools (trustctl tool list) ---"
cargo run --manifest-path "$TRUST_DIR/Cargo.toml" -p trustctl -- tool list

# 2. Dynamic Schema Introspection
echo -e "\n--- 2. Dynamic Schema Introspection (trustctl tool run <tool> --help) ---"
cargo run --manifest-path "$TRUST_DIR/Cargo.toml" -p trustctl -- tool run claw_hello_world --help || true

# 3. Successful Governed Tool Execution (Exit Code 0)
echo -e "\n--- 3. Governed Tool Execution with Arguments (Exit Code 0) ---"
cargo run --manifest-path "$TRUST_DIR/Cargo.toml" -p trustctl -- tool run claw_hello_world --message "Hello Sovereign Gateway"
echo "✅ Exit code: $?"

# 4. Schema Validation Error (Exit Code 1)
echo -e "\n--- 4. Missing Required Parameter Simulation (Exit Code 1) ---"
set +e
cargo run --manifest-path "$TRUST_DIR/Cargo.toml" -p trustctl -- tool run claw_hello_world
EXIT_CODE=$?
set -e
echo "⚡ Exit code returned: $EXIT_CODE (Expected: 1 for missing required arguments)"
if [ "$EXIT_CODE" -eq 1 ]; then
    echo "✅ Successfully enforced client-side schema validation."
else
    echo "❌ Unexpected exit code!"
fi

# 5. Unknown Tool Identifier (Exit Code 127)
echo -e "\n--- 5. Unknown Tool Simulation (Exit Code 127) ---"
set +e
cargo run --manifest-path "$TRUST_DIR/Cargo.toml" -p trustctl -- tool run non_existent_tool
EXIT_CODE=$?
set -e
echo "⚡ Exit code returned: $EXIT_CODE (Expected: 127 for unknown tool)"
if [ "$EXIT_CODE" -eq 127 ]; then
    echo "✅ Successfully rejected unknown tool at registry boundary."
else
    echo "❌ Unexpected exit code!"
fi

echo -e "\n============================================================"
echo "🎉 All CLI PEP demonstration steps completed successfully!"
echo "============================================================"
