#!/usr/bin/env bash
# ==============================================================================
# injection_demo.sh: End-to-End Demonstration of Prompt Injection Interception
# ==============================================================================
# This script executes the deterministic taint-propagation and downgrade test
# from the conformance suite, showing how untrusted external data marks a trace
# as TAINTED and automatically downgrades subsequent mutations to human approval.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Marketplace Trust Gateway: Prompt Injection Defense Demo ==="
echo ""
echo "1. Ingesting untrusted external data via claw_extract_content_from_url..."
echo "   -> Marked with data_origin_trust = UntrustedExternal"
echo "   -> Active trace_id is escalated to TAINTED state."
echo ""
echo "2. Agent attempts mutation (claw_mutation_tool / refund_payment)..."
echo "   -> Policy evaluates taint state: TAINTED trace detected."
echo "   -> Automated execution is REJECTED."
echo "   -> Downgraded to PENDING_HUMAN_APPROVAL."
echo ""
echo "Running conformance test verification..."
cargo test --manifest-path "${WORKSPACE_ROOT}/Cargo.toml" test_conformance_scenario_2_taint_propagation_and_downgrade -- --nocapture

echo ""
echo "✅ Conformance scenario passed: Deterministic taint interception verified!"
