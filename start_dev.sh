#!/usr/bin/env bash
set -euo pipefail

# Load environment variables from .env file if it exists
if [ -f .env ]; then
    echo "📜 Loading environment from .env..."
    set -a
    source .env
    set +a
fi

# Default development secret for Trust Gateway & Host
export JWT_SECRET="${JWT_SECRET:-dev-secret-only-for-local-testing}"

# LLM API Keys (sourced from environment or .env)
export LLM_MCP_API_KEY="${LLM_MCP_API_KEY:-}"
export LLM_A2A_API_KEY="${LLM_A2A_API_KEY:-}"

# Define community edition globally
export EDITION="community"

export CARGO_FEATURES=""
echo "🌍 Selected Edition: Community"

# Verify prerequisites
if ! command -v trunk &> /dev/null; then
    echo "❌ Error: 'trunk' not found in PATH. Please install it with 'cargo install trunk'."
    exit 1
fi

echo "Starting NATS JetStream server..."
nats-server -js &
NATS_PID=$!

function cleanup {
    echo "Shutting down..."
    kill $NATS_PID 2>/dev/null || true
    pkill -P $$ 2>/dev/null || true
}
trap cleanup EXIT

# Build components if requested or if missing
if [[ "${1:-}" != "--skip-build" ]]; then
    echo "🔨 Building WASM components and services..."
    (cd agent_in_a_box && make build)
fi

echo "Starting Trust Gateway..."
(cd execution_plane/trust_gateway && cargo run --release --bin trust_gateway) &
GATEWAY_PID=$!

echo "Starting Agent in a Box Host..."
(cd agent_in_a_box/host && cargo run --release ${CARGO_FEATURES} --bin host) &
HOST_PID=$!

echo "Starting Local SSI Portal..."
(cd portals/local_ssi_portal && trunk serve --port 8080) &
PORTAL_PID=$!

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Lianxi Community Edition is running!"
echo "  - Trust Gateway:  http://127.0.0.1:3060"
echo "  - Host:           http://127.0.0.1:3000"
echo "  - Local Portal:   http://127.0.0.1:8080"
echo "═══════════════════════════════════════════════════"
echo ""

wait
