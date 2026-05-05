#!/usr/bin/env bash
set -euo pipefail

# Load environment variables from .env file if it exists
if [ -f .env ]; then
    echo "📜 Loading environment from .env..."
    set -a
    source .env
    set +a
fi

# JWT_SECRET: REQUIRED. Must be shared across trust_gateway, native_skill_executor,
# and the host. Generate a random one if not set in .env.
if [ -z "${JWT_SECRET:-}" ]; then
    export JWT_SECRET=$(openssl rand -base64 32)
    echo "🔐 Generated random JWT_SECRET (set JWT_SECRET in .env for persistence)"
else
    export JWT_SECRET
fi

# LLM API Keys (sourced from environment or .env)
export LLM_MCP_API_KEY="${LLM_MCP_API_KEY:-}"
#export LLM_A2A_API_KEY="${LLM_A2A_API_KEY:-}"

# Google / OAuth
export GOOGLE_CLIENT_ID="${GOOGLE_CLIENT_ID:-}"
export GOOGLE_CLIENT_SECRET="${GOOGLE_CLIENT_SECRET:-}"
export GOOGLE_REDIRECT_URI="${GOOGLE_REDIRECT_URI:-http://localhost:3050/oauth/google/callback}"

# Define edition globally
export EDITION="${EDITION:-community}"

export ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-http://localhost:8080,http://127.0.0.1:8080,http://localhost:8083,http://127.0.0.1:8083}"

# ── WS1: Ed25519 Grant Signing Keys ──────────────────────
ROOT_DIR=$(pwd)
KEYS_DIR="${ROOT_DIR}/.keys"
mkdir -p "$KEYS_DIR"

if [ ! -f "$KEYS_DIR/grant_signing.pem" ]; then
    echo "🔑 Generating Ed25519 key pair for grant signing..."
    openssl genpkey -algorithm Ed25519 -out "$KEYS_DIR/grant_signing.pem" 2>/dev/null
    openssl pkey -in "$KEYS_DIR/grant_signing.pem" -pubout -out "$KEYS_DIR/grant_verify.pem" 2>/dev/null
fi
export GRANT_SIGNING_KEY_PATH="$KEYS_DIR/grant_signing.pem"
export GRANT_VERIFY_KEY_PATH="$KEYS_DIR/grant_verify.pem"
export GRANT_SIGNING_KEY_ID="${GRANT_SIGNING_KEY_ID:-gateway-ed25519-1}"

for arg in "$@"; do
    case "$arg" in
        --skip-build) : ;;
        community)    EDITION="community" ;;
        professional) EDITION="professional" ;;
        entreprise)   EDITION="entreprise" ;;
    esac
done

if [ "$EDITION" = "community" ]; then
    export CARGO_FEATURES=""
else
    export CARGO_FEATURES="--features messaging"
fi

echo "🌍 Selected Edition: $EDITION"

# Verify prerequisites
if ! command -v trunk &> /dev/null; then
    echo "❌ Error: 'trunk' not found in PATH. Please install it with 'cargo install trunk'."
    exit 1
fi

echo "Starting NATS JetStream server with local persistence and WebSocket..."
nats-server -c nats-server.conf &
NATS_PID=$!

function cleanup {
    echo "Shutting down..."
    kill $NATS_PID 2>/dev/null || true
    pkill -P $$ 2>/dev/null || true
}
trap cleanup EXIT

# Build components if requested or if missing
if [[ "${1:-}" != "--skip-build" ]]; then
    echo "🔨 Ensuring all components are built..."
    # We rely on 'cargo run --release' and 'trunk serve --release' to handle 
    # incremental builds efficiently. If the user ran 'make', these will be instant.
else
    echo "⏩ Skipping build checks (--skip-build set)"
fi

echo "Starting OAuth Connector MCP Server..."
(cd execution_plane/connector_mcp_server && cargo run --release --bin connector_mcp_server) &
CONNECTOR_PID=$!

echo "Starting Native Skill Executor (Claw)..."
(cd execution_plane/native_skill_executor && \
    GRANT_VERIFY_KEY_PATH="$GRANT_VERIFY_KEY_PATH" \
    cargo run --release --bin native_skill_executor) &
EXECUTOR_PID=$!

echo "Starting Trust Gateway..."
(cd execution_plane/trust_gateway && \
    POLICY_PATH="../../agent_in_a_box/host/config/policy.toml" \
    GRANT_SIGNING_KEY_PATH="$GRANT_SIGNING_KEY_PATH" \
    GRANT_SIGNING_KEY_ID="$GRANT_SIGNING_KEY_ID" \
    cargo run --release --bin trust_gateway) &
GATEWAY_PID=$!

echo "Starting Agent in a Box Host..."
(cd agent_in_a_box/host && \
    POLICY_PATH="config/policy.toml" \
    cargo run --release ${CARGO_FEATURES} --bin host) &
HOST_PID=$!

echo "Starting Local SSI Portal..."
(cd portals/local_ssi_portal && EDITION=${EDITION} trunk serve --release --port 8080) &
PORTAL_PID=$!

echo "⏳ Waiting for services to initialize..."
# Wait for Trust Gateway (3060), Host (3000), and Portal (8080)
while ! (nc -z localhost 3060 2>/dev/null && nc -z localhost 3000 2>/dev/null && nc -z localhost 8080 2>/dev/null); do
    sleep 1
done

# Small buffer to let final initialization logs flush
sleep 2

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Lianxi Community Edition is running!"
echo "  - Trust Gateway:  http://127.0.0.1:3060"
echo "  - Host:           http://127.0.0.1:3000"
echo "  - Local Portal:   http://127.0.0.1:8080"
echo "═══════════════════════════════════════════════════"
echo ""
echo ""
echo "🚀 Trust Gateway is running! Find this useful? Give us a star: https://github.com/fcn06/trust_gateway"

wait
