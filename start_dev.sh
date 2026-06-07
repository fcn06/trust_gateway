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
export GOOGLE_REDIRECT_URI="${GOOGLE_REDIRECT_URI:-http://localhost:3060/oauth/google/callback}"

export DEFAULT_TOOLS="${DEFAULT_TOOLS:-search_skills,switch_context,list_bundles,vp_search,claw_weather,google_calendar_create_event,google_calendar_list_events}"
export EDITION="${EDITION:-community}"

export ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-http://localhost:8080,http://127.0.0.1:8080,http://localhost:8083,http://127.0.0.1:8083}"

# Phase 4: UI Projection Layer
export UI_PROJECTION_ENABLED="${UI_PROJECTION_ENABLED:-1}"

# Phase 6: Policy Signature Verification
export POLICY_SIGNATURE_REQUIRED="${POLICY_SIGNATURE_REQUIRED:-0}"
# export POLICY_SIGNATURE_PUBLIC_KEY="<ed25519-hex-public-key>"

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

# ── Phase 1: Ephemeral NATS Authentication ──────────────────
# Path to the nk binary (assumed in path or in the root directory for dev)
NK_BIN="nk"
if [ -x "./nk" ]; then
    NK_BIN="./nk"
elif ! command -v nk &> /dev/null; then
    echo "❌ Error: 'nk' not found. Please install the nkeys CLI tool or place the binary in the current directory."
    exit 1
fi

echo "🔑 Generating ephemeral NATS nkeys for services..."
export NATS_NKEY_SEED_HOST=$($NK_BIN -gen user)
PUB_HOST=$(echo "$NATS_NKEY_SEED_HOST" | $NK_BIN -inkey /dev/stdin -pubout)

export NATS_NKEY_SEED_SSI=$($NK_BIN -gen user)
PUB_SSI=$(echo "$NATS_NKEY_SEED_SSI" | $NK_BIN -inkey /dev/stdin -pubout)

export NATS_NKEY_SEED_TG=$($NK_BIN -gen user)
PUB_TG=$(echo "$NATS_NKEY_SEED_TG" | $NK_BIN -inkey /dev/stdin -pubout)

export NATS_NKEY_SEED_CONN=$($NK_BIN -gen user)
PUB_CONN=$(echo "$NATS_NKEY_SEED_CONN" | $NK_BIN -inkey /dev/stdin -pubout)

export NATS_NKEY_SEED_NSE=$($NK_BIN -gen user)
PUB_NSE=$(echo "$NATS_NKEY_SEED_NSE" | $NK_BIN -inkey /dev/stdin -pubout)

export NATS_NKEY_SEED_VP=$($NK_BIN -gen user)
PUB_VP=$(echo "$NATS_NKEY_SEED_VP" | $NK_BIN -inkey /dev/stdin -pubout)

export NATS_NKEY_SEED_B2B=$($NK_BIN -gen user)
PUB_B2B=$(echo "$NATS_NKEY_SEED_B2B" | $NK_BIN -inkey /dev/stdin -pubout)

# Generate nats-server-auth.conf
cat <<EOF > nats-server-auth.conf
authorization {
  users = [
    { nkey: "$PUB_HOST",
      publish: { allow: ["a2a.v1.>", "approval.v1.>", "host.v1.>", "trust.v1.discovery.list_tools", "mcp.v1.discovery.reply.>"] },
      subscribe: { allow: ["trust.v1.>", "ui.v1.>", "host.v1.>", "approval.v1.*.requested"] } },
    { nkey: "$PUB_SSI",
      publish: { allow: ["trust.v1.>"] },
      subscribe: { allow: ["a2a.v1.>", "trust.v1.>", "mcp.v1.discovery.reply.>"] } },
    { nkey: "$PUB_TG",
      publish: { allow: ["trust.v1.>", "approval.v1.*.requested", "audit.action.>", "host.v1.escalation.>", "mcp.v1.webhook.>", "ui.v1.>", "exec.v1.>"] },
      subscribe: { allow: ["trust.v1.>", "approval.v1.*.decided", "host.v1.tools.>", "claw.v1.>", "exec.v1.reply.>"] } },
    { nkey: "$PUB_CONN",
      subscribe: { allow: ["connector.v1.>", "exec.v1.*.connector.invoke"] },
      publish: { allow: ["connector.v1.>", "exec.v1.reply.>"] } },
    { nkey: "$PUB_NSE",
      subscribe: { allow: ["executor.v1.>", "exec.v1.*.native-tool.invoke"] },
      publish: { allow: ["executor.v1.>", "claw.v1.tools.changed", "exec.v1.reply.>"] } },
    { nkey: "$PUB_VP",
      subscribe: { allow: ["vp.v1.>", "exec.v1.*.vp.invoke"] },
      publish: { allow: ["vp.v1.>", "exec.v1.reply.>"] } },
    { nkey: "$PUB_B2B",
      subscribe: { allow: ["a2a.v1.*.b2b.send"] },
      publish: { allow: ["trust.v1.>"] } },
  ]
}
EOF
echo "🔒 Ephemeral NATS authorization config generated."

for arg in "$@"; do
    case "$arg" in
        --skip-build) : ;;
        community)    EDITION="community" ;;
        professional) EDITION="professional" ;;
        entreprise)   EDITION="entreprise" ;;
    esac
done

export CARGO_FEATURES=""

echo "🌍 Selected Edition: $EDITION"

# Verify prerequisites
if ! command -v trunk &> /dev/null; then
    echo "❌ Error: 'trunk' not found in PATH. Please install it with 'cargo install trunk'."
    exit 1
fi

echo "Starting NATS JetStream server with local persistence and WebSocket..."
nats-server -c nats-server.conf &
NATS_PID=$!
sleep 2

# Initialize Global Infrastructure
echo "🔧 Initializing NATS infrastructure (buckets, TTLs)..."
./agent_in_a_box/scripts/init_global_infra.sh

function cleanup {
    echo "Shutting down..."
    kill $TGX_PID 2>/dev/null || true
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



# REC-1: Unified executor_host replaces legacy native_skill_executor
echo "Starting Executor Host (native-tool profile)..."
(cd execution_plane/executor_host && \
    EXECUTOR_PROFILE=native-tool \
    NATIVE_TOOLS_DIR="$(pwd)/native_tools" \
    GRANT_VERIFY_KEY_PATH="$GRANT_VERIFY_KEY_PATH" \
    NATS_NKEY_SEED="$NATS_NKEY_SEED_NSE" \
    cargo run --release --bin executor_host) &
EXECUTOR_PID=$!

echo "Starting Executor Host (connector profile)..."
(cd execution_plane/executor_host && \
    EXECUTOR_PROFILE=connector \
    GRANT_VERIFY_KEY_PATH="$GRANT_VERIFY_KEY_PATH" \
    NATS_NKEY_SEED="$NATS_NKEY_SEED_CONN" \
    cargo run --release --bin executor_host) &
CONNECTOR_PID=$!

echo "Starting Legacy OAuth Helper (Connector MCP on Port 3050)..."
(cd execution_plane/connector_mcp_server && \
    CONNECTOR_LISTEN=0.0.0.0:3050 \
    NATS_URL="nats://127.0.0.1:4222" \
    NATS_NKEY_SEED="$NATS_NKEY_SEED_CONN" \
    GOOGLE_CLIENT_ID="$GOOGLE_CLIENT_ID" \
    GOOGLE_CLIENT_SECRET="$GOOGLE_CLIENT_SECRET" \
    GOOGLE_REDIRECT_URI="$GOOGLE_REDIRECT_URI" \
    JWT_SECRET="$JWT_SECRET" \
    ALLOWED_ORIGINS="$ALLOWED_ORIGINS" \
    cargo run --release --bin connector_mcp_server) &
CONNECTOR_MCP_PID=$!



echo "Starting Trust Gateway..."
(cd execution_plane/trust_gateway && \
    POLICY_PATH="../../agent_in_a_box/host/config/policy.toml" \
    GRANT_SIGNING_KEY_PATH="$GRANT_SIGNING_KEY_PATH" \
    GRANT_SIGNING_KEY_ID="$GRANT_SIGNING_KEY_ID" \
    NATS_NKEY_SEED="$NATS_NKEY_SEED_TG" \
    cargo run --release --bin trust_gateway) &
GATEWAY_PID=$!

echo "Starting VP Search Executor..."
(cd execution_plane/executor_host && \
    EXECUTOR_PROFILE=vp \
    GRANT_VERIFY_KEY_PATH="$GRANT_VERIFY_KEY_PATH" \
    NATS_NKEY_SEED="$NATS_NKEY_SEED_VP" \
    cargo run --release --bin executor_host) &
VP_EXECUTOR_PID=$!

echo "Starting Agent in a Box Host..."
(cd agent_in_a_box/host && \
    POLICY_PATH="config/policy.toml" \
    NATS_NKEY_SEED="$NATS_NKEY_SEED_HOST" \
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
