#!/usr/bin/env bash
# start.sh
# Automates the startup of the Trust Gateway community ecosystem using Docker Compose.

set -euo pipefail

# Ensure we run from the script's directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 1. Generate Ed25519 Grant Keys
KEYS_DIR="./keys"
mkdir -p "$KEYS_DIR"

if [ ! -f "$KEYS_DIR/grant_signing.pem" ]; then
    echo "🔑 Generating Ed25519 key pair for grant signing..."
    openssl genpkey -algorithm Ed25519 -out "$KEYS_DIR/grant_signing.pem" 2>/dev/null
    openssl pkey -in "$KEYS_DIR/grant_signing.pem" -pubout -out "$KEYS_DIR/grant_verify.pem" 2>/dev/null
fi

# 2. Download and run NATS 'nk' tool to generate ephemeral credentials
NK_BIN="nk"
if [ -x "./nk" ]; then
    NK_BIN="./nk"
elif ! command -v nk &> /dev/null; then
    echo "📥 Downloading 'nk' tool..."
    curl -sf https://binaries.nats.dev/nats-io/nkeys/nk@latest | sh
    NK_BIN="./nk"
fi

echo "🔑 Generating ephemeral NATS nkeys for services..."
NATS_NKEY_SEED_HOST=$($NK_BIN -gen user)
PUB_HOST=$(echo "$NATS_NKEY_SEED_HOST" | $NK_BIN -inkey /dev/stdin -pubout)

NATS_NKEY_SEED_SSI=$($NK_BIN -gen user)
PUB_SSI=$(echo "$NATS_NKEY_SEED_SSI" | $NK_BIN -inkey /dev/stdin -pubout)

NATS_NKEY_SEED_TG=$($NK_BIN -gen user)
PUB_TG=$(echo "$NATS_NKEY_SEED_TG" | $NK_BIN -inkey /dev/stdin -pubout)

NATS_NKEY_SEED_CONN=$($NK_BIN -gen user)
PUB_CONN=$(echo "$NATS_NKEY_SEED_CONN" | $NK_BIN -inkey /dev/stdin -pubout)

NATS_NKEY_SEED_NSE=$($NK_BIN -gen user)
PUB_NSE=$($NK_BIN -gen user) # Use a separate seed for NSE
PUB_NSE_KEY=$(echo "$NATS_NKEY_SEED_NSE" | $NK_BIN -inkey /dev/stdin -pubout)

NATS_NKEY_SEED_VP=$($NK_BIN -gen user)
PUB_VP=$(echo "$NATS_NKEY_SEED_VP" | $NK_BIN -inkey /dev/stdin -pubout)

NATS_NKEY_SEED_B2B=$($NK_BIN -gen user)
PUB_B2B=$(echo "$NATS_NKEY_SEED_B2B" | $NK_BIN -inkey /dev/stdin -pubout)

# 3. Generate nats-server-auth.conf
echo "🔒 Generating NATS server authorization config..."
cat <<EOF > nats-server-auth.conf
authorization {
  users = [
    { nkey: "$PUB_HOST",
      publish: { allow: ["a2a.v1.>", "approval.v1.>", "host.v1.>", "trust.v1.discovery.list_tools", "mcp.v1.discovery.reply.>", "_INBOX.>"] },
      subscribe: { allow: ["trust.v1.>", "ui.v1.>", "host.v1.>", "approval.v1.*.requested", "_INBOX.>"] } },
    { nkey: "$PUB_SSI",
      publish: { allow: ["trust.v1.>", "_INBOX.>"] },
      subscribe: { allow: ["a2a.v1.>", "trust.v1.>", "mcp.v1.discovery.reply.>", "_INBOX.>"] } },
    { nkey: "$PUB_TG",
      publish: { allow: ["trust.v1.>", "approval.v1.*.requested", "audit.action.>", "host.v1.escalation.>", "mcp.v1.webhook.>", "ui.v1.>", "exec.v1.>", "$JS.>", "$KV.>", "_INBOX.>"] },
      subscribe: { allow: ["trust.v1.>", "approval.v1.*.decided", "host.v1.tools.>", "claw.v1.>", "exec.v1.reply.>", "$JS.>", "$KV.>", "_INBOX.>"] } },
    { nkey: "$PUB_CONN",
      subscribe: { allow: ["connector.v1.>", "exec.v1.*.connector.invoke", "_INBOX.>"] },
      publish: { allow: ["connector.v1.>", "exec.v1.reply.>", "_INBOX.>"] } },
    { nkey: "$PUB_NSE_KEY",
      subscribe: { allow: ["executor.v1.>", "exec.v1.*.native-tool.invoke", "_INBOX.>"] },
      publish: { allow: ["executor.v1.>", "claw.v1.tools.changed", "exec.v1.reply.>", "_INBOX.>"] } },
    { nkey: "$PUB_VP",
      subscribe: { allow: ["vp.v1.>", "exec.v1.*.vp.invoke", "_INBOX.>"] },
      publish: { allow: ["vp.v1.>", "exec.v1.reply.>", "_INBOX.>"] } },
    { nkey: "$PUB_B2B",
      subscribe: { allow: ["a2a.v1.*.b2b.send", "_INBOX.>"] },
      publish: { allow: ["trust.v1.>", "_INBOX.>"] } },
  ]
}
EOF

# 4. Prepare env file by merging user .env and generated keys
echo "📝 Merging environment variables into .env.docker..."
JWT_SECRET=$(openssl rand -base64 32)
EDITION="community"
LLM_MCP_API_KEY=""
LLM_A2A_API_KEY=""
GOOGLE_CLIENT_ID=""
GOOGLE_CLIENT_SECRET=""
GOOGLE_REDIRECT_URI="http://localhost:3060/oauth/google/callback"
ALLOWED_ORIGINS="http://localhost:8080,http://127.0.0.1:8080,http://localhost:8083,http://127.0.0.1:8083"

if [ -f .env ]; then
    # Parse existing variables
    JWT_SECRET=$(grep -E "^JWT_SECRET=" .env | cut -d'=' -f2- || echo "$JWT_SECRET")
    EDITION=$(grep -E "^EDITION=" .env | cut -d'=' -f2- || echo "community")
    LLM_MCP_API_KEY=$(grep -E "^LLM_MCP_API_KEY=" .env | cut -d'=' -f2- || echo "")
    LLM_A2A_API_KEY=$(grep -E "^LLM_A2A_API_KEY=" .env | cut -d'=' -f2- || echo "")
    GOOGLE_CLIENT_ID=$(grep -E "^GOOGLE_CLIENT_ID=" .env | cut -d'=' -f2- || echo "")
    GOOGLE_CLIENT_SECRET=$(grep -E "^GOOGLE_CLIENT_SECRET=" .env | cut -d'=' -f2- || echo "")
    GOOGLE_REDIRECT_URI=$(grep -E "^GOOGLE_REDIRECT_URI=" .env | cut -d'=' -f2- || echo "$GOOGLE_REDIRECT_URI")
    ALLOWED_ORIGINS=$(grep -E "^ALLOWED_ORIGINS=" .env | cut -d'=' -f2- || echo "$ALLOWED_ORIGINS")
fi

cat <<EOF > .env.docker
JWT_SECRET=$JWT_SECRET
EDITION=$EDITION
LLM_MCP_API_KEY=$LLM_MCP_API_KEY
LLM_A2A_API_KEY=$LLM_A2A_API_KEY
GOOGLE_CLIENT_ID=$GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET=$GOOGLE_CLIENT_SECRET
GOOGLE_REDIRECT_URI=$GOOGLE_REDIRECT_URI
ALLOWED_ORIGINS=$ALLOWED_ORIGINS
UI_PROJECTION_ENABLED=1
POLICY_SIGNATURE_REQUIRED=0
LIANXI_ENV=development

# Ephemeral seeds
NATS_NKEY_SEED_HOST=$NATS_NKEY_SEED_HOST
NATS_NKEY_SEED_SSI=$NATS_NKEY_SEED_SSI
NATS_NKEY_SEED_TG=$NATS_NKEY_SEED_TG
NATS_NKEY_SEED_CONN=$NATS_NKEY_SEED_CONN
NATS_NKEY_SEED_NSE=$NATS_NKEY_SEED_NSE
NATS_NKEY_SEED_VP=$NATS_NKEY_SEED_VP
NATS_NKEY_SEED_B2B=$NATS_NKEY_SEED_B2B
EOF

# Make sure permissions of start.sh and init_infra.sh are executable
chmod +x "$SCRIPT_DIR/start.sh"
if [ -f "$SCRIPT_DIR/init_infra.sh" ]; then
    chmod +x "$SCRIPT_DIR/init_infra.sh"
fi

echo "🚀 Starting Docker Compose environment..."
docker compose --env-file .env.docker up --build "$@"
