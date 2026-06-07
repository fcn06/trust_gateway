#!/bin/bash
# init_global_infra.sh
# Initializes NATS JetStream infrastructure for Agent-in-a-Box Global Server
# Must be run after NATS server starts, before Global Portal starts

set -e

NATS_URL="${NATS_URL:-nats://localhost:4222}"

echo "🔧 Initializing Global Infrastructure..."
echo "   NATS URL: $NATS_URL"

# Handle nkey authentication if provided
NATS_OPTS=""
if [ -n "$NATS_NKEY_SEED" ]; then
    SEED_FILE=$(mktemp)
    echo "$NATS_NKEY_SEED" > "$SEED_FILE"
    # Ensure we bypass any existing nats context
    export NATS_CONTEXT=""
    NATS_OPTS="--nkey $SEED_FILE"
    trap 'rm -f "$SEED_FILE"' EXIT
fi

# Check if nats CLI is installed
if ! command -v nats &> /dev/null; then
    echo "❌ 'nats' CLI not found. Please install it:"
    echo "   curl -sf https://binaries.nats.dev/nats-io/natscli/nats@latest | sh"
    exit 1
fi

# Create dht_discovery bucket (for blind DID pointers, persistent)
echo "📦 Creating 'dht_discovery' bucket..."
if nats kv info dht_discovery --server "$NATS_URL" $NATS_OPTS &> /dev/null; then
    echo "   ✓ 'dht_discovery' bucket already exists"
else
    nats kv add dht_discovery \
        --server "$NATS_URL" \
        $NATS_OPTS \
        --history 1 \
        --description "DHT discovery pointers (persistent)"
    echo "   ✓ 'dht_discovery' bucket created"
fi

echo "✅ Global Infrastructure initialized successfully!"
echo ""
echo "You can now start the Global Portal service."
