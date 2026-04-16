#!/bin/bash
# init_global_infra.sh
# Initializes NATS JetStream infrastructure for Agent-in-a-Box Global Server
# Must be run after NATS server starts, before Global Portal starts

set -e

NATS_URL="${NATS_URL:-nats://localhost:4222}"

echo "🔧 Initializing Global Infrastructure..."
echo "   NATS URL: $NATS_URL"

# Check if nats CLI is installed
if ! command -v nats &> /dev/null; then
    echo "❌ 'nats' CLI not found. Please install it:"
    echo "   curl -sf https://binaries.nats.dev/nats-io/natscli/nats@latest | sh"
    exit 1
fi

# Create provisioning bucket (for Bridge Codes, TTL 5 min)
echo "📦 Creating 'provisioning' bucket..."
if nats kv info provisioning --server "$NATS_URL" &> /dev/null; then
    echo "   ✓ 'provisioning' bucket already exists"
else
    nats kv add provisioning \
        --server "$NATS_URL" \
        --ttl 5m \
        --history 1 \
        --description "Bridge code provisioning (TTL 5min)"
    echo "   ✓ 'provisioning' bucket created"
fi

# Create dht_discovery bucket (for blind DID pointers, TTL 10 min)
echo "📦 Creating 'dht_discovery' bucket..."
if nats kv info dht_discovery --server "$NATS_URL" &> /dev/null; then
    echo "   ✓ 'dht_discovery' bucket already exists"
else
    nats kv add dht_discovery \
        --server "$NATS_URL" \
        --ttl 10m \
        --history 1 \
        --description "DHT discovery pointers (TTL 10min)"
    echo "   ✓ 'dht_discovery' bucket created"
fi

echo "✅ Global Infrastructure initialized successfully!"
echo ""
echo "You can now start the Global Portal service."
