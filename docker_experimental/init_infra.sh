#!/bin/sh
# init_infra.sh
# Runs inside the nats-box container to initialize NATS JetStream KV buckets.

set -e

NATS_URL="${NATS_URL:-nats://nats:4222}"

echo "⏳ Waiting for NATS server at $NATS_URL to become ready..."
until nats --server "$NATS_URL" ping 2>/dev/null; do
    sleep 1
done
echo "✅ NATS server is reachable."

NATS_OPTS=""
if [ -n "${NATS_NKEY_SEED:-}" ]; then
    SEED_FILE=$(mktemp)
    echo "$NATS_NKEY_SEED" > "$SEED_FILE"
    NATS_OPTS="--nkey $SEED_FILE"
    trap 'rm -f "$SEED_FILE"' EXIT
fi

# Initialize telegram_rate_limit bucket (TTL 30 min)
echo "📦 Checking 'telegram_rate_limit' bucket..."
if nats kv info telegram_rate_limit --server "$NATS_URL" $NATS_OPTS >/dev/null 2>&1; then
    echo "   ✓ 'telegram_rate_limit' bucket already exists"
else
    echo "   ➕ Creating 'telegram_rate_limit' bucket..."
    nats kv add telegram_rate_limit \
        --server "$NATS_URL" \
        $NATS_OPTS \
        --ttl 30m \
        --history 1 \
        --description "Telegram linking rate limit (TTL 30min)"
fi

# Initialize dht_discovery bucket (persistent)
echo "📦 Checking 'dht_discovery' bucket..."
if nats kv info dht_discovery --server "$NATS_URL" $NATS_OPTS >/dev/null 2>&1; then
    echo "   ✓ 'dht_discovery' bucket already exists"
else
    echo "   ➕ Creating 'dht_discovery' bucket..."
    nats kv add dht_discovery \
        --server "$NATS_URL" \
        $NATS_OPTS \
        --history 1 \
        --description "DHT discovery pointers (persistent)"
fi

echo "🎉 NATS JetStream Infrastructure Initialized Successfully!"
