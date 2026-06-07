# global_domain Makefile
ENABLE_MCP ?= false
.PHONY: all build build-public-gateway \
        run-public-gateway \
        clean nats-reset-kv init generate-keys

all: build

# ── Build ──────────────────────────────────────────────
build: build-public-gateway

build-public-gateway:
	@echo "🌐 Building Public Gateway..."
	cd public_gateway && cargo build --release

# ── Run ────────────────────────────────────────────────
run-public-gateway:
	@echo "🌐 Starting Public Gateway on http://localhost:3002"
	cd public_gateway && cargo run --release

# ── Cleanup ────────────────────────────────────────────
clean:
	cargo clean
	rm -rf target

# ── Infrastructure ─────────────────────────────────────
nats-reset-kv:
	@echo "⚠️  Wiping all NATS KV data..."
	@echo y | ./scripts/reset_nats_kv.sh
	./scripts/init_global_infra.sh

generate-keys:
	@echo "🔑 Generating Gateway Keys..."
	@if [ ! -f public_gateway/.env ]; then \
		PRIV=$$(openssl rand -base64 32); \
		echo "GATEWAY_PRIVATE_KEY=$$PRIV" > public_gateway/.env; \
		echo "✅ Generated public_gateway/.env"; \
	else \
		echo "⚠️  public_gateway/.env already exists, skipping generation."; \
	fi
	@echo "----------------------------------------------------------------"
	@echo "📦 GATEWAY PUBLIC KEY:"
	@cd public_gateway && cargo run --release -- --print-pub-key-only
	@echo "----------------------------------------------------------------"

init: nats-reset-kv generate-keys
	@echo "✅ Global Domain initialization complete!"
