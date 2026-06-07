# agent_in_a_box Makefile
.PHONY: all build build-crypto build-wasm build-host build-frontend build-box-demo-shop \
        build-trust-policy \
        test test-crypto test-wasm \
        run run-frontend run-box-demo-shop \
        clean nats-reset-kv

all: build

# ── Build ──────────────────────────────────────────────
# NOTE: build-frontend is intentionally excluded here.
# The portal is built once by `trunk serve --release` in start_dev.sh.
# To build it standalone, run: make build-frontend
build: build-crypto build-wasm build-host

build-crypto:
	@echo "🔐 Building ssi_crypto..."
	cargo build --release -p ssi_crypto


build-wasm:
	@echo "🧱 Building WASM components..."
	cargo component build --release -p ssi_vault --target wasm32-wasip2

build-host:
	@echo "🤖 Building Host orchestrator..."
	cd host && OPENSSL_NO_VENDOR=1 cargo build --release $(CARGO_FEATURES)

build-frontend:
	@echo "💻 Building Local SSI Portal..."
	rm -rf ../portals/local_ssi_portal/dist
	cd ../portals/local_ssi_portal && ENABLE_MCP=$(ENABLE_MCP) EDITION=$(EDITION) trunk build --release



build-box-demo-shop:
	@echo "🏪 Building Box Demo Shop..."
	cd ../../lianxi-entreprise/box_demo_shop && cargo build --release

# ── Test ───────────────────────────────────────────────
test: test-crypto test-wasm

test-crypto:
	cargo test -p ssi_crypto



test-wasm:
	cargo component test -p ssi_vault

# ── Run ────────────────────────────────────────────────
run:
	@echo "🤖 Starting Host Orchestrator..."
	cd host && OPENSSL_NO_VENDOR=1 cargo run --release --bin host

run-frontend:
	@echo "💻 Starting Frontend on http://localhost:8080"
	rm -rf ../portals/local_ssi_portal/dist
	cd ../portals/local_ssi_portal && ENABLE_MCP=$(ENABLE_MCP) trunk serve --release



run-box-demo-shop:
	@echo "🏪 Starting Box Demo Shop on http://localhost:3002"
	cd ../../lianxi-entreprise/box_demo_shop && cargo run --release

# ── Cleanup ────────────────────────────────────────────
clean:
	cargo clean
	rm -rf target
	rm -rf ../portals/local_ssi_portal/dist
	cd ../../lianxi-entreprise/box_demo_shop && cargo clean || true

nats-reset-kv:
	./scripts/reset_nats_kv.sh
