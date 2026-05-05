EDITION ?= community
ifeq ($(EDITION),community)
    CARGO_FEATURES =
else
    CARGO_FEATURES = --features messaging
endif

.PHONY: all build dev clean test trust-gateway host portal public-gateway connector-mcp skill-executor wasm-components update reset

all: build
	@echo "✅ Full project built in RELEASE mode."

build: trust-gateway host portal public-gateway connector-mcp skill-executor vp-mcp
	@echo "🚀 Build complete."

trust-gateway:
	@echo "🔨 Building Trust Gateway..."
	cd execution_plane/trust_gateway && cargo build --release

host: wasm-components
	@echo "🔨 Building Host..."
	cd agent_in_a_box/host && cargo build --release $(CARGO_FEATURES)

wasm-components:
	@echo "🧱 Building WASM components..."
	cd agent_in_a_box && cargo component build --release --workspace \
		--exclude host \
		--exclude local_ssi_portal \
		--exclude public_gateway \
		--exclude ssi_crypto \
		--target wasm32-wasip2

public-gateway:
	@echo "🔨 Building Public Gateway..."
	cd platform/global_domain/public_gateway && cargo build --release

portal:
	@echo "🔨 Building Local SSI Portal..."
	cd portals/local_ssi_portal && EDITION=$(EDITION) trunk build --release

connector-mcp:
	@echo "🔨 Building Connector MCP Server..."
	cd execution_plane/connector_mcp_server && cargo build --release

skill-executor:
	@echo "🔨 Building Native Skill Executor (Claw)..."
	cd execution_plane/native_skill_executor && cargo build --release

vp-mcp:
	@echo "🔨 Building VP MCP Server..."
	cd execution_plane/vp_mcp_server && cargo build --release

dev:
	./start_dev.sh $(EDITION)

update:
	@echo "🔄 Updating all Cargo crates in lianxi-community..."
	cd agent_in_a_box && cargo update
	cd execution_plane && cargo update
	cd agents/ssi_agent && cargo update
	cd platform && cargo update
	cd examples/restaurant_demo/state_service && cargo update || true
	cd portals/local_ssi_portal && cargo update || true
	@echo "✅ All crates updated successfully."

reset:
	@echo "🔄 Resetting NATS buckets and reinitializing infrastructure..."
	@echo "y" | ./agent_in_a_box/scripts/reset_nats_kv.sh
	./agent_in_a_box/scripts/init_global_infra.sh
	@echo "✅ Infrastructure reset complete."

clean:
	cd agent_in_a_box && $(MAKE) clean || true
	cd execution_plane && cargo clean || true
	cd agents/ssi_agent && cargo clean || true
	cd platform && cargo clean || true
	cd examples/restaurant_demo/state_service && cargo clean || true
	cd portals/local_ssi_portal && cargo clean || true
	rm -rf portals/local_ssi_portal/target || true
	rm -rf portals/local_ssi_portal/dist || true
	rm -rf logs || true
	rm -rf ./dist/ || true

test:
	cd execution_plane/trust_gateway && cargo test
	cd agent_in_a_box/host && cargo test
	cd portals/local_ssi_portal && EDITION=$(EDITION) cargo test
