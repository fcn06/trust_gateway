EDITION ?= community
ifeq ($(EDITION),community)
    CARGO_FEATURES =
else
    CARGO_FEATURES = --features messaging
endif

.PHONY: all build dev clean test trust-gateway host portal public-gateway connector-mcp skill-executor wasm-components update reset executor-host

all: build
	@echo "✅ Full project built in RELEASE mode."

build: trust-gateway host portal public-gateway executor-host connector-mcp
	@echo "🚀 Build complete."

trust-gateway:
	@echo "🔨 Building Trust Gateway..."
	cd execution_plane/trust_gateway && cargo build --release

host: wasm-components
	@echo "🔨 Building Host..."
	cd agent_in_a_box/host && cargo build --release $(CARGO_FEATURES)

wasm-components:
	@echo "🧱 Building WASM components..."
	cd agent_in_a_box && cargo component build --release -p ssi_vault --target wasm32-wasip2

public-gateway:
	@echo "🔨 Building Public Gateway..."
	cd platform/global_domain/public_gateway && cargo build --release

portal:
	@echo "🔨 Building Local SSI Portal..."
	cd portals/local_ssi_portal && EDITION=$(EDITION) trunk build --release

# REC-1: Unified executor_host replaces connector_mcp_server, native_skill_executor, vp_mcp_server.
executor-host:
	@echo "⚡ Building executor_host (unified: native-skill, connector, vp profiles)..."
	cd execution_plane/executor_host && cargo build --release

connector-mcp:
	@echo "🔨 Building Connector MCP Server (OAuth Helper)..."
	cd execution_plane/connector_mcp_server && cargo build --release

# Legacy aliases (backward compatibility)
skill-executor: executor-host
vp-mcp: executor-host



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
	../stop_dev.sh || true
	pkill nats-server || true
	cd agent_in_a_box && $(MAKE) clean || true
	cd execution_plane && cargo clean || true
	cd agents/ssi_agent && cargo clean || true
	cd platform && cargo clean || true
	cd portals/local_ssi_portal && cargo clean || true
	rm -rf portals/local_ssi_portal/dist || true
	cd ../scripts/nkey_gen && cargo clean || true
	cd agent_in_a_box/host/inspect_kv && cargo clean || true
	rm -rf ../.keys || true
	rm -rf ../.nats_data || true
	rm -rf logs || true
	rm -rf ./dist/ || true
	@if [ -f portals/local_ssi_portal/config.json ]; then \
		jq '.cloudflare_beacon_token = ""' portals/local_ssi_portal/config.json > tmp.json && mv tmp.json portals/local_ssi_portal/config.json || true; \
	fi


test:
	cd execution_plane/trust_gateway && cargo test
	cd agent_in_a_box/host && cargo test
	cd portals/local_ssi_portal && EDITION=$(EDITION) cargo test
