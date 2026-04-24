EDITION ?= community
ifeq ($(EDITION),community)
    CARGO_FEATURES =
else
    CARGO_FEATURES = --features messaging
endif

.PHONY: all build dev clean test trust-gateway host portal connector-mcp skill-executor wasm-components

all: build
	@echo "✅ Full project built in RELEASE mode."

build: trust-gateway host portal connector-mcp skill-executor
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

portal:
	@echo "🔨 Building Local SSI Portal..."
	cd portals/local_ssi_portal && EDITION=$(EDITION) trunk build --release

connector-mcp:
	@echo "🔨 Building Connector MCP Server..."
	cd execution_plane/connector_mcp_server && cargo build --release

skill-executor:
	@echo "🔨 Building Native Skill Executor (Claw)..."
	cd execution_plane/native_skill_executor && cargo build --release

dev:
	./start_dev.sh $(EDITION)

clean:
	cd execution_plane/trust_gateway && cargo clean
	cd agent_in_a_box/host && cargo clean
	cd portals/local_ssi_portal && cargo clean
	cd execution_plane/connector_mcp_server && cargo clean
	cd execution_plane/native_skill_executor && cargo clean
	rm -rf ./dist/

test:
	cd execution_plane/trust_gateway && cargo test
	cd agent_in_a_box/host && cargo test
	cd portals/local_ssi_portal && EDITION=$(EDITION) cargo test
