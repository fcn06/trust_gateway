EDITION ?= community

.PHONY: all build dev clean test

all: build

build:
	cd execution_plane/trust_gateway && cargo build
	cd agent_in_a_box/host && cargo build
	cd portals/local_ssi_portal && EDITION=$(EDITION) trunk build

dev:
	./start_dev.sh $(EDITION)

clean:
	cd execution_plane/trust_gateway && cargo clean
	cd agent_in_a_box/host && cargo clean
	cd portals/local_ssi_portal && cargo clean

test:
	cd execution_plane/trust_gateway && cargo test
	cd agent_in_a_box/host && cargo test
	cd portals/local_ssi_portal && EDITION=$(EDITION) cargo test
