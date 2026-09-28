# trust-gateway Makefile
# Convenience targets for building, testing, and running trust-gateway.

.PHONY: all check test quickstart demo-docker conformance audit lint doctor clean

all: check test conformance

# ── Build ──────────────────────────────────────────────
check:
	@echo "🔍 Checking workspace compilation..."
	cargo check --workspace

demo-docker:
	@echo "🐳 Building quickstart demo Docker image..."
	docker build -t trust-gateway-demo -f deploy/Dockerfile.demo .

# ── Test ───────────────────────────────────────────────
test:
	@echo "🧪 Running unit tests..."
	cargo test --workspace --lib

quickstart:
	@echo "🛡️  Running standalone quickstart demo..."
	cargo run -p quickstart-standalone

conformance:
	@echo "📋 Running conformance test vectors..."
	cargo run -p conformance -- --vectors-dir test-vectors

audit:
	@echo "🔐 Running CLI audit verification..."
	cargo run -p trustctl -- audit verify test-vectors/valid_grant.json

# ── Code Quality ───────────────────────────────────────
lint:
	@echo "🧹 Checking formatting..."
	cargo fmt --all -- --check
	@echo "📎 Running clippy..."
	cargo clippy --workspace --all-targets -- -D warnings

# ── Environment ────────────────────────────────────────
doctor:
	@echo "🩺 Running environment doctor..."
	@bash scripts/doctor.sh

# ── Cleanup ────────────────────────────────────────────
clean:
	@echo "🧹 Cleaning trust-gateway workspace..."
	cargo clean || true
	@echo "🧹 Cleaning trust-gateway examples..."
	@for d in examples/*; do \
		if [ -d "$$d" ] && [ -f "$$d/Cargo.toml" ]; then \
			(cd "$$d" && cargo clean) || true; \
		fi; \
	done
	find . -name "target" -type d -prune -exec rm -rf {} +
	find examples -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find examples -type f -name "*.pyc" -delete 2>/dev/null || true
	find examples -type f -name "*.pyo" -delete 2>/dev/null || true
	find examples -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
