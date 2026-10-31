#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
banned='tokio|axum|async-nats|reqwest|rusqlite|hyper|sqlx|redb|dashmap'

if command -v cargo-deny >/dev/null 2>&1; then
  echo "Enforcing SDK purity via cargo-deny check bans..."
  cargo deny check bans --config deny.toml
fi

if cargo tree -p trust-sdk --prefix none 2>/dev/null | grep -Ei "^(${banned}) " ; then
  echo "FAIL: trust-sdk pulls a banned dependency" >&2
  exit 1
fi
start=$(date +%s); cargo build -p trust-sdk --quiet; end=$(date +%s)
echo "trust-sdk build time: $((end-start))s"
