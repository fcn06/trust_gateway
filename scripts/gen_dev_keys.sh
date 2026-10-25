#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEV_DIR="${ROOT}/dev"
mkdir -p "$DEV_DIR"

PRIV_KEY="${DEV_DIR}/grant_signing.pem"
PUB_KEY="${DEV_DIR}/grant_signing.pub.pem"

if [[ ! -f "$PRIV_KEY" ]]; then
  openssl genpkey -algorithm ed25519 -out "$PRIV_KEY"
  openssl pkey -in "$PRIV_KEY" -pubout -out "$PUB_KEY"
  chmod 600 "$PRIV_KEY"
  echo "Generated dev keys at ${DEV_DIR}"
else
  echo "Dev keys already exist at ${DEV_DIR}"
fi
