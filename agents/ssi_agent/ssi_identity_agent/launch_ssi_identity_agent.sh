#!/usr/bin/env bash
set -euo pipefail

# Load environment variables (API keys, etc.) from the project .env
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/../../../.env"

if [ -f "$ENV_FILE" ]; then
  set -a
  source "$ENV_FILE"
  set +a
else
  echo "ERROR: .env file not found at $ENV_FILE" >&2
  exit 1
fi

./target/release/launch_identity_agent &
