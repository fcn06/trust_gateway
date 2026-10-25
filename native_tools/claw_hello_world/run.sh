#!/usr/bin/env bash
set -euo pipefail
ARGS="${TOOL_ARGS:-${SKILL_ARGS:-}}"
MESSAGE="Hello from Claw!"
if [[ -n "$ARGS" ]]; then
  PARSED=$(echo "$ARGS" | sed -n 's/.*"message"[ \t]*:[ \t]*"\([^"]*\)".*/\1/p')
  if [[ -n "$PARSED" ]]; then
    MESSAGE="$PARSED"
  fi
fi
SAFE_NAME="${TOOL_NAME:-${SKILL_NAME:-claw_hello_world}}"
SAFE_ACTION_ID="${TOOL_ACTION_ID:-${SKILL_ACTION_ID:-none}}"
echo "{\"result\": \"${MESSAGE}\", \"skill\": \"${SAFE_NAME}\", \"action_id\": \"${SAFE_ACTION_ID}\"}"
