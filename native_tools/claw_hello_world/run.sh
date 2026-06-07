#!/bin/bash
# Example Claw skill: echoes back the provided message
# Arguments are available via:
#   SKILL_ARGS env var (JSON string)
#   stdin (JSON string)

ARGS="${TOOL_ARGS:-${SKILL_ARGS}}"
MESSAGE=$(echo "$ARGS" | python3 -c "import sys, json; print(json.load(sys.stdin).get('message', 'Hello from Claw!'))" 2>/dev/null || echo "Hello from Claw!")

SAFE_NAME="${TOOL_NAME:-${SKILL_NAME}}"
SAFE_ACTION_ID="${TOOL_ACTION_ID:-${SKILL_ACTION_ID}}"
echo "{\"result\": \"${MESSAGE}\", \"skill\": \"${SAFE_NAME}\", \"action_id\": \"${SAFE_ACTION_ID}\"}"
