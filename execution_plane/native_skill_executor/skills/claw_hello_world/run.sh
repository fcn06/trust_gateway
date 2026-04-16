#!/bin/bash
# Example Claw skill: echoes back the provided message
# Arguments are available via:
#   SKILL_ARGS env var (JSON string)
#   stdin (JSON string)

ARGS="${SKILL_ARGS}"
MESSAGE=$(echo "$ARGS" | python3 -c "import sys, json; print(json.load(sys.stdin).get('message', 'Hello from Claw!'))" 2>/dev/null || echo "Hello from Claw!")

echo "{\"result\": \"${MESSAGE}\", \"skill\": \"${SKILL_NAME}\", \"action_id\": \"${SKILL_ACTION_ID}\"}"
