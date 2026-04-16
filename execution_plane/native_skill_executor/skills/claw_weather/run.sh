#!/bin/bash
# Claw Weather Skill: Fetches current weather from wttr.in
# Arguments are provided via SKILL_ARGS environment variable

ARGS="${SKILL_ARGS:-{}}"
NAME="${SKILL_NAME:-claw_weather}"
ACTION="${SKILL_ACTION_ID:-}"

# Parse and URL-encode 'location' using jq
LOCATION=$(echo "$ARGS" | jq -r '.location | select(. != null) | @uri' 2>/dev/null)

if [ -z "$LOCATION" ]; then
    jq -n --arg err "Missing 'location' argument" \
          --arg skill "$NAME" \
          --arg action "$ACTION" \
          '{error: $err, skill: $skill, action_id: $action}'
    exit 0
fi

# Fetch JSON weather data from wttr.in
WEATHER_JSON=$(curl -s "https://wttr.in/${LOCATION}?format=j1" 2>/dev/null)

if [ -z "$WEATHER_JSON" ]; then
    jq -n --arg err "Failed to retrieve data from wttr.in" \
          --arg skill "$NAME" \
          --arg action "$ACTION" \
          '{error: $err, skill: $skill, action_id: $action}'
    exit 0
fi

# Verify the response is valid JSON
if ! echo "$WEATHER_JSON" | jq -e . >/dev/null 2>&1; then
    jq -n --arg err "Invalid JSON from wttr.in" \
          --arg raw "$WEATHER_JSON" \
          --arg skill "$NAME" \
          --arg action "$ACTION" \
          '{result: {error: $err, raw: $raw}, skill: $skill, action_id: $action}'
    exit 0
fi

# Extract only current condition and nearest area to avoid overwhelming the LLM with 40KB of forecast data
TRIMMED_JSON=$(echo "$WEATHER_JSON" | jq '{current_condition: .current_condition[0], area: .nearest_area[0]}' 2>/dev/null)

if [ -z "$TRIMMED_JSON" ] || [ "$TRIMMED_JSON" == "null" ]; then
    TRIMMED_JSON="$WEATHER_JSON"
fi

# Output the successful JSON wrapped in the standardized schema
echo "$TRIMMED_JSON" | jq --arg skill "$NAME" --arg action "$ACTION" \
    '{result: ., skill: $skill, action_id: $action}'
