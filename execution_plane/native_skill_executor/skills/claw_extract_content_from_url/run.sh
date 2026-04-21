#!/bin/bash
# Skill: claw_extract_content_from_url
# Extracts text content from a given URL using ParseJet API.

# 1. Parse 'url' argument from SKILL_ARGS using sed
URL=$(echo "${SKILL_ARGS}" | sed -n 's/.*"url"[ \t]*:[ \t]*"\([^"]*\)".*/\1/p')

if [ -z "$URL" ]; then
    echo '{"error": "Missing or empty \"url\" in skill arguments."}'
    exit 1
fi

# 2. Execute the curl request, capturing the raw HTTP body Output
RESPONSE=$(curl -s -X POST https://api.parsejet.com/v1/parse/auto/url \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"${URL}\"}")

SAFE_SKILL_NAME="${SKILL_NAME:-claw_extract_content_from_url}"
SAFE_ACTION_ID="${SKILL_ACTION_ID:-none}"

# 3. Extract the "text" field specifically and ensure valid JSON output
if command -v jq >/dev/null 2>&1; then
    # jq is universally the best and safest tool for JSON in shell scripts
    ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error.message // .error // empty')
    if [ "$ERROR_MSG" != "" ] && [ "$ERROR_MSG" != "null" ]; then
        TEXT="Extraction API Error: $ERROR_MSG"
    else
        TEXT=$(echo "$RESPONSE" | jq -r '.text // empty')
    fi
    
    jq -n \
      --arg result "$TEXT" \
      --arg skill "$SAFE_SKILL_NAME" \
      --arg action_id "$SAFE_ACTION_ID" \
      '{result: $result, skill: $skill, action_id: $action_id}'
else
    # Fallback to sed for pure basic shell environments 
    # This strips `{"text":"` from the start and the next field `","something":` onward from the end
    TEXT=$(echo "$RESPONSE" | sed -n 's/^[^{]*{"text":"//; s/","[a-zA-Z0-9_]*":.*$//p')

    # Escape sensitive characters to inject safely as a string
    ESCAPED_TEXT=$(echo "$TEXT" | sed -e 's/\\/\\\\/g' | sed -e 's/"/\\"/g' | tr '\n' ' ' | sed -e 's/\r//g')

    cat <<EOF
{
  "result": "$ESCAPED_TEXT",
  "skill": "$SAFE_SKILL_NAME",
  "action_id": "$SAFE_ACTION_ID"
}
EOF
fi
