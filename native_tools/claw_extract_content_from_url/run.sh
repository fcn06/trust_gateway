#!/bin/bash
# Skill: claw_extract_content_from_url
# Extracts text content from a given URL using Jina Reader.

RAW_ARGS="${TOOL_ARGS:-${SKILL_ARGS:-}}"
# 1. Parse 'url' argument from RAW_ARGS using sed
URL=$(echo "${RAW_ARGS}" | sed -n 's/.*"url"[ \t]*:[ \t]*"\([^"]*\)".*/\1/p')

if [ -z "$URL" ]; then
    echo '{"error": "Missing or empty \"url\" in skill arguments."}'
    exit 1
fi

SAFE_SKILL_NAME="${TOOL_NAME:-${SKILL_NAME:-claw_extract_content_from_url}}"
SAFE_ACTION_ID="${TOOL_ACTION_ID:-${SKILL_ACTION_ID:-none}}"

# 2. Execute Jina Reader request
# Jina Reader returns clean Markdown by prepending the URL or using the Accept header
RESPONSE_WITH_CODE=$(curl --max-time 15 -s -w "%{http_code}" -H "Accept: text/markdown" "https://r.jina.ai/${URL}")
JINA_HTTP_CODE="${RESPONSE_WITH_CODE: -3}"

TEXT=""
if [ "$JINA_HTTP_CODE" = "200" ]; then
    TEXT="${RESPONSE_WITH_CODE%???}"
else
    TEXT="Extraction API Error: No text content could be extracted from this URL (Jina Reader failed, HTTP $JINA_HTTP_CODE).\n\n**CRITICAL INSTRUCTION TO AGENT: DO NOT USE THE SEARCH TOOL (vp_search) TO FIND THIS CONTENT under any circumstances. The source website is rate-limited or blocked. Report this extraction failure directly to the user as a final response and stop.**"
fi

# 4. Final JSON Output
if command -v jq >/dev/null 2>&1; then
    jq -n \
      --arg result "$TEXT" \
      --arg skill "$SAFE_SKILL_NAME" \
      --arg action_id "$SAFE_ACTION_ID" \
      '{result: $result, skill: $skill, action_id: $action_id}'
else
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
