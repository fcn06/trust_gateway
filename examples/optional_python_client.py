#!/usr/bin/env python3
"""
OPTIONAL EXAMPLE ONLY: Not required to build, test, or run the gateway.

This script demonstrates how an external agent or script written in Python
can interact with the Marketplace Trust Gateway MCP messages endpoint.
"""

import json
import os
import urllib.request

API_KEY = os.environ.get("TRUST_GATEWAY_API_KEY", "sk_default_dev_key")
GATEWAY_URL = "http://127.0.0.1:8080/v1/mcp/messages"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {API_KEY}",
}

def call_tool(tool_name: str, arguments: dict):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }
    req = urllib.request.Request(
        GATEWAY_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers=HEADERS,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"Tool {tool_name} response:", json.dumps(data, indent=2))
    except Exception as e:
        print(f"Failed to call gateway: {e}")

if __name__ == "__main__":
    print("Calling claw_weather on local Trust Gateway...")
    call_tool("claw_weather", {"location": "London"})
