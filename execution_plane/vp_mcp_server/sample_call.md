To invoke the 
list_files
 tool on your agent_mcp_server running on port 3000, you need to handle two things:

MCP Protocol (SSE): The server uses Server-Sent Events (SSE). You must listen to the SSE stream to receive the response.
SSI Authentication: The server enforces SSI middleware, so you must provide the _meta object with X-Envelope and X-Instruction (Signed Intent).
Since curl is synchronous and stateless, you cannot simply "get a response" in one command. You need two terminals.

Step 1: Subscribe to Events (Terminal 1)
Run this to see the tool output (content) when it arrives.

bash
curl -N http://localhost:3001/sse
Keep this running. You will see an endpoint event containing a sessionId.

Step 2: Call the Tool (Terminal 2)
Replace SESSION_ID with the ID from Terminal 1. You also need to verify if you have a valid Signed Intent (VP). If you are just testing and want to verify connectivity (expecting a 401 Unauthorized), use this:

bash
# Replace SESSION_ID with the uuid from Terminal 1
curl -X POST "http://localhost:3001/message?sessionId=SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "list_files",
      "arguments": {
        "path": "<YOUR-DEFAULT-PATH>",
        "_meta": {
          "X-Envelope": "PLACEHOLDER_VP_JWT_HERE",
          "X-Instruction": "PLACEHOLDER_INSTRUCTION_STRING"
        }
      }
    },
    "id": 1
  }'
Why this is complex with CURL
The SSI Middleware protecting your server blindly rejects requests without a cryptographic signature (X-Envelope). To make a truly "functional" call that lists files, you would need a client that:

Generates an Ed25519 signature of the instruction.
Wraps it in a Verifiable Presentation (VP).
Establishes the SSE connection.
If you simply want to test the 
list_files
 logic without the crypto overhead for development, let me know, and I can add a debug flag to disable the middleware temporarily.

