
## Interactive Walkthrough: From Intent to Execution

Once you have the stack running (via `./start_dev.sh`), follow these steps to see the governance layer in action.

### Step 1: Propose an Action via API

Simulate an agent intent by proposing a Google Calendar event. You will need a session JWT, which you can find in the **Local SSI Portal** session debug logs or session storage.

```bash
curl -X POST http://localhost:3060/v1/actions/propose \
  -H "Authorization: Bearer <your-session-jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "action_name": "google.calendar.event.create",
    "arguments": { "summary": "Strategy Meeting", "start": "2026-04-24T11:00:00Z" }
  }'
```

**Expected Response:**
The Gateway intercepts the request and, based on the default policy, flags it for manual approval:
```json
{
  "action_id": "7f7f7213-f7ba-458d-8d4f-2fd62de3fab2",
  "status": "pending_approval",
  "approval_id": "5b9c6bff-e830-4f81-bc26-195be95f3470",
  "escalation": "tier1_portal_click"
}
```

### Step 2: Human-in-the-Loop Validation

1. Open the **Local SSI Portal** at `http://localhost:8080`.
2. Navigate to the **Validation** area.
3. You will see the pending `google.calendar.event.create` request. Here you can inspect the raw arguments and decide whether to **Approve** or **Deny** the action.

### Step 3: Verified Execution

If you are connected via an MCP-compatible client (like Claude Desktop or another agent runtime):
1. Upon clicking **Approve**, the Gateway issues a cryptographic execution grant.
2. The Gateway dispatches the action to the appropriate connector.
3. The agent receives the confirmation and the full return payload (e.g., the created calendar event details).
