curl -X POST http://127.0.0.1:3060/v1/actions/propose \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_SESSION_JWT>" \
  -d '{
    "action_name": "google.calendar.event.create",
    "source_type": "picoclaw",
    "arguments": {
      "summary": "Swarm Synchronization Meeting",
      "description": "Discussing cross-agent workflows and API alignment.",
      "start": "2026-04-20T14:00:00Z",
      "end": "2026-04-20T15:00:00Z",
      "attendees": ["test-agent@example.com"]
    }
  }'