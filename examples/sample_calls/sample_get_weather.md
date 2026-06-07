curl -X POST http://127.0.0.1:3060/v1/actions/propose \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_SESSION_JWT>" \
  -d '{
    "action_name": "claw_weather",
    "source_type": "picoclaw",
    "arguments": {
      "location": "Nice"
    }
  }'