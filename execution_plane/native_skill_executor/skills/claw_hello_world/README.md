# claw_hello_world

## Purpose

A diagnostic echo skill that returns the provided message. Useful for:
- Testing that the Native Skill Executor (Claw backend) is operational.
- Verifying the Trust Gateway → NSE routing pipeline.
- Confirming ExecutionGrant JWT validation works end-to-end.

## Input

| Parameter | Type   | Required | Description          |
|----------|--------|----------|----------------------|
| `message` | string | ✅       | Message to echo back |

## Usage

```json
{
  "message": "Hello from the sovereign host!"
}
```

## Procedure

This is an **atomic** (single-call) skill:

1. Call `claw_hello_world` with `{"message": "<your message>"}`.
2. The skill echoes the message back with metadata about the execution environment.
3. Returns a JSON object with the echoed message and a timestamp.

## Output Format

```json
{
  "skill": "claw_hello_world",
  "message": "Hello from the sovereign host!",
  "echoed_at": "2026-04-02T21:00:00Z"
}
```

## Error Handling

- If `message` is empty, the skill returns a warning suggesting a non-empty message.

## When to Use

- Use this skill to verify that the Claw skill pipeline is working correctly.
- Good for health-check scenarios from the agent's perspective.
- Also serves as a reference implementation for creating new Claw skills.
