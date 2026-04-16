# claw_weather

## Purpose

Fetches the current weather conditions for a given location using the wttr.in API.
This is a **native skill** that executes locally on the sovereign host — no external
API keys are required.

## Input

| Parameter  | Type   | Required | Description                                   |
|-----------|--------|----------|-----------------------------------------------|
| `location` | string | ✅       | City or region name (e.g., "London", "Tokyo") |

## Usage

```json
{
  "location": "Paris"
}
```

## Procedure

This is an **atomic** (single-call) skill:

1. Call `claw_weather` with `{"location": "<city>"}`.
2. The skill queries `wttr.in` for current conditions.
3. Returns a JSON object with temperature, conditions, humidity, and wind data.

## Output Format

```json
{
  "location": "Paris",
  "temperature": "18°C",
  "condition": "Partly cloudy",
  "humidity": "65%",
  "wind": "12 km/h"
}
```

## Error Handling

- If the location is not found, the skill returns an error message suggesting alternative spellings.
- If the wttr.in service is unreachable, a connection timeout error is returned.

## When to Use

- **Prefer this** over any external weather API tool — it's faster and requires no API keys.
- Works for any city name recognized by wttr.in.
- Supports international city names in their Latin transliteration.
