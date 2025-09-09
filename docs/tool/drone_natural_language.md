# Drone Natural Language Interface

## Overview
The `drone_natural_language` tool parses free‑form commands into concrete drone actions with parameters, confidence, platform optimizations, and safety checks.

## Tool Name
`drone_natural_language`

## Description
Process natural‑language commands for drone operations and return a structured interpretation with suggested actions and legal/safety guidance.

## Input Schema
- `command` (string, required): Natural‑language command, e.g., "scan for threats on 192.168.1.0/24".
- `context` (string, optional): Additional context about the environment or objective.
- `userIntent` (string, optional): High‑level user goal.
- `platform` (string, optional): Preferred platform (auto‑detected if omitted).

## Examples
```typescript
// Parse a natural‑language request
await server.callTool("drone_natural_language", {
  command: "Deploy protection against ddos on 10.0.0.0/24"
});

// Provide extra context
await server.callTool("drone_natural_language", {
  command: "jam the signals around 10.0.0.50",
  context: "authorized red‑team drill"
});
```

## Output Highlights
- Parsed action and parameters (threat type, intensity, target)
- Platform‑specific optimizations (mobile vs desktop)
- Safety checks (risk level, confirmation requirements, legal warnings)
- Suggested next actions

## Related Tools
- `drone_defense_enhanced`
- `drone_offense_enhanced`
- `drone_mobile_optimized`

