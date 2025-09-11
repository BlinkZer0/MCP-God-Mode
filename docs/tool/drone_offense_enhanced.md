# Enhanced Drone Offense

## Overview
The `drone_offense_enhanced` tool executes tightly‑gated offensive operations with cross‑platform support and explicit legal/safety controls. It supports a natural‑language option and mobile‑aware optimizations.

## Tool Name
`drone_offense_enhanced`

## Description
Cross‑platform offensive actions (with risk acknowledgment and double‑confirmation when applicable). Real-world operations by default with actual signal jamming, decoy deployment, and counter-strike capabilities, desktop/mobile tuning, and comprehensive legal warnings in responses.

## Input Schema
- `action` (string, required): Offensive action. Options:
  - `jam_signals` – Disrupt/overwhelm targeted channels with real signal jamming
  - `deploy_decoy` – Plant decoys and diversion targets with actual honeypots
  - `counter_strike` – Controlled counter‑actions with real reconnaissance
- `targetIp` (string, required): Target (host/IP/CIDR depending on action).
- `intensity` (string, optional, default `"low"`): `low` | `medium` | `high`.
- `riskAcknowledged` (boolean, required): Must be `true` to proceed.
- `threatLevel` (number, optional, default `5`): 1–10; `>7` requires double confirmation.
- `autoConfirm` (boolean, optional, default `false`): Skip prompts (requires `MCPGM_REQUIRE_CONFIRMATION=false`).
- `naturalLanguageCommand` (string, optional): e.g., "jam the signals", "deploy a decoy", "strike back".

## Natural Language Access
Sample requests:
- "Jam the attacker’s signals, medium intensity"
- "Deploy a decoy to distract the probe"
- "Strike back at 10.0.0.50, low intensity"

## Examples
```typescript
// Jam signals (real-world operations by default)
await server.callTool("drone_offense_enhanced", {
  action: "jam_signals",
  targetIp: "10.0.0.50",
  intensity: "medium",
  riskAcknowledged: true,
  threatLevel: 6
});

// Natural‑language command with fallback
await server.callTool("drone_offense_enhanced", {
  naturalLanguageCommand: "deploy a decoy for the intruder",
  action: "deploy_decoy",
  targetIp: "10.0.0.99",
  riskAcknowledged: true,
  autoConfirm: true
});
```

## Platform Support
- Windows, Linux, macOS (full capabilities)
- Android, iOS (mobile‑optimized behavior)

## Safety & Compliance
- Requires explicit risk acknowledgment
- Double‑confirmation for high‑threat operations
- Returns legal warnings in the response

## Related Tools
- `drone_defense_enhanced` – Defensive operations
- `drone_mobile_optimized` – Mobile‑first drone operations
- `drone_natural_language` – Natural‑language parser for drone intents

## Use Cases
- Red/blue team tabletop exercises
- Response playbooks with simulated counter‑measures
- Research of deception/decoy strategies under strict guardrails
