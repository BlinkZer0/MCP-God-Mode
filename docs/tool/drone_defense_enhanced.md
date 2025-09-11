# Enhanced Drone Defense

## Overview
The `drone_defense_enhanced` tool deploys defensive drone operations with cross‑platform support (desktop and mobile). It adds a natural‑language command option, audit logging awareness, and mobile‑optimized behavior for Android/iOS.

## Tool Name
`drone_defense_enhanced`

## Description
Cross‑platform defensive drone operations with real threat detection, automated responses, and optional natural‑language command parsing.

## Input Schema
- `action` (string, required): Defense action to perform. Options:
  - `scan_surroundings` – Scan network/devices and collect indicators
  - `deploy_shield` – Apply protective controls and hardening
  - `evade_threat` – Reroute/segment/evade active threats
- `threatType` (string, optional, default `"general"`): Threat descriptor (e.g., `ddos`, `intrusion`, `probe`).
- `target` (string, required): Target network or system (e.g., `192.168.1.0/24`).
- `autoConfirm` (boolean, optional, default `false`): Skip confirmation prompts (requires `MCPGM_REQUIRE_CONFIRMATION=false`).
- `naturalLanguageCommand` (string, optional): Free‑form text such as "scan for threats" or "deploy protection".

## Natural Language Access
You can issue requests like:
- "Scan our network for active threats"
- "Deploy a defensive shield against DDoS"
- "Evade the current intrusion on the office subnet"

## Examples

```typescript
// Scan surroundings
await server.callTool("drone_defense_enhanced", {
  action: "scan_surroundings",
  threatType: "probe",
  target: "192.168.1.0/24"
});

// Natural language command
await server.callTool("drone_defense_enhanced", {
  naturalLanguageCommand: "scan for ddos threats on the corp network",
  action: "scan_surroundings",    // fallback
  target: "10.0.0.0/24",
  autoConfirm: true
});
```

## Platform Support
- Windows, Linux, macOS (full capabilities)
- Android, iOS (mobile‑optimized operations)

## Safety & Compliance
- Honors confirmation flags and audit logging configuration
- Real-world operations by default with actual network scanning and firewall modifications
- Optional related flags: `MCPGM_REQUIRE_CONFIRMATION` (default true), `MCPGM_AUDIT_ENABLED` (default true), `MCPGM_FLIPPER_ENABLED` (hardware bridge; defaults to enabled on the refactored server)

## Related Tools
- `drone_offense_enhanced` – Offensive counter‑measures with safety gates
- `drone_mobile_optimized` – Mobile‑first drone operations
- `drone_natural_language` – Parse natural‑language drone commands

## Use Cases
- Blue‑team incident response drills
- Automated defensive posture validation
- Rapid response to scans/intrusions/DDOS indicators
