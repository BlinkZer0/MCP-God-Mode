# Drone Management Tools Documentation

## Overview
The Drone Management category provides natural‑language‑driven defensive and offensive operations with strict safety controls and full cross‑platform awareness, including mobile‑optimized behavior for Android/iOS.

## Tools in this Category (4 tools)

### 1. mcp_mcp-god-mode_drone_defense_enhanced
**Description**: Enhanced cross‑platform defensive drone operations with threat detection, automated responses, and optional natural‑language parsing.
**Parameters**:
- `action` (string): `scan_surroundings` | `deploy_shield` | `evade_threat`
- `threatType` (string): Threat descriptor (e.g., ddos, intrusion, probe)
- `target` (string): Target network/system (e.g., 192.168.1.0/24)
- `autoConfirm` (boolean): Skip confirmation prompts
- `naturalLanguageCommand` (string): Free‑form instruction

**Use Cases**:
- Defensive scans and posture hardening
- Evasion workflows during active incidents
- Blue‑team simulations with audit logging

### 2. mcp_mcp-god-mode_drone_offense_enhanced
**Description**: Cross-platform offensive actions with strict legal/safety gates and mobile-aware optimizations. Live mode by default; simulation can be enabled via environment flag.
**Parameters**:
- `action` (string): `jam_signals` | `deploy_decoy` | `counter_strike`
- `targetIp` (string): Target host/IP/CIDR
- `intensity` (string): `low` | `medium` | `high`
- `riskAcknowledged` (boolean): Must be true
- `threatLevel` (number): 1–10; >7 requires double confirmation
- `autoConfirm` (boolean): Skip prompts
- `naturalLanguageCommand` (string): Free‑form instruction

**Use Cases**:
- Deception/decoy drills and research
- Controlled counter‑measure simulations
- Incident tabletop exercises

### 3. mcp_mcp-god-mode_drone_natural_language
**Description**: Natural‑language interface that converts free‑form commands into structured actions with safety checks and platform optimizations.
**Parameters**:
- `command` (string): Natural‑language input
- `context` (string): Optional context
- `userIntent` (string): Optional goal
- `platform` (string): Optional preference (auto‑detected)

**Use Cases**:
- Conversational control with safety annotations
- Intent parsing for orchestration pipelines

### 4. mcp_mcp-god-mode_drone_mobile_optimized
**Description**: Mobile‑first drone operations returning battery/data/time metrics and platform limitations.
**Parameters**:
- `operationType` (string): `scan_surroundings` | `deploy_shield` | `evade_threat` | `jam_signals` | `deploy_decoy` | `counter_strike`
- `parameters` (object): Operation parameters (e.g., target, intensity, threatType)
- `enableBatteryOptimization` (boolean)
- `enableNetworkOptimization` (boolean)
- `enableBackgroundMode` (boolean)

**Use Cases**:
- On‑device IR/blue‑team drills
- Low‑power scanning from field devices

## Notes
- All drone tools respect audit/confirmation environment flags.
- Live mode by default. Enable simulation by setting `MCPGM_DRONE_SIM_ONLY=true`.
