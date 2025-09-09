# Mobile‑Optimized Drone Operations

## Overview
The `drone_mobile_optimized` tool executes drone operations with mobile‑first accommodations including battery/network optimization and platform‑specific limits for Android and iOS.

## Tool Name
`drone_mobile_optimized`

## Description
Execute drone operations on mobile platforms with adaptive optimizations, returning detailed performance metrics (battery/data/time) and recorded limitations.

## Input Schema
- `operationType` (string, required): One of:
  - `scan_surroundings`, `deploy_shield`, `evade_threat`,
  - `jam_signals`, `deploy_decoy`, `counter_strike`
- `parameters` (object, required): Operation parameters (e.g., `target`, `intensity`, `threatType`).
- `enableBatteryOptimization` (boolean, optional, default `true`).
- `enableNetworkOptimization` (boolean, optional, default `true`).
- `enableBackgroundMode` (boolean, optional, default `false`).

## Examples
```typescript
// Mobile scan with optimizations
await server.callTool("drone_mobile_optimized", {
  operationType: "scan_surroundings",
  parameters: { target: "192.168.1.0/24", threatType: "probe" },
  enableBackgroundMode: true
});

// Mobile decoy deployment
await server.callTool("drone_mobile_optimized", {
  operationType: "deploy_decoy",
  parameters: { target: "10.0.0.99", intensity: "low" }
});
```

## Platform Support
- Android, iOS (primary)
- Returns guidance if called from desktop

## Output Highlights
- Operation success/failure
- Battery used, data used (MB), elapsed time (ms)
- Platform capabilities and limitations

## Related Tools
- `drone_defense_enhanced`
- `drone_offense_enhanced`
- `drone_natural_language`

