# Advanced Threat Hunting

Overview: Sophisticated threat detection and hunting with behavioral analysis, IOC tracking, and event correlation.

- Tool name: `advanced_threat_hunting`
- Category: Security / Detection
- Platforms: Cross‑platform

Input parameters
- `action`: `hunt_threats` | `analyze_behavior` | `track_iocs` | `correlate_events`
- `target` (optional): System/network scope
- `timeframe` (optional): Time window

Example
```javascript
await server.callTool("advanced_threat_hunting", {
  action: "hunt_threats",
  target: "10.0.0.0/24",
  timeframe: "last_24h"
});
```

Notes
- Use for proactive hunts, purple-team drills, and IOC sweeps.
- Outputs summary plus details per action.
