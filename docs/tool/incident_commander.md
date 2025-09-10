# Incident Commander

Overview: Coordinate response, automate workflows, handle stakeholder comms, and orchestrate recovery.

- Tool name: `incident_commander`
- Category: Security / IR
- Platforms: Cross‑platform

Input parameters
- `action`: `coordinate_response` | `automate_workflow` | `communicate_stakeholders` | `orchestrate_recovery`
- `incident_type` (optional): e.g., ransomware, outage
- `severity` (optional): e.g., low/medium/high

Example
```javascript
await server.callTool("incident_commander", {
  action: "coordinate_response",
  incident_type: "ransomware",
  severity: "high"
});
```

Notes
- Summaries include tasks, owners, and timing where appropriate.
