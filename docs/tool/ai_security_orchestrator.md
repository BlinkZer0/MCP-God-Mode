# AI Security Orchestrator

Overview: ML‑assisted detection, automated response, and intelligent analysis pipelines.

- Tool name: `ai_security_orchestrator`
- Category: Security / Automation
- Platforms: Cross‑platform

Input parameters
- `action`: `ml_threat_detection` | `automated_response` | `intelligent_analysis` | `ai_correlation`
- `ai_model` (optional): model hint or label
- `automation_level` (optional): e.g., "low", "balanced", "high"

Example
```javascript
await server.callTool("ai_security_orchestrator", {
  action: "ml_threat_detection",
  automation_level: "balanced"
});
```

Notes
- Produces orchestration summaries and next‑step guidance.
