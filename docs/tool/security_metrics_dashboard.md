# Security Metrics Dashboard

Overview: Track KPIs, analyze trends, generate reports, and monitor security metrics in real time.

- Tool name: `security_metrics_dashboard`
- Category: Security / Reporting
- Platforms: Cross‑platform

Input parameters
- `action`: `track_kpis` | `analyze_trends` | `generate_reports` | `monitor_realtime`
- `metric_type` (optional): metric focus
- `timeframe` (optional): analysis window

Example
```javascript
await server.callTool("security_metrics_dashboard", {
  action: "analyze_trends",
  metric_type: "vuln_findings",
  timeframe: "30d"
});
```

Notes
- Useful for exec briefings and weekly ops reviews.
