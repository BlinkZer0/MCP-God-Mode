# SIEM Toolkit

Overview: SIEM workflow helpers for parsing, enrichment, and correlation recipes.

- Tool name: `siem_toolkit`
- Category: Security / Operations

Example
```javascript
await server.callTool("siem_toolkit", {
  action: "enrich",
  indicator: "1.2.3.4"
});
```

Notes
- Complements `threat_intelligence` and log analysis tools.
