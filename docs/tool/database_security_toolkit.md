# Database Security Toolkit

Overview: Assess database configurations, permissions, and exposure; generate remediation guidance.

- Tool name: `database_security_toolkit`
- Category: Security / Database

Example
```javascript
await server.callTool("database_security_toolkit", {
  action: "audit",
  target: "postgres://user@db.internal"
});
```

Notes
- Intended for authorized environments; supports audit‑style summaries.
