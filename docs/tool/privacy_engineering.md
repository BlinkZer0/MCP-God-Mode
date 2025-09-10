# Privacy Engineering

Overview: Data minimization, anonymization, audits, and privacy‑by‑design checks.

- Tool name: `privacy_engineering`
- Category: Security / Privacy
- Platforms: Cross‑platform

Input parameters
- `action`: `data_minimization` | `anonymization` | `privacy_audit` | `compliance_validation`
- `data_type` (optional): e.g., PII, PHI
- `regulation` (optional): e.g., GDPR, HIPAA

Example
```javascript
await server.callTool("privacy_engineering", {
  action: "privacy_audit",
  data_type: "PII",
  regulation: "GDPR"
});
```

Notes
- Produces actionable recommendations and audit notes.
