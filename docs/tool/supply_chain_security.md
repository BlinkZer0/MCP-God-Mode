# Supply Chain Security

Overview: Vendor assessment, dependency scanning, and third‑party risk analysis.

- Tool name: `supply_chain_security`
- Category: Security / GRC
- Platforms: Cross‑platform

Input parameters
- `action`: `assess_vendors` | `scan_dependencies` | `validate_security` | `risk_analysis`
- `scope` (optional): assessment scope
- `risk_level` (optional): tolerance level

Example
```javascript
await server.callTool("supply_chain_security", {
  action: "scan_dependencies",
  scope: "backend-services"
});
```

Notes
- Useful for SBOM programs and vendor intake workflows.
