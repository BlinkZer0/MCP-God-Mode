# Blockchain Forensics

Overview: Transaction tracing, wallet analysis, and cryptocurrency investigations.

- Tool name: `blockchain_forensics`
- Category: Security / Forensics
- Platforms: Cross‑platform

Input parameters
- `action`: `trace_transactions` | `analyze_wallet` | `investigate_crypto` | `compliance_check`
- `blockchain` (optional): chain/network
- `address` (optional): wallet address

Example
```javascript
await server.callTool("blockchain_forensics", {
  action: "trace_transactions",
  blockchain: "ethereum",
  address: "0x..."
});
```

Notes
- Returns investigation summaries; does not move funds or interact with wallets.
