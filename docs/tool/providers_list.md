# Providers List

Overview: List all available AI service providers and their capabilities.

- Tool name: `providers_list`
- Category: Web UI Bridge

Input parameters
- `platform` (optional): `desktop` | `android` | `ios`

Example
```javascript
await server.callTool("providers_list", {});
```

Notes
- Returns provider IDs, names, platforms, and capability flags.
