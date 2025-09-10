# Session Management

Overview: Manage encrypted sessions for Web UI providers.

- Tool name: `session_management`
- Category: Web UI Bridge

Input parameters
- `action` (enum): `list` | `clear` | `cleanup`
- `provider` (optional): required for `clear`
- `platform` (optional): `desktop` | `android` | `ios`

Example
```javascript
await server.callTool("session_management", { action: "list" });
```

Notes
- Supports secure session cleanup and multi‑platform stores.
