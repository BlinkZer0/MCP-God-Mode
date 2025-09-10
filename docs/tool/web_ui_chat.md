# Web UI Chat

Overview: Chat with AI services through their web UIs (no APIs required). Supports streaming responses and session persistence.

- Tool name: `web_ui_chat`
- Category: Web UI Bridge
- Platforms: Desktop, Android, iOS

Input parameters
- `provider` (string): Provider ID (e.g., `chatgpt`, `grok`, `claude`, custom)
- `prompt` (string): Message to send
- `timeoutMs` (number, optional, default 240000)
- `variables` (object, optional): Macro/script variables
- `platform` (enum): `desktop` | `android` | `ios`
- `headless` (boolean, optional)

Example
```javascript
await server.callTool("web_ui_chat", {
  provider: "chatgpt",
  prompt: "Summarize our incident response plan"
});
```

Notes
- Backed by the MCP Web UI Bridge driver (Playwright/Appium).
