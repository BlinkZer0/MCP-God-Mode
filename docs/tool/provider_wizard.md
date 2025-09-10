# Provider Wizard

Overview: Interactive wizard to capture selectors and configure custom AI provider entries for the Web UI Bridge.

- Tool name: `provider_wizard`
- Category: Web UI Bridge
- Platforms: Desktop, Android, iOS

Input parameters
- `startUrl` (string): Provider chat URL
- `providerName` (string): Display name
- `platform` (enum): `desktop` | `android` | `ios`
- `headless` (boolean, optional)

Example
```javascript
await server.callTool("provider_wizard", {
  startUrl: "https://example.ai/chat",
  providerName: "ExampleAI",
  platform: "desktop"
});
```

Notes
- Saves validated configuration to the bridge registry.
