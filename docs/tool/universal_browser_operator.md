# Universal Browser Operator

Overview: High‑level browser control that abstracts device/driver details across platforms.

- Tool name: `universal_browser_operator`
- Category: Web / Automation

Example
```javascript
await server.callTool("universal_browser_operator", {
  action: "navigate",
  url: "https://example.com"
});
```

Notes
- For complex UI automation, see also `browser_control` and `web_automation`.
