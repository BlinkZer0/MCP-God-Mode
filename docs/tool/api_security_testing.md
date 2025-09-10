# API Security Testing

Overview: Perform API‑focused security checks including auth, rate‑limits, and input handling.

- Tool name: `api_security_testing`
- Category: Security / Testing

Example
```javascript
await server.callTool("api_security_testing", {
  target: "https://api.example.com",
  tests: ["auth", "input_validation"]
});
```

Notes
- Complements `security_testing` with API‑centric workflows.
