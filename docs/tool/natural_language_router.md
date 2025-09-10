# Natural Language Router

Overview: Suggests and orders tools based on a natural‑language request.

- Tool name: `natural_language_router`
- Category: Discovery / Routing

Example
```javascript
await server.callTool("natural_language_router", {
  query: "scan my subnet and graph open ports"
});
```

Notes
- Returns suggested tool names with confidence scores.
