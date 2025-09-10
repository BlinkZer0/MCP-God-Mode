# Macro Record

Overview: Record user actions into a portable JSON macro for later replay.

- Tool name: `macro_record`
- Category: Web UI Bridge

Input parameters (core)
- `target`: object with `provider` and/or driver config
- `scope` (optional): `dom` | `driver` | `auto`
- `name` (optional): macro name
- `description` (optional)
- `platform` (optional): `desktop` | `android` | `ios`

Example
```javascript
await server.callTool("macro_record", {
  target: { provider: "chatgpt" },
  scope: "auto",
  name: "answer_then_copy"
});
```

Notes
- Use with `macro_run` to automate routine UI tasks safely.
