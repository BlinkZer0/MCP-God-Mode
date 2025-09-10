# Macro Run

Overview: Execute a previously recorded macro with optional variable substitution.

- Tool name: `macro_run`
- Category: Web UI Bridge

Input parameters
- `macroId` (string): ID of the macro to execute
- `variables` (object, optional): key/value map
- `dryRun` (boolean, optional): plan without execution

Example
```javascript
await server.callTool("macro_run", {
  macroId: "answer_then_copy",
  variables: { query: "Summarize this document" }
});
```

Notes
- Pairs with `macro_record`. Supports headless or visible sessions.
