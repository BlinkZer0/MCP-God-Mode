<p align="center">
  <img src="../../assets/headers/animated-header-4.svg" alt="Usage & Examples" />
</p>

# Usage & Examples

Sample MCP content payloads for interacting with the Tool Router.

## List Catalog

```json
{
  "tool": "tool.list_catalog",
  "input": { "q": "echo", "tags": ["utility"], "page": 1, "pageSize": 20 }
}
```

## Describe Tool

```json
{
  "tool": "tool.describe",
  "input": { "name": "demo.echo" }
}
```

## Call Tool

```json
{
  "tool": "tool.call",
  "input": { "name": "demo.echo", "version": "1.0.0", "args": { "text": "hello" } }
}
```

Response:

```json
{
  "content": [
    { "type": "json", "json": { "ok": true, "echo": { "text": "hello" } } }
  ]
}
```

## Error Responses

Unknown tool:

```json
{
  "content": [
    { "type": "json", "json": { "error": { "failure_class": "unknown_tool", "hint": "No such tool: nope.sorry" } } }
  ]
}
```

Overloaded:

```json
{
  "content": [
    { "type": "json", "json": { "error": { "failure_class": "overloaded", "hint": "too many calls", "retry_after_ms": 500 } } }
  ]
}
```

Version mismatch:

```json
{
  "content": [
    { "type": "json", "json": { "error": { "failure_class": "version_mismatch", "hint": "Expected 1.0.0; got 2.0.0" } } }
  ]
}
```

Copy, paste, and be paste-tive: your tools will thank you.

