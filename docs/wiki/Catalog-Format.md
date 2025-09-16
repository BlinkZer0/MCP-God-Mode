<p align="center">
  <img src="../../assets/headers/animated-header-3.svg" alt="Architecture" />
</p>

# Catalog Format

The router reads `servers/router-registry/tools.json`. Entries define the shape and location of dynamically callable tools.

## Fields

- `name`: unique identifier like `domain.action`.
- `version`: semantic version string (clients can pin or assert).
- `summary`: short human-friendly description.
- `tags`: optional string tags for filtering.
- `input_schema`: JSON Schema–like object for input validation.
- `output_schema`: JSON Schema–like object for output validation.
- `handlerPath`: module path (relative to `servers/router-registry/` or absolute). Must export `default` or `handler`.

## Minimal Example

```json
[
  {
    "name": "demo.echo",
    "version": "1.0.0",
    "summary": "Echo arguments back",
    "tags": ["demo", "utility"],
    "input_schema": { "type": "object", "properties": { "text": { "type": "string" } }, "required": ["text"] },
    "output_schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "echo": { "type": "object" } }, "required": ["ok", "echo"] },
    "handlerPath": "handlers/echo.js"
  }
]
```

## Validation Notes

- The current implementation stubs validation to always succeed. For production, integrate AJV and keep schemas strict enough to be useful—but not so strict they become a traffic cone.

## Conventions

- Namespaces: prefer `feature.action` style.
- Version bumps: change when handler behavior or I/O contracts change.
- Tags: help clients discover or group tools. Sprinkle generously.

If your catalog gets unruly, don’t worry—we’ve got the tag-nets.

