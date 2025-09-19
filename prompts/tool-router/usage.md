# Tool Router Usage Guide

## Basic Workflow
1. **Discover Tools**: Use `tool.list_catalog` to find available tools:
   ```json
   {"q": "search terms", "tags": ["filter"], "page": 1, "pageSize": 10}
   ```

2. **Get Tool Details**: Use `tool.describe` to understand a tool's requirements:
   ```json
   {"name": "tool.name"}
   ```

3. **Call Tools**: Use `tool.call` with exact schema-matching arguments:
   ```json
   {"name": "tool.name", "args": {"param1": "value"}}
   ```

## Error Handling
- **Version Mismatch**: First call `tool.describe` to get current version
- **Invalid Args**: Check the schema and fix your arguments
- **Overloaded**: Wait for `retry_after_ms` before trying again

## Best Practices
- Always follow list → describe → call sequence
- Never invent fields - use only what's in the schema
- Prefer smallest possible changes when retrying
