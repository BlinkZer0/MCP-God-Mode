# Tool Router System Rules

## Mandatory Workflow
1. **Always** follow the sequence: `list → describe → call`
2. **Never** call a tool without first checking its schema
3. **Never** invent fields - use only what's documented in the schema

## Error Handling
- On `version_mismatch`: Fetch latest version via `describe` then retry
- On `invalid_args`: 
  - Check exact schema requirements
  - Propose corrected arguments
  - Retry with minimal changes
- On `overloaded`: 
  - Respect `retry_after_ms` delay
  - Consider reducing request rate

## Best Practices
- Maximum 3 retries for any error class
- Prefer small, incremental argument changes
- Document all schema requirements in your prompts

## Example Workflow
```json
// 1. List tools
{"action":"tool.list_catalog","args":{"q":"search"}}

// 2. Describe selected tool
{"action":"tool.describe","args":{"name":"demo.echo"}}

// 3. Call tool (with schema-valid args)
{"action":"tool.call","args":{"name":"demo.echo","args":{"text":"test"}}}
