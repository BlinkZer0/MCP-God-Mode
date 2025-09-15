# MCP God Mode Tool Manifest System (v2.0d)

This document describes the tool manifest system used by MCP God Mode to manage and document the 16 available tools.

## Overview

The tool manifest (`tools.manifest.json`) serves as the single source of truth for all tools in the MCP God Mode system. It provides machine-readable metadata about each tool, including:

- Tool name and category
- Entry point and invocation details
- Input parameters and their types
- Environment requirements
- Safety and privilege requirements
- Smoke test configuration

## Current Tool Statistics

- **Total Tools**: 16
- **Categories**: Security, AI, System, Legal, Analytics, Automation, Forensics
- **Last Updated**: 2025-09-15

## Manifest Structure

The manifest is a JSON file with the following structure:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "MCP God Mode Tools Manifest",
  "type": "object",
  "tools": [
    {
      "name": "tool_name",
      "category": "tool_category",
      "entry_file": "path/to/entry.js",
      "invoke": "functionName",
      "args": [
        {
          "name": "param1",
          "type": "string|number|boolean|enum[value1,value2]",
          "required": true,
          "description": "Parameter description"
        }
      ],
      "env_vars": ["REQUIRED_ENV_VAR1", "OPTIONAL_ENV_VAR2"],
      "requires_privilege": false,
      "side_effects": "Description of any side effects",
      "safe_mode": true,
      "tags": ["tag1", "tag2"],
      "smoke_test": {
        "cmd": "node",
        "args": ["-e", "console.log('test')"],
        "expect_code": 0,
        "timeout_ms": 5000
      }
    }
  ]
}
```

## Tool Categories

1. **Security Tools**
   - Advanced Security Assessment
   - Advanced Threat Hunting
   - Cyber Deception Platform
   - Zero Trust Architect
   - Quantum Cryptography Suite
   - AI Security Orchestrator
   - Session Management

2. **AI Tools**
   - Web UI Chat
   - Providers List
   - Provider Wizard

3. **System Tools**
   - Cross-Platform System Manager
   - Enterprise Integration Hub

4. **Legal Tools**
   - Enhanced Legal Compliance

5. **Analytics Tools**
   - Advanced Analytics Engine

6. **Automation Tools**
   - Macro Record
   - Macro Run

## Smoke Testing

Each tool in the manifest includes a smoke test configuration that verifies basic functionality. The smoke test runner will:

1. Execute the specified command with arguments
2. Verify the exit code matches the expected value
3. Enforce a timeout to prevent hanging tests

### Running Smoke Tests

Run all smoke tests:
```bash
npm test
```

Run only manifest validation:
```bash
npm run test:validate
```

Run only smoke tests:
```bash
npm run test:smoke
```

List all available tools:
```bash
npm run smoke:list
```

## Adding a New Tool

To add a new tool to the system:

1. Create your tool implementation in the appropriate directory under `dev/src/tools/`
2. Add a new entry to `tools.manifest.json` with all required fields
3. Include a smoke test that verifies basic functionality
4. Update the documentation in `docs/TOOL_REFERENCE.md`
5. Run `npm test` to validate your changes

## Best Practices

1. **Documentation**: Always provide clear descriptions for tools and parameters
2. **Safety**: Mark tools that require elevated privileges with `"requires_privilege": true`
3. **Side Effects**: Document any side effects in the `side_effects` field
4. **Testing**: Ensure smoke tests are fast, reliable, and non-destructive
5. **Categories**: Use consistent categories to group related tools
6. **Tags**: Add relevant tags to make tools more discoverable

## Troubleshooting

If a smoke test fails:

1. Check the error message for details
2. Verify the tool's entry in the manifest is correct
3. Ensure all required environment variables are set
4. Check file permissions and paths
5. Run the smoke test manually with `node scripts/run-smoke-tests.js --tool=tool_name` for more verbose output

## Version History

- **v2.0d (2025-09-15)**: Updated tool count to 16, added comprehensive documentation
- **v2.0c (2025-01-27)**: Initial version with 16 core tools
