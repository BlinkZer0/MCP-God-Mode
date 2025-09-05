# MCP God Mode - Test Suite

This directory contains all test files for the MCP God Mode project.

## Test Files

### Core Tests
- **`smoke.mjs`** - Comprehensive smoke test that verifies MCP protocol communication and basic tool functionality
- **`test-all-tools.mjs`** - Tests all 69+ tools systematically to verify they're working correctly
- **`test-mcp-connection.js`** - Simple MCP protocol test to verify server communication
- **`test-minimal-mcp.js`** - Minimal test server for basic MCP functionality verification

### Output Files
- **`out.txt`** - Test output and results from previous test runs

## Running Tests

### Smoke Test
```bash
# From project root
node tests/smoke.mjs
```

### Comprehensive Tool Test
```bash
# From project root
node tests/test-all-tools.mjs
```

### MCP Connection Test
```bash
# From project root
node tests/test-mcp-connection.js
```

### Minimal MCP Test
```bash
# From project root
node tests/test-minimal-mcp.js
```

## Test Requirements

- Node.js 18.0.0 or higher
- Built server files in `../dev/dist/`
- MCP God Mode dependencies installed

## Test Results

Tests will provide detailed output including:
- Server startup status
- MCP protocol communication
- Tool registration and functionality
- Success/failure rates
- Detailed error reporting

## Troubleshooting

If tests fail:
1. Ensure the server is built: `npm run build`
2. Check that all dependencies are installed: `npm install`
3. Verify the server files exist in `../dev/dist/`
4. Check the test output for specific error messages
