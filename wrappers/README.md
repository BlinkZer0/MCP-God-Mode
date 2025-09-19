# MCP God Mode - Wrapper Scripts

This directory contains wrapper scripts that provide alternative ways to launch and interact with the MCP God Mode server.

## Wrapper Files

### Core Wrappers
- **`mcp-stdio-wrapper.js`** - Wrapper to ensure MCP server writes ONLY JSON-RPC to stdout, redirecting logs to stderr for Cursor compatibility
- **`simple-test-server.js`** - Simple MCP test server launcher for Cursor connection testing

## Usage

### MCP Stdio Wrapper
```bash
# From project root
node wrappers/mcp-stdio-wrapper.js
```

This wrapper is designed to work with Cursor IDE's MCP integration by ensuring clean JSON-RPC communication.

### Simple Test Server
```bash
# From project root
node wrappers/simple-test-server.js
```

This launcher provides a simple way to test MCP server connectivity with Cursor.

## Configuration

Both wrappers automatically locate the main server file at `../dev/dist/server-refactored.js` and will provide clear error messages if the server is not found.

## Integration

These wrappers can be used in MCP configuration files:

```json
{
  "mcpServers": {
    "mcp-god-mode": {
      "command": "node",
      "args": ["./wrappers/mcp-stdio-wrapper.js"]
    }
  }
}
```

## Troubleshooting

If wrappers fail to start:
1. Ensure the main server is built: `npm run build`
2. Check that `../dev/dist/server-refactored.js` exists
3. Verify Node.js version is 18.0.0 or higher
4. Check wrapper output for specific error messages
