# MCP God Mode Setup Guide

## Overview
This guide explains how to set up the MCP God Mode plugin for LM Studio and other MCP-compatible applications.

## Quick Fix for Module Not Found Error

The error you were experiencing:
```
Error: Cannot find module 'C:\Users\Randy\.lmstudio\extensions\plugins\mcp\windows-god-mode\dev\dist\server.js'
```

Has been resolved by creating proper entry points and updating the configuration.

## Files Created/Updated

1. **`start-mcp.js`** - Cross-platform startup script that automatically finds the correct server file
2. **`server.js`** - Root entry point for the MCP server
3. **`package.json`** - Root package configuration
4. **`MCPGodMode.json`** - Updated MCP configuration

## Configuration

The MCP configuration now uses:
```json
{
  "mcpServers": {
    "windows-god-mode": {
      "command": "node",
      "args": ["start-mcp.js"],
      "env": {
        "ALLOWED_ROOT": "",
        "WEB_ALLOWLIST": "",
        "PROC_ALLOWLIST": "",
        "EXTRA_PATH": ""
      }
    }
  }
}
```

## How It Works

1. **`start-mcp.js`** - The main entry point that:
   - Detects the operating system
   - Searches for available server files in `dev/dist/`
   - Provides detailed error messages if files are missing
   - Loads the appropriate server implementation

2. **Cross-platform support** - Works on Windows, macOS, and Linux

3. **Automatic fallback** - Tries multiple server implementations if the primary one isn't available

## Testing

To test if the setup works:
```bash
node start-mcp.js
```

You should see:
```
Starting MCP God Mode Server on win32 x64
Found server at: E:\GitHub Projects\MCP-God-Mode\dev\dist\server.js
Loading server from: E:\GitHub Projects\MCP-God-Mode\dev\dist\server.js
info: MCP Server starting...
```

## Troubleshooting

If you still get errors:

1. **Check file paths** - Ensure all files exist in the expected locations
2. **Verify Node.js version** - Requires Node.js 18.0.0 or higher
3. **Check permissions** - Ensure the plugin directory is readable
4. **Review logs** - The startup script provides detailed error information

## Environment Variables

You can configure the server behavior using these environment variables:
- `ALLOWED_ROOT` - Restrict file access to specific directories
- `WEB_ALLOWLIST` - Restrict web access to specific domains
- `PROC_ALLOWLIST` - Restrict process execution to specific commands
- `EXTRA_PATH` - Add additional paths to the system PATH
- `LOG_LEVEL` - Set logging level (debug, info, warn, error)
- `MAX_FILE_SIZE` - Maximum file size for operations (default: 1MB)
- `COMMAND_TIMEOUT` - Command execution timeout (default: 30s)
- `ENABLE_SECURITY_CHECKS` - Enable/disable security features (default: true)

## Support

If you continue to experience issues, check:
1. The server logs for detailed error messages
2. That all dependencies are properly installed
3. That the file paths in your MCP configuration are correct
