# 🚀 Build Server Documentation

## Overview

The `build-server.js` script is a powerful tool that allows you to create custom MCP servers with only the tools you need. This eliminates the need to deploy the full MCP God Mode server when you only need specific functionality.

## Quick Start

### Basic Usage

```bash
# Build a server with specific tools
node build-server.js health system_info send_email parse_email

# Build with custom output file
node build-server.js health system_info send_email my-server.ts

# Build with custom name and output file
node build-server.js health system_info send_email my-server.ts "My Custom Server"
```

### Predefined Configurations

```bash
# Email-only server
npm run build:email-only

# Minimal server
npm run build:minimal

# Core-only server
npm run build:core-only

# Custom configuration
npm run build:custom
```

## Command Line Arguments

The build script accepts the following arguments:

1. **Tool Names** (required): List of tools to include in your server
2. **Output File** (optional): Custom filename for the generated server (default: `custom-server.ts`)
3. **Server Name** (optional): Custom name for your server (default: "Custom Server")

### Examples

```bash
# Basic server with core tools
node build-server.js health system_info

# Email-focused server
node build-server.js health system_info send_email parse_email

# Security testing server
node build-server.js health system_info wifi_security_toolkit bluetooth_security_toolkit

# Custom filename and server name
node build-server.js health system_info send_email email-server.ts "Email Management Server"
```

## Available Tools

### Core Tools
- `health` - System health check
- `system_info` - System information

### Email Tools
- `send_email` - Send emails via SMTP
- `parse_email` - Parse email content

### File System Tools
- `fs_list` - List files and directories

### Security Tools (Coming Soon)
- `wifi_security_toolkit` - Wi-Fi security testing
- `bluetooth_security_toolkit` - Bluetooth security testing
- `sdr_security_toolkit` - Radio frequency security

### Mobile Tools (Coming Soon)
- `mobile_device_info` - Mobile device information
- `mobile_file_ops` - Mobile file operations
- `mobile_system_tools` - Mobile system management
- `mobile_hardware` - Mobile hardware access

### Network Tools (Coming Soon)
- `network_diagnostics` - Network testing
- `packet_sniffer` - Packet capture and analysis

### Virtualization Tools (Coming Soon)
- `vm_management` - Virtual machine management
- `docker_management` - Docker container management

### Utility Tools (Coming Soon)
- `calculator` - Mathematical calculations
- `math_calculate` - Advanced math functions
- `git_status` - Git operations
- `web_scraper` - Web scraping
- `browser_control` - Browser automation
- `system_restore` - System backup and restore

## Generated Server Structure

The generated server includes:

1. **All necessary imports** - MCP SDK, utility modules, and selected tools
2. **Tool registration calls** - Each selected tool is properly registered
3. **Server startup code** - Complete server initialization and connection
4. **Error handling** - Proper error handling and logging
5. **Console output** - Information about the server and available tools

### Example Generated Server

```typescript
#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
// ... other imports ...

// Import and register selected tools
import { registerHealth } from "./tools/core/health";
import { registerSystemInfo } from "./tools/core/system_info";
import { registerSendEmail } from "./tools/email/send_email";

const server = new McpServer({ name: "custom-mcp-server", version: "1.0.0" });

// Register all selected tools
registerHealth(server);
registerSystemInfo(server);
registerSendEmail(server);

// Start the server
const transport = new StdioServerTransport();
server.connect(transport);

console.log(`Custom Server started with 3 tools`);
console.log('Available tools:', 'health, system_info, send_email');
```

## Use Cases

### Email-Only Server
```bash
node build-server.js health system_info send_email parse_email
```
**Use Case**: Email management applications, notification systems

### Security Testing Server
```bash
node build-server.js health system_info wifi_security_toolkit bluetooth_security_toolkit
```
**Use Case**: Security audits, penetration testing, vulnerability assessment

### Mobile Development Server
```bash
node build-server.js health system_info mobile_device_info mobile_file_ops
```
**Use Case**: Mobile app development, device testing, mobile automation

### Minimal Production Server
```bash
node build-server.js health system_info fs_list send_email
```
**Use Case**: Production deployments, resource-constrained environments

## Building and Running

### 1. Generate the Custom Server
```bash
node build-server.js health system_info send_email parse_email
```

### 2. Compile the TypeScript
```bash
npx tsc custom-server.ts --outDir dist --target es2020 --module es2020 --moduleResolution node --esModuleInterop --allowSyntheticDefaultImports
```

### 3. Run the Server
```bash
node dist/custom-server.js
```

## Customization

### Adding New Tools

1. **Create the tool module** in `src/tools/`
2. **Add to the build script** in `AVAILABLE_TOOLS`
3. **Test the build** with your new tool

### Modifying Generated Servers

The generated servers are fully customizable:
- Add your own tools
- Modify server configuration
- Add custom middleware
- Implement custom error handling

## Troubleshooting

### Common Issues

1. **Tool not found**: Check that the tool name is in `AVAILABLE_TOOLS`
2. **Import errors**: Verify tool module exports
3. **Compilation errors**: Check TypeScript configuration
4. **Runtime errors**: Verify all dependencies are available

### Debug Tips

1. **Check generated code** - Review the output file for errors
2. **Test individual tools** - Build minimal servers first
3. **Verify dependencies** - Ensure all required packages are installed
4. **Check console output** - Look for error messages during build

## Advanced Usage

### Custom Build Scripts

You can create your own build scripts:

```javascript
const { buildCustomServer } = require('./build-server.js');

// Build a specialized server
buildCustomServer(
  ['health', 'system_info', 'send_email'],
  'email-server.ts',
  'Email Management Server'
);
```

### Integration with CI/CD

```yaml
# GitHub Actions example
- name: Build Custom Server
  run: |
    node build-server.js health system_info send_email parse_email
    npx tsc custom-server.ts --outDir dist
```

## Support

For issues or questions:
1. Check the generated server code for errors
2. Verify tool names and dependencies
3. Review the main README for tool information
4. Check the tools documentation in `docs/tools-README.md`

---

**Happy Building! 🚀**
