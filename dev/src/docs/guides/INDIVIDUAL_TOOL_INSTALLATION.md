# Individual Tool Installation Guide

## Overview

The MCP God Mode modular server now supports individual tool specification, allowing users to install only the specific tools they need rather than entire categories. This provides fine-grained control over the server configuration and helps reduce resource usage.

## Installation Methods

### 1. Individual Tools Only

Install specific tools by name:

```bash
# Install specific tools
node install.js --modular --tools health,system_info,fs_list

# Install with automatic dependency inclusion
node install.js --modular --tools port_scanner --auto-deps
```

### 2. Categories + Individual Tools

Combine category-based installation with individual tool selection:

```bash
# Install core category plus additional tools
node install.js --modular --categories core,network --tools packet_sniffer
```

### 3. Using build-server.js

Alternative method using the build-server script:

```bash
# Create modular configuration
node build-server.js --modular health,system_info,fs_list

# Create custom server file
node build-server.js health,system_info,fs_list
```

## Available Tools

### Core Tools
- `health` - System health monitoring
- `system_info` - Basic system information

### File System Tools
- `fs_list` - Directory listing
- `fs_read_text` - Text file reading
- `fs_write_text` - Text file writing
- `fs_search` - File search
- `file_ops` - Advanced file operations
- `file_watcher` - File system monitoring

### Network Tools
- `network_diagnostics` - Network troubleshooting
- `network_discovery` - Network reconnaissance
- `port_scanner` - Port scanning
- `packet_sniffer` - Network packet analysis
- `ip_geolocation` - IP geolocation
- `osint_reconnaissance` - OSINT gathering

### Security Tools
- `vulnerability_scanner` - Vulnerability assessment
- `penetration_testing_toolkit` - Penetration testing
- `password_cracker` - Password security testing
- `exploit_framework` - Exploit development
- `malware_analysis` - Malware analysis

### Mobile Tools
- `mobile_device_info` - Mobile device information
- `mobile_device_management` - Mobile device management
- `mobile_app_security_toolkit` - Mobile app security testing

### And many more...

## Tool Dependencies

Some tools have dependencies on other tools. The system automatically detects and warns about missing dependencies:

### Automatic Dependency Resolution

Use the `--auto-deps` flag to automatically include required dependencies:

```bash
# This will automatically include proc_run as a dependency
node install.js --modular --tools port_scanner --auto-deps
```

### Manual Dependency Management

If you prefer manual control, the system will warn you about missing dependencies:

```bash
# Will show warnings about missing dependencies
node install.js --modular --tools port_scanner
```

## Common Dependency Patterns

- **Network tools** often depend on `proc_run` for command execution
- **Security tools** may depend on network discovery tools
- **Mobile tools** often depend on `system_info`
- **Enhanced tools** depend on their basic counterparts

## Configuration File

The installation creates a `tool-config.json` file that specifies which tools are enabled:

```json
{
  "enabledTools": ["health", "system_info", "fs_list"],
  "disabledTools": [],
  "toolCategories": {
    "core": { "enabled": false, "tools": ["health", "system_info"] },
    "file_system": { "enabled": false, "tools": ["fs_list", "fs_read_text", ...] }
  },
  "customTools": []
}
```

## Usage Examples

### Minimal Security Testing Setup

```bash
node install.js --modular --tools port_scanner,vulnerability_scanner,network_discovery --auto-deps
```

### File Management Only

```bash
node install.js --modular --tools fs_list,fs_read_text,fs_write_text,file_ops
```

### Mobile Development Tools

```bash
node install.js --modular --tools mobile_device_info,mobile_app_security_toolkit --auto-deps
```

### Mixed Configuration

```bash
node install.js --modular --categories core,file_system --tools packet_sniffer,port_scanner
```

## Listing Available Tools

To see all available tools organized by category:

```bash
node install.js --list-tools
```

## Building and Running

After installation, build and run the modular server:

```bash
npm run build
node dist/server-modular.js
```

## Best Practices

1. **Start Small**: Begin with core tools and add specific tools as needed
2. **Use Dependencies**: Enable `--auto-deps` to avoid missing dependencies
3. **Test Configuration**: Verify your tool selection works before production use
4. **Document Choices**: Keep track of why specific tools were selected
5. **Regular Updates**: Review and update tool selections as needs change

## Troubleshooting

### Invalid Tool Names

If you get "Invalid tools found" errors:
- Use `node install.js --list-tools` to see available tools
- Check tool names for typos
- Ensure tools are available in your version

### Missing Dependencies

If tools don't work as expected:
- Use `--auto-deps` to include dependencies
- Check the dependency warnings in the output
- Manually add required tools to your configuration

### Configuration Issues

If the server doesn't start:
- Check `tool-config.json` for syntax errors
- Verify all specified tools exist
- Try a minimal configuration first

## Advanced Usage

### Custom Tool Lists

Create custom tool lists for different use cases:

```bash
# Development environment
node install.js --modular --tools health,fs_list,fs_read_text,fs_write_text,git_status

# Security testing environment  
node install.js --modular --tools network_discovery,port_scanner,vulnerability_scanner,penetration_testing_toolkit --auto-deps

# Mobile development environment
node install.js --modular --tools mobile_device_info,mobile_app_security_toolkit,mobile_app_testing_toolkit --auto-deps
```

### Integration with CI/CD

Use individual tool installation in automated environments:

```bash
# In your CI/CD pipeline
node install.js --modular --tools health,system_info,fs_list
npm run build
node dist/server-modular.js
```

This approach provides maximum flexibility while maintaining the power and capabilities of the MCP God Mode platform.
