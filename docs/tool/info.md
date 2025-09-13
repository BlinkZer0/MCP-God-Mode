# Info Tool

## Overview
The **Info Tool** is a comprehensive system information utility that provides detailed information about the current system, environment, and configuration. It offers cross-platform support and comprehensive system diagnostics.

## Features
- **System Information**: Detailed system and hardware information
- **Environment Information**: Environment variables and configuration
- **Platform Detection**: Automatic platform and architecture detection
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Configuration Details**: System configuration and settings
- **Performance Metrics**: System performance and resource information
- **Security Information**: Security-related system information

## Usage

### Basic Information
```bash
# Get system information
{
  "action": "get_system_info"
}

# Get environment information
{
  "action": "get_environment_info"
}

# Get platform information
{
  "action": "get_platform_info"
}
```

### Detailed Information
```bash
# Get detailed system information
{
  "action": "get_detailed_info",
  "include_hardware": true,
  "include_software": true,
  "include_network": true
}

# Get performance information
{
  "action": "get_performance_info"
}

# Get security information
{
  "action": "get_security_info"
}
```

### Configuration Information
```bash
# Get configuration information
{
  "action": "get_config_info"
}

# Get environment variables
{
  "action": "get_env_vars"
}

# Get system settings
{
  "action": "get_system_settings"
}
```

## Parameters

### Information Parameters
- **action**: Information action to perform
- **include_hardware**: Include hardware information
- **include_software**: Include software information
- **include_network**: Include network information

## Output Format
```json
{
  "success": true,
  "action": "get_system_info",
  "result": {
    "platform": "windows",
    "architecture": "x64",
    "os_version": "Windows 10",
    "os_build": "19042",
    "hostname": "DESKTOP-ABC123",
    "username": "user",
    "home_directory": "C:\\Users\\user",
    "current_directory": "E:\\GitHub Projects\\MCP-God-Mode",
    "shell": "PowerShell",
    "cpu_count": 8,
    "memory_total": "16 GB",
    "memory_available": "8 GB",
    "disk_space": "500 GB",
    "network_interfaces": [
      {
        "name": "Ethernet",
        "ip": "192.168.1.100",
        "status": "connected"
      }
    ],
    "environment_variables": {
      "PATH": "C:\\Windows\\System32;...",
      "USERNAME": "user",
      "COMPUTERNAME": "DESKTOP-ABC123"
    }
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows-specific information
- **Linux**: Complete functionality with Linux-specific details
- **macOS**: Full feature support with macOS integration
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Basic System Information
```bash
# Get system information
{
  "action": "get_system_info"
}

# Result
{
  "success": true,
  "result": {
    "platform": "windows",
    "architecture": "x64",
    "os_version": "Windows 10",
    "hostname": "DESKTOP-ABC123",
    "username": "user"
  }
}
```

### Example 2: Detailed Information
```bash
# Get detailed information
{
  "action": "get_detailed_info",
  "include_hardware": true,
  "include_software": true
}

# Result
{
  "success": true,
  "result": {
    "platform": "windows",
    "hardware": {
      "cpu": "Intel Core i7-8700K",
      "memory": "16 GB",
      "storage": "500 GB SSD"
    },
    "software": {
      "os": "Windows 10",
      "version": "19042",
      "build": "19042.1234"
    }
  }
}
```

### Example 3: Environment Information
```bash
# Get environment information
{
  "action": "get_environment_info"
}

# Result
{
  "success": true,
  "result": {
    "environment_variables": {
      "PATH": "C:\\Windows\\System32;...",
      "USERNAME": "user",
      "COMPUTERNAME": "DESKTOP-ABC123"
    },
    "current_directory": "E:\\GitHub Projects\\MCP-God-Mode",
    "shell": "PowerShell"
  }
}
```

## Error Handling
- **System Errors**: Proper handling of system access issues
- **Permission Errors**: Secure handling of permission problems
- **Platform Errors**: Cross-platform compatibility handling
- **Information Errors**: Robust error handling for information retrieval

## Related Tools
- **System Management**: System management tools
- **Configuration**: Configuration management tools
- **Diagnostics**: System diagnostic tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Info Tool, please refer to the main MCP God Mode documentation or contact the development team.
