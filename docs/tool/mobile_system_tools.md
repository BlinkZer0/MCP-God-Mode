# Mobile System Tools

## Overview
Comprehensive mobile system management and administration tools for Android and iOS devices. Monitor processes, manage services, analyze network connections, check storage, examine installed packages, and review system permissions. Supports both standard and rooted/jailbroken devices.

## Description
Comprehensive mobile system management and administration tools for Android and iOS devices. Monitor processes, manage services, analyze network connections, check storage, examine installed packages, and review system permissions. Supports both standard and rooted/jailbroken devices.

## Input Schema
- **tool** (required): System tool to use. 'processes' lists running apps/services, 'services' manages system services, 'network' shows connections, 'storage' analyzes disk usage, 'users' lists accounts, 'packages' shows installed apps, 'permissions' reviews app permissions, 'system_info' provides device details.
- **action** (optional): Action to perform with the selected tool. Examples: 'list', 'start', 'stop', 'kill', 'enable', 'disable', 'analyze', 'monitor'. Actions vary by tool type.
- **filter** (optional): Filter results by name or criteria. Examples: 'chrome', 'system', 'user', 'com.android.*', 'running'. Helps narrow down results for specific items.
- **target** (optional): Specific target for the action. Examples: process ID, package name, service name, user account. Required for targeted operations like kill, start, stop.

## Output Schema
Returns system information, process lists, service status, network connections, storage analysis, user accounts, installed packages, and permission details based on the selected tool.

## Natural Language Access
Users can request mobile system operations using natural language:
- "Show me running processes on my Android device"
- "List all installed apps on my iPhone"
- "Check storage usage on my mobile device"
- "Monitor network connections on my Android phone"
- "Review app permissions on my mobile device"
- "Analyze system performance on my device"
- "Kill a specific app process on my mobile device"

## Usage Examples

### Monitor Running Processes
```javascript
// List all running processes
const result = await mobile_system_tools({
  tool: "processes",
  action: "list",
  filter: "running"
});
```

### Check Installed Packages
```javascript
// List all installed applications
const result = await mobile_system_tools({
  tool: "packages",
  action: "list",
  filter: "user"
});
```

### Analyze Storage Usage
```javascript
// Check disk space and storage details
const result = await mobile_system_tools({
  tool: "storage",
  action: "analyze"
});
```

### Review App Permissions
```javascript
// Check permissions for a specific app
const result = await mobile_system_tools({
  tool: "permissions",
  action: "list",
  target: "com.example.app"
});
```

### Monitor Network Connections
```javascript
// Show active network connections
const result = await mobile_system_tools({
  tool: "network",
  action: "monitor",
  filter: "active"
});
```

## Platform Support
- **Android**: Full support with ADB, Termux, and system commands
- **iOS**: Limited support through system APIs and jailbreak tools
- **Windows**: Android emulator and device support
- **Linux**: Full Android and iOS device support
- **macOS**: Full iOS device support, Android via ADB

## System Capabilities

### Process Management
- List running processes and services
- Kill specific processes
- Monitor process resource usage
- Analyze process dependencies

### Service Management
- Start/stop system services
- Enable/disable services
- Monitor service status
- Service dependency analysis

### Network Analysis
- Active connection monitoring
- Network interface status
- Connection filtering and analysis
- Network performance metrics

### Storage Analysis
- Disk space usage
- File system information
- Storage optimization recommendations
- Cache and temporary file management

### Package Management
- Installed application listing
- Package information and metadata
- Permission analysis
- App size and resource usage

### User Management
- User account listing
- Permission and access control
- User activity monitoring
- Security policy enforcement

## Security Features
- Permission validation for system operations
- Root privilege escalation when needed
- Secure system access protocols
- Audit logging for system changes
- Sandboxed operation execution

## Error Handling
- Permission denied with escalation options
- Device compatibility warnings
- Network connectivity issues
- Storage access limitations
- Service availability checks

## Related Tools
- `mobile_device_info` - Device information and capabilities
- `mobile_file_ops` - File system operations
- `mobile_hardware` - Hardware access and sensors
- `win_processes` - Windows process management
- `win_services` - Windows service management

## Use Cases
- **System Monitoring**: Track device performance and resource usage
- **Troubleshooting**: Diagnose system issues and performance problems
- **Security Auditing**: Review app permissions and system security
- **Performance Optimization**: Identify resource-intensive processes
- **System Maintenance**: Manage services and system components
- **Development Testing**: Monitor app behavior and system interactions
