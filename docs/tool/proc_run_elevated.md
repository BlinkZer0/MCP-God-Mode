# Elevated Process Execution Tool

## Overview
The `proc_run_elevated` tool allows you to run processes with elevated privileges (admin/root/sudo) across all platforms. This tool automatically detects when elevation is needed and provides secure execution methods.

## Tool Name
`proc_run_elevated`

## Description
Run a process with elevated privileges (admin/root/sudo) across all platforms

## Input Schema
- `command` (string, required): The command to execute with elevated privileges. Examples: 'netstat', 'systemctl', 'sc', 'launchctl'. Commands that require admin/root access.
- `args` (array, optional): Array of command-line arguments to pass to the command. Examples: ['-tuln'] for 'netstat -tuln', ['status', 'ssh'] for 'systemctl status ssh'. Default: []
- `cwd` (string, optional): The working directory where the command will be executed. Examples: './project', '/home/user/documents', 'C:\\Users\\User\\Desktop'. Leave empty to use the current working directory.
- `interactive` (boolean, optional): Whether to use interactive elevation prompt. Set to true for commands that require user input during elevation. Default: false

## Natural Language Access
Users can ask for this tool using natural language such as:
- "Run this command as administrator"
- "Execute with elevated privileges"
- "Run as root user"
- "Execute with sudo permissions"
- "Run this system command with admin rights"
- "Execute with elevated access"
- "Run as privileged user"

## Examples

### Basic Elevated Execution
```typescript
// Run system command with elevation
const result = await server.callTool("proc_run_elevated", { 
  command: "netstat",
  args: ["-tuln"]
});

// Run service management command
const result = await server.callTool("proc_run_elevated", { 
  command: "systemctl",
  args: ["status", "ssh"]
});
```

### Interactive Commands
```typescript
// Run interactive command requiring user input
const result = await server.callTool("proc_run_elevated", { 
  command: "passwd",
  args: ["username"],
  interactive: true
});

// Run setup command with prompts
const result = await server.callTool("proc_run_elevated", { 
  command: "dpkg-reconfigure",
  args: ["package-name"],
  interactive: true
});
```

### Platform-Specific Examples
```typescript
// Windows: Check services
const result = await server.callTool("proc_run_elevated", { 
  command: "sc",
  args: ["query", "spooler"]
});

// Linux: Manage systemd services
const result = await server.callTool("proc_run_elevated", { 
  command: "systemctl",
  args: ["enable", "docker"]
});

// macOS: Manage launchd services
const result = await server.callTool("proc_run_elevated", { 
  command: "launchctl",
  args: ["load", "/Library/LaunchDaemons/service.plist"]
});
```

## Platform Support
- ✅ Windows (UAC elevation)
- ✅ Linux (sudo/su)
- ✅ macOS (sudo)
- ⚠️ Android (limited, requires root)
- ⚠️ iOS (very limited, requires jailbreak)

## Elevation Methods

### Windows
- **UAC (User Account Control)**: Standard Windows elevation
- **Run as Administrator**: Right-click elevation
- **PowerShell**: Elevated PowerShell execution
- **Command Prompt**: Elevated CMD execution

### Linux
- **sudo**: Standard Linux privilege escalation
- **su**: Switch user to root
- **pkexec**: PolicyKit execution
- **gksudo**: Graphical sudo frontend

### macOS
- **sudo**: Standard macOS privilege escalation
- **Authorization Services**: Native macOS elevation
- **PolicyKit**: Advanced policy management

### Mobile Platforms
- **Android**: Requires root access (SuperSU, Magisk)
- **iOS**: Requires jailbreak (Cydia, Sileo)

## Security Features
- Automatic elevation detection
- Command validation and sanitization
- Secure privilege escalation
- Audit logging of elevated operations
- Permission boundary enforcement

## Safety Checks
- Validates commands before elevation
- Checks if elevation is actually needed
- Prevents dangerous command execution
- Monitors elevated process behavior
- Automatic privilege de-escalation

## Common Use Cases

### System Administration
- Service management (start/stop/enable/disable)
- Network configuration
- User account management
- System updates and maintenance
- Hardware configuration

### Security Operations
- Firewall configuration
- Security policy management
- Access control configuration
- Audit log management
- Security tool execution

### Development and Testing
- Development environment setup
- Testing with elevated permissions
- Debugging system-level issues
- Performance monitoring
- System profiling

## Error Handling
- Graceful fallback for failed elevation
- Clear error messages for permission issues
- Automatic retry with different methods
- Fallback to non-elevated execution when safe
- Comprehensive error logging

## Best Practices
- Only use elevation when absolutely necessary
- Validate all commands before execution
- Use the minimum required privileges
- Document all elevated operations
- Monitor elevated process behavior
- Implement proper audit logging
- Follow principle of least privilege

## Security Considerations
⚠️ **IMPORTANT**: Elevated execution carries security risks:
- Commands run with full system access
- Potential for system damage if misused
- Risk of privilege escalation attacks
- Audit trail requirements
- Compliance implications

## Related Tools
- `proc_run` - Standard process execution
- `win_services` - Windows service management
- `win_processes` - Windows process management
- `system_restore` - System backup and restore

## Compliance and Auditing
- All elevated operations are logged
- Command history is maintained
- User accountability is enforced
- Audit trails are preserved
- Compliance reporting is available
