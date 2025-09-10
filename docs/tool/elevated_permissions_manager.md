# Elevated Permissions Manager

## Overview

The **Elevated Permissions Manager** is a comprehensive security and control system for MCP God Mode that allows users to manage which tools can execute with elevated privileges (admin/root/sudo) across all platforms. This tool provides granular control over elevated permissions, dangerous command blocking, and security settings.

## Key Features

- **Global Elevated Mode**: Enable/disable elevated privileges for all tools system-wide
- **Tool-Specific Permissions**: Control which individual tools can use elevated privileges
- **Dangerous Command Blocking**: Automatically block potentially harmful commands
- **Safe Mode**: Enhanced security with automatic dangerous command detection
- **Confirmation Prompts**: User confirmation for sensitive operations
- **Cross-Platform Support**: Works on Windows, Linux, macOS, Android, and iOS
- **Configuration Persistence**: Settings are saved and restored across sessions
- **Audit Logging**: Comprehensive audit trail for all permission operations
- **Configuration Export/Import**: Backup and restore configurations in multiple formats
- **Platform-Specific Elevation**: Automatic detection of elevation methods per platform

## Available Actions

### Configuration Management
- `get_config` - Retrieve current elevated permissions configuration
- `set_global_elevated_mode` - Enable/disable global elevated mode for all tools
- `reset_to_defaults` - Reset configuration to default security settings

### Tool Permission Management
- `add_allowed_tool` - Add a tool to the allowed elevated execution list
- `remove_allowed_tool` - Remove a tool from the allowed elevated execution list
- `list_allowed_tools` - List all tools currently allowed to use elevated privileges
- `check_tool_permission` - Check if a specific tool can execute with elevated privileges

### Command Safety Management
- `add_dangerous_command` - Add a command to the dangerous commands list
- `remove_dangerous_command` - Remove a command from the dangerous commands list
- `list_dangerous_commands` - List all commands considered dangerous
- `check_command_safety` - Check if a specific command is considered dangerous

### Security Settings
- `set_safe_mode` - Enable/disable safe mode (blocks dangerous commands)
- `set_require_confirmation` - Enable/disable confirmation prompts for sensitive operations
- `get_security_status` - Get comprehensive security status and configuration summary

### Audit and Compliance
- `get_audit_log` - Retrieve audit log of all permission operations
- `clear_audit_log` - Clear the audit log (use with caution)
- `export_config` - Export configuration in JSON, YAML, or CSV format
- `import_config` - Import configuration from JSON data

### Cross-Platform Support
- `get_elevation_method` - Get the elevation method for the current platform
- `get_elevation_prompt` - Get the appropriate elevation prompt for the platform
- `check_platform_support` - Verify platform support and available features

## Input Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action` | string | Yes | The action to perform with the elevated permissions manager |
| `tool_name` | string | No | Name of the tool to add/remove from allowed list or check permissions for |
| `command` | string | No | Command to add/remove from dangerous commands list or check safety for |
| `global_elevated_mode` | boolean | No | Whether to enable/disable global elevated mode for all tools |
| `safe_mode` | boolean | No | Whether to enable/disable safe mode (blocks dangerous commands) |
| `confirmation_required` | boolean | No | Whether to require confirmation for elevated operations |
| `reset_confirm` | boolean | No | Confirmation that you want to reset to default settings (set to true to confirm) |

## Output Schema

| Field | Type | Description |
|-------|------|-------------|
| `success` | boolean | Whether the operation was successful |
| `action` | string | The action that was performed |
| `config` | object | Current elevated permissions configuration (when applicable) |
| `result` | any | Result of the operation (varies by action) |
| `message` | string | Human-readable message about the operation result |
| `elevation_method` | string | Platform-specific elevation method (runas, sudo, etc.) |
| `elevation_prompt` | string | User-friendly prompt about elevation requirements |

### Configuration Object Structure

```json
{
  "globalElevatedMode": false,
  "allowedTools": ["proc_run_elevated", "win_services", "file_ops"],
  "dangerousCommands": ["rm", "del", "format", "dd"],
  "safeMode": true,
  "requireConfirmation": true
}
```

## Natural Language Access
Users can request elevated permissions manager operations using natural language:
- "Manage elevated permissions"
- "Control system privileges"
- "Grant admin access"
- "Manage user permissions"
- "Control system rights"

## Usage Examples

### Get Current Configuration
```json
{
  "action": "get_config"
}
```

### Enable Global Elevated Mode
```json
{
  "action": "set_global_elevated_mode",
  "global_elevated_mode": true
}
```

### Add Tool to Allowed List
```json
{
  "action": "add_allowed_tool",
  "tool_name": "custom_security_tool"
}
```

### Check Command Safety
```json
{
  "action": "check_command_safety",
  "command": "rm -rf /"
}
```

### Reset to Default Settings
```json
{
  "action": "reset_to_defaults",
  "reset_confirm": true
}
```

## Technical Details

### Default Allowed Tools
The system comes pre-configured with a curated list of tools that commonly require elevated privileges:

- **Process Management**: `proc_run_elevated`
- **System Services**: `win_services`, `win_processes`
- **System Management**: `system_restore`, `vm_management`, `docker_management`
- **Mobile Tools**: `mobile_system_tools`, `mobile_hardware`
- **Security Tools**: `wifi_security_toolkit`, `wifi_hacking`, `bluetooth_security_toolkit`, `bluetooth_hacking`
- **Radio Tools**: `sdr_security_toolkit`, `radio_security`, `signal_analysis`
- **Network Tools**: `packet_sniffer`, `port_scanner`, `vulnerability_scanner`
- **Security Testing**: `password_cracker`, `exploit_framework`, `hack_network`, `security_testing`, `network_penetration`
- **File Operations**: `file_ops`, `fs_write_text`, `fs_read_text`, `fs_list`, `fs_search`

### Default Dangerous Commands
The system automatically blocks these potentially harmful commands:

- **File Deletion**: `rm`, `del`, `shred`
- **Disk Operations**: `format`, `fdisk`, `mkfs`, `dd`
- **Permission Changes**: `chmod`, `chown`, `chattr`
- **Mount Operations**: `mount`, `umount`
- **Service Management**: `systemctl`, `service`, `sc`
- **Network Operations**: `net stop`, `net start`
- **Process Management**: `taskkill`, `tasklist`, `wmic`
- **PowerShell**: `powershell`

### Platform-Specific Elevation Methods

- **Windows**: `runas` (User Account Control)
- **Linux/macOS**: `sudo` (Superuser Do)
- **Android**: System-level permissions
- **iOS**: Jailbreak-dependent elevation

## Advanced Features

### Safe Mode
When enabled, safe mode automatically blocks any command that matches patterns in the dangerous commands list, providing an additional layer of security.

### Confirmation Prompts
For sensitive operations, the system can require explicit user confirmation before proceeding, helping prevent accidental privilege escalation.

### Configuration Persistence
All settings are automatically saved to a configuration file and restored when the system restarts, ensuring consistent behavior across sessions.

## Security Considerations

### Principle of Least Privilege
The system follows the principle of least privilege by default, requiring explicit permission for tools to use elevated privileges.

### Command Validation
All commands are validated against the dangerous commands list before execution, preventing accidental system damage.

### Audit Trail
All permission changes and elevated operations are logged for security auditing purposes.

### Safe Defaults
The system starts with secure default settings that prioritize system safety over convenience.

## Limitations & Considerations

### Platform Differences
Elevation methods and available privileges vary significantly between operating systems and mobile platforms.

### User Permissions
The effectiveness of elevated permissions depends on the user's actual system privileges and security policies.

### Command Detection
Dangerous command detection is based on pattern matching and may not catch all potentially harmful operations.

### Mobile Limitations
Mobile platforms have additional restrictions that may limit the effectiveness of elevated permissions.

## Related Tools

- **Process Execution**: `proc_run`, `proc_run_elevated`
- **System Management**: `win_services`, `win_processes`, `system_restore`
- **File Operations**: `file_ops`, `fs_write_text`, `fs_read_text`
- **Security Testing**: Various security and penetration testing tools

## What's New in v1.4a

- **Initial Release**: First implementation of comprehensive elevated permissions management
- **Cross-Platform Support**: Works across all supported platforms
- **Configuration Persistence**: Settings are automatically saved and restored
- **Integration**: Seamlessly integrates with existing tools that require elevated privileges
- **Security Focus**: Built with security best practices and safe defaults

---

*The Elevated Permissions Manager provides the foundation for secure, controlled access to system-level operations across all platforms supported by MCP God Mode.*
