# 🔐 Elevated Permissions Guide - MCP God Mode

## Overview

MCP God Mode automatically handles elevated permissions (admin/root/sudo) across all supported operating systems to ensure tools work properly without manual intervention. This guide explains how elevation works, which tools require it, and how to configure it.

## 🌍 Cross-Platform Support

### Windows
- **Elevation Method**: User Account Control (UAC) - Administrator privileges
- **Implementation**: PowerShell `Start-Process -Verb RunAs` or `runas` command
- **Requirements**: User must be in Administrators group
- **User Experience**: UAC prompt appears when elevation is needed

### Linux
- **Elevation Method**: `sudo` - Root privileges
- **Implementation**: Automatic sudo execution with proper error handling
- **Requirements**: User must have sudo access configured
- **User Experience**: Password prompt appears when elevation is needed

### macOS
- **Elevation Method**: `sudo` - Administrator privileges
- **Implementation**: Automatic sudo execution with proper error handling
- **Requirements**: User must have sudo access configured
- **User Experience**: Password prompt appears when elevation is needed

### Android
- **Elevation Method**: `su` - Root access (if available)
- **Implementation**: Automatic su execution with fallback to normal execution
- **Requirements**: Device must be rooted or have su available
- **User Experience**: Root prompt appears when elevation is needed

### iOS
- **Elevation Method**: No elevation available
- **Implementation**: Runs with normal user privileges
- **Requirements**: Limited by iOS security model
- **User Experience**: No elevation prompts, limited functionality

## 🛠️ Tools That Automatically Use Elevated Permissions

### System Administration Tools
These tools automatically detect when they need elevation and request it:

- **`win_services`** - Lists system services across all platforms
- **`win_processes`** - Lists system processes with full access
- **`system_monitor`** - Monitors system resources and performance
- **`system_backup`** - Creates system backups and restore points
- **`system_repair`** - Performs system diagnostics and repairs
- **`security_audit`** - Runs security audits and vulnerability scans
- **`event_log_analyzer`** - Analyzes system event logs
- **`disk_management`** - Manages disk partitions and storage

### Network and Security Tools
These tools require elevated access for network interface operations:

- **`wifi_security_toolkit`** - Wi-Fi security testing and penetration
- **`wifi_hacking`** - Advanced Wi-Fi security assessment
- **`packet_sniffer`** - Network packet capture and analysis
- **`bluetooth_security_toolkit`** - Bluetooth security testing
- **`bluetooth_hacking`** - Advanced Bluetooth security assessment
- **`sdr_security_toolkit`** - Software Defined Radio security testing
- **`radio_security`** - Radio frequency security analysis
- **`signal_analysis`** - Signal analysis and decoding
- **`hack_network`** - Network penetration testing
- **`security_testing`** - Comprehensive security assessments
- **`wireless_security`** - Wireless network security testing
- **`network_penetration`** - Network penetration testing

### Virtualization and Container Tools
These tools need elevated access for system-level operations:

- **`vm_management`** - Virtual machine lifecycle management
- **`docker_management`** - Docker container and image management

### Mobile System Tools
These tools require elevated access for full device control:

- **`mobile_system_tools`** - Mobile device system management
- **`mobile_hardware`** - Mobile device hardware access

### File System Operations
Certain file operations automatically use elevation when needed:

- **`file_ops`** - Advanced file operations (chmod, chown, system file access)

## 🚀 New Elevated Process Execution Tool

### `proc_run_elevated`
A new tool specifically designed for running commands with elevated privileges:

```typescript
server.registerTool("proc_run_elevated", {
  description: "Run a process with elevated privileges (admin/root/sudo) across all platforms",
  inputSchema: { 
    command: z.string().describe("The command to execute with elevated privileges"),
    args: z.array(z.string()).default([]).describe("Command-line arguments"),
    cwd: z.string().optional().describe("Working directory"),
    interactive: z.boolean().default(false).describe("Use interactive elevation prompt")
  }
});
```

**Features:**
- **Automatic Detection**: Detects when commands need elevation
- **Platform-Specific**: Uses appropriate elevation method for each OS
- **Interactive Mode**: Supports interactive elevation prompts
- **Security Validation**: Blocks dangerous commands from elevation
- **Fallback Handling**: Gracefully handles elevation failures

## 🔒 Security Features

### Command Validation
The system automatically blocks dangerous commands from elevation:

```typescript
const dangerousCommands = [
  'format', 'del', 'rmdir', 'shutdown', 'taskkill', 'rm', 'dd',
  'diskpart', 'reg', 'sc', 'wmic', 'powershell', 'cmd',
  'sudo', 'su', 'chmod', 'chown', 'mkfs', 'fdisk'
];
```

### Permission Checking
Tools automatically check if they already have elevated privileges:

```typescript
export async function hasElevatedPrivileges(): Promise<boolean> {
  if (IS_WINDOWS) {
    const { stdout } = await execAsync('net session', { timeout: 5000 });
    return !stdout.includes('Access is denied');
  } else if (IS_LINUX || IS_MACOS) {
    return process.getuid?.() === 0;
  }
  // ... other platforms
}
```

### Graceful Degradation
If elevation fails, tools fall back to normal execution when possible:

```typescript
try {
  const result = await executeElevated(command, args);
  if (result.success) {
    return result;
  }
} catch (error) {
  // Fallback to normal execution
  return await executeNormal(command, args);
}
```

## ⚙️ Configuration

### Environment Variables
Configure elevation behavior through environment variables:

```bash
# Enable/disable security checks
ENABLE_SECURITY_CHECKS=true

# Command timeout for elevated operations
COMMAND_TIMEOUT=30000

# Maximum buffer size for elevated command output
MAX_BUFFER_SIZE=1048576
```

### Platform-Specific Settings
Each platform has optimized elevation settings:

```typescript
// Windows: PowerShell elevation with UAC
if (IS_WINDOWS) {
  return `powershell -Command "Start-Process -FilePath '${command}' -ArgumentList '${args.join(' ')}' -Verb RunAs -Wait"`;
}

// Linux/macOS: sudo elevation
if (IS_LINUX || IS_MACOS) {
  return `sudo ${command} ${args.join(' ')}`;
}

// Android: su elevation with fallback
if (IS_ANDROID) {
  return `su -c '${command} ${args.join(' ')}'`;
}
```

## 📱 Mobile Platform Considerations

### Android
- **Root Access**: Full functionality requires rooted device
- **Fallback Mode**: Non-rooted devices use limited functionality
- **Permission Handling**: Automatic permission requests for hardware access

### iOS
- **Security Restrictions**: Very limited due to iOS security model
- **No Elevation**: Runs with normal user privileges
- **Hardware Access**: Limited to user-approved permissions

## 🚨 Troubleshooting

### Common Issues

#### Windows
- **"Access is denied"**: User not in Administrators group
- **UAC not working**: UAC disabled in Group Policy
- **PowerShell execution policy**: Set to allow script execution

#### Linux/macOS
- **"sudo: command not found"**: sudo not installed
- **"user is not in sudoers"**: User not configured for sudo access
- **Password prompt loops**: Incorrect password or sudo configuration

#### Android
- **"su: command not found"**: Device not rooted
- **"Permission denied"**: Root access not granted
- **App not responding**: Root prompt waiting for user input

### Solutions

#### Windows
```cmd
# Check if user is administrator
net user %USERNAME% /domain

# Enable UAC (if disabled)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 1 /f
```

#### Linux
```bash
# Install sudo if missing
sudo apt-get install sudo

# Add user to sudoers
sudo usermod -aG sudo $USER

# Test sudo access
sudo whoami
```

#### macOS
```bash
# Check sudo access
sudo -l

# Reset sudo password
sudo passwd $USER
```

#### Android
```bash
# Check if device is rooted
su -c "id"

# Grant root access to app
# Use SuperSU or Magisk Manager
```

## 🔧 Development and Testing

### Testing Elevated Tools
Use the test scripts to verify elevation works:

```bash
# Test all tools with elevation
npm run test:elevated

# Test specific platform
npm run test:elevated:windows
npm run test:elevated:linux
npm run test:elevated:macos
```

### Debugging Elevation Issues
Enable debug logging for elevation operations:

```bash
# Set debug level
export LOG_LEVEL=debug

# Run with verbose output
npm run start:debug
```

### Custom Elevation Commands
Override default elevation commands for testing:

```typescript
// Custom elevation for testing
export function getCustomElevationCommand(command: string, args: string[]): string {
  if (process.env.CUSTOM_ELEVATION) {
    return `${process.env.CUSTOM_ELEVATION} ${command} ${args.join(' ')}`;
  }
  return getElevationCommand(command, args);
}
```

## 📊 Performance Impact

### Elevation Overhead
- **Windows**: ~100-500ms for UAC prompt
- **Linux/macOS**: ~50-200ms for sudo execution
- **Android**: ~200-1000ms for su execution
- **iOS**: No overhead (no elevation)

### Optimization Strategies
- **Caching**: Cache elevation status to avoid repeated checks
- **Batch Operations**: Group elevated commands when possible
- **Async Execution**: Non-blocking elevation for better UX
- **Fallback Mode**: Graceful degradation when elevation fails

## 🔮 Future Enhancements

### Planned Features
- **Persistent Elevation**: Remember elevation for session
- **Smart Elevation**: Only elevate when necessary
- **Batch Elevation**: Group multiple commands under single elevation
- **Custom Elevation**: User-defined elevation methods
- **Elevation Profiles**: Different elevation levels for different operations

### Platform Expansions
- **BSD Systems**: FreeBSD, OpenBSD, NetBSD support
- **Solaris/Illumos**: Enterprise Unix support
- **Embedded Linux**: IoT and embedded device support
- **Chrome OS**: Chromebook and Chrome OS support

## 📚 Additional Resources

### Documentation
- [Wi-Fi Security Toolkit](./WIFI_SECURITY_TOOLKIT.md)
- [Bluetooth Security Toolkit](./BLUETOOTH_SECURITY_TOOLKIT.md)
- [SDR Security Toolkit](./SDR_SECURITY_TOOLKIT.md)
- [Setup Guide](./SETUP_GUIDE.md)

### Examples
- [Cross-Platform Testing](./test_cross_platform.mjs)
- [Security Tool Testing](./test_all_toolkits.mjs)
- [Mobile Platform Testing](./test_comprehensive_tools.mjs)

### Support
- **GitHub Issues**: Report bugs and request features
- **Documentation**: Comprehensive guides and examples
- **Community**: Join discussions and share solutions

---

**Note**: This guide covers the current implementation of elevated permissions in MCP God Mode. For the latest updates and platform-specific information, refer to the main documentation and test results.
