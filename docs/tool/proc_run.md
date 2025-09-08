# ⚙️ Process Run Tool - MCP God Mode

## Overview
The **Process Run Tool** (`mcp_mcp-god-mode_proc_run`) is a comprehensive process execution utility that provides cross-platform process management capabilities across Windows, Linux, macOS, Android, and iOS platforms. It supports process execution, elevated privileges, working directory management, and professional process control with comprehensive security features and monitoring capabilities.

## Functionality
- **Process Execution**: Execute commands and processes across all platforms
- **Elevated Privileges**: Run processes with administrative/root privileges
- **Working Directory Management**: Control process working directory
- **Cross-Platform Support**: Native implementation across all supported operating systems
- **Security Features**: Secure process execution and privilege management
- **Advanced Features**: Process monitoring, output capture, and error handling

## Technical Details

### Tool Identifier
- **MCP Tool Name**: `mcp_mcp-god-mode_proc_run`
- **Category**: System & Process Management
- **Platform Support**: Windows, Linux, macOS, Android, iOS
- **Elevated Permissions**: Required for elevated process execution

### Input Parameters
```typescript
{
  command: string,          // The command to execute
  args?: string[],          // Array of command-line arguments
  cwd?: string             // Working directory where command will be executed
}
```

### Output Response
```typescript
{
  command: string,          // Command executed
  args: string[],           // Arguments passed to command
  cwd: string,              // Working directory used
  status: "success" | "error" | "partial",
  timestamp: string,        // Execution timestamp
  results?: {
    exit_code: number,      // Process exit code
    stdout: string,         // Standard output content
    stderr: string,         // Standard error content
    execution_time: number, // Execution time in milliseconds
    pid?: number,           // Process ID (if available)
    working_directory: string, // Actual working directory used
    command_path: string    // Full path to executed command
  },
  error?: string,           // Error message if execution failed
  warnings?: string[],      // Warning messages
  security_info?: {
    elevated: boolean,      // Whether process ran with elevated privileges
    user_context: string,   // User context used for execution
    security_level: string  // Security level applied
  }
}
```


## Natural Language Access
Users can request proc run operations using natural language:
- "Run system processes"
- "Execute commands"
- "Start system programs"
- "Launch applications"
- "Execute system tasks"
## Usage Examples

### Basic Command Execution
```typescript
const basicResult = await proc_run({
  command: "ls",
  args: ["-la"],
  cwd: "./documents"
});

if (basicResult.status === "success") {
  console.log(`Command executed successfully`);
  console.log(`Output: ${basicResult.results?.stdout}`);
  console.log(`Exit code: ${basicResult.results?.exit_code}`);
}
```

### Elevated Process Execution
```typescript
const elevatedResult = await proc_run({
  command: "systemctl",
  args: ["status", "ssh"],
  cwd: "/"
});

if (elevatedResult.status === "success") {
  console.log(`SSH service status:`);
  console.log(elevatedResult.results?.stdout);
  console.log(`Elevated execution: ${elevatedResult.security_info?.elevated}`);
}
```

### Cross-Platform Command Execution
```typescript
const platformCommand = process.platform === "win32" ? "dir" : "ls";
const result = await proc_run({
  command: platformCommand,
  args: process.platform === "win32" ? ["/w"] : ["-la"],
  cwd: "./"
});

if (result.status === "success") {
  console.log(`Directory listing (${process.platform}):`);
  console.log(result.results?.stdout);
}
```

### Complex Command with Arguments
```typescript
const complexResult = await proc_run({
  command: "ffmpeg",
  args: [
    "-i", "input.mp4",
    "-c:v", "libx264",
    "-c:a", "aac",
    "-b:v", "1000k",
    "-b:a", "128k",
    "output.mp4"
  ],
  cwd: "./videos"
});

if (complexResult.status === "success") {
  console.log(`Video conversion completed in ${complexResult.results?.execution_time}ms`);
} else {
  console.error(`Conversion failed: ${complexResult.error}`);
}
```

## Integration Points

### Server Integration
- **Full Server**: ✅ Included
- **Modular Server**: ❌ Not included
- **Minimal Server**: ✅ Included
- **Ultra-Minimal Server**: ✅ Included

### Dependencies
- Native process execution libraries
- Elevated privileges management
- Working directory management
- Process monitoring and control

## Platform-Specific Features

### Windows
- **PowerShell Integration**: PowerShell cmdlet execution
- **Command Prompt**: CMD command execution
- **UAC Integration**: User Account Control integration
- **Process Management**: Windows process management

### Linux
- **Shell Integration**: Bash and other shell execution
- **sudo Support**: sudo privilege elevation
- **Process Control**: Unix process control
- **Signal Handling**: Unix signal handling

### macOS
- **Terminal Integration**: Terminal command execution
- **sudo Support**: macOS sudo integration
- **Process Management**: macOS process management
- **Security Framework**: macOS security framework

### Mobile Platforms
- **Mobile Shell**: Mobile shell execution
- **Permission Management**: Mobile permission handling
- **Process Control**: Mobile process control
- **Security Context**: Mobile security context

## Process Execution Features

### Command Types
- **System Commands**: Native system commands
- **Shell Commands**: Shell script execution
- **Application Commands**: Application execution
- **Custom Scripts**: Custom script execution

### Execution Modes
- **Synchronous**: Blocking execution mode
- **Asynchronous**: Non-blocking execution mode
- **Background**: Background process execution
- **Interactive**: Interactive process execution

### Output Handling
- **Standard Output**: stdout capture and processing
- **Standard Error**: stderr capture and processing
- **Exit Codes**: Process exit code handling
- **Return Values**: Command return value processing

## Security Features

### Privilege Management
- **Elevated Execution**: Administrative privilege execution
- **User Context**: User context management
- **Security Levels**: Security level enforcement
- **Access Control**: Process access control

### Execution Security
- **Command Validation**: Command input validation
- **Path Security**: Working directory security
- **Environment Security**: Environment variable security
- **Sandboxing**: Process sandboxing support

## Error Handling

### Common Issues
- **Permission Denied**: Insufficient execution permissions
- **Command Not Found**: Command not available
- **Working Directory**: Invalid working directory
- **Process Failure**: Process execution failure

### Recovery Actions
- Automatic retry mechanisms
- Alternative execution methods
- Fallback command execution
- Comprehensive error reporting

## Performance Characteristics

### Execution Speed
- **Simple Commands**: < 100ms for basic commands
- **Complex Commands**: 100ms - 10 seconds
- **Long-Running**: Variable based on command duration
- **Elevated Commands**: Additional overhead for privilege elevation

### Resource Usage
- **CPU**: Variable (depends on executed command)
- **Memory**: Variable (depends on command requirements)
- **Network**: Variable (for network commands)
- **Disk**: Variable (for disk operations)

## Monitoring and Logging

### Process Monitoring
- **Execution Tracking**: Process execution tracking
- **Performance Metrics**: Execution performance tracking
- **Error Analysis**: Execution error analysis
- **Success Tracking**: Successful execution tracking

### Security Monitoring
- **Privilege Usage**: Elevated privilege usage monitoring
- **Command Execution**: Command execution logging
- **Access Control**: Access control monitoring
- **Security Events**: Security event logging

## Troubleshooting

### Execution Issues
1. Verify command availability
2. Check execution permissions
3. Review working directory
4. Confirm command syntax

### Performance Issues
1. Monitor system resources
2. Optimize command parameters
3. Use appropriate execution modes
4. Monitor process behavior

## Best Practices

### Implementation
- Use appropriate privilege levels
- Implement proper error handling
- Validate command inputs
- Monitor execution performance

### Security
- Minimize elevated privilege usage
- Validate command sources
- Implement access controls
- Monitor for suspicious activity

## Related Tools
- **System Info**: System information and monitoring
- **Process Management**: Process monitoring and control
- **File Operations**: File management and operations
- **Network Tools**: Network connectivity and management

## Version History
- **v1.0**: Initial implementation
- **v1.1**: Enhanced execution features
- **v1.2**: Advanced security features
- **v1.3**: Cross-platform improvements
- **v1.4a**: Professional process management features

---

**⚠️ IMPORTANT: Process execution can affect system stability and security. Always verify commands and use appropriate privilege levels.**

*This document is part of MCP God Mode v1.4a - Advanced AI Agent Toolkit*
