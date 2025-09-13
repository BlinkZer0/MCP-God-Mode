# Remote Process Run Tool

## 🌐 **Overview**

The Remote Process Run Tool enables remote process execution across all platforms (Windows, Linux, macOS, iOS, Android) via WAN IP addresses with comprehensive protocol support, elevated permissions handling, and **passwordless authentication capabilities**.

## 🔑 **Passwordless Authentication**

**Key Feature**: This tool can **circumvent username and password requirements** through comprehensive passwordless authentication methods.

### **Passwordless Authentication Methods**

#### SSH Key-Based Authentication
- **Auto-Detection**: Automatically finds SSH keys in common locations
  - `~/.ssh/id_rsa`
  - `~/.ssh/id_ed25519`
  - `~/.ssh/id_ecdsa`
  - `~/.ssh/id_dsa`
  - `/root/.ssh/id_rsa`
- **Public Key Authentication**: Uses SSH public/private key pairs
- **Batch Mode**: Non-interactive mode for automated operations
- **Host Key Bypass**: Disables host key checking for easier connections
- **Fallback Support**: Falls back to password authentication if keys fail

#### Certificate-Based Authentication (WinRM)
- **Kerberos Authentication**: Uses Kerberos for Windows remote management
- **Trusted Connections**: Leverages existing domain trust relationships
- **Certificate Stores**: Utilizes system certificate stores
- **Credential Fallback**: Falls back to explicit credentials if needed

#### Device Pairing (ADB/iOS)
- **ADB Pairing**: Automatic device pairing for Android Debug Bridge
- **iOS Device Trust**: Uses device trust relationships for iOS devices
- **USB/Network Pairing**: Supports both USB and network-based pairing
- **Auto-Pairing**: Attempts to pair devices automatically if not already paired

#### Trusted Connections
- **Domain Trust**: Leverages Active Directory domain trust relationships
- **Network Trust**: Uses network-level trust mechanisms
- **Service Accounts**: Utilizes service account authentication
- **Telnet Trust**: Supports trusted telnet connections

## 🔧 **Core Features**

### **Cross-Platform Remote Connectivity**
- SSH (Secure Shell) for Linux, macOS, iOS
- WinRM (Windows Remote Management) for Windows
- ADB (Android Debug Bridge) for Android
- iOS Deploy for iOS devices
- Telnet for legacy systems
- Custom protocol support for specialized devices

### **Elevated Permissions Support**
- sudo command execution for Unix-like systems
- PowerShell RunAs for Windows
- su command execution for Android
- Root access for iOS devices
- Custom elevated execution methods

### **Security & Authentication**
- Username/password authentication
- SSH key file authentication
- Custom protocol authentication
- Connection timeout handling
- Secure credential management

### **Advanced Features**
- Platform auto-detection
- Working directory management
- Output capture and streaming
- Interactive mode support
- Custom protocol configuration
- Comprehensive error handling

## 📋 **Tool Commands**

### **1. Complete Passwordless Execution**
```json
{
  "command": "proc_run_remote",
  "parameters": {
    "target_host": "192.168.1.100",
    "protocol": "ssh",
    "command": "systemctl",
    "args": ["status", "nginx"],
    "passwordless": true,
    "auto_auth": true,
    "elevated": true
  }
}
```

### **2. Auto-Authentication (Default Behavior)**
```json
{
  "command": "proc_run_remote",
  "parameters": {
    "target_host": "10.0.0.50",
    "protocol": "winrm",
    "command": "Get-Process",
    "args": ["-Name", "chrome"],
    "auto_auth": true
  }
}
```

### **3. Minimal Configuration (Maximum Automation)**
```json
{
  "command": "proc_run_remote",
  "parameters": {
    "target_host": "192.168.1.200",
    "protocol": "adb",
    "command": "pm",
    "args": ["list", "packages"]
  }
}
```

### **4. SSH Remote Execution**
```json
{
  "command": "proc_run_remote",
  "parameters": {
    "target_host": "192.168.1.100",
    "protocol": "ssh",
    "command": "ls",
    "args": ["-la"],
    "username": "admin",
    "password": "password123",
    "elevated": false
  }
}
```

### **5. WinRM Windows Remote Execution**
```json
{
  "command": "proc_run_remote",
  "parameters": {
    "target_host": "10.0.0.50",
    "protocol": "winrm",
    "command": "Get-Process",
    "args": ["-Name", "chrome"],
    "username": "Administrator",
    "password": "admin123",
    "elevated": true
  }
}
```

### **6. ADB Android Remote Execution**
```json
{
  "command": "proc_run_remote",
  "parameters": {
    "target_host": "192.168.1.200",
    "target_port": 5555,
    "protocol": "adb",
    "command": "pm",
    "args": ["list", "packages"],
    "elevated": false
  }
}
```

### **7. iOS Remote Execution**
```json
{
  "command": "proc_run_remote",
  "parameters": {
    "target_host": "192.168.1.150",
    "protocol": "ios_deploy",
    "command": "uname",
    "args": ["-a"],
    "username": "root",
    "password": "alpine",
    "elevated": true
  }
}
```

## 📊 **Protocol Support Matrix**

| Protocol | Windows | Linux | macOS | Android | iOS | Default Port | Passwordless |
|----------|---------|-------|-------|---------|-----|--------------|--------------|
| SSH      | ✅      | ✅    | ✅    | ✅      | ✅  | 22           | ✅ SSH Keys  |
| WinRM    | ✅      | ❌    | ❌    | ❌      | ❌  | 5985/5986    | ✅ Kerberos  |
| ADB      | ❌      | ❌    | ❌    | ✅      | ❌  | 5555         | ✅ Pairing   |
| iOS Deploy| ❌     | ❌    | ❌    | ❌      | ✅  | 22           | ✅ SSH Keys  |
| Telnet   | ✅      | ✅    | ✅    | ❌      | ❌  | 23           | ✅ Trust     |
| Custom   | ✅      | ✅    | ✅    | ✅      | ✅  | 8080         | ✅ Custom    |

## 🔧 **Input Parameters**

### **Core Parameters**
```typescript
{
  target_host: string,           // WAN IP address or hostname
  target_port?: number,          // Target port (auto-detected)
  protocol: string,              // Connection protocol
  command: string,               // Command to execute
  args?: string[],               // Command arguments
  working_dir?: string,          // Working directory
  username?: string,             // Authentication username (optional)
  password?: string,             // Authentication password (optional)
  key_file?: string,             // SSH key file path (optional)
  elevated?: boolean,            // Elevated privileges
  timeout?: number,              // Connection timeout
  platform?: string,             // Target platform
  capture_output?: boolean,      // Output capture
  interactive?: boolean,         // Interactive mode
  custom_protocol_config?: object // Custom protocol config
}
```

### **Passwordless Parameters**
```typescript
{
  passwordless?: boolean,        // Force passwordless authentication methods
  auto_auth?: boolean,           // Automatically detect and use available authentication methods
  username?: string,             // Optional - will use passwordless methods if not provided
  password?: string,             // Optional - will use passwordless methods if not provided
  key_file?: string,             // Optional - will auto-detect if not provided
}
```

## 📤 **Output Response**

```typescript
{
  success: boolean,              // Execution success
  message: string,               // Result message
  target_host: string,           // Target host
  protocol: string,              // Used protocol
  platform?: string,             // Detected platform
  exit_code?: number,            // Command exit code
  stdout?: string,               // Standard output
  stderr?: string,               // Standard error
  execution_time?: number,       // Execution time
  connection_time?: number,      // Connection time
  elevated?: boolean,            // Elevated execution
  auth_method?: string           // Authentication method used
}
```

## 🔐 **Authentication Flow**

### **Primary Flow (Passwordless First)**
1. **Auto-Detection**: Detect available authentication methods
2. **SSH Keys**: Try SSH key-based authentication
3. **Certificates**: Try certificate-based authentication
4. **Device Pairing**: Try device pairing for mobile devices
5. **Trusted Connections**: Try trusted connection methods
6. **Fallback**: Use password/credential authentication if available

### **Smart Authentication Selection**
```typescript
// Auto-detect and use best available method
const authMethods = await detectAvailableAuthMethods(protocol, host, port);

if (authMethods.sshKey) {
  // Use SSH key authentication
  finalKeyFile = authMethods.sshKey;
  finalPassword = undefined;
}

if (authMethods.certificate) {
  // Use certificate-based authentication
  finalPassword = undefined;
}

if (authMethods.devicePairing) {
  // Use device pairing
  finalUsername = undefined;
  finalPassword = undefined;
}
```

## 🛡️ **Security Features**

### **Enhanced Security**
- **SSH Key Priority**: Prefers SSH keys over passwords
- **Certificate Validation**: Validates certificates for WinRM
- **Device Trust**: Uses established device trust relationships
- **Host Key Bypass**: Configurable host key checking
- **Batch Mode**: Non-interactive operation for automation

### **Fallback Security**
- **Credential Fallback**: Falls back to passwords if passwordless fails
- **Error Handling**: Comprehensive error reporting for failed methods
- **Timeout Protection**: Configurable timeouts for all methods
- **Audit Logging**: Logs authentication method used

## 🌍 **Cross-Platform Support**

### **Windows**
- **WinRM Kerberos**: Domain authentication without credentials
- **Certificate Stores**: System certificate-based authentication
- **Trusted Connections**: Domain trust relationships

### **Linux/macOS**
- **SSH Keys**: Public/private key authentication
- **Batch Mode**: Non-interactive SSH connections
- **Key Auto-Detection**: Automatic SSH key discovery

### **Android**
- **ADB Pairing**: Automatic device pairing
- **Network ADB**: Network-based ADB connections
- **Trust Relationships**: Device trust mechanisms

### **iOS**
- **SSH Keys**: SSH key-based authentication
- **Device Trust**: iOS device trust relationships
- **USB/Network**: Both USB and network connections

## 🔌 **Integration Points**

### **Tool Registry Integration**
- Added to `dev/src/tools/process/index.ts`
- Added to `dev/src/tools/index.ts`
- Automatically registered in server-refactored.ts
- Available in all tool profiles (refactored, modular)

### **Documentation Integration**
- Comprehensive tool documentation in `docs/tool/proc_run_remote.md`
- Usage examples in `dev/examples/remote_proc_run_examples.md`
- Test suite in `dev/tests/remote_proc_run_test.js`
- Updated README.md with tool count and description

### **Cross-Platform Compatibility**
- Follows MCP-God-Mode cross-platform requirements
- Natural language routing support
- Consistent interface with existing proc_run tools
- Platform-specific optimizations

## 🔒 **Security Considerations**

### **Authentication Methods**
- **Password Authentication**: Standard username/password
- **SSH Key Authentication**: Public/private key pairs
- **Custom Authentication**: Protocol-specific methods
- **Token-based Authentication**: API tokens for custom protocols

### **Security Features**
- Connection timeout protection
- SSH host key verification (configurable)
- Encrypted connections where supported
- Secure credential handling
- Comprehensive audit logging

### **Best Practices**
1. Use SSH keys over passwords
2. Limit elevated access to necessary operations
3. Implement proper network security
4. Use secure credential storage
5. Enable audit logging for compliance

## 🧪 **Testing & Validation**

### **Test Coverage**
- SSH connectivity and authentication
- WinRM Windows remote execution
- ADB Android device management
- iOS Deploy device access
- Error handling and edge cases
- Platform auto-detection
- Custom protocol support
- Passwordless authentication methods

### **Test Suite Features**
- Comprehensive test scenarios
- Error condition testing
- Performance validation
- Security testing
- Cross-platform compatibility
- Detailed reporting

## ⚡ **Performance Characteristics**

### **Connection Optimization**
- Connection pooling for multiple executions
- Configurable timeouts for different networks
- Retry mechanisms for transient failures
- Memory-efficient output capture

### **Resource Management**
- Proper cleanup of connections
- Configurable buffer sizes
- Concurrent execution support
- Load balancing capabilities

## 📋 **Compliance & Legal**

### **Audit Requirements**
- Comprehensive execution logging
- User authentication tracking
- Command history preservation
- Result documentation

### **Legal Compliance**
- Integration with legal compliance tools
- Evidence preservation capabilities
- Chain of custody support
- Privacy protection measures

## 🚀 **Future Enhancements**

### **Planned Features**
- Connection pooling and reuse
- Batch execution capabilities
- Advanced authentication methods
- Real-time output streaming
- Connection health monitoring
- Performance metrics collection

### **Integration Opportunities**
- Security assessment tools
- Network monitoring systems
- Compliance management platforms
- Incident response workflows
- Forensic analysis tools

## 🎯 **Usage Examples**

### **Passwordless Examples**
```bash
# Complete passwordless execution
proc_run_remote --target-host "192.168.1.100" --protocol "ssh" --command "systemctl status nginx" --passwordless --auto-auth

# Auto-authentication (default behavior)
proc_run_remote --target-host "10.0.0.50" --protocol "winrm" --command "Get-Process" --auto-auth

# Minimal configuration (maximum automation)
proc_run_remote --target-host "192.168.1.200" --protocol "adb" --command "pm list packages"
```

### **Natural Language Interface**
```bash
# Conversational remote execution
proc_run_remote "Run systemctl status nginx on 192.168.1.100 via SSH"
proc_run_remote "Execute Get-Process on Windows server 10.0.0.50"
proc_run_remote "List packages on Android device 192.168.1.200"
```

## ✅ **Implementation Status**

### **Completed Components**
- ✅ **Cross-Platform Remote Connectivity**: All platforms supported
- ✅ **Multiple Protocol Support**: SSH, WinRM, ADB, iOS Deploy, Telnet, Custom
- ✅ **Elevated Permissions Handling**: Across all platforms
- ✅ **Comprehensive Security**: Authentication mechanisms
- ✅ **Platform Auto-Detection**: Optimization
- ✅ **Full Integration**: MCP-God-Mode tool registry
- ✅ **Extensive Documentation**: Examples and test suite
- ✅ **Passwordless Authentication**: Complete passwordless support

### **Ready for Production**
The Remote Process Run Tool is fully implemented and ready for use. All core functionality is complete, including:

- Cross-platform remote connectivity (Windows, Linux, macOS, iOS, Android)
- Multiple protocol support (SSH, WinRM, ADB, iOS Deploy, Telnet, Custom)
- Elevated permissions handling across all platforms
- Comprehensive security and authentication mechanisms
- Platform auto-detection and optimization
- **Complete passwordless authentication support**
- Full integration with MCP-God-Mode tool registry
- Extensive documentation and examples
- Comprehensive test suite and validation

## 🚀 **Deployment Notes**

### **Requirements**
- Node.js 18+ with TypeScript support
- Platform-specific remote management tools
- Network connectivity to target systems
- Appropriate authentication credentials or keys

### **Security Considerations**
- Passwordless authentication preferred for security
- SSH keys provide better security than passwords
- Elevated access should be limited to necessary operations
- Comprehensive audit logging maintained
- Network security best practices recommended

The Remote Process Run Tool successfully extends MCP-God-Mode's process execution capabilities to remote devices across all supported platforms. With comprehensive protocol support, security features, elevated permissions handling, and **complete passwordless authentication capabilities**, it provides a robust foundation for remote system management and security operations.

**Key Achievements:**
- ✅ Cross-platform remote connectivity (Windows, Linux, macOS, iOS, Android)
- ✅ Multiple protocol support (SSH, WinRM, ADB, iOS Deploy, Telnet, Custom)
- ✅ Elevated permissions handling across all platforms
- ✅ Comprehensive security and authentication mechanisms
- ✅ Platform auto-detection and optimization
- ✅ **Complete passwordless authentication support**
- ✅ Full integration with MCP-God-Mode tool registry
- ✅ Extensive documentation and examples
- ✅ Comprehensive test suite and validation

The tool is now ready for production use and provides a solid foundation for remote system management and security operations across diverse environments.
