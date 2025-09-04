# 💻 System Info Tool - MCP God Mode

## Overview
The **System Info Tool** (`mcp_mcp-god-mode_system_info`) is a comprehensive system information utility that provides cross-platform system details across Windows, Linux, macOS, Android, and iOS platforms. It supports hardware information, operating system details, performance metrics, and professional system analysis with comprehensive monitoring capabilities and security features.

## Functionality
- **Hardware Information**: CPU, memory, storage, and network details
- **Operating System**: OS version, architecture, and system details
- **Performance Metrics**: System performance and resource usage
- **Platform Detection**: Automatic platform detection and optimization
- **Cross-Platform Support**: Native implementation across all supported operating systems
- **Advanced Features**: Real-time monitoring, security analysis, and system diagnostics

## Technical Details

### Tool Identifier
- **MCP Tool Name**: `mcp_mcp-god-mode_system_info`
- **Category**: System & Information
- **Platform Support**: Windows, Linux, macOS, Android, iOS
- **Elevated Permissions**: Not required for basic system information

### Input Parameters
```typescript
{
  // No input parameters required - tool provides comprehensive system information
}
```

### Output Response
```typescript
{
  status: "success" | "error" | "partial",
  timestamp: string,        // Information timestamp
  platform: string,         // Detected platform
  results: {
    // Operating System Information
    os: {
      platform: string,     // Operating system platform
      version: string,      // OS version
      architecture: string, // System architecture
      hostname: string,     // System hostname
      uptime: number,       // System uptime in seconds
      kernel: string,       // Kernel version (Linux/macOS)
      build: string         // OS build number
    },
    
    // Hardware Information
    hardware: {
      cpu: {
        model: string,      // CPU model name
        cores: number,      // Number of CPU cores
        threads: number,    // Number of CPU threads
        speed: number,      // CPU speed in MHz
        architecture: string, // CPU architecture
        manufacturer: string  // CPU manufacturer
      },
      memory: {
        total: number,      // Total RAM in bytes
        available: number,  // Available RAM in bytes
        used: number,       // Used RAM in bytes
        free: number,       // Free RAM in bytes
        usage_percent: number // Memory usage percentage
      },
      storage: {
        drives: Array<{
          device: string,   // Drive device name
          mountpoint: string, // Drive mount point
          filesystem: string, // File system type
          total: number,    // Total space in bytes
          used: number,     // Used space in bytes
          free: number,     // Free space in bytes
          usage_percent: number // Usage percentage
        }>
      }
    },
    
    // Network Information
    network: {
      interfaces: Array<{
        name: string,       // Interface name
        type: string,       // Interface type
        address: string,    // IP address
        netmask: string,    // Subnet mask
        mac: string,        // MAC address
        status: string      // Interface status
      }>,
      hostname: string,     // Network hostname
      dns: string[],        // DNS servers
      gateway: string       // Default gateway
    },
    
    // Performance Metrics
    performance: {
      cpu_usage: number,    // Current CPU usage percentage
      memory_usage: number, // Current memory usage percentage
      disk_io: {
        read_bytes: number, // Bytes read from disk
        write_bytes: number, // Bytes written to disk
        read_ops: number,   // Read operations
        write_ops: number   // Write operations
      },
      network_io: {
        bytes_sent: number, // Bytes sent over network
        bytes_received: number, // Bytes received over network
        packets_sent: number,   // Packets sent
        packets_received: number // Packets received
      }
    },
    
    // Security Information
    security: {
      users: Array<{
        username: string,   // Username
        uid: number,        // User ID
        groups: string[],   // User groups
        home: string,       // Home directory
        shell: string       // Default shell
      }>,
      processes: number,    // Number of running processes
      services: number,     // Number of system services
      firewall_status: string // Firewall status
    }
  },
  error?: string,           // Error message if operation failed
  warnings?: string[],      // Warning messages
  execution_time?: number   // Execution time in milliseconds
}
```

## Usage Examples

### Basic System Information
```typescript
const systemInfo = await system_info();

if (systemInfo.status === "success") {
  const os = systemInfo.results?.os;
  const hardware = systemInfo.results?.hardware;
  
  console.log(`Operating System: ${os?.platform} ${os?.version}`);
  console.log(`Architecture: ${os?.architecture}`);
  console.log(`CPU: ${hardware?.cpu?.model} (${hardware?.cpu?.cores} cores)`);
  console.log(`Memory: ${(hardware?.memory?.total / (1024**3)).toFixed(2)} GB`);
}
```

### Performance Monitoring
```typescript
const performanceInfo = await system_info();

if (performanceInfo.status === "success") {
  const perf = performanceInfo.results?.performance;
  
  console.log(`CPU Usage: ${perf?.cpu_usage?.toFixed(2)}%`);
  console.log(`Memory Usage: ${perf?.memory_usage?.toFixed(2)}%`);
  console.log(`Disk I/O: ${(perf?.disk_io?.read_bytes / (1024**2)).toFixed(2)} MB read`);
  console.log(`Network I/O: ${(perf?.network_io?.bytes_sent / (1024**2)).toFixed(2)} MB sent`);
}
```

### Storage Analysis
```typescript
const storageInfo = await system_info();

if (storageInfo.status === "success") {
  const storage = systemInfo.results?.hardware?.storage;
  
  console.log("Storage Drives:");
  storage?.drives?.forEach(drive => {
    const totalGB = (drive.total / (1024**3)).toFixed(2);
    const usedGB = (drive.used / (1024**3)).toFixed(2);
    const usagePercent = drive.usage_percent?.toFixed(1);
    
    console.log(`- ${drive.device}: ${usedGB}GB / ${totalGB}GB (${usagePercent}% used)`);
  });
}
```

### Network Configuration
```typescript
const networkInfo = await system_info();

if (networkInfo.status === "success") {
  const network = systemInfo.results?.network;
  
  console.log("Network Interfaces:");
  network?.interfaces?.forEach(iface => {
    console.log(`- ${iface.name}: ${iface.address} (${iface.type})`);
  });
  
  console.log(`Hostname: ${network?.hostname}`);
  console.log(`Gateway: ${network?.gateway}`);
  console.log(`DNS Servers: ${network?.dns?.join(', ')}`);
}
```

## Integration Points

### Server Integration
- **Full Server**: ✅ Included
- **Modular Server**: ❌ Not included
- **Minimal Server**: ✅ Included
- **Ultra-Minimal Server**: ✅ Included

### Dependencies
- Native system information libraries
- Platform-specific APIs
- Performance monitoring tools
- Security analysis frameworks

## Platform-Specific Features

### Windows
- **Windows Management**: Windows Management Instrumentation (WMI)
- **Registry Access**: Windows registry information
- **Performance Counters**: Windows performance counters
- **System Services**: Windows service information

### Linux
- **Proc Filesystem**: /proc filesystem integration
- **Sysfs Integration**: /sys filesystem access
- **Systemd Support**: systemd service information
- **Package Management**: Package manager integration

### macOS
- **macOS Frameworks**: macOS system frameworks
- **System Profiler**: System profiler integration
- **Launch Services**: Launch service information
- **Keychain Access**: Keychain information access

### Mobile Platforms
- **Mobile APIs**: Mobile platform APIs
- **Device Information**: Device-specific information
- **Battery Status**: Battery and power information
- **Sensor Data**: Device sensor information

## System Information Features

### Hardware Detection
- **CPU Information**: Processor details and capabilities
- **Memory Analysis**: RAM configuration and usage
- **Storage Details**: Disk and storage information
- **Network Hardware**: Network interface details

### Operating System Details
- **Platform Detection**: Automatic platform identification
- **Version Information**: OS version and build details
- **Architecture Details**: System architecture information
- **Kernel Information**: Kernel version and details

### Performance Monitoring
- **Resource Usage**: CPU, memory, and disk usage
- **I/O Statistics**: Disk and network I/O metrics
- **Process Information**: Running process details
- **Service Status**: System service information

## Security Features

### System Security
- **User Information**: User account details
- **Permission Analysis**: File and system permissions
- **Service Security**: Service security status
- **Firewall Status**: Firewall configuration

### Access Control
- **User Management**: User account management
- **Group Information**: User group details
- **Permission Validation**: Permission verification
- **Security Auditing**: Security audit information

## Error Handling

### Common Issues
- **Permission Denied**: Insufficient access permissions
- **Platform Detection**: Platform detection failures
- **API Errors**: System API errors
- **Resource Limitations**: System resource limitations

### Recovery Actions
- Automatic retry mechanisms
- Alternative information sources
- Fallback data collection
- Comprehensive error reporting

## Performance Characteristics

### Information Collection
- **Basic Info**: < 100ms for basic system information
- **Hardware Scan**: 100ms - 1 second for hardware details
- **Performance Metrics**: 1-5 seconds for performance data
- **Full Scan**: 5-30 seconds for comprehensive information

### Resource Usage
- **CPU**: Low (1-10% during collection)
- **Memory**: Low (10-100MB)
- **Network**: Minimal (local information only)
- **Disk**: Low (temporary storage only)

## Monitoring and Logging

### System Monitoring
- **Real-time Monitoring**: Real-time system monitoring
- **Performance Tracking**: Performance metric tracking
- **Resource Monitoring**: Resource usage monitoring
- **Security Monitoring**: Security status monitoring

### Information Logging
- **System Logging**: System information logging
- **Performance Logging**: Performance data logging
- **Security Logging**: Security event logging
- **Audit Logging**: System audit logging

## Troubleshooting

### Information Issues
1. Verify system permissions
2. Check platform compatibility
3. Review API availability
4. Confirm system resources

### Performance Issues
1. Monitor system resources
2. Optimize collection methods
3. Use appropriate APIs
4. Monitor collection performance

## Best Practices

### Implementation
- Use appropriate permission levels
- Implement proper error handling
- Validate collected information
- Monitor collection performance

### Security
- Minimize elevated privilege usage
- Validate information sources
- Implement access controls
- Monitor for suspicious activity

## Related Tools
- **Health Check**: System health monitoring
- **Process Management**: Process and service management
- **File Operations**: File system operations
- **Network Tools**: Network connectivity and management

## Version History
- **v1.0**: Initial implementation
- **v1.1**: Enhanced system information
- **v1.2**: Advanced performance monitoring
- **v1.3**: Cross-platform improvements
- **v1.4**: Professional system analysis features

---

**⚠️ IMPORTANT: System information collection can reveal sensitive system details. Always use appropriate security measures and access controls.**

*This document is part of MCP God Mode v1.4 - Advanced AI Agent Toolkit*
