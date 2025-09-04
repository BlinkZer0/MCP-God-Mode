# 🔍 Port Scanner Tool - MCP God Mode

## Overview
The **Port Scanner Tool** (`mcp_mcp-god-mode_port_scanner`) is an advanced cross-platform network reconnaissance tool designed for authorized corporate security testing. It provides comprehensive TCP/UDP port scanning capabilities with service detection, banner grabbing, and detailed network analysis across Windows, Linux, macOS, Android, and iOS platforms.

## Functionality
- **TCP/UDP Port Scanning**: Comprehensive port range scanning with customizable options
- **Service Detection**: Automatic identification of running services and protocols
- **Banner Grabbing**: Extraction of service version and configuration information
- **Network Reconnaissance**: Detailed network topology and service mapping
- **Security Assessment**: Identification of open ports and potential vulnerabilities
- **Cross-Platform Support**: Native implementation across all supported operating systems

## Technical Details

### Tool Identifier
- **MCP Tool Name**: `mcp_mcp-god-mode_port_scanner`
- **Category**: Network Security & Penetration Testing
- **Platform Support**: Windows, Linux, macOS, Android, iOS
- **Elevated Permissions**: Required for low-level network access

### Input Parameters
```typescript
{
  target: string,        // Target IP address or hostname
  ports?: string,        // Port range (e.g., "1-1000", "80,443,8080")
  protocol?: "tcp" | "udp", // Protocol to scan (default: tcp)
  timeout?: number,      // Connection timeout in milliseconds
  scan_type?: "connect" | "syn" | "udp", // Scan methodology
  service_detection?: boolean, // Enable service detection
  banner_grabbing?: boolean,   // Enable banner grabbing
  rate_limit?: number    // Packets per second limit
}
```

### Output Response
```typescript
{
  target: string,        // Scanned target
  scan_type: string,     // Type of scan performed
  protocol: string,      // Protocol scanned
  start_time: string,    // Scan start timestamp
  end_time: string,      // Scan completion timestamp
  open_ports: Array<{
    port: number,        // Port number
    protocol: string,    // Protocol (TCP/UDP)
    service: string,     // Detected service name
    version?: string,    // Service version (if available)
    banner?: string,     // Banner information (if available)
    state: "open" | "closed" | "filtered"
  }>,
  summary: {
    total_ports: number, // Total ports scanned
    open_count: number,  // Number of open ports
    closed_count: number, // Number of closed ports
    filtered_count: number, // Number of filtered ports
    scan_duration: number // Scan duration in milliseconds
  },
  recommendations: string[] // Security recommendations
}
```

## Usage Examples

### Basic Port Scan
```typescript
const scanResult = await port_scanner({
  target: "192.168.1.1",
  ports: "1-1000",
  protocol: "tcp",
  service_detection: true
});

console.log(`Found ${scanResult.summary.open_count} open ports`);
scanResult.open_ports.forEach(port => {
  console.log(`Port ${port.port}: ${port.service} (${port.state})`);
});
```

### Web Service Enumeration
```typescript
const webScan = await port_scanner({
  target: "example.com",
  ports: "80,443,8080,8443",
  protocol: "tcp",
  service_detection: true,
  banner_grabbing: true
});

// Focus on web services
const webPorts = webScan.open_ports.filter(port => 
  port.service.includes("http") || port.service.includes("ssl")
);
```

### Network Security Assessment
```typescript
const securityScan = await port_scanner({
  target: "10.0.0.0/24", // Network range
  ports: "22,23,3389,5900", // Common admin ports
  protocol: "tcp",
  timeout: 5000,
  rate_limit: 100
});

// Identify potential security risks
const riskyPorts = securityScan.open_ports.filter(port => 
  [22, 23, 3389, 5900].includes(port.port)
);
```

## Integration Points

### Server Integration
- **Full Server**: ✅ Included
- **Modular Server**: ✅ Included  
- **Minimal Server**: ❌ Not included
- **Ultra-Minimal Server**: ❌ Not included

### Dependencies
- Platform-specific network tools (nmap, netcat, PowerShell)
- Node.js native `net` module for fallback
- Elevated permissions for low-level network access

## Platform-Specific Implementation

### Windows
- **Primary Tool**: PowerShell `Test-NetConnection`
- **Fallback**: Node.js native socket implementation
- **Features**: Windows Firewall integration, service detection
- **Limitations**: May require elevated permissions

### Linux
- **Primary Tool**: `nmap` (if available)
- **Fallback**: `netcat` and native socket implementation
- **Features**: Full nmap capabilities, SYN scanning
- **Limitations**: Requires nmap installation for advanced features

### macOS
- **Primary Tool**: Built-in network utilities
- **Fallback**: Node.js native implementation
- **Features**: BSD-compatible network tools
- **Limitations**: May require additional tools for advanced scanning

### Android
- **Primary Tool**: Native Android network APIs
- **Fallback**: Node.js mobile implementation
- **Features**: Mobile-optimized scanning
- **Limitations**: Platform restrictions, permission requirements

### iOS
- **Primary Tool**: iOS network frameworks
- **Fallback**: Node.js mobile implementation
- **Features**: iOS-optimized scanning
- **Limitations**: App Store restrictions, permission requirements

## Security Features

### Safe Mode Operations
- **Rate Limiting**: Configurable packet rate to avoid detection
- **Timeout Controls**: Prevents hanging connections
- **Permission Checks**: Automatic elevation when required
- **Audit Logging**: Complete scan activity logging

### Authorization Controls
- **Target Validation**: Ensures authorized scanning targets
- **Permission Verification**: Checks for proper authorization
- **Compliance Documentation**: Generates compliance reports
- **Risk Assessment**: Provides security recommendations

## Error Handling

### Common Issues
- **Permission Denied**: Insufficient network access permissions
- **Target Unreachable**: Network connectivity problems
- **Firewall Blocking**: Security software interference
- **Rate Limiting**: Network provider restrictions

### Recovery Actions
- Automatic permission elevation attempts
- Fallback to alternative scanning methods
- Graceful degradation of features
- Comprehensive error reporting

## Performance Characteristics

### Scan Speed
- **Fast Scan**: 1000 ports in ~30 seconds
- **Standard Scan**: 1000 ports in ~2 minutes
- **Thorough Scan**: 1000 ports in ~5 minutes
- **Stealth Scan**: Variable based on rate limiting

### Resource Usage
- **CPU**: Moderate (10-30% during active scanning)
- **Memory**: Low (< 50MB)
- **Network**: Variable based on scan intensity
- **Disk**: Minimal (logging only)

## Monitoring and Compliance

### Audit Requirements
- **Scan Logging**: Complete activity recording
- **Authorization Tracking**: Permission verification logging
- **Compliance Reporting**: Automated compliance documentation
- **Risk Assessment**: Security recommendation generation

### Compliance Standards
- **PCI DSS**: Payment card industry compliance
- **SOX**: Sarbanes-Oxley compliance
- **HIPAA**: Healthcare information protection
- **ISO 27001**: Information security management

## Troubleshooting

### Scan Failures
1. Verify target accessibility
2. Check network permissions
3. Review firewall settings
4. Confirm authorization status

### Performance Issues
1. Adjust rate limiting settings
2. Optimize port ranges
3. Use appropriate scan types
4. Monitor system resources

## Best Practices

### Implementation
- Always obtain proper authorization
- Use appropriate scan types for targets
- Implement rate limiting to avoid detection
- Log all scanning activities

### Security
- Validate target authorization
- Use least privilege principles
- Monitor for unauthorized access
- Regular security assessments

## Related Tools
- **Vulnerability Scanner**: Comprehensive security assessment
- **Packet Sniffer**: Network traffic analysis
- **Network Diagnostics**: Connectivity testing
- **Exploit Framework**: Vulnerability testing
- **Password Cracker**: Authentication testing

## Version History
- **v1.0**: Initial implementation
- **v1.1**: Enhanced service detection
- **v1.2**: Cross-platform improvements
- **v1.3**: Advanced scanning capabilities
- **v1.4a**: Professional security features

---

**⚠️ IMPORTANT: This tool is designed for authorized corporate security testing only. Always obtain proper authorization before testing any systems.**

*This document is part of MCP God Mode v1.4a - Advanced AI Agent Toolkit*
