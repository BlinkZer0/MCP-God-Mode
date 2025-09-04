# 🏥 Health Check Tool - MCP God Mode

## Overview
The **Health Check Tool** (`mcp_mcp-god-mode_health`) is a comprehensive system health monitoring utility that provides cross-platform health assessment capabilities across Windows, Linux, macOS, Android, and iOS platforms. It supports system health monitoring, performance analysis, resource assessment, and professional health diagnostics with comprehensive reporting and alerting capabilities.

## Functionality
- **System Health Monitoring**: Real-time system health assessment
- **Performance Analysis**: System performance and resource analysis
- **Resource Assessment**: CPU, memory, storage, and network health
- **Cross-Platform Support**: Native implementation across all supported operating systems
- **Advanced Features**: Health scoring, trend analysis, and predictive health monitoring
- **Professional Reporting**: Comprehensive health reports and recommendations

## Technical Details

### Tool Identifier
- **MCP Tool Name**: `mcp_mcp-god-mode_health`
- **Category**: System & Health Monitoring
- **Platform Support**: Windows, Linux, macOS, Android, iOS
- **Elevated Permissions**: Not required for basic health checks

### Input Parameters
```typescript
{
  // No input parameters required - tool provides comprehensive health assessment
}
```

### Output Response
```typescript
{
  status: "success" | "error" | "partial",
  timestamp: string,        // Health check timestamp
  platform: string,         // Detected platform
  results: {
    // Overall Health Score
    health_score: number,   // Overall health score (0-100)
    health_status: "excellent" | "good" | "fair" | "poor" | "critical",
    
    // System Health Metrics
    system_health: {
      cpu_health: number,   // CPU health score (0-100)
      memory_health: number, // Memory health score (0-100)
      storage_health: number, // Storage health score (0-100)
      network_health: number, // Network health score (0-100)
      overall_health: number  // Overall system health score
    },
    
    // Performance Metrics
    performance: {
      cpu_usage: number,    // Current CPU usage percentage
      memory_usage: number, // Current memory usage percentage
      disk_usage: number,   // Current disk usage percentage
      network_latency: number, // Network latency in milliseconds
      response_time: number // System response time in milliseconds
    },
    
    // Resource Status
    resources: {
      cpu: {
        cores: number,      // Number of CPU cores
        threads: number,    // Number of CPU threads
        temperature?: number, // CPU temperature (if available)
        frequency: number,  // Current CPU frequency
        load_average: number // System load average
      },
      memory: {
        total: number,      // Total RAM in bytes
        available: number,  // Available RAM in bytes
        used: number,       // Used RAM in bytes
        free: number,       // Free RAM in bytes
        swap_total: number, // Total swap space
        swap_used: number   // Used swap space
      },
      storage: {
        drives: Array<{
          device: string,   // Drive device name
          mountpoint: string, // Drive mount point
          filesystem: string, // File system type
          total: number,    // Total space in bytes
          used: number,     // Used space in bytes
          free: number,     // Free space in bytes
          health_status: string, // Drive health status
          temperature?: number   // Drive temperature (if available)
        }>
      },
      network: {
        interfaces: Array<{
          name: string,     // Interface name
          status: string,   // Interface status
          speed: number,    // Interface speed in Mbps
          errors: number,   // Interface error count
          dropped: number   // Dropped packet count
        }>,
        connectivity: {
          internet: boolean, // Internet connectivity status
          dns: boolean,     // DNS resolution status
          latency: number   // Network latency in ms
        }
      }
    },
    
    // Health Alerts
    alerts: Array<{
      level: "info" | "warning" | "error" | "critical",
      category: string,     // Alert category
      message: string,      // Alert message
      recommendation: string, // Recommended action
      timestamp: string     // Alert timestamp
    }>,
    
    // Health Trends
    trends: {
      cpu_trend: "improving" | "stable" | "declining",
      memory_trend: "improving" | "stable" | "declining",
      storage_trend: "improving" | "stable" | "declining",
      network_trend: "improving" | "stable" | "declining"
    }
  },
  error?: string,           // Error message if health check failed
  warnings?: string[],      // Warning messages
  execution_time?: number   // Health check execution time in milliseconds
}
```

## Usage Examples

### Basic Health Check
```typescript
const healthCheck = await health();

if (healthCheck.status === "success") {
  const results = healthCheck.results;
  
  console.log(`System Health: ${results.health_status.toUpperCase()}`);
  console.log(`Health Score: ${results.health_score}/100`);
  console.log(`CPU Health: ${results.system_health.cpu_health}/100`);
  console.log(`Memory Health: ${results.system_health.memory_health}/100`);
  console.log(`Storage Health: ${results.system_health.storage_health}/100`);
}
```

### Performance Monitoring
```typescript
const performanceCheck = await health();

if (performanceCheck.status === "success") {
  const perf = performanceCheck.results?.performance;
  
  console.log("Performance Metrics:");
  console.log(`CPU Usage: ${perf?.cpu_usage?.toFixed(2)}%`);
  console.log(`Memory Usage: ${perf?.memory_usage?.toFixed(2)}%`);
  console.log(`Disk Usage: ${perf?.disk_usage?.toFixed(2)}%`);
  console.log(`Network Latency: ${perf?.network_latency}ms`);
  console.log(`Response Time: ${perf?.response_time}ms`);
}
```

### Resource Health Analysis
```typescript
const resourceCheck = await health();

if (resourceCheck.status === "success") {
  const resources = resourceCheck.results?.resources;
  
  // CPU Analysis
  const cpu = resources?.cpu;
  console.log(`CPU Cores: ${cpu?.cores}, Threads: ${cpu?.threads}`);
  console.log(`Load Average: ${cpu?.load_average?.toFixed(2)}`);
  
  // Memory Analysis
  const memory = resources?.memory;
  const memoryGB = (memory?.total / (1024**3)).toFixed(2);
  const usedGB = (memory?.used / (1024**3)).toFixed(2);
  console.log(`Memory: ${usedGB}GB / ${memoryGB}GB`);
  
  // Storage Analysis
  const storage = resources?.storage;
  storage?.drives?.forEach(drive => {
    const totalGB = (drive.total / (1024**3)).toFixed(2);
    const usedGB = (drive.used / (1024**3)).toFixed(2);
    console.log(`${drive.device}: ${usedGB}GB / ${totalGB}GB (${drive.health_status})`);
  });
}
```

### Health Alerts and Recommendations
```typescript
const alertCheck = await health();

if (alertCheck.status === "success") {
  const alerts = alertCheck.results?.alerts;
  
  if (alerts && alerts.length > 0) {
    console.log("Health Alerts:");
    alerts.forEach(alert => {
      const icon = {
        info: "ℹ️",
        warning: "⚠️",
        error: "❌",
        critical: "🚨"
      }[alert.level];
      
      console.log(`${icon} ${alert.level.toUpperCase()}: ${alert.message}`);
      console.log(`   Recommendation: ${alert.recommendation}`);
    });
  } else {
    console.log("✅ No health alerts - system is healthy!");
  }
}
```

## Integration Points

### Server Integration
- **Full Server**: ✅ Included
- **Modular Server**: ❌ Not included
- **Minimal Server**: ✅ Included
- **Ultra-Minimal Server**: ✅ Included

### Dependencies
- Native system monitoring libraries
- Platform-specific health APIs
- Performance monitoring tools
- Health assessment frameworks

## Platform-Specific Features

### Windows
- **Windows Performance**: Windows Performance Counters
- **Event Logs**: Windows Event Log integration
- **System Health**: Windows System Health monitoring
- **Resource Monitor**: Windows Resource Monitor integration

### Linux
- **Proc Filesystem**: /proc filesystem health data
- **Sysfs Integration**: /sys filesystem health information
- **Systemd Health**: systemd health monitoring
- **SMART Data**: S.M.A.R.T. drive health data

### macOS
- **macOS Health**: macOS system health frameworks
- **Activity Monitor**: Activity Monitor integration
- **System Profiler**: System profiler health data
- **Diagnostic Reports**: macOS diagnostic reports

### Mobile Platforms
- **Mobile Health**: Mobile platform health APIs
- **Battery Health**: Battery health monitoring
- **Device Health**: Device health information
- **Performance Metrics**: Mobile performance metrics

## Health Monitoring Features

### System Health Assessment
- **Health Scoring**: Comprehensive health scoring system
- **Performance Metrics**: Real-time performance monitoring
- **Resource Analysis**: Resource health analysis
- **Trend Analysis**: Health trend monitoring

### Health Categories
- **CPU Health**: Processor performance and health
- **Memory Health**: RAM usage and health
- **Storage Health**: Disk health and performance
- **Network Health**: Network connectivity and performance

### Alert System
- **Health Alerts**: Automated health alerts
- **Warning Levels**: Multiple alert severity levels
- **Recommendations**: Actionable health recommendations
- **Trend Monitoring**: Health trend analysis

## Security Features

### Health Data Security
- **Data Privacy**: Health data privacy protection
- **Access Control**: Health data access control
- **Audit Logging**: Health check audit logging
- **Secure Transmission**: Secure health data transmission

### Monitoring Security
- **Secure Monitoring**: Secure health monitoring
- **Permission Validation**: Health check permission validation
- **Data Validation**: Health data validation
- **Security Auditing**: Health monitoring security audits

## Error Handling

### Common Issues
- **Permission Denied**: Insufficient monitoring permissions
- **Platform Detection**: Platform detection failures
- **API Errors**: Health monitoring API errors
- **Resource Limitations**: System resource limitations

### Recovery Actions
- Automatic retry mechanisms
- Alternative monitoring methods
- Fallback health checks
- Comprehensive error reporting

## Performance Characteristics

### Health Check Speed
- **Basic Check**: < 100ms for basic health assessment
- **Detailed Check**: 100ms - 1 second for detailed analysis
- **Full Scan**: 1-5 seconds for comprehensive health scan
- **Trend Analysis**: 5-30 seconds for trend analysis

### Resource Usage
- **CPU**: Low (1-15% during health checks)
- **Memory**: Low (10-100MB)
- **Network**: Minimal (local monitoring only)
- **Disk**: Low (temporary storage only)

## Monitoring and Logging

### Health Monitoring
- **Real-time Monitoring**: Real-time health monitoring
- **Performance Tracking**: Health performance tracking
- **Alert Management**: Health alert management
- **Trend Analysis**: Health trend analysis

### Health Logging
- **Health Logging**: Health check logging
- **Performance Logging**: Health performance logging
- **Alert Logging**: Health alert logging
- **Trend Logging**: Health trend logging

## Troubleshooting

### Health Check Issues
1. Verify monitoring permissions
2. Check platform compatibility
3. Review API availability
4. Confirm system resources

### Performance Issues
1. Monitor system resources
2. Optimize health checks
3. Use appropriate APIs
4. Monitor check performance

## Best Practices

### Implementation
- Use appropriate permission levels
- Implement proper error handling
- Validate health data
- Monitor health check performance

### Security
- Minimize elevated privilege usage
- Validate health data sources
- Implement access controls
- Monitor for suspicious activity

## Related Tools
- **System Info**: System information and monitoring
- **Process Management**: Process and service management
- **File Operations**: File system operations
- **Network Tools**: Network connectivity and management

## Version History
- **v1.0**: Initial implementation
- **v1.1**: Enhanced health monitoring
- **v1.2**: Advanced performance analysis
- **v1.3**: Cross-platform improvements
- **v1.4**: Professional health monitoring features

---

**⚠️ IMPORTANT: Health monitoring can reveal sensitive system information. Always use appropriate security measures and access controls.**

*This document is part of MCP God Mode v1.4 - Advanced AI Agent Toolkit*
