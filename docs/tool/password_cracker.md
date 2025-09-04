# 🔐 Password Cracker Tool - MCP God Mode

## Overview
The **Password Cracker Tool** (`mcp_mcp-god-mode_password_cracker`) is an advanced authentication testing framework designed for authorized corporate security assessments. It provides comprehensive password strength testing and authentication mechanism evaluation across SSH, FTP, RDP, SMB, HTTP, and database services on Windows, Linux, macOS, Android, and iOS platforms.

## Functionality
- **Multi-Protocol Testing**: Support for SSH, FTP, RDP, SMB, HTTP, and database authentication
- **Dictionary Attacks**: Efficient wordlist-based password testing
- **Brute Force Testing**: Systematic password generation and testing
- **Hybrid Methods**: Combination of dictionary and brute force approaches
- **Rainbow Table Attacks**: Pre-computed hash table utilization
- **Cross-Platform Support**: Native implementation across all supported operating systems

## Technical Details

### Tool Identifier
- **MCP Tool Name**: `mcp_mcp-god-mode_password_cracker`
- **Category**: Security & Penetration Testing
- **Platform Support**: Windows, Linux, macOS, Android, iOS
- **Elevated Permissions**: Required for system-level authentication testing

### Input Parameters
```typescript
{
  target: string,        // Target system or service to test
  service: "ssh" | "ftp" | "rdp" | "smb" | "http" | "database", // Service type
  username?: string,     // Username to test (or username list)
  password_list?: string[], // Custom password list
  attack_type: "dictionary" | "brute_force" | "hybrid" | "rainbow_table", // Attack method
  max_attempts?: number, // Maximum password attempts
  timeout?: number,      // Connection timeout in milliseconds
  rate_limit?: number,   // Attempts per second limit
  wordlist_path?: string // Path to custom wordlist file
}
```

### Output Response
```typescript
{
  target: string,        // Tested target
  service: string,       // Tested service
  attack_type: string,   // Attack method used
  start_time: string,    // Test start timestamp
  end_time: string,      // Test completion timestamp
  results: {
    successful_credentials?: {
      username: string,  // Successful username
      password: string,  // Successful password
      service: string,   // Service where successful
      timestamp: string  // Discovery timestamp
    },
    tested_combinations: number, // Total combinations tested
    successful_attempts: number, // Number of successful logins
    failed_attempts: number,     // Number of failed attempts
    blocked_attempts: number     // Number of blocked attempts
  },
  security_assessment: {
    password_strength: "weak" | "medium" | "strong" | "very_strong",
    common_vulnerabilities: string[], // Identified security issues
    recommendations: string[],        // Security improvement suggestions
    risk_score: number               // Overall risk score (0-100)
  },
  audit_log: {
    attempts: Array<{
      username: string,
      password: string,
      result: "success" | "failure" | "blocked",
      timestamp: string,
      response_time: number
    }>
  }
}
```

## Usage Examples

### SSH Password Testing
```typescript
const sshTest = await password_cracker({
  target: "192.168.1.100",
  service: "ssh",
  username: "admin",
  attack_type: "dictionary",
  password_list: ["admin", "password", "123456", "admin123"],
  max_attempts: 100,
  rate_limit: 10
});

if (sshTest.results.successful_credentials) {
  console.log("SSH access gained:", sshTest.results.successful_credentials);
}
```

### Web Application Testing
```typescript
const webTest = await password_cracker({
  target: "https://webapp.company.com",
  service: "http",
  username: "admin",
  attack_type: "hybrid",
  max_attempts: 1000,
  timeout: 5000,
  rate_limit: 5
});

console.log("Security Assessment:", webTest.security_assessment);
console.log("Risk Score:", webTest.security_assessment.risk_score);
```

### Database Authentication Testing
```typescript
const dbTest = await password_cracker({
  target: "database.company.com:3306",
  service: "database",
  username: "root",
  attack_type: "brute_force",
  max_attempts: 500,
  rate_limit: 20
});

// Analyze security posture
const vulnerabilities = dbTest.security_assessment.common_vulnerabilities;
vulnerabilities.forEach(vuln => console.log("Vulnerability:", vuln));
```

## Integration Points

### Server Integration
- **Full Server**: ✅ Included
- **Modular Server**: ✅ Included  
- **Minimal Server**: ❌ Not included
- **Ultra-Minimal Server**: ❌ Not included

### Dependencies
- Platform-specific authentication tools
- Custom wordlists and dictionaries
- Rainbow table databases
- Elevated permissions for system access

## Platform-Specific Features

### Windows
- **RDP Testing**: Remote Desktop Protocol authentication
- **SMB Testing**: Windows file sharing authentication
- **Active Directory**: AD user account testing
- **Windows Services**: Service account authentication

### Linux
- **SSH Testing**: Secure Shell authentication
- **FTP Testing**: File Transfer Protocol authentication
- **Database Testing**: MySQL, PostgreSQL, MongoDB
- **Service Accounts**: System service authentication

### macOS
- **SSH Testing**: macOS SSH service authentication
- **File Sharing**: AFP and SMB authentication
- **System Services**: macOS service authentication
- **User Accounts**: Local user authentication

### Mobile Platforms
- **Android Services**: Android service authentication
- **iOS Services**: iOS service authentication
- **Mobile Apps**: Application authentication testing
- **Network Services**: Mobile network authentication

## Attack Methodologies

### Dictionary Attacks
- **Common Passwords**: Standard password lists
- **Custom Wordlists**: Organization-specific passwords
- **Pattern Matching**: Username-based variations
- **Language-Specific**: Localized password lists

### Brute Force Attacks
- **Character Sets**: Alphanumeric combinations
- **Length Variations**: Different password lengths
- **Pattern Generation**: Systematic password creation
- **Smart Brute Force**: Context-aware generation

### Hybrid Attacks
- **Dictionary + Brute Force**: Combined approach
- **Username Variations**: Username-based modifications
- **Common Patterns**: Known password patterns
- **Contextual Guessing**: Environment-specific passwords

### Rainbow Table Attacks
- **Pre-computed Hashes**: Hash table utilization
- **Hash Types**: MD5, SHA1, SHA256 support
- **Salt Handling**: Salted hash processing
- **Collision Detection**: Hash collision identification

## Security Features

### Safe Mode Operations
- **Non-Intrusive Testing**: Safe authentication testing
- **Rate Limiting**: Configurable attempt rates
- **Permission Verification**: Automatic authorization checks
- **Audit Logging**: Complete testing activity recording

### Risk Management
- **Attempt Limits**: Configurable maximum attempts
- **Timeout Controls**: Connection timeout management
- **Block Detection**: Account lockout detection
- **Graceful Degradation**: Safe fallback mechanisms

## Authentication Protocols

### SSH (Secure Shell)
- **Password Authentication**: Standard password login
- **Public Key Authentication**: Key-based authentication
- **Two-Factor Authentication**: 2FA support
- **Brute Force Protection**: Fail2ban integration

### FTP (File Transfer Protocol)
- **Standard FTP**: Basic FTP authentication
- **FTPS**: FTP over SSL/TLS
- **SFTP**: SSH File Transfer Protocol
- **Anonymous Access**: Anonymous login testing

### RDP (Remote Desktop Protocol)
- **Windows Authentication**: Windows domain authentication
- **Local Accounts**: Local user authentication
- **Network Level Authentication**: NLA support
- **Credential Security**: Credential manager integration

### SMB (Server Message Block)
- **Windows File Sharing**: Windows file system access
- **Domain Authentication**: Active Directory integration
- **Local Authentication**: Local user access
- **Guest Access**: Anonymous access testing

### HTTP/HTTPS
- **Basic Authentication**: HTTP basic auth
- **Form Authentication**: Web form login
- **Session Management**: Cookie and session testing
- **API Authentication**: REST API authentication

### Database Services
- **MySQL**: MySQL authentication
- **PostgreSQL**: PostgreSQL authentication
- **MongoDB**: MongoDB authentication
- **SQL Server**: Microsoft SQL Server authentication

## Error Handling

### Common Issues
- **Account Lockout**: Account temporarily locked
- **Rate Limiting**: Service rate limiting
- **Connection Failures**: Network connectivity issues
- **Permission Denied**: Insufficient access permissions

### Recovery Actions
- Automatic retry with delays
- Alternative authentication methods
- Graceful degradation of features
- Comprehensive error reporting

## Performance Characteristics

### Testing Speed
- **Dictionary Attack**: 100-1000 attempts/second
- **Brute Force**: 10-100 attempts/second
- **Hybrid Attack**: 50-500 attempts/second
- **Rainbow Table**: 1000+ attempts/second

### Resource Usage
- **CPU**: Moderate (20-40% during active testing)
- **Memory**: Low to moderate (20-100MB)
- **Network**: Variable based on target and rate
- **Disk**: Minimal (logging and temporary files)

## Monitoring and Compliance

### Audit Requirements
- **Attempt Logging**: Complete authentication attempt recording
- **Success Tracking**: Successful authentication logging
- **Failure Analysis**: Failed attempt analysis
- **Compliance Reporting**: Automated compliance documentation

### Compliance Standards
- **PCI DSS**: Payment card industry compliance
- **SOX**: Sarbanes-Oxley compliance
- **HIPAA**: Healthcare information protection
- **ISO 27001**: Information security management

## Troubleshooting

### Testing Failures
1. Verify target accessibility
2. Check authentication permissions
3. Review rate limiting settings
4. Confirm authorization status

### Performance Issues
1. Adjust rate limiting parameters
2. Optimize wordlist selection
3. Monitor network performance
4. Use appropriate attack types

## Best Practices

### Implementation
- Always obtain proper authorization
- Use appropriate testing methods
- Implement proper rate limiting
- Log all testing activities

### Security
- Validate target authorization
- Use least privilege principles
- Monitor for unauthorized access
- Regular security assessments

## Related Tools
- **Port Scanner**: Service enumeration and discovery
- **Vulnerability Scanner**: Comprehensive security assessment
- **Exploit Framework**: Vulnerability testing and exploitation
- **Packet Sniffer**: Network traffic analysis
- **Network Diagnostics**: Connectivity and performance testing

## Version History
- **v1.0**: Initial implementation
- **v1.1**: Enhanced protocol support
- **v1.2**: Advanced attack methodologies
- **v1.3**: Cross-platform improvements
- **v1.4**: Professional security features

---

**⚠️ IMPORTANT: This tool is designed for authorized corporate security testing only. Always obtain proper authorization before testing any systems.**

*This document is part of MCP God Mode v1.4 - Advanced AI Agent Toolkit*
