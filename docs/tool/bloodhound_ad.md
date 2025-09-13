# BloodHound AD Tool

## Overview
The **BloodHound AD Tool** is an advanced BloodHound Active Directory attack path analysis and enumeration tool. It provides comprehensive AD reconnaissance capabilities including user enumeration, group analysis, privilege escalation paths, lateral movement opportunities, and attack path visualization.

## Features
- **AD Reconnaissance**: Comprehensive Active Directory enumeration
- **Attack Path Analysis**: Identify privilege escalation and lateral movement paths
- **User Enumeration**: Detailed user account analysis
- **Group Analysis**: Security group and permission analysis
- **Privilege Escalation**: Identify privilege escalation opportunities
- **Lateral Movement**: Discover lateral movement paths
- **Attack Path Visualization**: Visual representation of attack paths
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Natural Language**: Conversational interface for AD operations

## Usage

### AD Reconnaissance
```bash
# Start BloodHound
{
  "action": "start_bloodhound",
  "neo4j_host": "localhost",
  "neo4j_port": 7687,
  "neo4j_user": "neo4j",
  "neo4j_password": "password"
}

# Connect to Neo4j
{
  "action": "connect_neo4j",
  "neo4j_host": "localhost",
  "neo4j_port": 7687,
  "neo4j_user": "neo4j",
  "neo4j_password": "password"
}
```

### Data Collection
```bash
# Collect AD data
{
  "action": "collect_data",
  "domain": "example.com",
  "username": "user@example.com",
  "password": "password",
  "dc_ip": "192.168.1.10",
  "collection_method": "sharphound"
}

# Collect data with PowerShell
{
  "action": "collect_data",
  "domain": "example.com",
  "username": "user@example.com",
  "password": "password",
  "dc_ip": "192.168.1.10",
  "collection_method": "powershell"
}
```

### Attack Path Analysis
```bash
# Analyze attack paths
{
  "action": "analyze_paths",
  "domain": "example.com",
  "query_type": "prebuilt"
}

# Find shortest path
{
  "action": "find_shortest_path",
  "domain": "example.com",
  "source": "user1",
  "target": "domain_admin"
}

# Find all paths
{
  "action": "find_all_paths",
  "domain": "example.com",
  "source": "user1",
  "target": "domain_admin"
}
```

### High Value Target Analysis
```bash
# Find high value targets
{
  "action": "find_high_value_targets",
  "domain": "example.com"
}

# Analyze Kerberoastable accounts
{
  "action": "analyze_kerberoastable",
  "domain": "example.com"
}

# Analyze ASREPRoastable accounts
{
  "action": "analyze_asreproastable",
  "domain": "example.com"
}
```

### Delegation Analysis
```bash
# Analyze unconstrained delegation
{
  "action": "analyze_unconstrained_delegation",
  "domain": "example.com"
}

# Analyze constrained delegation
{
  "action": "analyze_constrained_delegation",
  "domain": "example.com"
}
```

### Privilege Analysis
```bash
# Analyze DCSync privileges
{
  "action": "analyze_dcsync",
  "domain": "example.com"
}

# Analyze GPO abuse
{
  "action": "analyze_gpo_abuse",
  "domain": "example.com"
}

# Analyze ACL abuse
{
  "action": "analyze_acl_abuse",
  "domain": "example.com"
}
```

### Session Analysis
```bash
# Analyze active sessions
{
  "action": "analyze_sessions",
  "domain": "example.com"
}

# Analyze logged on users
{
  "action": "analyze_logged_on",
  "domain": "example.com"
}
```

### Access Analysis
```bash
# Analyze RDP access
{
  "action": "analyze_rdp_access",
  "domain": "example.com"
}

# Analyze PowerShell remote access
{
  "action": "analyze_psremote_access",
  "domain": "example.com"
}

# Analyze SQL admin access
{
  "action": "analyze_sql_admin",
  "domain": "example.com"
}
```

### Permission Analysis
```bash
# Analyze force change password
{
  "action": "analyze_force_change_password",
  "domain": "example.com"
}

# Analyze add member permissions
{
  "action": "analyze_add_member",
  "domain": "example.com"
}

# Analyze generic all permissions
{
  "action": "analyze_generic_all",
  "domain": "example.com"
}
```

### Custom Queries
```bash
# Execute custom Cypher query
{
  "action": "custom_query",
  "domain": "example.com",
  "query_type": "cypher",
  "cypher_query": "MATCH (u:User) RETURN u.name, u.enabled LIMIT 10"
}
```

### Reporting
```bash
# Generate report
{
  "action": "generate_report",
  "domain": "example.com",
  "output_format": "html"
}

# Export data
{
  "action": "export_data",
  "domain": "example.com",
  "output_format": "json"
}
```

## Parameters

### Connection Parameters
- **neo4j_host**: Neo4j database host
- **neo4j_port**: Neo4j database port
- **neo4j_user**: Neo4j username
- **neo4j_password**: Neo4j password

### Data Collection Parameters
- **domain**: Target domain for analysis
- **username**: Username for data collection
- **password**: Password for data collection
- **dc_ip**: Domain controller IP address
- **collection_method**: Data collection method (sharphound, bloodhound_python, powershell)

### Analysis Parameters
- **query_type**: Query type (cypher, prebuilt, custom)
- **cypher_query**: Custom Cypher query
- **output_format**: Output format (json, csv, html, pdf)

### Safety Parameters
- **safe_mode**: Enable safe mode to prevent actual data collection
- **verbose**: Enable verbose output

## Output Format
```json
{
  "success": true,
  "action": "analyze_paths",
  "domain": "example.com",
  "result": {
    "attack_paths": [
      {
        "path_id": "path_001",
        "source": "user1",
        "target": "domain_admin",
        "steps": [
          {
            "step": 1,
            "from": "user1",
            "to": "group1",
            "relationship": "MemberOf"
          },
          {
            "step": 2,
            "from": "group1",
            "to": "domain_admin",
            "relationship": "AdminTo"
          }
        ],
        "total_steps": 2,
        "risk_level": "high"
      }
    ],
    "total_paths": 1,
    "analysis_time": "00:00:15"
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

### Example 1: Basic AD Analysis
```bash
# Start BloodHound and analyze domain
{
  "action": "start_bloodhound",
  "neo4j_host": "localhost",
  "neo4j_port": 7687,
  "neo4j_user": "neo4j",
  "neo4j_password": "password"
}

# Result
{
  "success": true,
  "message": "BloodHound started successfully",
  "neo4j_connection": "connected"
}
```

### Example 2: Attack Path Analysis
```bash
# Find attack paths
{
  "action": "find_shortest_path",
  "domain": "example.com",
  "source": "user1",
  "target": "domain_admin"
}

# Result
{
  "success": true,
  "result": {
    "shortest_path": {
      "steps": 2,
      "path": ["user1", "group1", "domain_admin"],
      "risk_level": "high"
    }
  }
}
```

## Error Handling
- **Connection Errors**: Proper handling of Neo4j connection issues
- **Authentication Errors**: Secure handling of authentication failures
- **Query Errors**: Robust error handling for query failures
- **Data Collection Errors**: Safe handling of data collection issues

## Related Tools
- **AD Security**: Active Directory security tools
- **Penetration Testing**: Penetration testing tools
- **Network Security**: Network security analysis tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the BloodHound AD Tool, please refer to the main MCP God Mode documentation or contact the development team.

## Legal Notice
This tool is designed for authorized security testing and research only. Users must ensure they have proper authorization before using any AD analysis capabilities. Unauthorized use may violate laws and regulations.
