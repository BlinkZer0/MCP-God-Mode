# Crime Reporter Unified Tool

## Overview
The **Crime Reporter Unified Tool** is a comprehensive crime reporting system that provides natural language processing, jurisdiction resolution, case preparation, automated filing, and configuration testing. It includes privacy protection, audit logging, and legal compliance features.

## Features
- **Natural Language Processing**: Convert conversational commands into structured crime reports
- **Jurisdiction Resolution**: Automatically identify the correct law enforcement agency
- **Case Preparation**: Generate properly formatted crime reports
- **Automated Filing**: Submit reports to appropriate agencies
- **Privacy Protection**: Anonymous reporting capabilities with data protection
- **Audit Logging**: Complete audit trail for legal compliance
- **Legal Compliance**: Built-in legal warnings and compliance checks

## Usage

### Natural Language Commands
```bash
# Report a theft with photos
"Report a theft in Minneapolis with these photos, anonymously"

# Report cybercrime
"File a cybercrime report for identity theft in California"

# Report with specific details
"Report a burglary at 123 Main St, New York, with witness statements"
```

### Structured Commands
```bash
# Search for jurisdiction
{
  "command": "searchJurisdiction",
  "parameters": {
    "location": "Minneapolis, MN",
    "crimeType": "theft"
  }
}

# Prepare report
{
  "command": "prepareReport",
  "parameters": {
    "crimeType": "theft",
    "location": "Minneapolis, MN",
    "description": "Stolen laptop from coffee shop",
    "anonymous": true
  }
}

# File report
{
  "command": "fileReport",
  "parameters": {
    "reportId": "CR-2025-001",
    "jurisdiction": "Minneapolis Police Department"
  }
}
```

## Parameters

### Natural Language Processing
- **naturalLanguageCommand**: Conversational command for crime reporting
- **mode**: Operation mode (command, natural_language, test)

### Structured Commands
- **command**: Specific command to execute
- **parameters**: Command-specific parameters

## Output Format
```json
{
  "success": true,
  "reportId": "CR-2025-001",
  "jurisdiction": {
    "name": "Minneapolis Police Department",
    "type": "local",
    "contact": "311",
    "website": "https://www.minneapolismn.gov/police",
    "forms": ["Online Report", "Phone Report"]
  },
  "legalCompliance": {
    "privacyProtected": true,
    "anonymousReporting": true,
    "auditTrail": true,
    "legalWarnings": ["Report must be truthful", "False reports are illegal"]
  },
  "auditLog": ["Report created", "Jurisdiction identified", "Privacy protection applied"]
}
```

## Legal Compliance
- **Privacy Protection**: All personal data is protected and anonymized
- **Audit Trail**: Complete logging of all operations
- **Legal Warnings**: Built-in warnings about false reporting
- **Anonymous Reporting**: Support for anonymous crime reporting
- **Jurisdiction Compliance**: Ensures reports go to correct agencies

## Security Features
- **Data Encryption**: All sensitive data is encrypted
- **Access Control**: Restricted access to crime reporting functions
- **Audit Logging**: Complete audit trail for compliance
- **Privacy Protection**: Automatic anonymization of personal data

## Cross-Platform Support
- **Windows**: Full support with native integration
- **Linux**: Complete functionality
- **macOS**: Full feature support
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Anonymous Theft Report
```bash
# Natural language command
"Report a stolen bicycle from downtown Minneapolis, anonymously"

# Result
{
  "success": true,
  "reportId": "CR-2025-002",
  "jurisdiction": "Minneapolis Police Department",
  "anonymous": true,
  "status": "submitted"
}
```

### Example 2: Cybercrime Report
```bash
# Structured command
{
  "command": "prepareReport",
  "parameters": {
    "crimeType": "cybercrime",
    "subtype": "identity_theft",
    "location": "California",
    "description": "Unauthorized credit card charges",
    "evidence": ["bank_statements.pdf", "fraud_alerts.txt"]
  }
}
```

## Error Handling
- **Invalid Commands**: Clear error messages for invalid inputs
- **Jurisdiction Errors**: Fallback options for jurisdiction resolution
- **Filing Errors**: Retry mechanisms for failed submissions
- **Privacy Errors**: Automatic data protection enforcement

## Related Tools
- **Legal Compliance Manager**: Legal framework compliance
- **Audit Logger**: Comprehensive audit trail management
- **Privacy Protection**: Data anonymization and protection

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Crime Reporter Unified Tool, please refer to the main MCP God Mode documentation or contact the development team.
