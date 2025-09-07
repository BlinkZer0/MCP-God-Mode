# Legal Compliance & Forensic Readiness

MCP God Mode includes comprehensive legal compliance and forensic readiness capabilities designed to meet enterprise and legal requirements for audit logging, evidence preservation, legal hold management, and chain of custody tracking.

## 🔒 Overview

The legal compliance system provides:

- **Audit Logging**: Comprehensive logging of all system activities
- **Evidence Preservation**: Automated preservation of digital evidence with integrity verification
- **Legal Hold Management**: Creation and management of legal holds for litigation
- **Chain of Custody**: Complete tracking of evidence handling and transfers
- **Data Integrity**: Verification and protection of data integrity
- **Compliance Frameworks**: Support for SOX, HIPAA, GDPR, PCI DSS, and ISO 27001

## ⚙️ Configuration

### Environment Variables

Legal compliance is **disabled by default** and can be enabled through environment variables. Copy the template file and configure as needed:

```bash
cp dev/legal-compliance.env.template .env
```

### Quick Start

To enable basic legal compliance:

```bash
# Enable legal compliance system
LEGAL_COMPLIANCE_ENABLED=true

# Enable audit logging
AUDIT_LOGGING_ENABLED=true

# Enable evidence preservation
EVIDENCE_PRESERVATION_ENABLED=true

# Enable legal hold capabilities
LEGAL_HOLD_ENABLED=true
```

### Compliance Framework Presets

#### SOX Compliance (Financial Services)
```bash
LEGAL_COMPLIANCE_ENABLED=true
AUDIT_LOGGING_ENABLED=true
AUDIT_RETENTION_DAYS=2555  # 7 years
EVIDENCE_PRESERVATION_ENABLED=true
LEGAL_HOLD_ENABLED=true
CHAIN_OF_CUSTODY_ENABLED=true
DATA_INTEGRITY_ENABLED=true
COMPLIANCE_SOX=true
```

#### HIPAA Compliance (Healthcare)
```bash
LEGAL_COMPLIANCE_ENABLED=true
AUDIT_LOGGING_ENABLED=true
AUDIT_RETENTION_DAYS=2190  # 6 years
EVIDENCE_PRESERVATION_ENABLED=true
LEGAL_HOLD_ENABLED=true
DATA_INTEGRITY_ENABLED=true
COMPLIANCE_HIPAA=true
```

#### GDPR Compliance (EU Data Protection)
```bash
LEGAL_COMPLIANCE_ENABLED=true
AUDIT_LOGGING_ENABLED=true
AUDIT_RETENTION_DAYS=1095  # 3 years
EVIDENCE_PRESERVATION_ENABLED=true
LEGAL_HOLD_ENABLED=true
DATA_INTEGRITY_ENABLED=true
COMPLIANCE_GDPR=true
```

## 🛠️ Legal Compliance Manager Tool

The `legal_compliance_manager` tool provides programmatic access to all legal compliance features.

### Available Actions

#### System Management
- `enable_compliance` - Enable the legal compliance system
- `disable_compliance` - Disable the legal compliance system
- `configure_compliance` - Update compliance configuration
- `get_status` - Get current compliance status

#### Legal Hold Management
- `create_legal_hold` - Create a new legal hold
- `release_legal_hold` - Release an existing legal hold

#### Evidence Management
- `preserve_evidence` - Preserve digital evidence
- `verify_integrity` - Verify data integrity

#### Chain of Custody
- `record_custody` - Record chain of custody actions

#### Reporting
- `get_audit_logs` - Retrieve audit log entries
- `get_evidence_records` - Retrieve evidence records
- `get_legal_holds` - Retrieve legal hold records
- `get_chain_of_custody` - Retrieve chain of custody records

### Example Usage

#### Enable Legal Compliance
```json
{
  "action": "enable_compliance"
}
```

#### Create a Legal Hold
```json
{
  "action": "create_legal_hold",
  "caseName": "Smith vs. Company",
  "caseDescription": "Employment discrimination case",
  "createdBy": "legal@company.com",
  "affectedData": ["/data/employee_records", "/logs/hr_system"],
  "custodian": "IT Department",
  "legalBasis": "Litigation hold for pending lawsuit",
  "caseId": "CASE-2024-001"
}
```

#### Preserve Evidence
```json
{
  "action": "preserve_evidence",
  "sourcePath": "/var/log/system.log",
  "evidenceType": "log",
  "metadata": {
    "caseId": "CASE-2024-001",
    "description": "System logs for security incident"
  },
  "legalHoldIds": ["hold-12345"]
}
```

#### Record Chain of Custody
```json
{
  "action": "record_custody",
  "evidenceId": "evidence-67890",
  "custodyAction": "transferred",
  "toCustodian": "Forensic Analyst",
  "purpose": "Forensic analysis",
  "location": "Secure Lab Room 101",
  "witnesses": [
    {
      "name": "John Smith",
      "email": "john.smith@company.com"
    }
  ],
  "notes": "Evidence transferred for detailed analysis"
}
```

## 📊 Audit Logging

### Log Levels

- **Minimal**: Critical events only
- **Standard**: User actions and system events
- **Comprehensive**: All activities including data access

### Log Structure

Each audit log entry includes:

```json
{
  "id": "uuid",
  "timestamp": "2024-01-15T10:30:00Z",
  "eventType": "user_action|system_event|data_access|security_event|legal_hold|evidence_preservation",
  "severity": "low|medium|high|critical",
  "userId": "user@company.com",
  "sessionId": "session-12345",
  "toolName": "fs_read_text",
  "action": "file_read",
  "target": "/sensitive/data.txt",
  "result": "success|failure|partial",
  "details": {},
  "ipAddress": "192.168.1.100",
  "userAgent": "MCP-Client/1.0",
  "legalHoldId": "hold-12345",
  "evidenceId": "evidence-67890",
  "chainOfCustodyId": "custody-11111",
  "complianceFlags": ["sox", "audit_logging"],
  "hash": "sha256-hash",
  "signature": "digital-signature"
}
```

### Retention Policies

- **SOX**: 7 years (2555 days)
- **HIPAA**: 6 years (2190 days)
- **GDPR**: 3 years (1095 days)
- **PCI DSS**: 3 years (1095 days)
- **Custom**: Configurable

## 🗃️ Evidence Preservation

### Supported Evidence Types

- **File**: Individual files and documents
- **Data**: Database records and structured data
- **Log**: System and application logs
- **System State**: System configuration and state
- **Network Capture**: Network traffic captures
- **Memory Dump**: Memory snapshots

### Integrity Verification

All preserved evidence includes:

- **Hash Verification**: SHA-256, SHA-512, or MD5 hashes
- **Metadata**: Timestamps, user context, source information
- **Digital Signatures**: Cryptographic signatures for authenticity
- **Access Logs**: Complete audit trail of evidence access

### Storage Structure

```
legal/
├── evidence/
│   ├── evidence-12345.evidence    # Preserved evidence file
│   ├── evidence-12345.record.json # Evidence metadata
│   └── evidence-12345.hash        # Integrity hash
├── holds/
│   ├── hold-67890.json           # Legal hold record
│   └── hold-67890.notification   # Notification log
├── chain-of-custody/
│   └── custody-11111.json        # Chain of custody record
└── audit-logs/
    ├── audit-2024-01-15.jsonl    # Daily audit logs
    └── audit-2024-01-16.jsonl
```

## ⚖️ Legal Hold Management

### Legal Hold Lifecycle

1. **Creation**: Legal hold created with case details
2. **Active**: Data preservation and monitoring active
3. **Suspended**: Temporary suspension of hold
4. **Released**: Legal hold released and data can be purged
5. **Expired**: Automatic expiration based on retention policy

### Legal Hold Record

```json
{
  "id": "hold-12345",
  "caseId": "CASE-2024-001",
  "caseName": "Smith vs. Company",
  "description": "Employment discrimination case",
  "createdBy": "legal@company.com",
  "createdDate": "2024-01-15T10:30:00Z",
  "status": "active",
  "retentionPolicy": "indefinite",
  "affectedData": ["/data/employee_records"],
  "custodian": "IT Department",
  "legalBasis": "Litigation hold",
  "notificationSent": true,
  "notificationDate": "2024-01-15T10:35:00Z"
}
```

## 🔗 Chain of Custody

### Custody Actions

- **Created**: Evidence initially created
- **Transferred**: Evidence transferred between custodians
- **Accessed**: Evidence accessed for review
- **Modified**: Evidence modified (with backup)
- **Released**: Evidence released from legal hold
- **Destroyed**: Evidence destroyed (with approval)

### Chain of Custody Record

```json
{
  "id": "custody-11111",
  "evidenceId": "evidence-67890",
  "action": "transferred",
  "timestamp": "2024-01-15T14:30:00Z",
  "fromCustodian": "IT Department",
  "toCustodian": "Forensic Analyst",
  "purpose": "Forensic analysis",
  "location": "Secure Lab Room 101",
  "witnesses": [
    {
      "name": "John Smith",
      "email": "john.smith@company.com",
      "signature": "digital-signature"
    }
  ],
  "digitalSignature": "custody-signature",
  "notes": "Evidence transferred for detailed analysis",
  "legalHoldId": "hold-12345"
}
```

## 🔐 Data Integrity

### Integrity Verification

- **On Access**: Verify integrity when data is accessed
- **On Modification**: Verify integrity before and after changes
- **Backup Before Modification**: Create backup before any changes
- **Checksum Verification**: Continuous checksum verification

### Integrity Report

```json
{
  "valid": true,
  "hash": "sha256-hash-of-file",
  "error": null
}
```

## 📋 Compliance Frameworks

### Supported Frameworks

#### SOX (Sarbanes-Oxley Act)
- 7-year audit log retention
- Comprehensive audit trails
- Evidence preservation requirements
- Chain of custody tracking

#### HIPAA (Health Insurance Portability and Accountability Act)
- 6-year audit log retention
- Patient data protection
- Access logging requirements
- Data integrity verification

#### GDPR (General Data Protection Regulation)
- 3-year audit log retention
- Data subject rights
- Privacy by design
- Data minimization

#### PCI DSS (Payment Card Industry Data Security Standard)
- 3-year audit log retention
- Payment card data protection
- Access control requirements
- Regular security testing

#### ISO 27001 (Information Security Management)
- Comprehensive security controls
- Risk management
- Continuous improvement
- Management system requirements

## 🚀 Getting Started

### 1. Enable Legal Compliance

```bash
# Set environment variables
export LEGAL_COMPLIANCE_ENABLED=true
export AUDIT_LOGGING_ENABLED=true
export EVIDENCE_PRESERVATION_ENABLED=true
export LEGAL_HOLD_ENABLED=true

# Start the server
npm start
```

### 2. Verify Installation

```json
{
  "action": "get_status"
}
```

### 3. Create Your First Legal Hold

```json
{
  "action": "create_legal_hold",
  "caseName": "Test Case",
  "caseDescription": "Testing legal compliance system",
  "createdBy": "admin@company.com",
  "affectedData": ["/test/data"],
  "custodian": "IT Department",
  "legalBasis": "System testing"
}
```

## 🔧 Troubleshooting

### Common Issues

#### Legal Compliance Not Enabled
**Problem**: Legal compliance features not available
**Solution**: Ensure `LEGAL_COMPLIANCE_ENABLED=true` in environment

#### Audit Logs Not Created
**Problem**: No audit log files generated
**Solution**: Check `AUDIT_LOGGING_ENABLED=true` and directory permissions

#### Evidence Preservation Fails
**Problem**: Evidence preservation operations fail
**Solution**: Verify `EVIDENCE_PRESERVATION_PATH` exists and is writable

#### Legal Hold Creation Fails
**Problem**: Cannot create legal holds
**Solution**: Ensure `LEGAL_HOLD_ENABLED=true` and `LEGAL_HOLD_PATH` is writable

### Log Locations

- **Audit Logs**: `./legal/audit-logs/`
- **Evidence**: `./legal/evidence/`
- **Legal Holds**: `./legal/holds/`
- **Chain of Custody**: `./legal/chain-of-custody/`

### Performance Considerations

- **Audit Logging**: Minimal performance impact when enabled
- **Evidence Preservation**: Significant storage requirements
- **Data Integrity**: Moderate performance impact on file operations
- **Chain of Custody**: Minimal performance impact

## 📚 Legal Disclaimer

This legal compliance system is designed to assist with legal and regulatory requirements but does not constitute legal advice. Organizations should consult with legal counsel to ensure compliance with applicable laws and regulations.

## 🔄 Updates and Maintenance

### Regular Maintenance Tasks

1. **Audit Log Cleanup**: Automatic cleanup based on retention policies
2. **Evidence Verification**: Regular integrity verification of preserved evidence
3. **Legal Hold Review**: Regular review of active legal holds
4. **Chain of Custody Audit**: Periodic audit of chain of custody records

### Backup and Recovery

- **Configuration Backup**: Regular backup of compliance configuration
- **Evidence Backup**: Secure backup of preserved evidence
- **Audit Log Backup**: Regular backup of audit logs
- **Recovery Procedures**: Documented recovery procedures for all components

## 📞 Support

For legal compliance support:

1. Check the troubleshooting section above
2. Review the configuration template
3. Consult with your legal team
4. Contact system administrators

---

**Note**: Legal compliance features are disabled by default. Enable only when required for your specific legal or regulatory needs.
