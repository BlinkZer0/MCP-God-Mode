# Delete Emails Tool

## Overview
The **Delete Emails Tool** is a comprehensive email deletion and management utility that provides advanced email management, deletion, and cleanup capabilities. It offers cross-platform support and enterprise-grade email management features.

## Features
- **Email Deletion**: Advanced email deletion and cleanup capabilities
- **Email Management**: Comprehensive email management and organization
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **IMAP Support**: Full IMAP server support and integration
- **Batch Operations**: Batch email deletion and management
- **Email Organization**: Email organization and folder management

## Usage

### Email Deletion
```bash
# Delete emails
{
  "imap_server": "imap.gmail.com",
  "username": "user@gmail.com",
  "password": "password123",
  "email_ids": ["email_001", "email_002", "email_003"],
  "folder": "INBOX"
}

# Delete emails permanently
{
  "imap_server": "imap.gmail.com",
  "username": "user@gmail.com",
  "password": "password123",
  "email_ids": ["email_001", "email_002"],
  "folder": "INBOX",
  "permanent": true
}
```

### Email Management
```bash
# Delete from specific folder
{
  "imap_server": "imap.gmail.com",
  "username": "user@gmail.com",
  "password": "password123",
  "email_ids": ["email_001"],
  "folder": "Sent"
}

# Delete from multiple folders
{
  "imap_server": "imap.gmail.com",
  "username": "user@gmail.com",
  "password": "password123",
  "email_ids": ["email_001", "email_002"],
  "folder": "INBOX"
}
```

### Batch Operations
```bash
# Batch delete emails
{
  "imap_server": "imap.gmail.com",
  "username": "user@gmail.com",
  "password": "password123",
  "email_ids": ["email_001", "email_002", "email_003", "email_004", "email_005"],
  "folder": "INBOX"
}

# Delete all emails in folder
{
  "imap_server": "imap.gmail.com",
  "username": "user@gmail.com",
  "password": "password123",
  "email_ids": ["all"],
  "folder": "INBOX"
}
```

## Parameters

### Email Parameters
- **imap_server**: IMAP server address
- **username**: Email username
- **password**: Email password
- **email_ids**: Array of email IDs to delete
- **folder**: Email folder containing emails
- **permanent**: Whether to permanently delete emails (bypass trash)

### Server Parameters
- **server_port**: IMAP server port (default: 993)
- **use_ssl**: Whether to use SSL connection
- **timeout**: Connection timeout in seconds

### Deletion Parameters
- **delete_mode**: Deletion mode (soft, permanent)
- **batch_size**: Number of emails to delete in batch
- **confirmation**: Whether to require confirmation for deletion

## Output Format
```json
{
  "success": true,
  "result": {
    "emails_deleted": 3,
    "emails_failed": 0,
    "deletion_mode": "soft",
    "folder": "INBOX",
    "deleted_ids": ["email_001", "email_002", "email_003"]
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows email clients
- **Linux**: Complete functionality with Linux email clients
- **macOS**: Full feature support with macOS email clients
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Delete Emails
```bash
# Delete emails
{
  "imap_server": "imap.gmail.com",
  "username": "user@gmail.com",
  "password": "password123",
  "email_ids": ["email_001", "email_002", "email_003"],
  "folder": "INBOX"
}

# Result
{
  "success": true,
  "result": {
    "emails_deleted": 3,
    "emails_failed": 0,
    "deletion_mode": "soft",
    "folder": "INBOX"
  }
}
```

### Example 2: Permanent Deletion
```bash
# Delete emails permanently
{
  "imap_server": "imap.gmail.com",
  "username": "user@gmail.com",
  "password": "password123",
  "email_ids": ["email_001", "email_002"],
  "folder": "INBOX",
  "permanent": true
}

# Result
{
  "success": true,
  "result": {
    "emails_deleted": 2,
    "emails_failed": 0,
    "deletion_mode": "permanent",
    "folder": "INBOX"
  }
}
```

### Example 3: Batch Deletion
```bash
# Batch delete emails
{
  "imap_server": "imap.gmail.com",
  "username": "user@gmail.com",
  "password": "password123",
  "email_ids": ["email_001", "email_002", "email_003", "email_004", "email_005"],
  "folder": "INBOX"
}

# Result
{
  "success": true,
  "result": {
    "emails_deleted": 5,
    "emails_failed": 0,
    "deletion_mode": "soft",
    "folder": "INBOX",
    "batch_size": 5
  }
}
```

## Error Handling
- **Connection Errors**: Proper handling of IMAP server connection issues
- **Authentication Errors**: Secure handling of email authentication failures
- **Deletion Errors**: Robust error handling for email deletion failures
- **Permission Errors**: Safe handling of email access permission problems

## Related Tools
- **Email Management**: Email management and organization tools
- **IMAP Tools**: IMAP server integration and management tools
- **Email Security**: Email security and protection tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Delete Emails Tool, please refer to the main MCP God Mode documentation or contact the development team.
