# Delete Emails Tool

## Overview
The **Delete Emails Tool** is a comprehensive email management system that allows you to delete emails from IMAP servers across all platforms (Windows, Linux, macOS, Android, and iOS). This tool supports permanent deletion, moving emails to trash, and bulk deletion operations with proper error handling and confirmation mechanisms.

## Features
- **Cross-Platform Support**: Works on Windows, Linux, macOS, Android, and iOS
- **Multiple Email Providers**: Gmail, Outlook, Yahoo, and custom IMAP servers
- **Flexible Deletion Options**: Permanent deletion or move to trash
- **Bulk Operations**: Delete multiple emails efficiently
- **Range Support**: Delete emails by UID ranges
- **Confirmation System**: Built-in safety confirmations
- **Error Handling**: Comprehensive error handling and recovery
- **Audit Logging**: Track deletion operations for compliance

## Supported Email Services

### Gmail
- **Host**: imap.gmail.com
- **Port**: 993 (SSL)
- **Security**: SSL/TLS required
- **Authentication**: Email + App Password (if 2FA enabled)
- **Trash Folder**: [Gmail]/Trash

### Outlook/Hotmail
- **Host**: outlook.office365.com
- **Port**: 993 (SSL)
- **Security**: SSL/TLS required
- **Authentication**: Email + Password
- **Trash Folder**: Deleted Items

### Yahoo
- **Host**: imap.mail.yahoo.com
- **Port**: 993 (SSL)
- **Security**: SSL/TLS required
- **Authentication**: Email + App Password (if 2FA enabled)
- **Trash Folder**: Trash

### Custom IMAP Servers
- **Host**: Your custom IMAP server
- **Port**: 993 (SSL) or 143 (unencrypted)
- **Security**: Configurable SSL/TLS settings
- **Authentication**: Email + Password
- **Trash Folder**: Configurable


## Natural Language Access
Users can request delete emails operations using natural language:
- "Delete email messages"
- "Remove email content"
- "Clean up email inbox"
- "Purge email messages"
- "Clear email data"
## Usage Examples

### Delete Single Email
```typescript
// Delete a specific email by UID
const result = await deleteEmails({
  email_config: {
    service: "gmail",
    email: "user@gmail.com",
    password: "app_password"
  },
  email_uids: ["12345"],
  folder: "INBOX",
  permanent_delete: false,
  confirm_deletion: true
});
```

### Delete Multiple Emails
```typescript
// Delete multiple specific emails
const result = await deleteEmails({
  email_config: {
    service: "outlook",
    email: "user@outlook.com",
    password: "password"
  },
  email_uids: ["12345", "12346", "12347"],
  folder: "INBOX",
  permanent_delete: false,
  confirm_deletion: true
});
```

### Delete Email Range
```typescript
// Delete emails in a UID range
const result = await deleteEmails({
  email_config: {
    service: "yahoo",
    email: "user@yahoo.com",
    password: "app_password"
  },
  email_uids: ["12345-12350"],
  folder: "INBOX",
  permanent_delete: false,
  confirm_deletion: true
});
```

### Delete All Emails in Folder
```typescript
// Delete all emails in a folder
const result = await deleteEmails({
  email_config: {
    service: "gmail",
    email: "user@gmail.com",
    password: "app_password"
  },
  email_uids: ["all"],
  folder: "Spam",
  permanent_delete: true,
  confirm_deletion: true
});
```

### Permanent Deletion
```typescript
// Permanently delete emails (bypass trash)
const result = await deleteEmails({
  email_config: {
    service: "custom",
    email: "user@company.com",
    password: "password",
    host: "imap.company.com",
    port: 993,
    secure: true
  },
  email_uids: ["12345", "12346"],
  folder: "INBOX",
  permanent_delete: true,
  confirm_deletion: true
});
```

## Parameters

### Required Parameters
- **email_config**: Email server configuration object
  - **service**: Email service provider ("gmail", "outlook", "yahoo", "custom")
  - **email**: Email address for authentication
  - **password**: Password or app password for the account
- **email_uids**: Array of email UIDs to delete

### Optional Parameters
- **folder**: Email folder containing the emails to delete (default: "INBOX")
- **permanent_delete**: Whether to permanently delete emails or move to trash (default: false)
- **confirm_deletion**: Whether to require confirmation before deletion (default: true)

## Email UID Formats

### Single UID
```typescript
email_uids: ["12345"]
```

### Multiple UIDs
```typescript
email_uids: ["12345", "12346", "12347"]
```

### UID Range
```typescript
email_uids: ["12345-12350"]  // Deletes UIDs 12345 through 12350
```

### All Emails
```typescript
email_uids: ["all"]  // Deletes all emails in the specified folder
```

## Deletion Methods

### Move to Trash (Default)
- **Behavior**: Emails are moved to the trash/deleted items folder
- **Recovery**: Emails can be restored from trash
- **Storage**: Emails still consume storage space
- **Use Case**: Safe deletion for most scenarios

### Permanent Deletion
- **Behavior**: Emails are immediately and permanently removed
- **Recovery**: Emails cannot be recovered
- **Storage**: Emails no longer consume storage space
- **Use Case**: Sensitive data removal, storage cleanup

## Return Data Structure

The tool returns a comprehensive result object with the following structure:

```typescript
interface DeleteResult {
  success: boolean;
  deleted_count: number;
  failed_count: number;
  deleted_uids: string[];
  failed_uids: string[];
  errors: DeleteError[];
  summary: string;
}

interface DeleteError {
  uid: string;
  error: string;
  details: string;
}
```

## Security Features

### Confirmation System
- **Built-in Confirmation**: Prevents accidental deletions
- **Bulk Operation Warning**: Special warnings for bulk deletions
- **UID Verification**: Verify UIDs before deletion
- **Folder Validation**: Ensure folder exists and is accessible

### Access Control
- **Authentication Required**: Valid credentials required for all operations
- **Folder Permissions**: Check folder access permissions
- **UID Ownership**: Verify UID belongs to authenticated user
- **Rate Limiting**: Prevent rapid deletion operations

### Audit Logging
- **Operation Logging**: Log all deletion operations
- **User Tracking**: Track which user performed deletions
- **Timestamp Recording**: Record when deletions occurred
- **Error Logging**: Log all deletion errors and failures

## Error Handling

### Common Error Scenarios
1. **Authentication Failed**
   - Invalid credentials
   - 2FA requirements not met
   - Account locked or suspended

2. **Permission Denied**
   - Insufficient folder permissions
   - Read-only folder access
   - Account restrictions

3. **UID Not Found**
   - Email already deleted
   - Invalid UID format
   - UID out of range

4. **Folder Issues**
   - Folder doesn't exist
   - Folder not accessible
   - Folder permissions changed

5. **Server Errors**
   - IMAP server unavailable
   - Connection timeout
   - Server-side restrictions

### Error Response Format
```typescript
{
  success: false,
  error: "Error description",
  details: "Additional error information",
  partialResult?: DeleteResult // Partial results if available
}
```

## Best Practices

### Safety Measures
- **Always Use Confirmation**: Keep confirm_deletion enabled
- **Test with Small Batches**: Test deletion with few emails first
- **Verify UIDs**: Double-check UIDs before deletion
- **Use Trash First**: Use permanent deletion sparingly

### Performance Optimization
- **Batch Operations**: Delete emails in reasonable batches
- **UID Ranges**: Use UID ranges for sequential emails
- **Folder Selection**: Target specific folders for efficiency
- **Error Handling**: Handle errors gracefully and continue

### Compliance and Auditing
- **Log All Operations**: Maintain deletion audit trails
- **User Accountability**: Track who performed deletions
- **Recovery Procedures**: Document recovery processes
- **Legal Compliance**: Ensure compliance with data retention policies

## Platform-Specific Considerations

### Windows
- **PowerShell Integration**: Native PowerShell email cmdlets
- **Outlook Integration**: Direct integration with Microsoft Outlook
- **Security**: Windows Credential Manager integration
- **Performance**: Windows-specific optimizations

### Linux/macOS
- **Command Line Tools**: Integration with mail, mutt, and other CLI tools
- **System Integration**: Native system email applications
- **Security**: Keychain and credential storage integration
- **Performance**: Unix-specific optimizations

### Mobile (Android/iOS)
- **Native Apps**: Integration with device email applications
- **Touch Interface**: Mobile-optimized deletion interface
- **Storage**: Mobile storage optimization
- **Performance**: Battery and memory efficient processing

## Troubleshooting

### Common Issues
1. **"Authentication failed"**
   - Verify email and password are correct
   - Check if 2FA is enabled and use app password
   - Ensure account allows IMAP access

2. **"Permission denied"**
   - Check folder permissions
   - Verify account access rights
   - Contact email provider for assistance

3. **"UID not found"**
   - Verify UID exists in the folder
   - Check if email was already deleted
   - Refresh folder contents

4. **"Folder not accessible"**
   - Verify folder name and path
   - Check folder permissions
   - Ensure folder exists on the server

### Debug Information
Enable debug mode for detailed deletion information:
```typescript
// Enable debug logging
process.env.DEBUG = "email:delete:*";
```

## Related Tools
- **Read Emails Tool**: Read emails from IMAP servers
- **Send Email Tool**: Send emails using SMTP
- **Parse Email Tool**: Parse and analyze email content
- **Sort Emails Tool**: Organize and categorize emails
- **Manage Email Accounts Tool**: Configure email accounts

## Compliance and Legal Considerations

### Data Retention
- **Legal Requirements**: Comply with data retention laws
- **Corporate Policies**: Follow company data policies
- **Audit Requirements**: Maintain deletion audit trails
- **Recovery Procedures**: Document recovery processes

### Privacy Protection
- **Personal Data**: Handle personal data appropriately
- **Sensitive Information**: Protect sensitive content
- **Access Control**: Restrict deletion access
- **Monitoring**: Monitor deletion activities

### Corporate Governance
- **Policy Compliance**: Follow corporate email policies
- **Approval Processes**: Implement deletion approval workflows
- **Documentation**: Maintain deletion documentation
- **Training**: Provide user training on deletion procedures

## Future Enhancements
- **Scheduled Deletion**: Automatic deletion based on rules
- **Advanced Filtering**: Delete emails based on content criteria
- **Bulk Operations**: Enhanced bulk deletion capabilities
- **Recovery Tools**: Advanced email recovery features
- **Analytics**: Deletion analytics and reporting

---

*This tool is designed for legitimate email management and cleanup purposes. Always ensure compliance with applicable laws and company policies when deleting emails.*
