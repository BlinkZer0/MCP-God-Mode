# Sort Emails Tool

## Overview
The **Sort Emails Tool** is a comprehensive email organization and management system that allows you to sort, filter, and organize emails from IMAP servers across all platforms (Windows, Linux, macOS, Android, and iOS). This tool provides intelligent email categorization, automated organization rules, and bulk processing capabilities for efficient email management.

## Features
- **Cross-Platform Support**: Works on Windows, Linux, macOS, Android, and iOS
- **Multiple Email Providers**: Gmail, Outlook, Yahoo, and custom IMAP servers
- **Advanced Sorting**: Sort by date, sender, subject, size, priority, and more
- **Smart Filtering**: Filter by sender, subject, date range, attachments, and content
- **Automated Organization**: Apply rules for automatic email categorization
- **Bulk Operations**: Process large numbers of emails efficiently
- **Folder Management**: Organize emails into custom folders
- **Flagging System**: Add flags and labels to important emails

## Supported Email Services

### Gmail
- **Host**: imap.gmail.com
- **Port**: 993 (SSL)
- **Security**: SSL/TLS required
- **Authentication**: Email + App Password (if 2FA enabled)
- **Labels**: Gmail-specific label system

### Outlook/Hotmail
- **Host**: outlook.office365.com
- **Port**: 993 (SSL)
- **Security**: SSL/TLS required
- **Authentication**: Email + Password
- **Categories**: Outlook category system

### Yahoo
- **Host**: imap.mail.yahoo.com
- **Port**: 993 (SSL)
- **Security**: SSL/TLS required
- **Authentication**: Email + App Password (if 2FA enabled)
- **Folders**: Standard IMAP folder system

### Custom IMAP Servers
- **Host**: Your custom IMAP server
- **Port**: 993 (SSL) or 143 (unencrypted)
- **Security**: Configurable SSL/TLS settings
- **Authentication**: Email + Password
- **Folders**: Custom folder structure


## Natural Language Access
Users can request sort emails operations using natural language:
- "Sort email messages"
- "Organize email content"
- "Categorize emails"
- "Filter email messages"
- "Manage email organization"
## Usage Examples

### Basic Email Sorting
```typescript
// Sort emails by date (newest first)
const result = await sortEmails({
  email_config: {
    service: "gmail",
    email: "user@gmail.com",
    password: "app_password"
  },
  source_folder: "INBOX",
  sort_criteria: "date",
  sort_order: "desc",
  limit: 50
});
```

### Advanced Filtering and Sorting
```typescript
// Sort unread emails with attachments by sender
const result = await sortEmails({
  email_config: {
    service: "outlook",
    email: "user@outlook.com",
    password: "password"
  },
  source_folder: "INBOX",
  sort_criteria: "sender",
  sort_order: "asc",
  filter_criteria: {
    unread_only: true,
    has_attachments: true,
    from: "@company.com"
  },
  limit: 100
});
```

### Automated Organization Rules
```typescript
// Apply automatic organization rules
const result = await sortEmails({
  email_config: {
    service: "yahoo",
    email: "user@yahoo.com",
    password: "app_password"
  },
  source_folder: "INBOX",
  sort_criteria: "date",
  sort_order: "desc",
  organization_rules: [
    {
      condition: "FROM:spam@example.com",
      action: "move",
      target_folder: "Spam"
    },
    {
      condition: "SUBJECT:newsletter",
      action: "move",
      target_folder: "Newsletters"
    },
    {
      condition: "FROM:boss@company.com",
      action: "flag",
      flag: "Important"
    }
  ],
  limit: 200
});
```

### Date Range Filtering
```typescript
// Sort emails from specific date range
const result = await sortEmails({
  email_config: {
    service: "custom",
    email: "user@company.com",
    password: "password",
    host: "imap.company.com",
    port: 993,
    secure: true
  },
  source_folder: "INBOX",
  sort_criteria: "date",
  sort_order: "desc",
  filter_criteria: {
    date_range: {
      start_date: "2024-01-01",
      end_date: "2024-12-31"
    },
    from: "@company.com"
  },
  limit: 500
});
```

## Parameters

### Required Parameters
- **email_config**: Email server configuration object
  - **service**: Email service provider ("gmail", "outlook", "yahoo", "custom")
  - **email**: Email address for authentication
  - **password**: Password or app password for the account
- **sort_criteria**: Primary sorting criteria

### Optional Parameters
- **source_folder**: Source folder to sort emails from (default: "INBOX")
- **sort_order**: Sorting order ("asc" or "desc", default: "desc")
- **filter_criteria**: Filtering criteria object
- **organization_rules**: Array of organization rules
- **limit**: Maximum number of emails to process (default: 50)

## Sorting Criteria

### Available Sort Options
- **date**: Sort by email date/timestamp
- **sender**: Sort by sender email address
- **subject**: Sort by email subject line
- **size**: Sort by email size in bytes
- **priority**: Sort by email priority level
- **unread**: Sort by unread status
- **has_attachments**: Sort by attachment presence

### Sort Order
- **asc**: Ascending order (oldest first, A-Z)
- **desc**: Descending order (newest first, Z-A)

## Filtering Criteria

### Basic Filters
- **from**: Filter by sender email or domain
- **subject**: Filter by subject keywords
- **unread_only**: Filter only unread emails
- **has_attachments**: Filter emails with or without attachments

### Advanced Filters
- **date_range**: Filter by date range
  - **start_date**: Start date (ISO format)
  - **end_date**: End date (ISO format)
- **size_limit**: Maximum email size in bytes

### Filter Examples
```typescript
filter_criteria: {
  from: "boss@company.com",           // Specific sender
  from: "@company.com",               // Domain filter
  subject: "urgent",                  // Subject keyword
  unread_only: true,                  // Only unread
  has_attachments: true,              // With attachments
  size_limit: 1000000,                // Under 1MB
  date_range: {
    start_date: "2024-01-01",
    end_date: "2024-12-31"
  }
}
```

## Organization Rules

### Rule Structure
```typescript
interface OrganizationRule {
  condition: string;        // Search condition
  action: string;          // Action to perform
  target_folder?: string;  // Target folder for move action
  flag?: string;           // Flag for flag action
}
```

### Available Actions
- **move**: Move email to specified folder
- **flag**: Add flag to email
- **mark_read**: Mark email as read
- **mark_unread**: Mark email as unread
- **delete**: Delete email

### Rule Examples
```typescript
organization_rules: [
  {
    condition: "FROM:spam@example.com",
    action: "move",
    target_folder: "Spam"
  },
  {
    condition: "SUBJECT:meeting",
    action: "flag",
    flag: "Important"
  },
  {
    condition: "SINCE:2024-01-01",
    action: "mark_read"
  }
]
```

## Return Data Structure

The tool returns a comprehensive result object with the following structure:

```typescript
interface SortResult {
  success: boolean;
  processed_count: number;
  organized_count: number;
  skipped_count: number;
  errors: SortError[];
  summary: string;
  organized_emails: OrganizedEmail[];
}

interface OrganizedEmail {
  uid: string;
  subject: string;
  from: string;
  date: string;
  action_taken: string;
  target_folder?: string;
  flag?: string;
}

interface SortError {
  uid: string;
  error: string;
  details: string;
}
```

## Advanced Features

### Intelligent Categorization
- **Sender Analysis**: Categorize by sender patterns
- **Content Analysis**: Analyze email content for categorization
- **Time Patterns**: Identify time-based patterns
- **Priority Detection**: Automatic priority detection

### Bulk Processing
- **Batch Operations**: Process emails in configurable batches
- **Progress Tracking**: Monitor processing progress
- **Error Recovery**: Continue processing after errors
- **Performance Optimization**: Optimize for large email volumes

### Custom Rules Engine
- **Rule Chaining**: Apply multiple rules in sequence
- **Conditional Logic**: Complex conditional expressions
- **Regular Expressions**: Pattern-based matching
- **Template Rules**: Reusable rule templates

## Security Features

### Access Control
- **Authentication Required**: Valid credentials required for all operations
- **Folder Permissions**: Check folder access permissions
- **Operation Validation**: Validate all operations before execution
- **Rate Limiting**: Prevent rapid operations

### Data Protection
- **Local Processing**: All operations processed locally
- **No Data Storage**: No persistent storage of email content
- **Secure Transmission**: Encrypted communication with email servers
- **Audit Logging**: Log all organization operations

## Performance Optimization

### Memory Management
- **Streaming Processing**: Process emails in streams
- **Batch Processing**: Handle emails in manageable batches
- **Resource Monitoring**: Monitor memory and CPU usage
- **Garbage Collection**: Automatic cleanup of temporary data

### Caching Strategies
- **Folder Cache**: Cache folder structure information
- **Rule Cache**: Cache compiled organization rules
- **Result Cache**: Cache sorting and filtering results
- **Connection Pooling**: Reuse IMAP connections

## Platform-Specific Considerations

### Windows
- **PowerShell Integration**: Native PowerShell email cmdlets
- **Outlook Integration**: Direct integration with Microsoft Outlook
- **Performance**: Windows-specific optimizations
- **Security**: Windows Credential Manager integration

### Linux/macOS
- **Command Line Tools**: Integration with mail, mutt, and other CLI tools
- **System Integration**: Native system email applications
- **Performance**: Unix-specific optimizations
- **Security**: Keychain and credential storage integration

### Mobile (Android/iOS)
- **Native Apps**: Integration with device email applications
- **Touch Interface**: Mobile-optimized organization interface
- **Storage**: Mobile storage optimization
- **Performance**: Battery and memory efficient processing

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

3. **Folder Issues**
   - Folder doesn't exist
   - Folder not accessible
   - Folder permissions changed

4. **Rule Processing Errors**
   - Invalid rule conditions
   - Target folder not found
   - Action execution failed

### Error Response Format
```typescript
{
  success: false,
  error: "Error description",
  details: "Additional error information",
  partialResult?: SortResult // Partial results if available
}
```

## Best Practices

### Organization Strategy
- **Start Small**: Begin with simple rules and expand gradually
- **Test Rules**: Test rules on small email sets first
- **Regular Review**: Periodically review and update rules
- **Backup Strategy**: Maintain backup of important emails

### Performance Optimization
- **Batch Processing**: Use appropriate batch sizes
- **Selective Processing**: Process only necessary emails
- **Rule Optimization**: Optimize rule conditions for performance
- **Resource Monitoring**: Monitor system resources during processing

### Security Considerations
- **Access Control**: Restrict access to organization tools
- **Audit Logging**: Log all organization activities
- **Data Protection**: Protect sensitive email content
- **Compliance**: Ensure compliance with data policies

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

3. **"Rule processing failed"**
   - Verify rule syntax
   - Check target folder existence
   - Ensure rule conditions are valid

4. **"Performance issues"**
   - Reduce batch sizes
   - Optimize rule conditions
   - Monitor system resources

### Debug Information
Enable debug mode for detailed processing information:
```typescript
// Enable debug logging
process.env.DEBUG = "email:sort:*";
```

## Related Tools
- **Read Emails Tool**: Read emails from IMAP servers
- **Send Email Tool**: Send emails using SMTP
- **Parse Email Tool**: Parse and analyze email content
- **Delete Emails Tool**: Remove emails from servers
- **Manage Email Accounts Tool**: Configure email accounts

## Compliance and Legal Considerations

### Data Management
- **Data Retention**: Comply with data retention policies
- **Data Classification**: Handle data according to classification
- **Access Control**: Restrict access to authorized personnel
- **Audit Requirements**: Maintain operation audit trails

### Corporate Policies
- **Email Usage**: Follow company email policies
- **Organization Standards**: Use approved organization methods
- **Security Standards**: Meet corporate security requirements
- **Training Requirements**: Provide user training on tools

## Future Enhancements
- **AI-Powered Organization**: Machine learning-based categorization
- **Advanced Analytics**: Email usage analytics and reporting
- **Integration**: Third-party service integrations
- **Automation**: Scheduled organization tasks
- **Collaboration**: Team-based organization rules

---

*This tool is designed for legitimate email organization and management purposes. Always ensure compliance with applicable laws and company policies when organizing emails.*
