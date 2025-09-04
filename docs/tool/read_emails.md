# Read Emails Tool

## Overview
The `read_emails` tool allows you to read emails from IMAP servers across all platforms. This tool supports Gmail, Outlook, Yahoo, and custom IMAP servers with secure authentication and comprehensive email retrieval capabilities.

## Tool Name
`read_emails`

## Description
Read emails from IMAP servers across all platforms (Windows, Linux, macOS, Android, iOS)

## Input Schema
- `email_config` (object, required): Email server configuration including:
  - `service` (string, required): Email service provider. Options: 'gmail', 'outlook', 'yahoo', 'custom'
  - `email` (string, required): Email address for authentication
  - `password` (string, required): Password or app password for the email account
  - `host` (string, optional): IMAP host for custom servers
  - `port` (number, optional): IMAP port for custom servers
  - `secure` (boolean, optional): Whether to use SSL/TLS encryption
  - `name` (string, optional): Display name for the email account

- `folder` (string, optional): Email folder to read from. Examples: 'INBOX', 'Sent', 'Drafts', 'Trash', 'Archive'. Default: "INBOX"

- `limit` (number, optional): Maximum number of emails to retrieve. Examples: 5 for recent emails, 20 for more emails, 100 for comprehensive retrieval. Default: 10

- `unread_only` (boolean, optional): Whether to retrieve only unread emails. Set to true to get only unread messages, false to get all messages. Default: false

- `search_criteria` (string, optional): Search criteria for filtering emails. Examples: 'FROM:user@example.com', 'SUBJECT:meeting', 'SINCE:2024-01-01', 'LARGER:1000000' for emails larger than 1MB

## Natural Language Access
Users can ask for this tool using natural language such as:
- "Read my emails from Gmail"
- "Check my inbox for new messages"
- "Read emails from a specific sender"
- "Get unread emails from Outlook"
- "Read emails with a specific subject"
- "Check emails from yesterday"
- "Read emails larger than 1MB"
- "Get emails from the Sent folder"

## Examples

### Basic Email Reading
```typescript
// Read emails from Gmail
const result = await server.callTool("read_emails", { 
  email_config: {
    service: "gmail",
    email: "user@gmail.com",
    password: "app_password_here"
  },
  limit: 10
});

// Read emails from Outlook
const result = await server.callTool("read_emails", { 
  email_config: {
    service: "outlook",
    email: "user@outlook.com",
    password: "password_here"
  },
  folder: "INBOX",
  limit: 20
});
```

### Advanced Email Filtering
```typescript
// Read only unread emails
const result = await server.callTool("read_emails", { 
  email_config: {
    service: "gmail",
    email: "user@gmail.com",
    password: "app_password_here"
  },
  unread_only: true,
  limit: 50
});

// Search for specific emails
const result = await server.callTool("read_emails", { 
  email_config: {
    service: "yahoo",
    email: "user@yahoo.com",
    password: "password_here"
  },
  search_criteria: "FROM:boss@company.com SUBJECT:meeting",
  limit: 100
});
```

### Custom IMAP Server
```typescript
// Read from custom IMAP server
const result = await server.callTool("read_emails", { 
  email_config: {
    service: "custom",
    email: "user@company.com",
    password: "password_here",
    host: "imap.company.com",
    port: 993,
    secure: true
  },
  folder: "INBOX",
  limit: 25
});
```

## Platform Support
- ✅ Windows
- ✅ Linux
- ✅ macOS
- ✅ Android
- ✅ iOS

## Supported Email Services

### Gmail
- **IMAP Host**: imap.gmail.com
- **Port**: 993 (SSL)
- **Authentication**: OAuth2 or App Password
- **Features**: Full IMAP support, labels, filters

### Outlook/Hotmail
- **IMAP Host**: outlook.office365.com
- **Port**: 993 (SSL)
- **Authentication**: Modern authentication or password
- **Features**: Full IMAP support, folders, rules

### Yahoo Mail
- **IMAP Host**: imap.mail.yahoo.com
- **Port**: 993 (SSL)
- **Authentication**: App-specific password required
- **Features**: Full IMAP support, folders

### Custom IMAP Servers
- **Host**: Any IMAP server
- **Port**: 993 (SSL) or 143 (non-SSL)
- **Authentication**: Username/password
- **Features**: Full IMAP protocol support

## Email Retrieval Features

### Basic Operations
- **List Emails**: Retrieve email headers and metadata
- **Read Content**: Get full email body and attachments
- **Folder Navigation**: Access different email folders
- **Search and Filter**: Find specific emails

### Advanced Features
- **Unread Filtering**: Get only unread messages
- **Size Filtering**: Filter by email size
- **Date Filtering**: Filter by date ranges
- **Sender Filtering**: Filter by sender address
- **Subject Filtering**: Filter by subject content

### Search Criteria
- **FROM**: Search by sender email or domain
- **TO**: Search by recipient
- **SUBJECT**: Search by subject line
- **SINCE**: Emails since specific date
- **BEFORE**: Emails before specific date
- **LARGER**: Emails larger than specified size
- **SMALLER**: Emails smaller than specified size

## Security Features
- **SSL/TLS Encryption**: Secure connection to IMAP servers
- **Password Protection**: Secure password handling
- **OAuth2 Support**: Modern authentication for Gmail/Outlook
- **App Passwords**: Secure access for 2FA-enabled accounts
- **Connection Validation**: Verify server authenticity

## Error Handling
- **Authentication Errors**: Invalid credentials handling
- **Connection Errors**: Network connectivity issues
- **Server Errors**: IMAP server problems
- **Permission Errors**: Access denied issues
- **Rate Limiting**: Handle service provider limits

## Performance Features
- **Batch Retrieval**: Efficient email fetching
- **Connection Pooling**: Reuse connections when possible
- **Caching**: Cache email metadata for faster access
- **Async Operations**: Non-blocking email operations
- **Memory Optimization**: Efficient memory usage

## Related Tools
- `send_email` - Send emails via SMTP
- `parse_email` - Parse and analyze email content
- `delete_emails` - Delete emails from servers
- `sort_emails` - Organize and sort emails
- `manage_email_accounts` - Manage email configurations

## Use Cases
- **Email Monitoring**: Check for new messages
- **Customer Support**: Read support emails
- **Business Communication**: Monitor business emails
- **Personal Email**: Check personal email accounts
- **Email Analysis**: Analyze email patterns
- **Backup and Archive**: Retrieve emails for backup
- **Compliance**: Email compliance monitoring
- **Automation**: Automated email processing

## Best Practices
- **Use App Passwords**: For 2FA-enabled accounts
- **Limit Retrieval**: Don't retrieve unnecessary emails
- **Handle Errors**: Implement proper error handling
- **Secure Storage**: Store credentials securely
- **Rate Limiting**: Respect service provider limits
- **Connection Management**: Close connections properly
- **Logging**: Log email operations for audit
- **Privacy**: Respect email privacy and content

## Troubleshooting

### Common Issues
1. **Authentication Failed**: Check credentials and 2FA settings
2. **Connection Refused**: Verify server host and port
3. **SSL Errors**: Check SSL/TLS configuration
4. **Rate Limited**: Wait before retrying
5. **Folder Not Found**: Verify folder names

### Solutions
1. **Gmail**: Enable IMAP and use App Password
2. **Outlook**: Enable IMAP in account settings
3. **Yahoo**: Generate App-specific password
4. **Custom**: Verify IMAP server configuration
5. **Network**: Check firewall and proxy settings

## Security Considerations
- **Credential Protection**: Never expose passwords in code
- **Connection Security**: Always use SSL/TLS
- **Access Control**: Limit tool access as needed
- **Audit Logging**: Log all email access
- **Data Privacy**: Handle email content responsibly
