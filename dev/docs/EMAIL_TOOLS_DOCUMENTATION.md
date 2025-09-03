# 📧 Email Tools Documentation - MCP God Mode

## Overview

The MCP God Mode server now includes comprehensive email functionality across all server iterations (refactored, minimal, and ultra-minimal). These tools provide cross-platform email capabilities for Windows, Linux, macOS, Android, and iOS.

## 🛠️ Available Email Tools

### 1. `send_email` - Send Emails via SMTP

**Description:** Send emails using SMTP across all platforms with support for Gmail, Outlook, Yahoo, and custom SMTP servers.

**Features:**
- ✅ Cross-platform compatibility (Windows, Linux, macOS, Android, iOS)
- ✅ Multiple email service providers (Gmail, Outlook, Yahoo, Custom)
- ✅ HTML and plain text email support
- ✅ File attachments (base64 encoded)
- ✅ CC and BCC recipients
- ✅ Custom sender names
- ✅ Secure authentication with TLS/SSL

**Input Schema:**
```typescript
{
  to: string,                    // Recipient email(s)
  subject: string,              // Email subject
  body: string,                 // Email content
  html?: boolean,               // HTML content flag
  from?: string,                // Sender email
  cc?: string,                  // CC recipients
  bcc?: string,                 // BCC recipients
  attachments?: Array<{         // File attachments
    filename: string,
    content: string,            // Base64 encoded
    contentType?: string
  }>,
  email_config: {               // Server configuration
    service: "gmail" | "outlook" | "yahoo" | "custom",
    email: string,              // Authentication email
    password: string,           // Authentication password
    host?: string,              // Custom SMTP host
    port?: number,              // Custom SMTP port
    secure?: boolean,           // SSL/TLS flag
    name?: string               // Display name
  }
}
```

**Output Schema:**
```typescript
{
  success: boolean,             // Operation success
  message_id?: string,          // Email message ID
  response?: string,            // Success message
  error?: string,               // Error message
  platform: string,             // Execution platform
  timestamp: string             // Operation timestamp
}
```

**Example Usage:**
```typescript
// Send a simple email via Gmail
{
  to: "recipient@example.com",
  subject: "Hello from MCP God Mode",
  body: "This is a test email sent using the MCP email tools.",
  email_config: {
    service: "gmail",
    email: "your-email@gmail.com",
    password: "your-app-password",
    name: "Your Name"
  }
}

// Send HTML email with attachment via custom SMTP
{
  to: "user@company.com",
  subject: "Report Attached",
  body: "<h1>Monthly Report</h1><p>Please find the attached report.</p>",
  html: true,
  attachments: [{
    filename: "report.pdf",
    content: "base64-encoded-content",
    contentType: "application/pdf"
  }],
  email_config: {
    service: "custom",
    email: "sender@company.com",
    password: "password123",
    host: "smtp.company.com",
    port: 587,
    secure: false
  }
}
```

### 2. `read_emails` - Read Emails via IMAP

**Description:** Read emails from IMAP servers with support for Gmail, Outlook, Yahoo, and custom IMAP servers.

**Features:**
- ✅ Cross-platform IMAP support
- ✅ Multiple email service providers
- ✅ Folder selection (INBOX, Sent, Drafts, etc.)
- ✅ Search criteria filtering
- ✅ Unread email filtering
- ✅ Email metadata extraction
- ✅ Attachment detection

**Input Schema:**
```typescript
{
  email_config: {               // Server configuration
    service: "gmail" | "outlook" | "yahoo" | "custom",
    email: string,              // Authentication email
    password: string,           // Authentication password
    host?: string,              // Custom IMAP host
    port?: number,              // Custom IMAP port
    secure?: boolean,           // SSL/TLS flag
    name?: string               // Display name
  },
  folder?: string,              // Email folder (default: "INBOX")
  limit?: number,               // Max emails to retrieve (default: 10)
  unread_only?: boolean,        // Unread emails only (default: false)
  search_criteria?: string      // IMAP search criteria
}
```

**Output Schema:**
```typescript
{
  success: boolean,             // Operation success
  emails?: Array<{              // Email list
    uid: string,                // Unique identifier
    subject: string,            // Email subject
    from: string,               // Sender information
    to: string,                 // Recipient information
    date: string,               // Send date
    size: number,               // Email size in bytes
    flags: string[],            // Email flags
    preview: string,            // Content preview
    has_attachments: boolean    // Attachment flag
  }>,
  error?: string,               // Error message
  platform: string,             // Execution platform
  timestamp: string             // Operation timestamp
}
```

**Example Usage:**
```typescript
// Read recent emails from Gmail
{
  email_config: {
    service: "gmail",
    email: "your-email@gmail.com",
    password: "your-app-password"
  },
  folder: "INBOX",
  limit: 20,
  unread_only: true
}

// Search for specific emails
{
  email_config: {
    service: "outlook",
    email: "user@outlook.com",
    password: "password123"
  },
  search_criteria: "FROM:important@company.com SINCE:2024-01-01"
}
```

### 3. `parse_email` - Parse Email Content

**Description:** Parse and analyze email content to extract text, HTML, attachments, headers, and metadata.

**Features:**
- ✅ MIME format parsing
- ✅ File path support (.eml files)
- ✅ Attachment extraction
- ✅ Link and email extraction
- ✅ Header analysis
- ✅ Content type detection

**Input Schema:**
```typescript
{
  email_content: string,        // Raw email content or file path
  parse_attachments?: boolean,  // Parse attachments (default: true)
  extract_links?: boolean,      // Extract URLs (default: true)
  extract_emails?: boolean,     // Extract email addresses (default: true)
  include_headers?: boolean     // Include headers (default: true)
}
```

**Output Schema:**
```typescript
{
  success: boolean,             // Operation success
  parsed_email?: {              // Parsed email data
    from: string,               // Sender information
    to: string,                 // Recipient information
    subject: string,            // Email subject
    date: string,               // Send date
    message_id: string,         // Message identifier
    text_content: string,       // Plain text content
    html_content?: string,      // HTML content
    headers?: Record<string>,   // Email headers
    attachments?: Array<{       // File attachments
      filename: string,
      content_type: string,
      size: number,
      content?: string          // Base64 encoded
    }>,
    links?: string[],           // Extracted URLs
    emails?: string[],          // Extracted email addresses
    size: number                // Total email size
  },
  error?: string,               // Error message
  platform: string,             // Execution platform
  timestamp: string             // Operation timestamp
}
```

**Example Usage:**
```typescript
// Parse email content directly
{
  email_content: "From: sender@example.com\nSubject: Test\n\nHello world",
  parse_attachments: true,
  extract_links: true,
  extract_emails: true,
  include_headers: true
}

// Parse email file
{
  email_content: "./email.eml",
  parse_attachments: false,
  extract_links: true
}
```

## 🌍 Cross-Platform Support

### Supported Platforms
- **Windows** - Full email functionality with native SMTP/IMAP support
- **Linux** - Full email functionality with system email libraries
- **macOS** - Full email functionality with native email services
- **Android** - Email functionality via Node.js runtime
- **iOS** - Email functionality via Node.js runtime

### Platform-Specific Features
- **Windows**: Automatic UAC elevation for admin operations
- **Linux**: Automatic sudo execution for root privileges
- **macOS**: Native email service integration
- **Mobile**: Platform-specific permission handling

## 🔐 Email Service Configuration

### Gmail
```typescript
{
  service: "gmail",
  email: "your-email@gmail.com",
  password: "your-app-password",  // Use App Password if 2FA enabled
  name: "Your Display Name"
}
```

**Note:** For Gmail, you must:
1. Enable 2-Factor Authentication
2. Generate an App Password
3. Use the App Password instead of your regular password

### Outlook/Hotmail
```typescript
{
  service: "outlook",
  email: "your-email@outlook.com",
  password: "your-password",
  name: "Your Display Name"
}
```

### Yahoo Mail
```typescript
{
  service: "yahoo",
  email: "your-email@yahoo.com",
  password: "your-password",
  name: "Your Display Name"
}
```

### Custom SMTP Server
```typescript
{
  service: "custom",
  email: "user@company.com",
  password: "password123",
  host: "smtp.company.com",
  port: 587,                    // 587 for TLS, 465 for SSL, 25 for unencrypted
  secure: false,                // true for SSL, false for TLS
  name: "Company Name"
}
```

## 📁 File Attachments

### Supported Attachment Types
- **Documents**: PDF, DOC, DOCX, TXT, RTF
- **Images**: JPG, PNG, GIF, BMP, SVG
- **Spreadsheets**: XLS, XLSX, CSV
- **Presentations**: PPT, PPTX
- **Archives**: ZIP, RAR, 7Z
- **Any binary file** with proper MIME type

### Attachment Format
```typescript
{
  filename: "document.pdf",
  content: "base64-encoded-content-string",
  contentType: "application/pdf"  // Optional, auto-detected if not provided
}
```

## 🔍 Search and Filtering

### IMAP Search Criteria
- **FROM**: `FROM:user@example.com`
- **TO**: `TO:recipient@example.com`
- **SUBJECT**: `SUBJECT:meeting`
- **SINCE**: `SINCE:2024-01-01`
- **BEFORE**: `BEFORE:2024-12-31`
- **LARGER**: `LARGER:1000000` (1MB)
- **SMALLER**: `SMALLER:100000` (100KB)
- **UNSEEN**: `UNSEEN` (unread emails)
- **SEEN**: `SEEN` (read emails)

### Combined Search
```typescript
search_criteria: "FROM:boss@company.com SINCE:2024-01-01 UNSEEN"
```

## 🚀 Performance and Security

### Performance Features
- **Connection Caching**: Reuses email server connections
- **Batch Processing**: Handles multiple emails efficiently
- **Memory Management**: Optimized for large attachments
- **Timeout Handling**: Configurable operation timeouts

### Security Features
- **TLS/SSL Encryption**: Secure email transmission
- **Authentication**: Secure password handling
- **Input Validation**: Comprehensive parameter validation
- **Error Handling**: Secure error messages without information leakage

## 📊 Error Handling

### Common Error Scenarios
1. **Authentication Failed**: Invalid credentials or 2FA issues
2. **Connection Failed**: Network or server issues
3. **Rate Limiting**: Too many requests to email service
4. **Invalid Configuration**: Missing required parameters
5. **File System Errors**: Attachment or file access issues

### Error Response Format
```typescript
{
  success: false,
  error: "Descriptive error message",
  platform: "win32",
  timestamp: "2024-01-01T12:00:00.000Z"
}
```

## 🧪 Testing

### Test Commands
```bash
# Test email libraries
node test_email_simple.mjs

# Test server compilation
npm run build

# Test specific server
node dist/server-refactored.js
```

### Test Environment Variables
```bash
export TEST_EMAIL_SERVICE="gmail"
export TEST_EMAIL_ADDRESS="your-email@gmail.com"
export TEST_EMAIL_PASSWORD="your-app-password"
export TEST_EMAIL_TO="test@example.com"
```

## 🔧 Troubleshooting

### Common Issues
1. **Gmail Authentication**: Ensure 2FA is enabled and App Password is used
2. **Port Blocking**: Check firewall settings for SMTP/IMAP ports
3. **SSL/TLS Issues**: Verify certificate validity and port configuration
4. **Rate Limiting**: Implement delays between email operations
5. **Memory Issues**: Monitor attachment sizes and implement cleanup

### Debug Mode
Enable verbose logging by setting environment variables:
```bash
export DEBUG_EMAIL=true
export NODE_ENV=development
```

## 📈 Future Enhancements

### Planned Features
- **Email Templates**: Predefined email templates
- **Scheduling**: Delayed email sending
- **Bulk Operations**: Mass email operations
- **Email Analytics**: Send/receive statistics
- **Webhook Integration**: Real-time email notifications
- **Advanced Filtering**: AI-powered email categorization

### Integration Possibilities
- **CRM Systems**: Customer relationship management
- **Marketing Tools**: Email campaign management
- **Support Systems**: Ticket management integration
- **Workflow Automation**: Business process automation

## 📚 Additional Resources

### Documentation
- [Nodemailer Documentation](https://nodemailer.com/)
- [IMAP Protocol Specification](https://tools.ietf.org/html/rfc3501)
- [SMTP Protocol Specification](https://tools.ietf.org/html/rfc5321)
- [MIME Format Specification](https://tools.ietf.org/html/rfc2045)

### Support
- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Comprehensive usage examples
- **Community**: Developer community support
- **Security**: Security vulnerability reporting

---

**🎯 The email tools are now fully integrated across all MCP God Mode server iterations, providing comprehensive email functionality for cross-platform automation and communication needs.**
