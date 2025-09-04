# 📧 Send Email Tool - MCP God Mode

## Overview
The **Send Email Tool** (`mcp_mcp-god-mode_send_email`) is a comprehensive email sending utility that provides cross-platform email capabilities across Windows, Linux, macOS, Android, and iOS platforms. It supports multiple email service providers (Gmail, Outlook, Yahoo, custom SMTP), secure authentication, file attachments, and professional email formatting with HTML support.

## Functionality
- **Email Sending**: Send emails to single or multiple recipients
- **Service Integration**: Support for major email providers and custom SMTP servers
- **Authentication**: Secure email authentication with app passwords and OAuth
- **Attachments**: File attachment support with base64 encoding
- **HTML Support**: Rich HTML email formatting capabilities
- **Cross-Platform Support**: Native implementation across all supported operating systems
- **Security Features**: SSL/TLS encryption and secure authentication

## Technical Details

### Tool Identifier
- **MCP Tool Name**: `mcp_mcp-god-mode_send_email`
- **Category**: Communication & Email
- **Platform Support**: Windows, Linux, macOS, Android, iOS
- **Elevated Permissions**: Not required for standard email operations

### Input Parameters
```typescript
{
  to: string,              // Recipient email address(es)
  subject: string,         // Email subject line
  body: string,            // Email body content
  html?: boolean,          // Whether body contains HTML content
  from?: string,           // Sender email address
  cc?: string,             // CC recipient email address(es)
  bcc?: string,            // BCC recipient email address(es)
  attachments?: Array<{
    filename: string,       // Name of attachment file
    content: string,        // Base64 encoded content
    contentType: string     // MIME type of attachment
  }>,
  email_config: {
    service: "gmail" | "outlook" | "yahoo" | "custom",
    email: string,          // Email address for authentication
    password: string,       // Password or app password
    host?: string,          // SMTP host for custom servers
    port?: number,          // SMTP port for custom servers
    secure?: boolean,       // Whether to use SSL/TLS
    name?: string           // Display name for sender
  }
}
```

### Output Response
```typescript
{
  status: "success" | "error" | "partial",
  message_id?: string,     // Unique message identifier
  sent_to: string[],       // List of successfully sent recipients
  failed_recipients?: Array<{
    email: string,          // Failed recipient email
    reason: string          // Failure reason
  }>,
  attachments_sent?: number, // Number of attachments sent
  email_size?: number,      // Email size in bytes
  timestamp: string,        // Sending timestamp
  smtp_response?: string,   // SMTP server response
  error?: string,           // Error message if sending failed
  warnings?: string[],      // Warning messages
  delivery_time?: number    // Delivery time in milliseconds
}
```

## Usage Examples

### Basic Email Sending
```typescript
const emailResult = await send_email({
  to: "recipient@example.com",
  subject: "Test Email",
  body: "This is a test email from MCP God Mode",
  email_config: {
    service: "gmail",
    email: "sender@gmail.com",
    password: "app_password_here"
  }
});

if (emailResult.status === "success") {
  console.log("Email sent successfully to:", emailResult.sent_to);
}
```

### HTML Email with Attachments
```typescript
const htmlEmail = await send_email({
  to: "user@example.com",
  subject: "HTML Email with Attachment",
  body: "<h1>Hello</h1><p>This is an <strong>HTML</strong> email!</p>",
  html: true,
  attachments: [{
    filename: "document.pdf",
    content: "base64_encoded_content_here",
    contentType: "application/pdf"
  }],
  email_config: {
    service: "outlook",
    email: "sender@outlook.com",
    password: "password_here"
  }
});

console.log("HTML email sent:", htmlEmail);
```

### Multiple Recipients
```typescript
const multiEmail = await send_email({
  to: "user1@example.com,user2@example.com",
  cc: "manager@example.com",
  subject: "Team Update",
  body: "Important team update information",
  email_config: {
    service: "custom",
    email: "noreply@company.com",
    password: "smtp_password",
    host: "smtp.company.com",
    port: 587,
    secure: false
  }
});

console.log("Multi-recipient email result:", multiEmail);
```

## Integration Points

### Server Integration
- **Full Server**: ✅ Included
- **Modular Server**: ❌ Not included
- **Minimal Server**: ✅ Included
- **Ultra-Minimal Server**: ✅ Included

### Dependencies
- Native SMTP client libraries
- SSL/TLS encryption support
- Base64 encoding utilities
- MIME type handling

## Platform-Specific Features

### Windows
- **Windows Security**: Windows security framework integration
- **Network Stack**: Windows networking stack optimization
- **Certificate Management**: Windows certificate store integration
- **Proxy Support**: Windows proxy configuration support

### Linux
- **Unix Networking**: Native Unix networking support
- **OpenSSL Integration**: OpenSSL SSL/TLS support
- **Proxy Support**: Environment-based proxy configuration
- **Network Tools**: Integration with Linux network tools

### macOS
- **macOS Security**: macOS security framework integration
- **Network Framework**: macOS network framework
- **Keychain Integration**: macOS keychain integration
- **Certificate Management**: macOS certificate management

### Mobile Platforms
- **Mobile Networking**: Mobile-optimized networking
- **Cellular Networks**: Cellular network support
- **Wi-Fi Integration**: Wi-Fi network integration
- **Permission Management**: Network permission handling

## Email Service Support

### Gmail
- **App Passwords**: Two-factor authentication support
- **OAuth 2.0**: Modern authentication methods
- **SMTP Settings**: smtp.gmail.com:587 (TLS)
- **Security Features**: Gmail security features

### Outlook/Hotmail
- **Modern Authentication**: OAuth 2.0 support
- **SMTP Settings**: smtp-mail.outlook.com:587 (TLS)
- **Exchange Integration**: Exchange server support
- **Security Features**: Microsoft security features

### Yahoo
- **App Passwords**: Two-factor authentication support
- **SMTP Settings**: smtp.mail.yahoo.com:587 (TLS)
- **Security Features**: Yahoo security features
- **Legacy Support**: Legacy authentication support

### Custom SMTP
- **Flexible Configuration**: Custom server settings
- **Port Options**: Support for various ports (25, 465, 587)
- **Encryption Options**: SSL, TLS, or unencrypted
- **Authentication Methods**: Various authentication methods

## Email Features

### Content Support
- **Plain Text**: Standard text email support
- **HTML Content**: Rich HTML email formatting
- **Mixed Content**: Both text and HTML versions
- **Unicode Support**: Full Unicode character support

### Attachment Handling
- **File Types**: Support for all file types
- **Size Limits**: Configurable size limits
- **Encoding**: Base64 content encoding
- **MIME Types**: Automatic MIME type detection

### Recipient Management
- **Single Recipients**: Individual email addresses
- **Multiple Recipients**: Comma-separated lists
- **CC/BCC Support**: Carbon copy and blind carbon copy
- **Group Support**: Email group handling

## Security Features

### Authentication
- **Password Security**: Secure password handling
- **App Passwords**: Two-factor authentication support
- **OAuth Support**: Modern OAuth 2.0 authentication
- **Token Management**: Secure token handling

### Encryption
- **SSL/TLS Support**: Transport layer security
- **Certificate Validation**: SSL certificate validation
- **Secure Connections**: Encrypted SMTP connections
- **Data Protection**: Email content protection

### Privacy
- **Header Privacy**: Minimal header information
- **Content Security**: Content security policies
- **Metadata Protection**: Email metadata protection
- **Audit Logging**: Email activity logging

## Error Handling

### Common Issues
- **Authentication Failures**: Invalid credentials
- **Network Errors**: Connection and timeout issues
- **SMTP Errors**: Server-side email errors
- **Attachment Issues**: File encoding and size problems

### Recovery Actions
- Automatic retry mechanisms
- Alternative authentication methods
- Fallback SMTP servers
- Comprehensive error reporting

## Performance Characteristics

### Sending Speed
- **Single Email**: 1-5 seconds depending on size
- **Multiple Recipients**: 2-10 seconds for multiple recipients
- **Large Attachments**: 5-30 seconds for large files
- **Network Dependent**: Variable based on network performance

### Resource Usage
- **CPU**: Low (5-15% during sending)
- **Memory**: Low to moderate (10-100MB)
- **Network**: High during sending
- **Disk**: Minimal (temporary storage only)

## Monitoring and Logging

### Email Tracking
- **Delivery Status**: Email delivery tracking
- **Bounce Handling**: Bounce email handling
- **Spam Detection**: Spam filter monitoring
- **Success Tracking**: Successful delivery tracking

### Performance Monitoring
- **Sending Speed**: Email sending performance
- **Success Rates**: Delivery success rates
- **Error Analysis**: Error analysis and reporting
- **Resource Usage**: System resource monitoring

## Troubleshooting

### Authentication Issues
1. Verify email and password
2. Check two-factor authentication settings
3. Confirm app password usage
4. Review account security settings

### Sending Failures
1. Check network connectivity
2. Verify SMTP server settings
3. Review email content and attachments
4. Confirm recipient email addresses

## Best Practices

### Implementation
- Use app passwords for Gmail
- Implement appropriate error handling
- Validate email addresses before sending
- Monitor sending quotas and limits

### Security
- Never hardcode passwords
- Use secure SMTP connections
- Implement rate limiting
- Monitor for suspicious activity

## Related Tools
- **Read Emails**: Email reading and management
- **Parse Email**: Email content parsing
- **Network Diagnostics**: Network connectivity testing
- **File Operations**: Attachment file management

## Version History
- **v1.0**: Initial implementation
- **v1.1**: Enhanced service support
- **v1.2**: Advanced attachment features
- **v1.3**: Cross-platform improvements
- **v1.4**: Professional email features

---

**⚠️ IMPORTANT: Always use secure authentication methods and never share email credentials in code or configuration files.**

*This document is part of MCP God Mode v1.4 - Advanced AI Agent Toolkit*
