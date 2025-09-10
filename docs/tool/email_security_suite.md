# Email Security Suite

Overview: Analyze messages for phishing/malware, headers, and risky links; support takedown workflows.

- Tool name: `email_security_suite`
- Category: Security / Email

Example
```javascript
await server.callTool("email_security_suite", {
  action: "analyze",
  message: "<raw RFC822 content or reference>"
});
```

Notes
- Complements `send_email`, `read_emails`, `parse_email`, and `sort_emails`.
