"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerSendEmail = registerSendEmail;
const zod_1 = require("zod");
const environment_1 = require("../../config/environment");
const email_utils_1 = require("./email_utils");
function registerSendEmail(server) {
    server.registerTool("send_email", {
        description: "Send emails using SMTP across all platforms (Windows, Linux, macOS, Android, iOS). Supports Gmail, Outlook, Yahoo, and custom SMTP servers with proper authentication and security.",
        inputSchema: {
            to: zod_1.z.string().describe("Recipient email address(es). Examples: 'user@example.com', 'user1@example.com,user2@example.com' for multiple recipients."),
            subject: zod_1.z.string().describe("Email subject line. Examples: 'Meeting Reminder', 'Project Update', 'Hello from MCP God Mode'."),
            body: zod_1.z.string().describe("Email body content. Can be plain text or HTML. Examples: 'Hello, this is a test email.', '<h1>Hello</h1><p>This is HTML content.</p>'."),
            html: zod_1.z.boolean().default(false).describe("Whether the email body contains HTML content. Set to true for HTML emails, false for plain text."),
            from: zod_1.z.string().optional().describe("Sender email address. If not provided, uses the configured email address."),
            cc: zod_1.z.string().optional().describe("CC recipient email address(es). Examples: 'cc@example.com', 'cc1@example.com,cc2@example.com'."),
            bcc: zod_1.z.string().optional().describe("BCC recipient email address(es). Examples: 'bcc@example.com', 'bcc1@example.com,bcc2@example.com'."),
            attachments: zod_1.z.array(zod_1.z.object({
                filename: zod_1.z.string().describe("Name of the attachment file. Examples: 'document.pdf', 'image.jpg', 'report.xlsx'."),
                content: zod_1.z.string().describe("Base64 encoded content of the attachment file."),
                contentType: zod_1.z.string().optional().describe("MIME type of the attachment. Examples: 'application/pdf', 'image/jpeg', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'.")
            })).optional().describe("Array of file attachments to include with the email."),
            email_config: zod_1.z.object({
                service: zod_1.z.enum(["gmail", "outlook", "yahoo", "custom"]).describe("Email service provider. 'gmail' for Google Mail, 'outlook' for Microsoft Outlook/Hotmail, 'yahoo' for Yahoo Mail, 'custom' for other SMTP servers."),
                email: zod_1.z.string().describe("Email address for authentication. Examples: 'user@gmail.com', 'user@outlook.com', 'user@company.com'."),
                password: zod_1.z.string().describe("Password or app password for the email account. For Gmail, use App Password if 2FA is enabled."),
                host: zod_1.z.string().optional().describe("SMTP host for custom servers. Examples: 'smtp.company.com', 'mail.example.org'. Required when service is 'custom'."),
                port: zod_1.z.number().optional().describe("SMTP port for custom servers. Examples: 587 for TLS, 465 for SSL, 25 for unencrypted. Defaults to 587 for TLS."),
                secure: zod_1.z.boolean().optional().describe("Whether to use SSL/TLS encryption. Examples: true for port 465, false for port 587. Defaults to false for TLS."),
                name: zod_1.z.string().optional().describe("Display name for the sender. Examples: 'John Doe', 'Company Name', 'MCP God Mode'.")
            }).describe("Email server configuration including service provider, credentials, and connection settings.")
        },
        outputSchema: {
            success: zod_1.z.boolean().describe("Whether the email was sent successfully."),
            message_id: zod_1.z.string().optional().describe("Unique message ID returned by the email server."),
            response: zod_1.z.string().optional().describe("Response message from the email server."),
            error: zod_1.z.string().optional().describe("Error message if the email failed to send."),
            platform: zod_1.z.string().describe("Platform where the email tool was executed."),
            timestamp: zod_1.z.string().describe("Timestamp when the email was sent.")
        }
    }, async ({ to, subject, body, html = false, from, cc, bcc, attachments, email_config }) => {
        try {
            // Validate email configuration
            if (email_config.service === 'custom' && !email_config.host) {
                throw new Error('Host is required for custom SMTP servers');
            }
            const transport = await (0, email_utils_1.getEmailTransport)(email_config);
            // Build the from field
            let fromField;
            if (from) {
                fromField = from;
            }
            else if (email_config.name) {
                fromField = `"${email_config.name}" <${email_config.email}>`;
            }
            else {
                fromField = email_config.email;
            }
            const mailOptions = {
                from: fromField,
                to,
                subject,
                cc,
                bcc
            };
            // Set body content based on HTML flag
            if (html) {
                mailOptions.html = body;
            }
            else {
                mailOptions.text = body;
            }
            // Process attachments if provided
            if (attachments && attachments.length > 0) {
                mailOptions.attachments = attachments.map((att) => ({
                    filename: att.filename,
                    content: Buffer.from(att.content, 'base64'),
                    contentType: att.contentType || 'application/octet-stream'
                }));
            }
            const result = await transport.sendMail(mailOptions);
            return {
                content: [],
                structuredContent: {
                    success: true,
                    message_id: result.messageId,
                    response: `Email sent successfully to ${to}`,
                    error: undefined,
                    platform: environment_1.PLATFORM,
                    timestamp: new Date().toISOString()
                }
            };
        }
        catch (error) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    message_id: undefined,
                    response: undefined,
                    error: `Failed to send email: ${error.message}`,
                    platform: environment_1.PLATFORM,
                    timestamp: new Date().toISOString()
                }
            };
        }
    });
}
