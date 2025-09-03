"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerParseEmail = registerParseEmail;
const zod_1 = require("zod");
const mailparser_1 = require("mailparser");
const environment_js_1 = require("../../config/environment.js");
const email_utils_js_1 = require("./email_utils.js");
function registerParseEmail(server) {
    server.registerTool("parse_email", {
        description: "Parse and analyze email content across all platforms (Windows, Linux, macOS, Android, iOS). Extract text, HTML, attachments, links, and metadata from raw email content with comprehensive analysis capabilities.",
        inputSchema: {
            email_content: zod_1.z.string().describe("Raw email content to parse. Can be in MIME format, RFC 2822 format, or other email standards. Examples: Full email message with headers and body, MIME multipart content, or email file content."),
            extract_attachments: zod_1.z.boolean().default(true).describe("Whether to extract and analyze email attachments. Set to true to process attachments, false to skip attachment processing."),
            extract_links: zod_1.z.boolean().default(true).describe("Whether to extract URLs and links from email content. Set to true to find all links, false to skip link extraction."),
            extract_emails: zod_1.z.boolean().default(true).describe("Whether to extract email addresses from email content. Set to true to find all email addresses, false to skip email extraction."),
            include_raw: zod_1.z.boolean().default(false).describe("Whether to include raw email content in the output. Set to true for debugging, false for clean output.")
        },
        outputSchema: {
            success: zod_1.z.boolean().describe("Whether the email parsing operation was successful."),
            parsed_email: zod_1.z.object({
                from: zod_1.z.string().describe("Sender email address and name."),
                to: zod_1.z.string().describe("Recipient email address(es)."),
                subject: zod_1.z.string().describe("Email subject line."),
                date: zod_1.z.string().describe("Date and time when the email was sent."),
                text: zod_1.z.string().optional().describe("Plain text content of the email."),
                html: zod_1.z.string().optional().describe("HTML content of the email."),
                attachments: zod_1.z.array(zod_1.z.object({
                    filename: zod_1.z.string().describe("Name of the attachment file."),
                    contentType: zod_1.z.string().describe("MIME type of the attachment."),
                    size: zod_1.z.number().describe("Size of the attachment in bytes."),
                    content: zod_1.z.string().optional().describe("Base64 encoded content of the attachment.")
                })).describe("Array of email attachments with metadata."),
                links: zod_1.z.array(zod_1.z.string()).describe("Array of URLs and links found in the email content."),
                emails: zod_1.z.array(zod_1.z.string()).describe("Array of email addresses found in the email content."),
                headers: zod_1.z.record(zod_1.z.string()).optional().describe("Email headers and metadata."),
                raw_content: zod_1.z.string().optional().describe("Raw email content if requested.")
            }).describe("Parsed email information with extracted content and metadata."),
            message: zod_1.z.string().describe("Summary message of the parsing operation."),
            error: zod_1.z.string().optional().describe("Error message if the parsing operation failed."),
            platform: zod_1.z.string().describe("Platform where the email tool was executed."),
            timestamp: zod_1.z.string().describe("Timestamp when the parsing operation was performed.")
        }
    }, async ({ email_content, extract_attachments = true, extract_links = true, extract_emails = true, include_raw = false }) => {
        try {
            const parsed = await (0, mailparser_1.simpleParser)(email_content);
            // Extract links and emails from text content
            const textContent = parsed.text || '';
            const htmlContent = parsed.html || '';
            const combinedContent = textContent + ' ' + htmlContent;
            const links = extract_links ? (0, email_utils_js_1.extractLinksFromText)(combinedContent) : [];
            const emails = extract_emails ? (0, email_utils_js_1.extractEmailsFromText)(combinedContent) : [];
            // Process attachments
            const attachments = extract_attachments ? (parsed.attachments || []).map(att => ({
                filename: att.filename || 'unnamed',
                contentType: att.contentType || 'application/octet-stream',
                size: att.size || 0,
                content: att.content ? att.content.toString('base64') : undefined
            })) : [];
            // Handle recipient field properly
            const to = Array.isArray(parsed.to) ? parsed.to[0]?.text || 'Unknown Recipient' : parsed.to?.text || 'Unknown Recipient';
            return {
                content: [],
                structuredContent: {
                    success: true,
                    parsed_email: {
                        from: parsed.from?.text || 'Unknown Sender',
                        to,
                        subject: parsed.subject || 'No Subject',
                        date: parsed.date?.toISOString() || 'Unknown Date',
                        text: parsed.text,
                        html: parsed.html,
                        attachments,
                        links,
                        emails,
                        headers: include_raw ? parsed.headers : undefined,
                        raw_content: include_raw ? email_content : undefined
                    },
                    message: `Successfully parsed email with ${attachments.length} attachments, ${links.length} links, and ${emails.length} email addresses`,
                    error: undefined,
                    platform: environment_js_1.PLATFORM,
                    timestamp: new Date().toISOString()
                }
            };
        }
        catch (error) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    parsed_email: {
                        from: 'Unknown',
                        to: 'Unknown',
                        subject: 'Unknown',
                        date: 'Unknown',
                        text: undefined,
                        html: undefined,
                        attachments: [],
                        links: [],
                        emails: [],
                        headers: undefined,
                        raw_content: undefined
                    },
                    message: "Email parsing operation failed",
                    error: `Failed to parse email: ${error.message}`,
                    platform: environment_js_1.PLATFORM,
                    timestamp: new Date().toISOString()
                }
            };
        }
    });
}
