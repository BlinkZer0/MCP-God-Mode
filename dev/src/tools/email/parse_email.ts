import { z } from "zod";
import { simpleParser, AddressObject } from "mailparser";
import { PLATFORM } from "../../config/environment.js";
import { extractLinksFromText, extractEmailsFromText } from "./email_utils.js";

export function registerParseEmail(server: any) {
  server.registerTool("parse_email", {
    description: "Parse and analyze email content across all platforms (Windows, Linux, macOS, Android, iOS). Extract text, HTML, attachments, links, and metadata from raw email content with comprehensive analysis capabilities.",
    inputSchema: {
      email_content: z.string().describe("Raw email content to parse. Can be in MIME format, RFC 2822 format, or other email standards. Examples: Full email message with headers and body, MIME multipart content, or email file content."),
      extract_attachments: z.boolean().default(true).describe("Whether to extract and analyze email attachments. Set to true to process attachments, false to skip attachment processing."),
      extract_links: z.boolean().default(true).describe("Whether to extract URLs and links from email content. Set to true to find all links, false to skip link extraction."),
      extract_emails: z.boolean().default(true).describe("Whether to extract email addresses from email content. Set to true to find all email addresses, false to skip email extraction."),
      include_raw: z.boolean().default(false).describe("Whether to include raw email content in the output. Set to true for debugging, false for clean output.")
    },
    outputSchema: {
      success: z.boolean().describe("Whether the email parsing operation was successful."),
      parsed_email: z.object({
        from: z.string().describe("Sender email address and name."),
        to: z.string().describe("Recipient email address(es)."),
        subject: z.string().describe("Email subject line."),
        date: z.string().describe("Date and time when the email was sent."),
        text: z.string().optional().describe("Plain text content of the email."),
        html: z.string().optional().describe("HTML content of the email."),
        attachments: z.array(z.object({
          filename: z.string().describe("Name of the attachment file."),
          contentType: z.string().describe("MIME type of the attachment."),
          size: z.number().describe("Size of the attachment in bytes."),
          content: z.string().optional().describe("Base64 encoded content of the attachment.")
        })).describe("Array of email attachments with metadata."),
        links: z.array(z.string()).describe("Array of URLs and links found in the email content."),
        emails: z.array(z.string()).describe("Array of email addresses found in the email content."),
        headers: z.record(z.string()).optional().describe("Email headers and metadata."),
        raw_content: z.string().optional().describe("Raw email content if requested.")
      }).describe("Parsed email information with extracted content and metadata."),
      message: z.string().describe("Summary message of the parsing operation."),
      error: z.string().optional().describe("Error message if the parsing operation failed."),
      platform: z.string().describe("Platform where the email tool was executed."),
      timestamp: z.string().describe("Timestamp when the parsing operation was performed.")
    }
  }, async ({ email_content, extract_attachments = true, extract_links = true, extract_emails = true, include_raw = false }: {
    email_content: string;
    extract_attachments?: boolean;
    extract_links?: boolean;
    extract_emails?: boolean;
    include_raw?: boolean;
  }) => {
    try {
      const parsed = await simpleParser(email_content);
      
      // Extract links and emails from text content
      const textContent = parsed.text || '';
      const htmlContent = parsed.html || '';
      const combinedContent = textContent + ' ' + htmlContent;
      
      const links = extract_links ? extractLinksFromText(combinedContent) : [];
      const emails = extract_emails ? extractEmailsFromText(combinedContent) : [];
      
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
          platform: PLATFORM,
          timestamp: new Date().toISOString()
        }
      };
    } catch (error: any) {
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
          platform: PLATFORM,
          timestamp: new Date().toISOString()
        }
      };
    }
  });
}
