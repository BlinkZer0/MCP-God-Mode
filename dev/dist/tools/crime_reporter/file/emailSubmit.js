/**
 * Email Submission System
 *
 * Handles email-based crime report submission with attachments,
 * multiple transport options, and structured email formatting.
 */
import { ContentRenderer } from '../prepare/render.js';
export class EmailSubmitter {
    config;
    artifactManager;
    contentRenderer;
    nodemailer;
    constructor(config, artifactManager) {
        this.config = config;
        this.artifactManager = artifactManager;
        this.contentRenderer = new ContentRenderer();
    }
    /**
     * Submit report via email
     */
    async submitReport(report, options) {
        try {
            // Initialize nodemailer
            await this.initializeNodemailer();
            // Prepare email template
            const emailTemplate = await this.prepareEmailTemplate(report);
            // Validate attachments
            const validatedAttachments = await this.validateAttachments(report.attachments);
            // Create transport
            const transport = await this.createTransport();
            // Send email
            const result = await this.sendEmail(transport, emailTemplate, validatedAttachments);
            // Save receipt
            const receipt = await this.createReceipt(report, result);
            return {
                status: 'submitted',
                receipt,
                artifacts: {
                    json: await this.artifactManager.saveReceipt(receipt, report.caseId)
                },
                nextSteps: this.generateNextSteps(report, receipt)
            };
        }
        catch (error) {
            return {
                status: 'failed',
                errors: [error instanceof Error ? error.message : 'Unknown error occurred'],
                artifacts: {}
            };
        }
    }
    /**
     * Initialize nodemailer
     */
    async initializeNodemailer() {
        if (!this.nodemailer) {
            this.nodemailer = await import('nodemailer');
        }
    }
    /**
     * Prepare email template
     */
    async prepareEmailTemplate(report) {
        // Generate subject
        const subject = this.generateSubject(report);
        // Render content
        const htmlResult = await this.contentRenderer.renderReport(report, {
            format: 'html',
            includeHeader: true,
            includeFooter: true,
            includeAiNotes: true,
            includeEvidence: true,
            includeTimeline: true,
            style: 'official'
        });
        const textResult = await this.contentRenderer.renderReport(report, {
            format: 'plain',
            includeHeader: true,
            includeFooter: true,
            includeAiNotes: true,
            includeEvidence: true,
            includeTimeline: true
        });
        return {
            subject,
            htmlBody: htmlResult.content,
            textBody: textResult.content,
            attachments: []
        };
    }
    /**
     * Generate email subject
     */
    generateSubject(report) {
        const crimeType = report.fields.crime_type || 'Crime';
        const location = report.fields.location || 'Unknown Location';
        const date = new Date().toISOString().split('T')[0];
        const caseId = report.caseId;
        return `[Crime Report] ${crimeType} - ${location} - ${date} (${caseId})`;
    }
    /**
     * Validate attachments
     */
    async validateAttachments(attachments) {
        const validatedAttachments = [];
        for (const attachment of attachments) {
            if (attachment.kind === 'file') {
                try {
                    const fs = await import('fs/promises');
                    const stats = await fs.stat(attachment.path);
                    // Check file size
                    if (stats.size > this.config.maxAttachmentSize) {
                        console.warn(`File ${attachment.path} exceeds maximum size limit`);
                        continue;
                    }
                    // Check file type
                    const ext = attachment.path.split('.').pop()?.toLowerCase();
                    if (ext && !this.config.allowedAttachmentTypes.includes(ext)) {
                        console.warn(`File type ${ext} not allowed`);
                        continue;
                    }
                    // Read file content
                    const content = await fs.readFile(attachment.path);
                    const contentType = this.getContentType(attachment.path);
                    validatedAttachments.push({
                        filename: attachment.path.split('/').pop() || 'attachment',
                        content,
                        contentType,
                        size: stats.size
                    });
                }
                catch (error) {
                    console.warn(`Failed to process attachment ${attachment.path}: ${error}`);
                }
            }
        }
        // Check total size
        const totalSize = validatedAttachments.reduce((sum, att) => sum + att.size, 0);
        if (totalSize > this.config.maxTotalSize) {
            throw new Error(`Total attachment size (${totalSize} bytes) exceeds limit (${this.config.maxTotalSize} bytes)`);
        }
        return validatedAttachments;
    }
    /**
     * Get content type for file
     */
    getContentType(filename) {
        const ext = filename.split('.').pop()?.toLowerCase();
        const contentTypes = {
            'pdf': 'application/pdf',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'txt': 'text/plain',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'mp4': 'video/mp4',
            'avi': 'video/x-msvideo',
            'mov': 'video/quicktime',
            'zip': 'application/zip',
            'json': 'application/json',
            'xml': 'application/xml'
        };
        return contentTypes[ext || ''] || 'application/octet-stream';
    }
    /**
     * Create email transport
     */
    async createTransport() {
        switch (this.config.transport) {
            case 'smtp':
                return this.createSmtpTransport();
            case 'sendmail':
                return this.createSendmailTransport();
            case 'gmail':
                return this.createGmailTransport();
            case 'outlook':
                return this.createOutlookTransport();
            case 'custom':
                return this.createCustomTransport();
            default:
                throw new Error(`Unsupported transport: ${this.config.transport}`);
        }
    }
    /**
     * Create SMTP transport
     */
    createSmtpTransport() {
        if (!this.config.smtp) {
            throw new Error('SMTP configuration required');
        }
        return this.nodemailer.createTransporter({
            host: this.config.smtp.host,
            port: this.config.smtp.port,
            secure: this.config.smtp.secure,
            auth: this.config.smtp.auth
        });
    }
    /**
     * Create sendmail transport
     */
    createSendmailTransport() {
        return this.nodemailer.createTransporter({
            sendmail: true,
            newline: 'unix',
            path: '/usr/sbin/sendmail'
        });
    }
    /**
     * Create Gmail transport
     */
    createGmailTransport() {
        if (this.config.oauth2) {
            return this.nodemailer.createTransporter({
                service: 'gmail',
                auth: {
                    type: 'OAuth2',
                    user: this.config.from,
                    clientId: this.config.oauth2.clientId,
                    clientSecret: this.config.oauth2.clientSecret,
                    refreshToken: this.config.oauth2.refreshToken,
                    accessToken: this.config.oauth2.accessToken
                }
            });
        }
        else if (this.config.smtp?.auth) {
            return this.nodemailer.createTransporter({
                service: 'gmail',
                auth: this.config.smtp.auth
            });
        }
        else {
            throw new Error('Gmail transport requires OAuth2 or SMTP auth configuration');
        }
    }
    /**
     * Create Outlook transport
     */
    createOutlookTransport() {
        if (this.config.oauth2) {
            return this.nodemailer.createTransporter({
                service: 'hotmail',
                auth: {
                    type: 'OAuth2',
                    user: this.config.from,
                    clientId: this.config.oauth2.clientId,
                    clientSecret: this.config.oauth2.clientSecret,
                    refreshToken: this.config.oauth2.refreshToken,
                    accessToken: this.config.oauth2.accessToken
                }
            });
        }
        else if (this.config.smtp?.auth) {
            return this.nodemailer.createTransporter({
                service: 'hotmail',
                auth: this.config.smtp.auth
            });
        }
        else {
            throw new Error('Outlook transport requires OAuth2 or SMTP auth configuration');
        }
    }
    /**
     * Create custom transport
     */
    createCustomTransport() {
        // This would be configured based on custom requirements
        throw new Error('Custom transport not implemented');
    }
    /**
     * Send email
     */
    async sendEmail(transport, template, attachments) {
        const mailOptions = {
            from: this.config.from,
            replyTo: this.config.replyTo || this.config.from,
            to: this.extractEmailAddress(template.subject), // This would be extracted from jurisdiction
            subject: template.subject,
            text: template.textBody,
            html: template.htmlBody,
            attachments: attachments.map(att => ({
                filename: att.filename,
                content: att.content,
                contentType: att.contentType
            })),
            headers: {
                'X-Case-ID': this.extractCaseId(template.subject),
                'X-Report-Type': 'Crime Report',
                'X-Generated-By': 'Crime Reporter Tool',
                'X-Timestamp': new Date().toISOString()
            }
        };
        return await transport.sendMail(mailOptions);
    }
    /**
     * Extract email address from jurisdiction (placeholder)
     */
    extractEmailAddress(subject) {
        // This would extract the appropriate email address from the jurisdiction
        // For now, return a placeholder
        return 'crime-reports@example.gov';
    }
    /**
     * Extract case ID from subject
     */
    extractCaseId(subject) {
        const match = subject.match(/\(([^)]+)\)$/);
        return match ? match[1] : 'unknown';
    }
    /**
     * Create receipt from email result
     */
    async createReceipt(report, result) {
        return {
            referenceId: result.messageId,
            timestamp: new Date().toISOString(),
            method: 'email',
            confirmationNumber: result.messageId
        };
    }
    /**
     * Generate next steps
     */
    generateNextSteps(report, receipt) {
        const steps = [
            'Report has been submitted via email',
            'Keep a copy of this receipt for your records'
        ];
        if (receipt?.referenceId) {
            steps.push(`Message ID: ${receipt.referenceId}`);
        }
        steps.push('You should receive an automated confirmation email shortly', 'You may be contacted by law enforcement for additional information', 'If this is an emergency, call 911 immediately');
        return steps;
    }
    /**
     * Test email configuration
     */
    async testConfiguration() {
        try {
            await this.initializeNodemailer();
            const transport = await this.createTransport();
            // Send test email
            const testResult = await transport.sendMail({
                from: this.config.from,
                to: this.config.from, // Send to self for testing
                subject: 'Crime Reporter Test Email',
                text: 'This is a test email from the Crime Reporter tool.',
                html: '<p>This is a test email from the Crime Reporter tool.</p>'
            });
            return {
                success: true,
                message: 'Email configuration test successful',
                details: {
                    messageId: testResult.messageId,
                    accepted: testResult.accepted,
                    rejected: testResult.rejected
                }
            };
        }
        catch (error) {
            return {
                success: false,
                message: `Email configuration test failed: ${error}`,
                details: error
            };
        }
    }
    /**
     * Get supported attachment types
     */
    getSupportedAttachmentTypes() {
        return this.config.allowedAttachmentTypes;
    }
    /**
     * Get maximum attachment size
     */
    getMaxAttachmentSize() {
        return this.config.maxAttachmentSize;
    }
    /**
     * Get maximum total size
     */
    getMaxTotalSize() {
        return this.config.maxTotalSize;
    }
    /**
     * Update configuration
     */
    updateConfig(config) {
        this.config = { ...this.config, ...config };
    }
    /**
     * Create email template for specific jurisdiction
     */
    async createJurisdictionTemplate(report, jurisdictionEmail) {
        const template = await this.prepareEmailTemplate(report);
        // Customize template for specific jurisdiction
        template.htmlBody = this.customizeHtmlForJurisdiction(template.htmlBody, jurisdictionEmail);
        template.textBody = this.customizeTextForJurisdiction(template.textBody, jurisdictionEmail);
        return template;
    }
    /**
     * Customize HTML for jurisdiction
     */
    customizeHtmlForJurisdiction(html, jurisdictionEmail) {
        // Add jurisdiction-specific headers or formatting
        return html.replace('<body>', `<body>
        <div class="jurisdiction-header">
          <p><strong>Submitted to:</strong> ${jurisdictionEmail}</p>
          <p><strong>Submission Method:</strong> Email</p>
        </div>`);
    }
    /**
     * Customize text for jurisdiction
     */
    customizeTextForJurisdiction(text, jurisdictionEmail) {
        return `Submitted to: ${jurisdictionEmail}
Submission Method: Email

${text}`;
    }
}
