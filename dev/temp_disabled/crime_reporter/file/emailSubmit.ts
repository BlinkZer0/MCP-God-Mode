/**
 * Email Submission System
 * 
 * Handles email-based crime report submission with attachments,
 * multiple transport options, and structured email formatting.
 */

import { NormalizedReport, FilingResult, FilingOptions, EvidenceRef } from '../schema/types.js';
import { ArtifactManager } from './artifacts.js';
import { ContentRenderer } from '../prepare/render.js';

export interface EmailConfig {
  transport: 'smtp' | 'sendmail' | 'gmail' | 'outlook' | 'custom';
  smtp?: {
    host: string;
    port: number;
    secure: boolean;
    auth?: {
      user: string;
      pass: string;
    };
  };
  oauth2?: {
    clientId: string;
    clientSecret: string;
    refreshToken: string;
    accessToken?: string;
  };
  from: string;
  replyTo?: string;
  maxAttachmentSize: number;
  maxTotalSize: number;
  allowedAttachmentTypes: string[];
}

export interface EmailTemplate {
  subject: string;
  htmlBody: string;
  textBody: string;
  attachments: Array<{
    filename: string;
    content: Buffer | string;
    contentType: string;
  }>;
}

export class EmailSubmitter {
  private config: EmailConfig;
  private artifactManager: ArtifactManager;
  private contentRenderer: ContentRenderer;
  private nodemailer: any;

  constructor(config: EmailConfig, artifactManager: ArtifactManager) {
    this.config = config;
    this.artifactManager = artifactManager;
    this.contentRenderer = new ContentRenderer();
  }

  /**
   * Submit report via email
   */
  async submitReport(
    report: NormalizedReport,
    options: FilingOptions
  ): Promise<FilingResult> {
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

    } catch (error) {
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
  private async initializeNodemailer(): Promise<void> {
    if (!this.nodemailer) {
      this.nodemailer = await import('nodemailer');
    }
  }

  /**
   * Prepare email template
   */
  private async prepareEmailTemplate(report: NormalizedReport): Promise<EmailTemplate> {
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
  private generateSubject(report: NormalizedReport): string {
    const crimeType = report.fields.crime_type || 'Crime';
    const location = report.fields.location || 'Unknown Location';
    const date = new Date().toISOString().split('T')[0];
    const caseId = report.caseId;

    return `[Crime Report] ${crimeType} - ${location} - ${date} (${caseId})`;
  }

  /**
   * Validate attachments
   */
  private async validateAttachments(attachments: EvidenceRef[]): Promise<Array<{
    filename: string;
    content: Buffer;
    contentType: string;
    size: number;
  }>> {
    const validatedAttachments: Array<{
      filename: string;
      content: Buffer;
      contentType: string;
      size: number;
    }> = [];

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

        } catch (error) {
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
  private getContentType(filename: string): string {
    const ext = filename.split('.').pop()?.toLowerCase();
    
    const contentTypes: Record<string, string> = {
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
  private async createTransport(): Promise<any> {
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
  private createSmtpTransport(): any {
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
  private createSendmailTransport(): any {
    return this.nodemailer.createTransporter({
      sendmail: true,
      newline: 'unix',
      path: '/usr/sbin/sendmail'
    });
  }

  /**
   * Create Gmail transport
   */
  private createGmailTransport(): any {
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
    } else if (this.config.smtp?.auth) {
      return this.nodemailer.createTransporter({
        service: 'gmail',
        auth: this.config.smtp.auth
      });
    } else {
      throw new Error('Gmail transport requires OAuth2 or SMTP auth configuration');
    }
  }

  /**
   * Create Outlook transport
   */
  private createOutlookTransport(): any {
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
    } else if (this.config.smtp?.auth) {
      return this.nodemailer.createTransporter({
        service: 'hotmail',
        auth: this.config.smtp.auth
      });
    } else {
      throw new Error('Outlook transport requires OAuth2 or SMTP auth configuration');
    }
  }

  /**
   * Create custom transport
   */
  private createCustomTransport(): any {
    // This would be configured based on custom requirements
    throw new Error('Custom transport not implemented');
  }

  /**
   * Send email
   */
  private async sendEmail(
    transport: any,
    template: EmailTemplate,
    attachments: Array<{
      filename: string;
      content: Buffer;
      contentType: string;
      size: number;
    }>
  ): Promise<{
    messageId: string;
    envelope: any;
    accepted: string[];
    rejected: string[];
  }> {
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
  private extractEmailAddress(subject: string): string {
    // This would extract the appropriate email address from the jurisdiction
    // For now, return a placeholder
    return 'crime-reports@example.gov';
  }

  /**
   * Extract case ID from subject
   */
  private extractCaseId(subject: string): string {
    const match = subject.match(/\(([^)]+)\)$/);
    return match ? match[1] : 'unknown';
  }

  /**
   * Create receipt from email result
   */
  private async createReceipt(
    report: NormalizedReport,
    result: any
  ): Promise<FilingResult['receipt']> {
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
  private generateNextSteps(report: NormalizedReport, receipt?: FilingResult['receipt']): string[] {
    const steps = [
      'Report has been submitted via email',
      'Keep a copy of this receipt for your records'
    ];

    if (receipt?.referenceId) {
      steps.push(`Message ID: ${receipt.referenceId}`);
    }

    steps.push(
      'You should receive an automated confirmation email shortly',
      'You may be contacted by law enforcement for additional information',
      'If this is an emergency, call 911 immediately'
    );

    return steps;
  }

  /**
   * Test email configuration
   */
  async testConfiguration(): Promise<{
    success: boolean;
    message: string;
    details?: any;
  }> {
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

    } catch (error) {
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
  getSupportedAttachmentTypes(): string[] {
    return this.config.allowedAttachmentTypes;
  }

  /**
   * Get maximum attachment size
   */
  getMaxAttachmentSize(): number {
    return this.config.maxAttachmentSize;
  }

  /**
   * Get maximum total size
   */
  getMaxTotalSize(): number {
    return this.config.maxTotalSize;
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<EmailConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Create email template for specific jurisdiction
   */
  async createJurisdictionTemplate(
    report: NormalizedReport,
    jurisdictionEmail: string
  ): Promise<EmailTemplate> {
    const template = await this.prepareEmailTemplate(report);
    
    // Customize template for specific jurisdiction
    template.htmlBody = this.customizeHtmlForJurisdiction(template.htmlBody, jurisdictionEmail);
    template.textBody = this.customizeTextForJurisdiction(template.textBody, jurisdictionEmail);
    
    return template;
  }

  /**
   * Customize HTML for jurisdiction
   */
  private customizeHtmlForJurisdiction(html: string, jurisdictionEmail: string): string {
    // Add jurisdiction-specific headers or formatting
    return html.replace(
      '<body>',
      `<body>
        <div class="jurisdiction-header">
          <p><strong>Submitted to:</strong> ${jurisdictionEmail}</p>
          <p><strong>Submission Method:</strong> Email</p>
        </div>`
    );
  }

  /**
   * Customize text for jurisdiction
   */
  private customizeTextForJurisdiction(text: string, jurisdictionEmail: string): string {
    return `Submitted to: ${jurisdictionEmail}
Submission Method: Email

${text}`;
  }
}
