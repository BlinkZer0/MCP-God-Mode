/**
 * Case Normalization
 *
 * Converts CaseBundle to NormalizedReport with proper field mapping
 * and content preparation for different submission channels.
 */
export class CaseNormalizer {
    fieldMappings;
    constructor() {
        this.fieldMappings = new Map();
        this.initializeDefaultMappings();
    }
    /**
     * Prepare a normalized report from case bundle
     */
    async prepareReport(options) {
        const { caseBundle, targetJurisdiction, anonymous = true, includeAiNotes = true } = options;
        // Select the best channel
        const channel = this.selectBestChannel(targetJurisdiction);
        // Normalize the case bundle
        const normalizedBundle = await this.normalizeCaseBundle(caseBundle, anonymous);
        // Map fields for the target channel
        const fields = await this.mapFields(normalizedBundle, channel, targetJurisdiction);
        // Prepare attachments
        const attachments = await this.prepareAttachments(normalizedBundle.evidence || []);
        // Render content
        const renderedContent = await this.renderContent(normalizedBundle, includeAiNotes);
        return {
            caseId: normalizedBundle.caseId,
            jurisdiction: {
                name: targetJurisdiction?.name || 'Unknown',
                type: targetJurisdiction?.type || 'other',
                channel
            },
            fields,
            attachments,
            anonymous,
            renderedContent
        };
    }
    /**
     * Select the best available channel from jurisdiction
     */
    selectBestChannel(jurisdiction) {
        if (!jurisdiction || !jurisdiction.channels.length) {
            return {
                mode: 'email',
                urlOrAddress: 'No official channel available',
                notes: 'Fallback to email',
                priority: 3
            };
        }
        // Sort by priority and select the best
        const sortedChannels = jurisdiction.channels.sort((a, b) => a.priority - b.priority);
        return sortedChannels[0];
    }
    /**
     * Normalize case bundle with anonymization
     */
    async normalizeCaseBundle(bundle, anonymous) {
        const normalized = { ...bundle };
        // Ensure case ID
        if (!normalized.caseId) {
            normalized.caseId = this.generateCaseId();
        }
        // Ensure timestamp
        if (!normalized.createdAt) {
            normalized.createdAt = new Date().toISOString();
        }
        // Set anonymity
        normalized.anonymous = anonymous;
        // Anonymize if requested
        if (anonymous) {
            normalized.involved = this.anonymizePersons(normalized.involved || []);
        }
        return normalized;
    }
    /**
     * Generate unique case ID
     */
    generateCaseId() {
        const timestamp = Date.now().toString(36);
        const random = Math.random().toString(36).substring(2, 8);
        return `CR-${timestamp}-${random}`.toUpperCase();
    }
    /**
     * Anonymize person information
     */
    anonymizePersons(persons) {
        return persons.map(person => {
            const anonymized = { ...person };
            // Remove identifying information
            delete anonymized.name;
            delete anonymized.contact;
            delete anonymized.address;
            // Keep role and notes (sanitized)
            if (anonymized.notes) {
                anonymized.notes = this.sanitizeNotes(anonymized.notes);
            }
            return anonymized;
        });
    }
    /**
     * Sanitize notes to remove potential PII
     */
    sanitizeNotes(notes) {
        // Remove common PII patterns
        return notes
            .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN]') // SSN
            .replace(/\b\d{3}-\d{3}-\d{4}\b/g, '[PHONE]') // Phone
            .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL]') // Email
            .replace(/\b\d{1,5}\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd)\b/g, '[ADDRESS]'); // Address
    }
    /**
     * Map case bundle fields to form/email fields
     */
    async mapFields(bundle, channel, jurisdiction) {
        const fields = {};
        // Basic case information
        fields['case_id'] = bundle.caseId;
        fields['crime_type'] = bundle.crimeType || 'Unknown';
        fields['location'] = bundle.location.raw;
        fields['narrative'] = bundle.narrative;
        fields['date_occurred'] = this.extractDateFromTimeline(bundle.timeline);
        fields['time_occurred'] = this.extractTimeFromTimeline(bundle.timeline);
        // Contact information (if not anonymous)
        if (!bundle.anonymous) {
            const reporter = bundle.involved?.find(p => p.role === 'reporter');
            if (reporter) {
                fields['reporter_name'] = reporter.name || '';
                fields['reporter_phone'] = reporter.contact?.phone || '';
                fields['reporter_email'] = reporter.contact?.email || '';
                fields['reporter_address'] = reporter.address || '';
            }
        }
        // Legal flags
        if (bundle.legalFlags) {
            fields['immediate_danger'] = bundle.legalFlags.immediateDanger ? 'Yes' : 'No';
            fields['firearms_involved'] = bundle.legalFlags.firearms ? 'Yes' : 'No';
            fields['minors_involved'] = bundle.legalFlags.minorsInvolved ? 'Yes' : 'No';
        }
        // AI model notes summary
        if (bundle.aiNotes && bundle.aiNotes.length > 0) {
            fields['ai_analysis'] = this.summarizeAiNotes(bundle.aiNotes);
        }
        // Timeline summary
        if (bundle.timeline && bundle.timeline.length > 0) {
            fields['timeline'] = this.summarizeTimeline(bundle.timeline);
        }
        // Evidence summary
        if (bundle.evidence && bundle.evidence.length > 0) {
            fields['evidence_count'] = bundle.evidence.length.toString();
            fields['evidence_types'] = this.summarizeEvidence(bundle.evidence);
        }
        // Apply channel-specific field mappings
        const channelFields = this.getChannelFieldMappings(channel, jurisdiction);
        return this.applyFieldMappings(fields, channelFields);
    }
    /**
     * Extract date from timeline
     */
    extractDateFromTimeline(timeline) {
        if (!timeline || timeline.length === 0) {
            return new Date().toISOString().split('T')[0];
        }
        // Get the earliest event date
        const dates = timeline.map(event => new Date(event.when));
        const earliest = new Date(Math.min(...dates.map(d => d.getTime())));
        return earliest.toISOString().split('T')[0];
    }
    /**
     * Extract time from timeline
     */
    extractTimeFromTimeline(timeline) {
        if (!timeline || timeline.length === 0) {
            return 'Unknown';
        }
        // Get the earliest event time
        const dates = timeline.map(event => new Date(event.when));
        const earliest = new Date(Math.min(...dates.map(d => d.getTime())));
        return earliest.toTimeString().split(' ')[0];
    }
    /**
     * Summarize AI model notes
     */
    summarizeAiNotes(aiNotes) {
        return aiNotes.map(note => `${note.model}: ${note.summary}${note.confidence ? ` (${Math.round(note.confidence * 100)}% confidence)` : ''}`).join('\n');
    }
    /**
     * Summarize timeline
     */
    summarizeTimeline(timeline) {
        return timeline.map(event => `${event.when}: ${event.title}${event.details ? ` - ${event.details}` : ''}`).join('\n');
    }
    /**
     * Summarize evidence
     */
    summarizeEvidence(evidence) {
        const types = evidence.map(e => e.kind);
        const uniqueTypes = [...new Set(types)];
        return uniqueTypes.join(', ');
    }
    /**
     * Prepare attachments for submission
     */
    async prepareAttachments(evidence) {
        const attachments = [];
        for (const item of evidence) {
            if (item.kind === 'file') {
                // Validate file exists and is accessible
                const isValid = await this.validateFile(item.path);
                if (isValid) {
                    attachments.push(item);
                }
            }
            else if (item.kind === 'url') {
                // Validate URL is accessible
                const isValid = await this.validateUrl(item.url);
                if (isValid) {
                    attachments.push(item);
                }
            }
            else if (item.kind === 'text') {
                // Text evidence is included in the report body
                attachments.push(item);
            }
        }
        return attachments;
    }
    /**
     * Validate file exists and is accessible
     */
    async validateFile(path) {
        try {
            const fs = await import('fs/promises');
            await fs.access(path);
            return true;
        }
        catch (error) {
            console.warn(`File not accessible: ${path}`);
            return false;
        }
    }
    /**
     * Validate URL is accessible
     */
    async validateUrl(url) {
        try {
            const response = await fetch(url, { method: 'HEAD' });
            return response.ok;
        }
        catch (error) {
            console.warn(`URL not accessible: ${url}`);
            return false;
        }
    }
    /**
     * Render content in multiple formats
     */
    async renderContent(bundle, includeAiNotes) {
        return {
            html: this.renderHtml(bundle, includeAiNotes),
            markdown: this.renderMarkdown(bundle, includeAiNotes),
            plainText: this.renderPlainText(bundle, includeAiNotes)
        };
    }
    /**
     * Render HTML content
     */
    renderHtml(bundle, includeAiNotes) {
        const html = `
      <div class="crime-report">
        <h1>Crime Report - ${bundle.caseId}</h1>
        <div class="report-meta">
          <p><strong>Date:</strong> ${bundle.createdAt}</p>
          <p><strong>Crime Type:</strong> ${bundle.crimeType || 'Unknown'}</p>
          <p><strong>Location:</strong> ${bundle.location.raw}</p>
          <p><strong>Anonymous:</strong> ${bundle.anonymous ? 'Yes' : 'No'}</p>
        </div>
        
        <div class="narrative">
          <h2>Incident Description</h2>
          <p>${bundle.narrative}</p>
        </div>
        
        ${bundle.timeline && bundle.timeline.length > 0 ? `
          <div class="timeline">
            <h2>Timeline</h2>
            <ul>
              ${bundle.timeline.map(event => `
                <li>
                  <strong>${event.when}:</strong> ${event.title}
                  ${event.details ? `<br><em>${event.details}</em>` : ''}
                </li>
              `).join('')}
            </ul>
          </div>
        ` : ''}
        
        ${includeAiNotes && bundle.aiNotes && bundle.aiNotes.length > 0 ? `
          <div class="ai-analysis">
            <h2>AI Analysis</h2>
            ${bundle.aiNotes.map(note => `
              <div class="ai-note">
                <h3>${note.model}</h3>
                <p>${note.summary}</p>
                ${note.confidence ? `<p><em>Confidence: ${Math.round(note.confidence * 100)}%</em></p>` : ''}
              </div>
            `).join('')}
          </div>
        ` : ''}
        
        ${bundle.evidence && bundle.evidence.length > 0 ? `
          <div class="evidence">
            <h2>Evidence</h2>
            <ul>
              ${bundle.evidence.map(item => `
                <li>
                  <strong>${item.kind}:</strong> 
                  ${item.kind === 'file' ? item.path :
            item.kind === 'url' ? item.url :
                'Text evidence'}
                  ${item.description ? `<br><em>${item.description}</em>` : ''}
                </li>
              `).join('')}
            </ul>
          </div>
        ` : ''}
      </div>
    `;
        return html;
    }
    /**
     * Render Markdown content
     */
    renderMarkdown(bundle, includeAiNotes) {
        let markdown = `# Crime Report - ${bundle.caseId}\n\n`;
        markdown += `**Date:** ${bundle.createdAt}\n`;
        markdown += `**Crime Type:** ${bundle.crimeType || 'Unknown'}\n`;
        markdown += `**Location:** ${bundle.location.raw}\n`;
        markdown += `**Anonymous:** ${bundle.anonymous ? 'Yes' : 'No'}\n\n`;
        markdown += `## Incident Description\n\n${bundle.narrative}\n\n`;
        if (bundle.timeline && bundle.timeline.length > 0) {
            markdown += `## Timeline\n\n`;
            bundle.timeline.forEach(event => {
                markdown += `- **${event.when}:** ${event.title}`;
                if (event.details) {
                    markdown += `\n  - ${event.details}`;
                }
                markdown += '\n';
            });
            markdown += '\n';
        }
        if (includeAiNotes && bundle.aiNotes && bundle.aiNotes.length > 0) {
            markdown += `## AI Analysis\n\n`;
            bundle.aiNotes.forEach(note => {
                markdown += `### ${note.model}\n\n${note.summary}\n`;
                if (note.confidence) {
                    markdown += `*Confidence: ${Math.round(note.confidence * 100)}%*\n\n`;
                }
            });
        }
        if (bundle.evidence && bundle.evidence.length > 0) {
            markdown += `## Evidence\n\n`;
            bundle.evidence.forEach(item => {
                markdown += `- **${item.kind}:** `;
                if (item.kind === 'file') {
                    markdown += item.path;
                }
                else if (item.kind === 'url') {
                    markdown += item.url;
                }
                else {
                    markdown += 'Text evidence';
                }
                if (item.description) {
                    markdown += `\n  - ${item.description}`;
                }
                markdown += '\n';
            });
        }
        return markdown;
    }
    /**
     * Render plain text content
     */
    renderPlainText(bundle, includeAiNotes) {
        let text = `CRIME REPORT - ${bundle.caseId}\n\n`;
        text += `Date: ${bundle.createdAt}\n`;
        text += `Crime Type: ${bundle.crimeType || 'Unknown'}\n`;
        text += `Location: ${bundle.location.raw}\n`;
        text += `Anonymous: ${bundle.anonymous ? 'Yes' : 'No'}\n\n`;
        text += `INCIDENT DESCRIPTION:\n${bundle.narrative}\n\n`;
        if (bundle.timeline && bundle.timeline.length > 0) {
            text += `TIMELINE:\n`;
            bundle.timeline.forEach(event => {
                text += `${event.when}: ${event.title}`;
                if (event.details) {
                    text += ` - ${event.details}`;
                }
                text += '\n';
            });
            text += '\n';
        }
        if (includeAiNotes && bundle.aiNotes && bundle.aiNotes.length > 0) {
            text += `AI ANALYSIS:\n`;
            bundle.aiNotes.forEach(note => {
                text += `${note.model}: ${note.summary}`;
                if (note.confidence) {
                    text += ` (${Math.round(note.confidence * 100)}% confidence)`;
                }
                text += '\n';
            });
            text += '\n';
        }
        if (bundle.evidence && bundle.evidence.length > 0) {
            text += `EVIDENCE:\n`;
            bundle.evidence.forEach(item => {
                text += `${item.kind}: `;
                if (item.kind === 'file') {
                    text += item.path;
                }
                else if (item.kind === 'url') {
                    text += item.url;
                }
                else {
                    text += 'Text evidence';
                }
                if (item.description) {
                    text += ` - ${item.description}`;
                }
                text += '\n';
            });
        }
        return text;
    }
    /**
     * Initialize default field mappings
     */
    initializeDefaultMappings() {
        // Add default mappings for common form fields
        this.fieldMappings.set('default', {
            'case_id': 'case_id',
            'crime_type': 'crime_type',
            'location': 'location',
            'narrative': 'description',
            'date_occurred': 'date',
            'time_occurred': 'time',
            'reporter_name': 'name',
            'reporter_phone': 'phone',
            'reporter_email': 'email',
            'reporter_address': 'address'
        });
    }
    /**
     * Get channel-specific field mappings
     */
    getChannelFieldMappings(channel, jurisdiction) {
        const domain = jurisdiction?.domain || 'default';
        return this.fieldMappings.get(domain) || this.fieldMappings.get('default') || {};
    }
    /**
     * Apply field mappings to normalized fields
     */
    applyFieldMappings(fields, mappings) {
        const mapped = {};
        for (const [sourceField, targetField] of Object.entries(mappings)) {
            if (fields[sourceField]) {
                mapped[targetField] = fields[sourceField];
            }
        }
        return mapped;
    }
}
