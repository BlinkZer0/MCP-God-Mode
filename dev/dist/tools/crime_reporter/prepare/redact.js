/**
 * PII Redaction and Anonymization
 *
 * Provides comprehensive PII detection and redaction capabilities
 * for crime reports with configurable sensitivity levels.
 */
export class PIIRedactor {
    patterns;
    replacements;
    constructor() {
        this.patterns = new Map();
        this.replacements = new Map();
        this.initializePatterns();
    }
    /**
     * Redact PII from text content
     */
    redactText(text, options = { level: 'standard' }) {
        const redactions = [];
        let redactedText = text;
        let totalConfidence = 0;
        // Apply standard PII patterns
        const standardRedactions = this.applyStandardPatterns(redactedText, options);
        redactions.push(...standardRedactions.redactions);
        redactedText = standardRedactions.text;
        totalConfidence += standardRedactions.confidence;
        // Apply custom patterns if provided
        if (options.customPatterns) {
            const customRedactions = this.applyCustomPatterns(redactedText, options.customPatterns);
            redactions.push(...customRedactions.redactions);
            redactedText = customRedactions.text;
            totalConfidence += customRedactions.confidence;
        }
        // Apply level-specific redactions
        const levelRedactions = this.applyLevelRedactions(redactedText, options.level);
        redactions.push(...levelRedactions.redactions);
        redactedText = levelRedactions.text;
        totalConfidence += levelRedactions.confidence;
        // Sort redactions by position (reverse order to maintain indices)
        redactions.sort((a, b) => b.start - a.start);
        return {
            original: text,
            redacted: redactedText,
            redactions,
            confidence: totalConfidence / Math.max(1, redactions.length)
        };
    }
    /**
     * Redact PII from structured data
     */
    redactObject(obj, options = { level: 'standard' }) {
        if (typeof obj !== 'object' || obj === null) {
            return obj;
        }
        const redacted = Array.isArray(obj) ? [] : {};
        for (const [key, value] of Object.entries(obj)) {
            // Check if field should be blocked
            if (options.blockedFields?.includes(key)) {
                continue;
            }
            // Check if field is allowed
            if (options.allowedFields && !options.allowedFields.includes(key)) {
                continue;
            }
            if (typeof value === 'string') {
                const result = this.redactText(value, options);
                redacted[key] = result.redacted;
            }
            else if (typeof value === 'object') {
                redacted[key] = this.redactObject(value, options);
            }
            else {
                redacted[key] = value;
            }
        }
        return redacted;
    }
    /**
     * Initialize PII detection patterns
     */
    initializePatterns() {
        // Social Security Numbers
        this.patterns.set('ssn', /\b\d{3}-?\d{2}-?\d{4}\b/g);
        this.replacements.set('ssn', '[SSN]');
        // Phone Numbers
        this.patterns.set('phone', /\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g);
        this.replacements.set('phone', '[PHONE]');
        // Email Addresses
        this.patterns.set('email', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g);
        this.replacements.set('email', '[EMAIL]');
        // Credit Card Numbers
        this.patterns.set('creditcard', /\b(?:\d{4}[-\s]?){3}\d{4}\b/g);
        this.replacements.set('creditcard', '[CREDIT_CARD]');
        // Bank Account Numbers
        this.patterns.set('bankaccount', /\b\d{8,17}\b/g);
        this.replacements.set('bankaccount', '[BANK_ACCOUNT]');
        // Driver's License
        this.patterns.set('driverslicense', /\b[A-Z]{1,2}\d{6,8}\b/g);
        this.replacements.set('driverslicense', '[DRIVERS_LICENSE]');
        // Passport Numbers
        this.patterns.set('passport', /\b[A-Z]{1,2}\d{6,9}\b/g);
        this.replacements.set('passport', '[PASSPORT]');
        // IP Addresses
        this.patterns.set('ipaddress', /\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
        this.replacements.set('ipaddress', '[IP_ADDRESS]');
        // MAC Addresses
        this.patterns.set('macaddress', /\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b/g);
        this.replacements.set('macaddress', '[MAC_ADDRESS]');
        // URLs
        this.patterns.set('url', /https?:\/\/[^\s]+/g);
        this.replacements.set('url', '[URL]');
        // Names (common patterns)
        this.patterns.set('name', /\b[A-Z][a-z]+ [A-Z][a-z]+\b/g);
        this.replacements.set('name', '[NAME]');
        // Addresses
        this.patterns.set('address', /\b\d{1,5}\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Way|Circle|Ct|Court|Place|Pl)\b/g);
        this.replacements.set('address', '[ADDRESS]');
        // ZIP Codes
        this.patterns.set('zipcode', /\b\d{5}(?:-\d{4})?\b/g);
        this.replacements.set('zipcode', '[ZIP_CODE]');
        // Dates (various formats)
        this.patterns.set('date', /\b(?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2})\b/g);
        this.replacements.set('date', '[DATE]');
        // Times
        this.patterns.set('time', /\b\d{1,2}:\d{2}(?::\d{2})?(?:\s?[AP]M)?\b/gi);
        this.replacements.set('time', '[TIME]');
    }
    /**
     * Apply standard PII patterns
     */
    applyStandardPatterns(text, options) {
        const redactions = [];
        let redactedText = text;
        let totalConfidence = 0;
        for (const [type, pattern] of this.patterns) {
            const replacement = this.replacements.get(type) || `[${type.toUpperCase()}]`;
            let match;
            while ((match = pattern.exec(text)) !== null) {
                const start = match.index;
                const end = start + match[0].length;
                const confidence = this.calculateConfidence(type, match[0]);
                redactions.push({
                    type,
                    pattern: match[0],
                    start,
                    end,
                    replacement,
                    confidence
                });
                totalConfidence += confidence;
            }
            // Apply replacements
            redactedText = redactedText.replace(pattern, replacement);
        }
        return {
            text: redactedText,
            redactions,
            confidence: totalConfidence / Math.max(1, redactions.length)
        };
    }
    /**
     * Apply custom patterns
     */
    applyCustomPatterns(text, patterns) {
        const redactions = [];
        let redactedText = text;
        let totalConfidence = 0;
        for (const pattern of patterns) {
            let match;
            while ((match = pattern.exec(text)) !== null) {
                const start = match.index;
                const end = start + match[0].length;
                const confidence = 0.8; // Default confidence for custom patterns
                redactions.push({
                    type: 'custom',
                    pattern: match[0],
                    start,
                    end,
                    replacement: '[CUSTOM]',
                    confidence
                });
                totalConfidence += confidence;
            }
            redactedText = redactedText.replace(pattern, '[CUSTOM]');
        }
        return {
            text: redactedText,
            redactions,
            confidence: totalConfidence / Math.max(1, redactions.length)
        };
    }
    /**
     * Apply level-specific redactions
     */
    applyLevelRedactions(text, level) {
        const redactions = [];
        let redactedText = text;
        let totalConfidence = 0;
        switch (level) {
            case 'aggressive':
                // Additional aggressive patterns
                const aggressivePatterns = [
                    { pattern: /\b[A-Z][a-z]+\b/g, replacement: '[WORD]', type: 'word' },
                    { pattern: /\b\d+\b/g, replacement: '[NUMBER]', type: 'number' }
                ];
                for (const { pattern, replacement, type } of aggressivePatterns) {
                    let match;
                    while ((match = pattern.exec(text)) !== null) {
                        const start = match.index;
                        const end = start + match[0].length;
                        const confidence = 0.6;
                        redactions.push({
                            type,
                            pattern: match[0],
                            start,
                            end,
                            replacement,
                            confidence
                        });
                        totalConfidence += confidence;
                    }
                    redactedText = redactedText.replace(pattern, replacement);
                }
                break;
            case 'minimal':
                // Only redact the most sensitive information
                const minimalPatterns = [
                    { pattern: this.patterns.get('ssn'), replacement: this.replacements.get('ssn'), type: 'ssn' },
                    { pattern: this.patterns.get('creditcard'), replacement: this.replacements.get('creditcard'), type: 'creditcard' }
                ];
                for (const { pattern, replacement, type } of minimalPatterns) {
                    if (pattern) {
                        let match;
                        while ((match = pattern.exec(text)) !== null) {
                            const start = match.index;
                            const end = start + match[0].length;
                            const confidence = 0.9;
                            redactions.push({
                                type,
                                pattern: match[0],
                                start,
                                end,
                                replacement,
                                confidence
                            });
                            totalConfidence += confidence;
                        }
                        redactedText = redactedText.replace(pattern, replacement);
                    }
                }
                break;
        }
        return {
            text: redactedText,
            redactions,
            confidence: totalConfidence / Math.max(1, redactions.length)
        };
    }
    /**
     * Calculate confidence score for a pattern match
     */
    calculateConfidence(type, match) {
        switch (type) {
            case 'ssn':
                return match.length === 11 && match.includes('-') ? 0.95 : 0.8;
            case 'phone':
                return match.length >= 10 ? 0.9 : 0.7;
            case 'email':
                return match.includes('@') && match.includes('.') ? 0.95 : 0.8;
            case 'creditcard':
                return this.validateCreditCard(match) ? 0.9 : 0.6;
            case 'ipaddress':
                return this.validateIPAddress(match) ? 0.9 : 0.6;
            default:
                return 0.8;
        }
    }
    /**
     * Validate credit card number using Luhn algorithm
     */
    validateCreditCard(cardNumber) {
        const cleaned = cardNumber.replace(/[-\s]/g, '');
        if (!/^\d{13,19}$/.test(cleaned))
            return false;
        let sum = 0;
        let isEven = false;
        for (let i = cleaned.length - 1; i >= 0; i--) {
            let digit = parseInt(cleaned[i]);
            if (isEven) {
                digit *= 2;
                if (digit > 9)
                    digit -= 9;
            }
            sum += digit;
            isEven = !isEven;
        }
        return sum % 10 === 0;
    }
    /**
     * Validate IP address format
     */
    validateIPAddress(ip) {
        const parts = ip.split('.');
        if (parts.length !== 4)
            return false;
        return parts.every(part => {
            const num = parseInt(part);
            return num >= 0 && num <= 255;
        });
    }
    /**
     * Get redaction statistics
     */
    getRedactionStats(result) {
        const types = {};
        let totalConfidence = 0;
        for (const redaction of result.redactions) {
            types[redaction.type] = (types[redaction.type] || 0) + 1;
            totalConfidence += redaction.confidence;
        }
        const coverage = result.original.length > 0
            ? (result.redactions.reduce((sum, r) => sum + (r.end - r.start), 0) / result.original.length) * 100
            : 0;
        return {
            totalRedactions: result.redactions.length,
            types,
            averageConfidence: totalConfidence / Math.max(1, result.redactions.length),
            coverage
        };
    }
    /**
     * Restore original text from redacted version (if redactions are available)
     */
    restoreText(redactedText, redactions) {
        let restored = redactedText;
        // Sort redactions by position (reverse order to maintain indices)
        const sortedRedactions = [...redactions].sort((a, b) => b.start - a.start);
        for (const redaction of sortedRedactions) {
            const before = restored.substring(0, redaction.start);
            const after = restored.substring(redaction.end);
            restored = before + redaction.pattern + after;
        }
        return restored;
    }
}
