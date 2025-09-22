import { PLATFORM, IS_WINDOWS, IS_LINUX, IS_MACOS, IS_ANDROID, IS_IOS, IS_MOBILE } from '../../config/environment.js';
export class MentalHealthNaturalLanguageProcessor {
    platform;
    isMobile;
    constructor() {
        this.platform = PLATFORM;
        this.isMobile = IS_MOBILE;
    }
    parseCommand(command) {
        const lowerCommand = command.toLowerCase();
        // Extract text samples from command
        const textSamples = this.extractTextSamples(command);
        // Extract location
        const location = this.extractLocation(command);
        // Determine action type
        const action = this.determineAction(lowerCommand);
        // Determine mode
        const mode = this.determineMode(lowerCommand);
        // Extract search radius
        const searchRadius = this.extractSearchRadius(command);
        // Extract boolean flags
        const includeEmergencyResources = this.extractBooleanFlag(command, ['emergency', 'crisis', 'urgent']);
        const includeSupportGroups = this.extractBooleanFlag(command, ['support', 'group', 'therapy']);
        const detailedAnalysis = this.extractBooleanFlag(command, ['detailed', 'comprehensive', 'thorough']);
        return {
            action,
            textSamples,
            location,
            mode,
            searchRadius,
            includeEmergencyResources,
            includeSupportGroups,
            detailedAnalysis,
            originalCommand: command
        };
    }
    extractTextSamples(command) {
        const samples = [];
        // Look for quoted text
        const quotedMatches = command.match(/"([^"]+)"/g);
        if (quotedMatches) {
            samples.push(...quotedMatches.map(match => match.slice(1, -1)));
        }
        // Look for text after keywords
        const textKeywords = [
            'analyze this text:',
            'analyze these words:',
            'analyze this writing:',
            'analyze this message:',
            'analyze this post:',
            'analyze this journal entry:',
            'analyze this sample:',
            'text:',
            'writing:',
            'message:',
            'post:',
            'journal:',
            'sample:'
        ];
        for (const keyword of textKeywords) {
            const index = command.toLowerCase().indexOf(keyword);
            if (index !== -1) {
                const textAfterKeyword = command.slice(index + keyword.length).trim();
                if (textAfterKeyword) {
                    // Remove quotes if present
                    const cleanText = textAfterKeyword.replace(/^["']|["']$/g, '');
                    if (cleanText.length > 0) {
                        samples.push(cleanText);
                    }
                }
            }
        }
        // If no specific text samples found, use the entire command as context
        if (samples.length === 0 && command.length > 50) {
            samples.push(command);
        }
        return samples;
    }
    extractLocation(command) {
        // Look for location patterns
        const locationPatterns = [
            /(?:in|near|around|at)\s+([A-Za-z\s,]+?)(?:\s|$|,|\.)/g,
            /(?:location|city|area|zip|zipcode)\s*:?\s*([A-Za-z0-9\s,]+?)(?:\s|$|,|\.)/g,
            /(\d{5}(?:-\d{4})?)/g, // ZIP codes
            /([A-Za-z\s]+,\s*[A-Z]{2})/g // City, State format
        ];
        for (const pattern of locationPatterns) {
            const matches = command.match(pattern);
            if (matches && matches.length > 0) {
                return matches[0].replace(/^(?:in|near|around|at|location|city|area|zip|zipcode)\s*:?\s*/i, '').trim();
            }
        }
        return undefined;
    }
    determineAction(command) {
        if (command.includes('analyze') || command.includes('assess') || command.includes('evaluate')) {
            return 'analyze';
        }
        if (command.includes('find') && (command.includes('therapist') || command.includes('doctor') || command.includes('help'))) {
            return 'find_resources';
        }
        if (command.includes('security') || command.includes('exploit') || command.includes('vulnerability')) {
            return 'security_assessment';
        }
        if (command.includes('crisis') || command.includes('emergency') || command.includes('urgent') || command.includes('suicide')) {
            return 'crisis_check';
        }
        if (command.includes('diagnose') || command.includes('diagnosis') || command.includes('condition')) {
            return 'diagnosis';
        }
        if (command.includes('help') || command.includes('what can you do')) {
            return 'help';
        }
        return 'analyze'; // Default action
    }
    determineMode(command) {
        if (command.includes('security') || command.includes('exploit') || command.includes('attack') ||
            command.includes('vulnerability') || command.includes('social engineering')) {
            return 'security_awareness';
        }
        return 'support';
    }
    extractSearchRadius(command) {
        const radiusPatterns = [
            /(\d+)\s*(?:mile|miles|mi|km|kilometer|kilometers)/g,
            /(?:within|radius|distance)\s*:?\s*(\d+)/g
        ];
        for (const pattern of radiusPatterns) {
            const match = command.match(pattern);
            if (match) {
                const radius = parseInt(match[1]);
                if (!isNaN(radius) && radius > 0 && radius <= 100) {
                    return radius;
                }
            }
        }
        return 25; // Default radius
    }
    extractBooleanFlag(command, keywords) {
        const lowerCommand = command.toLowerCase();
        // Check for explicit "yes" or "no"
        for (const keyword of keywords) {
            const keywordIndex = lowerCommand.indexOf(keyword);
            if (keywordIndex !== -1) {
                const afterKeyword = lowerCommand.slice(keywordIndex + keyword.length, keywordIndex + keyword.length + 20);
                if (afterKeyword.includes('no') || afterKeyword.includes('not') || afterKeyword.includes('false')) {
                    return false;
                }
                if (afterKeyword.includes('yes') || afterKeyword.includes('true') || afterKeyword.includes('include')) {
                    return true;
                }
            }
        }
        // Check for negative indicators
        const negativeKeywords = ['no', 'not', 'without', 'exclude', 'skip'];
        for (const negative of negativeKeywords) {
            for (const keyword of keywords) {
                if (lowerCommand.includes(`${negative} ${keyword}`) || lowerCommand.includes(`${keyword} ${negative}`)) {
                    return false;
                }
            }
        }
        // Default to true if keywords are present
        return keywords.some(keyword => lowerCommand.includes(keyword));
    }
    generateHelpResponse() {
        const platformInfo = this.getPlatformInfo();
        return `
🧠 **Mental Health Analyzer - Natural Language Interface**

**Available Commands:**
• "Analyze this text: [your text]" - Analyze psychological markers in text
• "Find therapists near [location]" - Find local mental health resources
• "Security assessment of [text]" - Generate security awareness report
• "Crisis check for [text]" - Assess crisis level and get emergency resources
• "Diagnose [text]" - Get diagnostic analysis based on DSM-V/ICD-10

**Examples:**
• "Analyze this journal entry: I've been feeling really sad lately and can't sleep"
• "Find therapists in New York, NY within 20 miles"
• "Security assessment of this person's social media posts"
• "Crisis check - they mentioned wanting to hurt themselves"
• "Diagnose this writing sample for depression"

**Platform Support:** ${platformInfo}
**Mobile Optimized:** ${this.isMobile ? 'Yes' : 'No'}

**Modes:**
• Support Mode: Therapeutic resources and healing recommendations
• Security Awareness Mode: Educational exploitation vector analysis

**Features:**
• DSM-V and ICD-10 diagnostic criteria
• Built-in therapeutic resource database
• Crisis intervention protocols
• Cross-platform compatibility
• Natural language processing
`;
    }
    getPlatformInfo() {
        if (IS_WINDOWS)
            return 'Windows (Full Support)';
        if (IS_LINUX)
            return 'Linux (Full Support)';
        if (IS_MACOS)
            return 'macOS (Full Support)';
        if (IS_ANDROID)
            return 'Android (Mobile Optimized)';
        if (IS_IOS)
            return 'iOS (Mobile Optimized)';
        return 'Cross-Platform';
    }
    // Cross-platform utility methods
    isPlatformSupported() {
        return true; // All platforms supported
    }
    getPlatformSpecificFeatures() {
        const features = ['Natural Language Processing', 'DSM-V/ICD-10 Analysis', 'Built-in Therapeutic Resources'];
        if (IS_MOBILE) {
            features.push('Mobile-Optimized Interface', 'Touch-Friendly Controls', 'Offline Capability');
        }
        else {
            features.push('Desktop Interface', 'Advanced Analysis', 'Full Feature Set');
        }
        return features;
    }
    adaptForPlatform(params) {
        // Mobile-specific adaptations
        if (IS_MOBILE) {
            return {
                ...params,
                searchRadius: Math.min(params.searchRadius || 25, 50), // Limit search radius on mobile
                detailedAnalysis: params.detailedAnalysis !== false, // Default to true on mobile
                includeEmergencyResources: true, // Always include emergency resources on mobile
                includeSupportGroups: true // Always include support groups on mobile
            };
        }
        return params;
    }
}
