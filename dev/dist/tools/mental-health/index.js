import { z } from "zod";
import { MentalHealthAnalyzer } from "./analyzer.js";
import { ResourceLocator } from "./resource-locator.js";
import { SecurityAwarenessFramework } from "./exploit-framework.js";
import { MentalHealthNaturalLanguageProcessor } from "./natural-language.js";
import { PLATFORM, IS_WINDOWS, IS_LINUX, IS_MACOS, IS_ANDROID, IS_IOS, IS_MOBILE } from "../../config/environment.js";
export function registerMentalHealthTool(server) {
    // Main structured tool
    server.registerTool("mental_health_analyzer", {
        description: "🧠 **Mental Health Analyzer** - Comprehensive psychological analysis incorporating DSM-V/ICD-10 knowledge with built-in therapeutic resources and security awareness capabilities. Analyzes text samples to identify mental health conditions, provides therapeutic resource recommendations, and generates security awareness reports for protection against social engineering attacks.",
        inputSchema: {
            textSamples: z.array(z.string()).describe("Array of text samples from the individual (journal entries, social media posts, emails, etc.)"),
            location: z.string().optional().describe("Location for finding local resources (city, state, zip code, or 'city, state' format)"),
            mode: z.enum(["support", "security_awareness"]).default("support").describe("Mode of operation: 'support' for therapeutic resources and healing recommendations, 'security_awareness' for educational exploitation vector analysis"),
            searchRadius: z.number().default(25).describe("Search radius in miles for local resources (default: 25 miles)"),
            includeEmergencyResources: z.boolean().default(true).describe("Include emergency mental health resources in results"),
            includeSupportGroups: z.boolean().default(true).describe("Include local support groups in results"),
            detailedAnalysis: z.boolean().default(true).describe("Provide detailed psychological analysis with confidence scores and specifiers")
        }
    }, async (params) => {
        const startTime = Date.now();
        const warnings = [];
        const recommendations = [];
        try {
            // Validate input parameters
            if (!params.textSamples || params.textSamples.length === 0) {
                throw new Error("Text samples are required for analysis");
            }
            if (params.textSamples.some(sample => typeof sample !== 'string' || sample.trim().length === 0)) {
                warnings.push("Some text samples are empty or invalid - analysis may be less accurate");
            }
            // Initialize analyzers
            const analyzer = new MentalHealthAnalyzer();
            const resourceLocator = new ResourceLocator();
            const securityFramework = new SecurityAwarenessFramework();
            // Perform psychological analysis
            const analysis = await analyzer.analyzeTextSamples(params.textSamples);
            // Add crisis warnings
            if (analysis.crisisLevel.level === 'critical') {
                warnings.push("CRITICAL: Immediate crisis intervention required - high risk of self-harm");
                recommendations.push("Contact emergency services (911) immediately");
                recommendations.push("Do not leave the person alone");
            }
            else if (analysis.crisisLevel.level === 'high') {
                warnings.push("HIGH RISK: Professional intervention needed immediately");
                recommendations.push("Contact mental health professional immediately");
            }
            // Add suicide risk warnings
            if (analysis.psychologicalProfile.markers.suicidal_ideation > 0.3) {
                warnings.push("SUICIDE RISK: Suicidal ideation detected - immediate intervention required");
                recommendations.push("Call National Suicide Prevention Lifeline: 988");
                recommendations.push("Remove access to means of self-harm");
            }
            // Add psychosis warnings
            if (analysis.psychologicalProfile.markers.psychosis > 0.3) {
                warnings.push("PSYCHOSIS: Psychotic symptoms detected - psychiatric evaluation needed");
                recommendations.push("Immediate psychiatric evaluation required");
                recommendations.push("Consider antipsychotic medication");
            }
            let resources;
            let securityAwarenessReport;
            // Generate mode-specific results
            if (params.mode === 'support') {
                if (params.location) {
                    try {
                        resources = await resourceLocator.findLocalResources(params.location, analysis.potentialDiagnoses, params.searchRadius || 25);
                        recommendations.push(`Found ${resources.totalFound} local resources within ${params.searchRadius || 25} miles`);
                        if (resources.crisisResources.length > 0) {
                            recommendations.push("Crisis resources available 24/7");
                        }
                    }
                    catch (error) {
                        warnings.push(`Error finding local resources: ${error.message}`);
                        recommendations.push("Use national crisis hotlines: 988 (Suicide Prevention), 741741 (Crisis Text Line)");
                    }
                }
                else {
                    warnings.push("No location provided - showing national crisis resources only");
                    recommendations.push("Provide location for local therapist and support group recommendations");
                }
                // Add diagnosis-specific recommendations
                for (const diagnosis of analysis.potentialDiagnoses.slice(0, 3)) {
                    recommendations.push(`${diagnosis.criteria.name}: ${diagnosis.severity} severity - professional treatment recommended`);
                }
                // Add risk factor recommendations
                for (const riskFactor of analysis.riskFactors) {
                    recommendations.push(`Risk Factor: ${riskFactor.factor} - ${riskFactor.mitigation}`);
                }
            }
            else if (params.mode === 'security_awareness') {
                try {
                    securityAwarenessReport = securityFramework.generateSecurityAwarenessReport(analysis.psychologicalProfile, analysis.potentialDiagnoses, analysis.crisisLevel);
                    warnings.push("SECURITY AWARENESS: This report is for educational purposes only");
                    warnings.push("Use this information to protect against social engineering attacks");
                    if (securityAwarenessReport.riskAssessment.overallRisk === 'critical') {
                        warnings.push("CRITICAL SECURITY RISK: Maximum vulnerability to exploitation detected");
                        recommendations.push("Implement immediate protective measures");
                        recommendations.push("Consider 24/7 monitoring and support");
                    }
                    else if (securityAwarenessReport.riskAssessment.overallRisk === 'high') {
                        warnings.push("HIGH SECURITY RISK: Significant vulnerability to social engineering");
                        recommendations.push("Implement enhanced security measures");
                        recommendations.push("Educate about common attack vectors");
                    }
                    // Add protective recommendations
                    for (const protection of securityAwarenessReport.protectiveRecommendations.slice(0, 5)) {
                        if (protection.priority === 'critical' || protection.priority === 'high') {
                            recommendations.push(`Protection: ${protection.recommendation}`);
                        }
                    }
                }
                catch (error) {
                    warnings.push(`Error generating security awareness report: ${error.message}`);
                }
            }
            const processingTime = Date.now() - startTime;
            return {
                analysis,
                resources,
                securityAwarenessReport,
                timestamp: new Date().toISOString(),
                processingTime,
                warnings,
                recommendations
            };
        }
        catch (error) {
            const processingTime = Date.now() - startTime;
            return {
                analysis: {
                    psychologicalProfile: {
                        markers: {},
                        dominantThemes: [],
                        emotionalTone: 'neutral',
                        cognitivePatterns: [],
                        behavioralIndicators: [],
                        riskLevel: 'low'
                    },
                    potentialDiagnoses: [],
                    crisisLevel: {
                        level: 'low',
                        score: 0,
                        description: 'Analysis failed',
                        immediateActions: ['Contact mental health professional'],
                        emergencyContacts: ['National Suicide Prevention Lifeline: 988']
                    },
                    riskFactors: [],
                    recommendations: ['Analysis failed - contact mental health professional'],
                    confidence: 0
                },
                timestamp: new Date().toISOString(),
                processingTime,
                warnings: [`Analysis failed: ${error.message}`],
                recommendations: [
                    'Contact mental health professional for assessment',
                    'Use crisis hotlines if in immediate danger: 988'
                ]
            };
        }
    });
    // Natural Language Interface Tool
    server.registerTool("mental_health_natural_language", {
        description: "🧠 **Mental Health Natural Language Interface** - Process natural language commands for mental health analysis. Converts conversational requests like 'Analyze this text for depression' or 'Find therapists near me' into structured mental health operations with cross-platform support.",
        inputSchema: {
            command: z.string().describe("Natural language command for mental health operations (e.g., 'Analyze this text: I feel sad', 'Find therapists in New York', 'Security assessment of this person')"),
            platform: z.string().optional().describe("Target platform (auto-detected if not specified)")
        }
    }, async ({ command, platform }) => {
        try {
            const nlProcessor = new MentalHealthNaturalLanguageProcessor();
            // Handle help requests
            if (command.toLowerCase().includes('help') || command.toLowerCase().includes('what can you do')) {
                return {
                    content: [{
                            type: "text",
                            text: nlProcessor.generateHelpResponse()
                        }]
                };
            }
            // Parse the natural language command
            const parsedCommand = nlProcessor.parseCommand(command);
            // Adapt for platform if specified
            const platformInfo = platform ? { platform } : { platform: PLATFORM };
            // Convert to structured parameters
            const params = {
                textSamples: parsedCommand.textSamples || [command],
                location: parsedCommand.location,
                mode: parsedCommand.mode || 'support',
                searchRadius: parsedCommand.searchRadius || 25,
                includeEmergencyResources: parsedCommand.includeEmergencyResources !== false,
                includeSupportGroups: parsedCommand.includeSupportGroups !== false,
                detailedAnalysis: parsedCommand.detailedAnalysis !== false
            };
            // Adapt for platform
            const adaptedParams = nlProcessor.adaptForPlatform(params);
            // Execute the analysis using the main tool logic
            const result = await executeMentalHealthAnalysis(adaptedParams);
            // Format response for natural language interface
            const response = formatNaturalLanguageResponse(result, parsedCommand, platformInfo);
            return {
                content: [{
                        type: "text",
                        text: response
                    }]
            };
        }
        catch (error) {
            return {
                content: [{
                        type: "text",
                        text: `❌ Natural language processing failed: ${error instanceof Error ? error.message : 'Unknown error'}\n\nTry: "Help" for available commands`
                    }]
            };
        }
    });
    // Cross-platform compatibility tool
    server.registerTool("mental_health_platform_info", {
        description: "🧠 **Mental Health Platform Information** - Get platform-specific information and capabilities for the mental health analyzer tool.",
        inputSchema: {
            platform: z.string().optional().describe("Platform to check (auto-detected if not specified)")
        }
    }, async ({ platform }) => {
        const nlProcessor = new MentalHealthNaturalLanguageProcessor();
        const currentPlatform = platform || PLATFORM;
        const platformInfo = {
            platform: currentPlatform,
            isMobile: IS_MOBILE,
            isWindows: IS_WINDOWS,
            isLinux: IS_LINUX,
            isMacOS: IS_MACOS,
            isAndroid: IS_ANDROID,
            isIOS: IS_IOS,
            supported: nlProcessor.isPlatformSupported(),
            features: nlProcessor.getPlatformSpecificFeatures(),
            capabilities: {
                naturalLanguageProcessing: true,
                dsmVICD10Analysis: true,
                localResourceSearch: true,
                crisisIntervention: true,
                securityAwareness: true,
                crossPlatformCompatibility: true,
                mobileOptimization: IS_MOBILE,
                offlineCapability: true
            }
        };
        return {
            content: [{
                    type: "text",
                    text: `🧠 **Mental Health Analyzer - Platform Information**

**Current Platform:** ${platformInfo.platform}
**Mobile Optimized:** ${platformInfo.isMobile ? 'Yes' : 'No'}
**Full Support:** ${platformInfo.supported ? 'Yes' : 'No'}

**Available Features:**
${platformInfo.features.map(feature => `• ${feature}`).join('\n')}

**Capabilities:**
${Object.entries(platformInfo.capabilities).map(([key, value]) => `• ${key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}: ${value ? 'Yes' : 'No'}`).join('\n')}

**Cross-Platform Support:**
✅ Windows (Full Support)
✅ Linux (Full Support)  
✅ macOS (Full Support)
✅ Android (Mobile Optimized)
✅ iOS (Mobile Optimized)

All features are available across all platforms with appropriate optimizations.`
                }]
        };
    });
}
// Helper function to execute mental health analysis
async function executeMentalHealthAnalysis(params) {
    const startTime = Date.now();
    const warnings = [];
    const recommendations = [];
    try {
        // Validate input parameters
        if (!params.textSamples || params.textSamples.length === 0) {
            throw new Error("Text samples are required for analysis");
        }
        if (params.textSamples.some(sample => typeof sample !== 'string' || sample.trim().length === 0)) {
            warnings.push("Some text samples are empty or invalid - analysis may be less accurate");
        }
        // Initialize analyzers
        const analyzer = new MentalHealthAnalyzer();
        const resourceLocator = new ResourceLocator();
        const securityFramework = new SecurityAwarenessFramework();
        // Perform psychological analysis
        const analysis = await analyzer.analyzeTextSamples(params.textSamples);
        // Add crisis warnings
        if (analysis.crisisLevel.level === 'critical') {
            warnings.push("CRITICAL: Immediate crisis intervention required - high risk of self-harm");
            recommendations.push("Contact emergency services (911) immediately");
            recommendations.push("Do not leave the person alone");
        }
        else if (analysis.crisisLevel.level === 'high') {
            warnings.push("HIGH RISK: Professional intervention needed immediately");
            recommendations.push("Contact mental health professional immediately");
        }
        // Add suicide risk warnings
        if (analysis.psychologicalProfile.markers.suicidal_ideation > 0.3) {
            warnings.push("SUICIDE RISK: Suicidal ideation detected - immediate intervention required");
            recommendations.push("Call National Suicide Prevention Lifeline: 988");
            recommendations.push("Remove access to means of self-harm");
        }
        // Add psychosis warnings
        if (analysis.psychologicalProfile.markers.psychosis > 0.3) {
            warnings.push("PSYCHOSIS: Psychotic symptoms detected - psychiatric evaluation needed");
            recommendations.push("Immediate psychiatric evaluation required");
            recommendations.push("Consider antipsychotic medication");
        }
        let resources;
        let securityAwarenessReport;
        // Generate mode-specific results
        if (params.mode === 'support') {
            if (params.location) {
                try {
                    resources = await resourceLocator.findLocalResources(params.location, analysis.potentialDiagnoses, params.searchRadius || 25);
                    recommendations.push(`Found ${resources.totalFound} local resources within ${params.searchRadius || 25} miles`);
                    if (resources.crisisResources.length > 0) {
                        recommendations.push("Crisis resources available 24/7");
                    }
                }
                catch (error) {
                    warnings.push(`Error finding local resources: ${error.message}`);
                    recommendations.push("Use national crisis hotlines: 988 (Suicide Prevention), 741741 (Crisis Text Line)");
                }
            }
            else {
                warnings.push("No location provided - showing national crisis resources only");
                recommendations.push("Provide location for local therapist and support group recommendations");
            }
            // Add diagnosis-specific recommendations
            for (const diagnosis of analysis.potentialDiagnoses.slice(0, 3)) {
                recommendations.push(`${diagnosis.criteria.name}: ${diagnosis.severity} severity - professional treatment recommended`);
            }
            // Add risk factor recommendations
            for (const riskFactor of analysis.riskFactors) {
                recommendations.push(`Risk Factor: ${riskFactor.factor} - ${riskFactor.mitigation}`);
            }
        }
        else if (params.mode === 'security_awareness') {
            try {
                securityAwarenessReport = securityFramework.generateSecurityAwarenessReport(analysis.psychologicalProfile, analysis.potentialDiagnoses, analysis.crisisLevel);
                warnings.push("SECURITY AWARENESS: This report is for educational purposes only");
                warnings.push("Use this information to protect against social engineering attacks");
                if (securityAwarenessReport.riskAssessment.overallRisk === 'critical') {
                    warnings.push("CRITICAL SECURITY RISK: Maximum vulnerability to exploitation detected");
                    recommendations.push("Implement immediate protective measures");
                    recommendations.push("Consider 24/7 monitoring and support");
                }
                else if (securityAwarenessReport.riskAssessment.overallRisk === 'high') {
                    warnings.push("HIGH SECURITY RISK: Significant vulnerability to social engineering");
                    recommendations.push("Implement enhanced security measures");
                    recommendations.push("Educate about common attack vectors");
                }
                // Add protective recommendations
                for (const protection of securityAwarenessReport.protectiveRecommendations.slice(0, 5)) {
                    if (protection.priority === 'critical' || protection.priority === 'high') {
                        recommendations.push(`Protection: ${protection.recommendation}`);
                    }
                }
            }
            catch (error) {
                warnings.push(`Error generating security awareness report: ${error.message}`);
            }
        }
        const processingTime = Date.now() - startTime;
        return {
            analysis,
            resources,
            securityAwarenessReport,
            timestamp: new Date().toISOString(),
            processingTime,
            warnings,
            recommendations
        };
    }
    catch (error) {
        const processingTime = Date.now() - startTime;
        return {
            analysis: {
                psychologicalProfile: {
                    markers: {},
                    dominantThemes: [],
                    emotionalTone: 'neutral',
                    cognitivePatterns: [],
                    behavioralIndicators: [],
                    riskLevel: 'low'
                },
                potentialDiagnoses: [],
                crisisLevel: {
                    level: 'low',
                    score: 0,
                    description: 'Analysis failed',
                    immediateActions: ['Contact mental health professional'],
                    emergencyContacts: ['National Suicide Prevention Lifeline: 988']
                },
                riskFactors: [],
                recommendations: ['Analysis failed - contact mental health professional'],
                confidence: 0
            },
            timestamp: new Date().toISOString(),
            processingTime,
            warnings: [`Analysis failed: ${error.message}`],
            recommendations: [
                'Contact mental health professional for assessment',
                'Use crisis hotlines if in immediate danger: 988'
            ]
        };
    }
}
// Helper function to format natural language response
function formatNaturalLanguageResponse(result, command, platformInfo) {
    let response = `🧠 **Mental Health Analysis Results**\n\n`;
    // Add platform info
    response += `**Platform:** ${platformInfo.platform}\n`;
    response += `**Processing Time:** ${result.processingTime}ms\n\n`;
    // Add warnings if any
    if (result.warnings.length > 0) {
        response += `⚠️ **Warnings:**\n`;
        result.warnings.forEach(warning => response += `• ${warning}\n`);
        response += `\n`;
    }
    // Add crisis level
    response += `🚨 **Crisis Level:** ${result.analysis.crisisLevel.level.toUpperCase()}\n`;
    response += `${result.analysis.crisisLevel.description}\n\n`;
    // Add immediate actions if critical
    if (result.analysis.crisisLevel.level === 'critical') {
        response += `🚨 **IMMEDIATE ACTIONS REQUIRED:**\n`;
        result.analysis.crisisLevel.immediateActions.forEach(action => response += `• ${action}\n`);
        response += `\n`;
    }
    // Add emergency contacts
    if (result.analysis.crisisLevel.emergencyContacts.length > 0) {
        response += `📞 **Emergency Contacts:**\n`;
        result.analysis.crisisLevel.emergencyContacts.forEach(contact => response += `• ${contact}\n`);
        response += `\n`;
    }
    // Add psychological profile
    response += `🧠 **Psychological Profile:**\n`;
    response += `• Emotional Tone: ${result.analysis.psychologicalProfile.emotionalTone}\n`;
    response += `• Risk Level: ${result.analysis.psychologicalProfile.riskLevel}\n`;
    response += `• Dominant Themes: ${result.analysis.psychologicalProfile.dominantThemes.join(', ')}\n\n`;
    // Add diagnoses
    if (result.analysis.potentialDiagnoses.length > 0) {
        response += `🏥 **Potential Diagnoses:**\n`;
        result.analysis.potentialDiagnoses.slice(0, 3).forEach(diagnosis => {
            response += `• ${diagnosis.criteria.name} (${diagnosis.criteria.code}) - ${diagnosis.severity}\n`;
        });
        response += `\n`;
    }
    // Add resources if available
    if (result.resources) {
        response += `📍 **Local Resources Found:**\n`;
        response += `• Crisis Resources: ${result.resources.crisisResources.length}\n`;
        response += `• Local Resources: ${result.resources.localResources.length}\n`;
        response += `• Support Groups: ${result.resources.supportGroups.length}\n`;
        response += `• Emergency Resources: ${result.resources.emergencyResources.length}\n\n`;
    }
    // Add recommendations
    if (result.recommendations.length > 0) {
        response += `💡 **Recommendations:**\n`;
        result.recommendations.slice(0, 10).forEach(rec => response += `• ${rec}\n`);
        response += `\n`;
    }
    // Add confidence score
    response += `📊 **Analysis Confidence:** ${Math.round(result.analysis.confidence * 100)}%\n\n`;
    // Add disclaimer for security awareness mode
    if (command.mode === 'security_awareness') {
        response += `⚠️ **Educational Purpose Only:** This security awareness report is for educational purposes to help protect against social engineering attacks.\n\n`;
    }
    return response;
}
// Export individual components for potential standalone use
export { MentalHealthAnalyzer } from './analyzer.js';
export { ResourceLocator } from './resource-locator.js';
export { SecurityAwarenessFramework } from './exploit-framework.js';
export { ALL_DIAGNOSTIC_CRITERIA, PSYCHOLOGICAL_MARKERS } from './diagnostic-data.js';
