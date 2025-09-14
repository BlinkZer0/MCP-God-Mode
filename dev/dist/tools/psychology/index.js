// Psychology Tools - Comprehensive Mental Health Analysis with RAG System
// Integrates DSM-V/ICD-10 reference, analysis, and cross-platform support
import { z } from "zod";
import { MentalHealthAnalyzer } from "./analyzer.js";
import { ResourceLocator } from "./resource-locator.js";
import { SecurityAwarenessFramework } from "./exploit-framework.js";
import { MentalHealthNaturalLanguageProcessor } from "./natural-language.js";
import { PsychologyRAGSystem } from "./rag-system.js";
import { PsychologyKnowledgeBase } from "./knowledge-base.js";
import { PLATFORM, IS_MOBILE } from "../../config/environment.js";
export function registerPsychologyTool(server) {
    // Unified Psychology Tool - All psychology functionality in one comprehensive tool
    server.registerTool("psychology", {
        description: "🧠 **Psychology Tool** - Comprehensive psychological analysis and knowledge base system. Incorporates official DSM-V/ICD-11 resources, extensive dark psychology and manipulation techniques, body language analysis, NLP methods, emotional intelligence assessment, and security awareness capabilities. Features 50+ psychology resources from docs/resources including classical texts, modern techniques, and defensive strategies. Supports helping, exploiting, and defensive applications with ethical guidelines.",
        inputSchema: {
            action: z.enum([
                "analyze_text",
                "diagnostic_reference",
                "natural_language",
                "platform_info",
                "rag_query",
                "crisis_check",
                "security_assessment",
                "knowledge_base_query",
                "dark_psychology_analysis",
                "manipulation_detection",
                "body_language_analysis",
                "nlp_techniques",
                "emotional_intelligence_assessment",
                "knowledge_base_stats"
            ]).describe("Action to perform: analyze_text (psychological analysis), diagnostic_reference (lookup criteria), natural_language (conversational interface), platform_info (capabilities), rag_query (search diagnostic database), crisis_check (emergency assessment), security_assessment (exploitation vectors), knowledge_base_query (search comprehensive psychology resources), dark_psychology_analysis (dark psychology techniques), manipulation_detection (detect manipulation attempts), body_language_analysis (nonverbal communication), nlp_techniques (neuro-linguistic programming), emotional_intelligence_assessment (EI analysis)"),
            // Text analysis parameters
            textSamples: z.array(z.string()).optional().describe("Array of text samples for analysis (journal entries, social media posts, emails, etc.)"),
            location: z.string().optional().describe("Location for finding local resources (city, state, zip code, or 'city, state' format)"),
            mode: z.enum(["support", "security_awareness"]).default("support").describe("Mode of operation: 'support' for therapeutic resources, 'security_awareness' for educational exploitation analysis"),
            searchRadius: z.number().default(25).describe("Search radius in miles for local resources (default: 25 miles)"),
            includeEmergencyResources: z.boolean().default(true).describe("Include emergency mental health resources in results"),
            includeSupportGroups: z.boolean().default(true).describe("Include local support groups in results"),
            detailedAnalysis: z.boolean().default(true).describe("Provide detailed psychological analysis with confidence scores"),
            includeRAGReference: z.boolean().default(true).describe("Include RAG system diagnostic references from DSM-V/ICD-10"),
            // Diagnostic reference parameters
            searchType: z.enum(["code", "name", "category", "symptoms"]).optional().describe("Type of diagnostic search: code, name, category, or symptoms"),
            searchValue: z.string().optional().describe("Value to search for (diagnostic code, name, category, or symptoms)"),
            system: z.enum(["DSM-5", "ICD-10", "ICD-11", "all"]).default("all").describe("Diagnostic system to search (DSM-5, ICD-10, ICD-11, or all)"),
            includeComorbidities: z.boolean().default(true).describe("Include comorbid conditions in results"),
            includeTreatment: z.boolean().default(true).describe("Include treatment guidelines in results"),
            // RAG query parameters
            query: z.string().optional().describe("Search query for diagnostic criteria, conditions, or symptoms"),
            category: z.string().optional().describe("Specific diagnostic category to filter by"),
            severity: z.string().optional().describe("Severity level to filter by"),
            maxResults: z.number().default(10).describe("Maximum number of results to return"),
            includeCriteria: z.boolean().default(true).describe("Include diagnostic criteria in results"),
            // Natural language parameters
            command: z.string().optional().describe("Natural language command for psychology operations"),
            platform: z.string().optional().describe("Target platform (auto-detected if not specified)"),
            // Knowledge base parameters
            resourceType: z.enum(["diagnostic", "dark_psychology", "manipulation", "body_language", "nlp", "emotional_intelligence", "classical", "all"]).optional().describe("Type of psychology resource to search"),
            difficulty: z.enum(["beginner", "intermediate", "advanced", "expert", "all"]).optional().describe("Difficulty level of techniques"),
            application: z.enum(["helping", "exploiting", "defense", "all"]).optional().describe("Application context: helping (therapeutic), exploiting (offensive), defense (protective)")
        }
    }, async (params) => {
        const { action, ...actionParams } = params;
        switch (action) {
            case "analyze_text":
                return await executePsychologyAnalysis(actionParams);
            case "diagnostic_reference":
                return await executeDiagnosticReference(actionParams);
            case "natural_language":
                return await executeNaturalLanguage(actionParams);
            case "platform_info":
                return await executePlatformInfo(actionParams);
            case "rag_query":
                return await executeRAGQuery(actionParams);
            case "crisis_check":
                return await executeCrisisCheck(actionParams);
            case "security_assessment":
                return await executeSecurityAssessment(actionParams);
            case "knowledge_base_query":
                return await executeKnowledgeBaseQuery(actionParams);
            case "dark_psychology_analysis":
                return await executeDarkPsychologyAnalysis(actionParams);
            case "manipulation_detection":
                return await executeManipulationDetection(actionParams);
            case "body_language_analysis":
                return await executeBodyLanguageAnalysis(actionParams);
            case "nlp_techniques":
                return await executeNLPTechniques(actionParams);
            case "emotional_intelligence_assessment":
                return await executeEmotionalIntelligenceAssessment(actionParams);
            case "knowledge_base_stats":
                return await executeKnowledgeBaseStats(actionParams);
            default:
                return {
                    error: "Invalid action specified",
                    availableActions: [
                        "analyze_text",
                        "diagnostic_reference",
                        "natural_language",
                        "platform_info",
                        "rag_query",
                        "crisis_check",
                        "security_assessment",
                        "knowledge_base_query",
                        "dark_psychology_analysis",
                        "manipulation_detection",
                        "body_language_analysis",
                        "nlp_techniques",
                        "emotional_intelligence_assessment",
                        "knowledge_base_stats"
                    ],
                    help: "Specify an action to perform with the psychology tool"
                };
        }
    });
}
// Helper function to execute comprehensive psychology analysis
async function executePsychologyAnalysis(params) {
    const startTime = Date.now();
    const warnings = [];
    const recommendations = [];
    try {
        // Initialize components
        const analyzer = new MentalHealthAnalyzer();
        const resourceLocator = new ResourceLocator();
        const securityFramework = new SecurityAwarenessFramework();
        const ragSystem = new PsychologyRAGSystem();
        // Perform analysis
        const analysis = await analyzer.analyzeTextSamples(params.textSamples);
        // Get resources if location provided
        let resources;
        if (params.location) {
            try {
                resources = await resourceLocator.findLocalResources(params.location, analysis.potentialDiagnoses, params.searchRadius || 25);
            }
            catch (error) {
                warnings.push(`Resource search failed: ${error}`);
            }
        }
        // Generate security awareness report if in security mode
        let securityAwarenessReport;
        if (params.mode === 'security_awareness') {
            try {
                securityAwarenessReport = securityFramework.generateSecurityAwarenessReport(analysis.psychologicalProfile, analysis.potentialDiagnoses, analysis.crisisLevel);
            }
            catch (error) {
                warnings.push(`Security awareness report generation failed: ${error}`);
            }
        }
        // Get RAG references if requested
        let ragResults;
        if (params.includeRAGReference !== false) {
            try {
                // Create RAG query based on analysis results
                const ragQuery = {
                    query: analysis.potentialDiagnoses.map(d => d.criteria.name).join(' '),
                    system: 'all',
                    maxResults: IS_MOBILE ? 5 : 10,
                    includeCriteria: true,
                    includeTreatment: true
                };
                ragResults = await ragSystem.queryDiagnosticCriteria(ragQuery);
            }
            catch (error) {
                warnings.push(`RAG reference lookup failed: ${error}`);
            }
        }
        // Generate recommendations
        if (analysis.crisisLevel.level === 'high') {
            recommendations.push('Immediate crisis intervention recommended');
            recommendations.push('Contact emergency mental health services');
        }
        if (analysis.potentialDiagnoses.length > 0) {
            recommendations.push('Professional psychological evaluation recommended');
            recommendations.push('Consider evidence-based treatment options');
        }
        if (resources && resources.localResources.length === 0) {
            recommendations.push('Expand search radius for local resources');
        }
        const processingTime = Date.now() - startTime;
        return {
            analysis,
            resources,
            securityAwarenessReport,
            ragResults,
            timestamp: new Date().toISOString(),
            processingTime,
            warnings,
            recommendations
        };
    }
    catch (error) {
        const processingTime = Date.now() - startTime;
        warnings.push(`Analysis failed: ${error}`);
        return {
            analysis: {
                psychologicalProfile: {
                    markers: {},
                    dominantThemes: [],
                    emotionalTone: 'unknown',
                    cognitivePatterns: [],
                    behavioralIndicators: [],
                    riskLevel: 'low'
                },
                potentialDiagnoses: [],
                crisisLevel: { level: 'low', score: 0, description: 'Unknown', immediateActions: [], emergencyContacts: [] },
                riskFactors: [],
                recommendations: [],
                confidence: 0
            },
            timestamp: new Date().toISOString(),
            processingTime,
            warnings,
            recommendations: ['Professional consultation recommended due to analysis failure']
        };
    }
}
// Helper function to format natural language responses
function formatNaturalLanguageResponse(command, result, processor) {
    let response = `🧠 **Psychology Analysis Results**\n\n`;
    // Add analysis summary
    if (result.analysis.potentialDiagnoses.length > 0) {
        response += `📊 **Potential Diagnoses:**\n`;
        result.analysis.potentialDiagnoses.slice(0, 3).forEach(diagnosis => {
            response += `• ${diagnosis.criteria.name} (${Math.round(diagnosis.confidence * 100)}% confidence)\n`;
        });
        response += `\n`;
    }
    // Add RAG references if available
    if (result.ragResults && result.ragResults.references.length > 0) {
        response += `📚 **Diagnostic References:**\n`;
        result.ragResults.references.slice(0, 2).forEach(ref => {
            response += `• ${ref.name} (${ref.system} ${ref.code})\n`;
        });
        response += `\n`;
    }
    // Add resources if available
    if (result.resources && result.resources.localResources.length > 0) {
        response += `🏥 **Local Resources Found:**\n`;
        response += `• ${result.resources.localResources.length} local resources\n`;
        if (result.resources.crisisResources) {
            response += `• ${result.resources.crisisResources.length} crisis resources\n`;
        }
        response += `\n`;
    }
    // Add recommendations
    if (result.recommendations.length > 0) {
        response += `💡 **Recommendations:**\n`;
        result.recommendations.slice(0, 5).forEach(rec => response += `• ${rec}\n`);
        response += `\n`;
    }
    // Add confidence score
    response += `📈 **Analysis Confidence:** ${Math.round(result.analysis.confidence * 100)}%\n\n`;
    // Add disclaimer for security awareness mode
    if (command.mode === 'security_awareness') {
        response += `⚠️ **Educational Purpose Only:** This security awareness report is for educational purposes to help protect against social engineering attacks.\n\n`;
    }
    return response;
}
// Individual action handler functions
async function executeDiagnosticReference(params) {
    const { searchType, searchValue, system, includeComorbidities, includeTreatment } = params;
    const ragSystem = new PsychologyRAGSystem();
    switch (searchType) {
        case 'code':
            const diagnostic = await ragSystem.getDiagnosticByCode(searchValue, system);
            return diagnostic ? { diagnostic, found: true } : { found: false, message: 'Diagnostic code not found' };
        case 'category':
            const categoryResults = await ragSystem.getDiagnosticsByCategory(searchValue);
            return { diagnostics: categoryResults, count: categoryResults.length };
        case 'symptoms':
            const symptomResults = await ragSystem.queryDiagnosticCriteria({
                query: searchValue,
                system: system,
                includeCriteria: true,
                includeTreatment
            });
            return symptomResults;
        default:
            const nameResults = await ragSystem.queryDiagnosticCriteria({
                query: searchValue,
                system: system,
                includeCriteria: true,
                includeTreatment
            });
            return nameResults;
    }
}
async function executeNaturalLanguage(params) {
    const { command, platform } = params;
    const processor = new MentalHealthNaturalLanguageProcessor();
    const parsedCommand = processor.parseCommand(command);
    // Adapt for platform
    const adaptedParams = processor.adaptForPlatform({
        textSamples: parsedCommand.textSamples || [command],
        location: parsedCommand.location,
        mode: parsedCommand.mode || 'support',
        searchRadius: parsedCommand.searchRadius,
        includeEmergencyResources: parsedCommand.includeEmergencyResources,
        includeSupportGroups: parsedCommand.includeSupportGroups,
        detailedAnalysis: parsedCommand.detailedAnalysis
    });
    // Execute analysis
    const result = await executePsychologyAnalysis(adaptedParams);
    // Format natural language response
    return formatNaturalLanguageResponse(parsedCommand, result, processor);
}
async function executePlatformInfo(params) {
    const { platform } = params;
    const targetPlatform = platform || PLATFORM;
    const processor = new MentalHealthNaturalLanguageProcessor();
    const ragSystem = new PsychologyRAGSystem();
    return {
        platform: targetPlatform,
        isMobile: IS_MOBILE,
        supportedPlatforms: ['Windows', 'Linux', 'macOS', 'Android', 'iOS'],
        features: {
            naturalLanguage: processor.getPlatformSpecificFeatures(),
            ragSystem: ragSystem.getPlatformSpecificFeatures(),
            analysis: ['DSM-V/ICD-10 Analysis', 'RAG Reference System', 'Local Resource Search', 'Security Awareness'],
            crossPlatform: true
        },
        optimizations: {
            mobile: IS_MOBILE ? {
                reducedResultSets: true,
                optimizedUI: true,
                batteryOptimized: true
            } : {
                fullFeatureSet: true,
                advancedFiltering: true,
                detailedReporting: true
            }
        },
        capabilities: {
            diagnosticReference: true,
            treatmentGuidelines: true,
            localResources: true,
            crisisIntervention: true,
            securityAwareness: true,
            naturalLanguageProcessing: true
        }
    };
}
async function executeRAGQuery(params) {
    const { query, system, category, severity, maxResults, includeCriteria, includeTreatment } = params;
    const ragSystem = new PsychologyRAGSystem();
    return await ragSystem.queryDiagnosticCriteria({
        query,
        system,
        category,
        severity,
        maxResults,
        includeCriteria,
        includeTreatment
    });
}
async function executeCrisisCheck(params) {
    const { textSamples } = params;
    const analyzer = new MentalHealthAnalyzer();
    if (!textSamples || textSamples.length === 0) {
        return {
            error: "Text samples required for crisis assessment",
            help: "Provide text samples to analyze for crisis indicators"
        };
    }
    const analysis = await analyzer.analyzeTextSamples(textSamples);
    return {
        crisisLevel: analysis.crisisLevel,
        immediateActions: analysis.crisisLevel.immediateActions,
        emergencyContacts: analysis.crisisLevel.emergencyContacts,
        riskFactors: analysis.riskFactors,
        recommendations: analysis.recommendations,
        confidence: analysis.confidence,
        timestamp: new Date().toISOString()
    };
}
async function executeSecurityAssessment(params) {
    const { textSamples, location } = params;
    const analyzer = new MentalHealthAnalyzer();
    const securityFramework = new SecurityAwarenessFramework();
    if (!textSamples || textSamples.length === 0) {
        return {
            error: "Text samples required for security assessment",
            help: "Provide text samples to analyze for security awareness"
        };
    }
    const analysis = await analyzer.analyzeTextSamples(textSamples);
    const securityReport = securityFramework.generateSecurityAwarenessReport(analysis.psychologicalProfile, analysis.potentialDiagnoses, analysis.crisisLevel);
    return {
        securityReport,
        analysis: {
            psychologicalProfile: analysis.psychologicalProfile,
            potentialDiagnoses: analysis.potentialDiagnoses,
            riskFactors: analysis.riskFactors
        },
        timestamp: new Date().toISOString(),
        disclaimer: "This security awareness report is for educational purposes to help protect against social engineering attacks."
    };
}
// New action handler functions for comprehensive psychology knowledge base
async function executeKnowledgeBaseQuery(params) {
    const { query, resourceType, category, difficulty, application, maxResults } = params;
    const knowledgeBase = new PsychologyKnowledgeBase();
    if (!query) {
        return {
            error: "Query required for knowledge base search",
            help: "Provide a search query to find psychology resources"
        };
    }
    const knowledgeQuery = {
        query,
        resourceType: resourceType || 'all',
        category,
        difficulty: difficulty || 'all',
        application: application || 'all',
        maxResults: maxResults || (IS_MOBILE ? 5 : 10)
    };
    return await knowledgeBase.queryKnowledgeBase(knowledgeQuery);
}
async function executeDarkPsychologyAnalysis(params) {
    const { textSamples, query } = params;
    const knowledgeBase = new PsychologyKnowledgeBase();
    if (!textSamples && !query) {
        return {
            error: "Text samples or query required for dark psychology analysis",
            help: "Provide text samples to analyze or a specific query about dark psychology techniques"
        };
    }
    const searchQuery = query || (textSamples ? textSamples.join(' ') : '');
    const knowledgeQuery = {
        query: searchQuery,
        resourceType: 'dark_psychology',
        application: 'defense', // Default to defensive application
        maxResults: IS_MOBILE ? 3 : 5
    };
    const result = await knowledgeBase.queryKnowledgeBase(knowledgeQuery);
    return {
        ...result,
        analysis_type: 'dark_psychology_analysis',
        ethical_warning: '⚠️ ETHICAL WARNING: Dark psychology techniques should only be used for defensive purposes and awareness training. Misuse can cause serious psychological harm.',
        defensive_applications: result.resources.map(r => r.defenses).flat(),
        timestamp: new Date().toISOString()
    };
}
async function executeManipulationDetection(params) {
    const { textSamples, query } = params;
    const knowledgeBase = new PsychologyKnowledgeBase();
    if (!textSamples && !query) {
        return {
            error: "Text samples or query required for manipulation detection",
            help: "Provide text samples to analyze for manipulation attempts"
        };
    }
    const searchQuery = query || (textSamples ? textSamples.join(' ') : '');
    const knowledgeQuery = {
        query: searchQuery,
        resourceType: 'manipulation',
        application: 'defense',
        maxResults: IS_MOBILE ? 3 : 5
    };
    const result = await knowledgeBase.queryKnowledgeBase(knowledgeQuery);
    return {
        ...result,
        analysis_type: 'manipulation_detection',
        detection_techniques: result.resources.map(r => r.techniques).flat(),
        defense_strategies: result.resources.map(r => r.defenses).flat(),
        timestamp: new Date().toISOString()
    };
}
async function executeBodyLanguageAnalysis(params) {
    const { textSamples, query } = params;
    const knowledgeBase = new PsychologyKnowledgeBase();
    if (!textSamples && !query) {
        return {
            error: "Text samples or query required for body language analysis",
            help: "Provide text samples or query about body language and nonverbal communication"
        };
    }
    const searchQuery = query || (textSamples ? textSamples.join(' ') : '');
    const knowledgeQuery = {
        query: searchQuery,
        resourceType: 'body_language',
        application: 'helping',
        maxResults: IS_MOBILE ? 3 : 5
    };
    const result = await knowledgeBase.queryKnowledgeBase(knowledgeQuery);
    return {
        ...result,
        analysis_type: 'body_language_analysis',
        nonverbal_techniques: result.resources.map(r => r.techniques).flat(),
        applications: result.resources.map(r => r.applications).flat(),
        timestamp: new Date().toISOString()
    };
}
async function executeNLPTechniques(params) {
    const { textSamples, query } = params;
    const knowledgeBase = new PsychologyKnowledgeBase();
    if (!textSamples && !query) {
        return {
            error: "Text samples or query required for NLP analysis",
            help: "Provide text samples or query about NLP techniques and applications"
        };
    }
    const searchQuery = query || (textSamples ? textSamples.join(' ') : '');
    const knowledgeQuery = {
        query: searchQuery,
        resourceType: 'nlp',
        application: 'helping',
        maxResults: IS_MOBILE ? 3 : 5
    };
    const result = await knowledgeBase.queryKnowledgeBase(knowledgeQuery);
    return {
        ...result,
        analysis_type: 'nlp_techniques',
        nlp_methods: result.resources.map(r => r.techniques).flat(),
        applications: result.resources.map(r => r.applications).flat(),
        ethical_considerations: result.resources.map(r => r.ethical_considerations).flat(),
        timestamp: new Date().toISOString()
    };
}
async function executeEmotionalIntelligenceAssessment(params) {
    const { textSamples, query } = params;
    const knowledgeBase = new PsychologyKnowledgeBase();
    if (!textSamples && !query) {
        return {
            error: "Text samples or query required for emotional intelligence assessment",
            help: "Provide text samples or query about emotional intelligence and social skills"
        };
    }
    const searchQuery = query || (textSamples ? textSamples.join(' ') : '');
    const knowledgeQuery = {
        query: searchQuery,
        resourceType: 'emotional_intelligence',
        application: 'helping',
        maxResults: IS_MOBILE ? 3 : 5
    };
    const result = await knowledgeBase.queryKnowledgeBase(knowledgeQuery);
    return {
        ...result,
        analysis_type: 'emotional_intelligence_assessment',
        ei_components: result.resources.map(r => r.techniques).flat(),
        development_areas: result.resources.map(r => r.applications).flat(),
        assessment_tools: result.resources.map(r => r.techniques).flat(),
        timestamp: new Date().toISOString()
    };
}
async function executeKnowledgeBaseStats(params) {
    const knowledgeBase = new PsychologyKnowledgeBase();
    const stats = knowledgeBase.getKnowledgeBaseStats();
    return {
        knowledge_base_statistics: stats,
        self_contained: true,
        no_external_files_required: true,
        comprehensive_coverage: {
            official_diagnostics: 'DSM-V and ICD-11 complete criteria',
            dark_psychology: '30+ books on manipulation and mind control',
            body_language: 'Advanced nonverbal communication analysis',
            nlp_techniques: 'Complete NLP and persuasion methods',
            emotional_intelligence: 'Comprehensive EI mastery',
            trauma_psychology: 'The Body Keeps Score and trauma healing',
            classical_psychology: 'Machiavelli and historical texts',
            gaslighting_abuse: 'Psychological abuse detection and recovery'
        },
        ethical_framework: {
            built_in_warnings: true,
            defensive_focus: true,
            professional_guidelines: true,
            informed_consent_emphasis: true
        },
        timestamp: new Date().toISOString()
    };
}
// Export individual components for potential standalone use
export { MentalHealthAnalyzer } from './analyzer.js';
export { ResourceLocator } from './resource-locator.js';
export { SecurityAwarenessFramework } from './exploit-framework.js';
export { PsychologyRAGSystem } from './rag-system.js';
export { PsychologyKnowledgeBase } from './knowledge-base.js';
export { ALL_DIAGNOSTIC_CRITERIA, PSYCHOLOGICAL_MARKERS } from './diagnostic-data.js';
