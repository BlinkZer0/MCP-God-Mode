import { z } from "zod";
/**
 * Autonomous Cascade Natural Language Interface
 *
 * Provides an intuitive natural language interface for the autonomous cascade system.
 * Handles complex queries and converts them into structured cascade operations.
 */
// Enhanced natural language patterns for cascade operations
const CASCADE_PATTERNS = {
    // Goal identification patterns
    GOAL_PATTERNS: [
        /(?:build|create|make|develop|generate)\s+(.+?)(?:\s+(?:until|for|with)|\s*$)/i,
        /(?:fix|repair|resolve|debug)\s+(.+?)(?:\s+(?:until|for|with)|\s*$)/i,
        /(?:analyze|research|investigate|study)\s+(.+?)(?:\s+(?:until|for|with)|\s*$)/i,
        /(?:search|find|discover|explore)\s+(.+?)(?:\s+(?:until|for|with)|\s*$)/i,
        /(?:optimize|improve|enhance|upgrade)\s+(.+?)(?:\s+(?:until|for|with)|\s*$)/i,
        /(?:deploy|publish|release|ship)\s+(.+?)(?:\s+(?:until|for|with)|\s*$)/i,
        /(?:test|validate|verify|check)\s+(.+?)(?:\s+(?:until|for|with)|\s*$)/i
    ],
    // Time constraint patterns
    TIME_PATTERNS: [
        /(?:for|within|in)\s+(\d+)\s*(?:minutes?|mins?)/i,
        /(?:for|within|in)\s+(\d+)\s*(?:hours?|hrs?)/i,
        /(?:for|within|in)\s+(\d+)\s*(?:seconds?|secs?)/i,
        /(\d+)\s*(?:minutes?|mins?)\s+(?:max|maximum|limit)/i,
        /(\d+)\s*(?:hours?|hrs?)\s+(?:max|maximum|limit)/i
    ],
    // Round constraint patterns
    ROUND_PATTERNS: [
        /(?:up to|maximum of|max)\s+(\d+)\s+(?:rounds?|steps?|iterations?)/i,
        /(\d+)\s+(?:rounds?|steps?|iterations?)\s+(?:max|maximum|limit)/i,
        /(?:limit|cap)\s+(?:to|at)\s+(\d+)\s+(?:rounds?|steps?|iterations?)/i
    ],
    // Risk level patterns
    RISK_PATTERNS: {
        READ_ONLY: [
            /read[\s-]?only/i,
            /no\s+(?:changes|modifications|writes)/i,
            /safe\s+mode/i,
            /view[\s-]?only/i,
            /analysis[\s-]?only/i
        ],
        WRITE_FS: [
            /(?:write|modify|change|edit)\s+files?/i,
            /file\s+(?:system|changes)/i,
            /local\s+(?:changes|modifications)/i,
            /trust\s+your\s+guidance/i,
            /until\s+done/i
        ],
        NETWORKED: [
            /(?:network|internet|web|online)/i,
            /(?:download|fetch|scrape|api)/i,
            /(?:external|remote)\s+(?:access|resources)/i,
            /(?:search|browse)\s+(?:web|internet)/i
        ]
    },
    // Autonomy level patterns
    AUTONOMY_PATTERNS: [
        /(?:fully\s+)?autonomous/i,
        /(?:complete\s+)?automation/i,
        /trust\s+your\s+(?:judgment|guidance|decisions)/i,
        /(?:run|execute|proceed)\s+(?:independently|autonomously)/i,
        /(?:no|minimal)\s+(?:intervention|supervision)/i,
        /until\s+(?:done|complete|finished)/i
    ],
    // Safety patterns
    SAFETY_PATTERNS: [
        /safe\s+mode/i,
        /(?:careful|cautious|conservative)/i,
        /(?:dry[\s-]?run|simulate|preview)/i,
        /(?:no|avoid)\s+(?:destructive|dangerous)\s+(?:actions|operations)/i,
        /(?:backup|preserve)\s+(?:first|before)/i
    ],
    // Tool specification patterns
    TOOL_PATTERNS: [
        /(?:only\s+use|limit\s+to|restrict\s+to)\s+(.+?)(?:\s+tools?|\s*$)/i,
        /(?:avoid|don't\s+use|exclude)\s+(.+?)(?:\s+tools?|\s*$)/i,
        /(?:with|using)\s+(.+?)(?:\s+tools?|\s*$)/i
    ]
};
// Common goal templates and their configurations
const GOAL_TEMPLATES = {
    // Development goals
    "build_website": {
        patterns: [/build.*website/i, /create.*site/i, /develop.*web/i],
        config: {
            risk: "write_fs",
            max_rounds: 25,
            hard_budget_seconds: 2400, // 40 minutes
            allowed_tools: ["fs_write_text", "fs_read_text", "web_search", "proc_run"]
        }
    },
    "fix_bugs": {
        patterns: [/fix.*bug/i, /debug/i, /resolve.*error/i, /repair.*issue/i],
        config: {
            risk: "write_fs",
            max_rounds: 15,
            hard_budget_seconds: 1800, // 30 minutes
            allowed_tools: ["fs_read_text", "fs_write_text", "proc_run", "grep"]
        }
    },
    "research_topic": {
        patterns: [/research/i, /investigate/i, /study.*topic/i, /analyze.*subject/i],
        config: {
            risk: "networked",
            max_rounds: 20,
            hard_budget_seconds: 1800,
            allowed_tools: ["web_search", "web_scraper", "fs_write_text", "download_file"]
        }
    },
    "optimize_code": {
        patterns: [/optimize/i, /improve.*performance/i, /enhance.*code/i],
        config: {
            risk: "write_fs",
            max_rounds: 20,
            hard_budget_seconds: 2400,
            allowed_tools: ["fs_read_text", "fs_write_text", "proc_run", "enhanced_data_analysis"]
        }
    },
    "security_audit": {
        patterns: [/security.*audit/i, /vulnerability.*scan/i, /penetration.*test/i],
        config: {
            risk: "read_only",
            max_rounds: 30,
            hard_budget_seconds: 3600,
            allowed_tools: ["vulnerability_scanner", "fs_read_text", "network_diagnostics"]
        }
    },
    "data_analysis": {
        patterns: [/analyze.*data/i, /data.*analysis/i, /process.*dataset/i],
        config: {
            risk: "write_fs",
            max_rounds: 25,
            hard_budget_seconds: 2400,
            allowed_tools: ["enhanced_data_analysis", "fs_read_text", "fs_write_text", "chart_generator"]
        }
    }
};
/**
 * Advanced Natural Language Processor for Cascade Operations
 */
class CascadeNaturalLanguageProcessor {
    /**
     * Parse a natural language input into a structured cascade specification
     */
    static parseInput(input) {
        const reasoning = [];
        let confidence = 0.7; // Base confidence
        // Extract goal
        let goal = input.trim();
        let extractedGoal = "";
        for (const pattern of CASCADE_PATTERNS.GOAL_PATTERNS) {
            const match = input.match(pattern);
            if (match && match[1]) {
                extractedGoal = match[1].trim();
                confidence += 0.1;
                reasoning.push(`Identified goal pattern: "${extractedGoal}"`);
                break;
            }
        }
        if (!extractedGoal) {
            extractedGoal = goal;
            reasoning.push("Using full input as goal (no specific pattern matched)");
        }
        // Check for goal templates
        let templateConfig = {};
        for (const [templateName, template] of Object.entries(GOAL_TEMPLATES)) {
            if (template.patterns.some(pattern => pattern.test(input))) {
                templateConfig = { ...template.config };
                confidence += 0.15;
                reasoning.push(`Matched goal template: ${templateName}`);
                break;
            }
        }
        // Extract time constraints
        let timeSeconds;
        for (const pattern of CASCADE_PATTERNS.TIME_PATTERNS) {
            const match = input.match(pattern);
            if (match && match[1]) {
                const value = parseInt(match[1]);
                if (pattern.source.includes('hour')) {
                    timeSeconds = value * 3600;
                }
                else if (pattern.source.includes('minute')) {
                    timeSeconds = value * 60;
                }
                else {
                    timeSeconds = value;
                }
                confidence += 0.1;
                reasoning.push(`Extracted time constraint: ${value} ${pattern.source.includes('hour') ? 'hours' : pattern.source.includes('minute') ? 'minutes' : 'seconds'}`);
                break;
            }
        }
        // Extract round constraints
        let maxRounds;
        for (const pattern of CASCADE_PATTERNS.ROUND_PATTERNS) {
            const match = input.match(pattern);
            if (match && match[1]) {
                maxRounds = parseInt(match[1]);
                confidence += 0.1;
                reasoning.push(`Extracted round constraint: ${maxRounds} rounds`);
                break;
            }
        }
        // Determine risk level
        let risk;
        for (const [riskLevel, patterns] of Object.entries(CASCADE_PATTERNS.RISK_PATTERNS)) {
            if (patterns.some((pattern) => pattern.test(input))) {
                risk = riskLevel.toLowerCase();
                confidence += 0.15;
                reasoning.push(`Detected risk level: ${risk}`);
                break;
            }
        }
        // Check for autonomy indicators
        const isAutonomous = CASCADE_PATTERNS.AUTONOMY_PATTERNS.some(pattern => pattern.test(input));
        if (isAutonomous) {
            if (!maxRounds)
                maxRounds = 20;
            if (!timeSeconds)
                timeSeconds = 1800; // 30 minutes
            if (!risk)
                risk = "write_fs";
            confidence += 0.1;
            reasoning.push("Detected autonomous operation request");
        }
        // Check for safety indicators
        let safeMode = false;
        let dryRun = false;
        for (const pattern of CASCADE_PATTERNS.SAFETY_PATTERNS) {
            if (pattern.test(input)) {
                if (pattern.source.includes('dry') || pattern.source.includes('simulate')) {
                    dryRun = true;
                    reasoning.push("Detected dry-run request");
                }
                else {
                    safeMode = true;
                    reasoning.push("Detected safety mode request");
                }
                confidence += 0.05;
            }
        }
        // Extract tool specifications
        let allowedTools;
        let disallowedTools;
        for (const pattern of CASCADE_PATTERNS.TOOL_PATTERNS) {
            const match = input.match(pattern);
            if (match && match[1]) {
                const tools = match[1].split(/[,\s]+/).filter(t => t.length > 0);
                if (pattern.source.includes('avoid') || pattern.source.includes("don't")) {
                    disallowedTools = tools;
                    reasoning.push(`Identified disallowed tools: ${tools.join(', ')}`);
                }
                else {
                    allowedTools = tools;
                    reasoning.push(`Identified allowed tools: ${tools.join(', ')}`);
                }
                confidence += 0.1;
            }
        }
        // Build result with template defaults and overrides
        const result = {
            goal: extractedGoal,
            context_hints: input !== extractedGoal ? `Original request: "${input}"` : undefined,
            max_rounds: maxRounds || templateConfig.max_rounds,
            hard_budget_seconds: timeSeconds || templateConfig.hard_budget_seconds,
            risk: risk || templateConfig.risk,
            allowed_tools: allowedTools || templateConfig.allowed_tools,
            disallowed_tools: disallowedTools,
            safe_mode: safeMode || templateConfig.safe_mode,
            dry_run: dryRun,
            confidence,
            reasoning
        };
        // Clean up undefined values
        Object.keys(result).forEach(key => {
            if (result[key] === undefined) {
                delete result[key];
            }
        });
        return result;
    }
    /**
     * Generate contextual suggestions based on the parsed input
     */
    static generateSuggestions(parsed) {
        const suggestions = [];
        // Risk level suggestions
        if (!parsed.risk) {
            suggestions.push("Consider specifying a risk level: 'read-only', 'write files', or 'networked'");
        }
        // Time budget suggestions
        if (!parsed.hard_budget_seconds) {
            suggestions.push("Consider adding a time limit: 'for 20 minutes' or 'within 1 hour'");
        }
        // Round limit suggestions
        if (!parsed.max_rounds) {
            suggestions.push("Consider setting a round limit: 'maximum 15 rounds' or 'up to 25 steps'");
        }
        // Safety suggestions
        if (parsed.risk === "write_fs" && !parsed.safe_mode) {
            suggestions.push("Consider enabling safe mode for file operations: 'with safe mode'");
        }
        // Tool suggestions based on goal
        const goalLower = parsed.goal.toLowerCase();
        if (goalLower.includes('web') && !parsed.allowed_tools?.some(t => t.includes('web'))) {
            suggestions.push("Consider specifying web tools: 'using web_search and web_scraper'");
        }
        if (goalLower.includes('file') && !parsed.allowed_tools?.some(t => t.includes('fs'))) {
            suggestions.push("Consider specifying file tools: 'using fs_read_text and fs_write_text'");
        }
        return suggestions;
    }
    /**
     * Validate the parsed configuration for potential issues
     */
    static validateConfiguration(parsed) {
        const warnings = [];
        const errors = [];
        // Check for conflicting configurations
        if (parsed.dry_run && parsed.risk === "networked") {
            warnings.push("Dry-run mode with networked risk may not prevent all external calls");
        }
        if (parsed.safe_mode && parsed.allowed_tools?.some(tool => ["vulnerability_scanner", "exploit_framework", "malware_analysis"].includes(tool))) {
            warnings.push("Safe mode enabled but potentially dangerous tools are allowed");
        }
        // Check for unrealistic constraints
        if (parsed.max_rounds && parsed.max_rounds > 50) {
            warnings.push("High round count may lead to excessive resource usage");
        }
        if (parsed.hard_budget_seconds && parsed.hard_budget_seconds > 7200) {
            warnings.push("Long time budget may cause timeout issues");
        }
        // Check for missing essential configurations
        if (!parsed.goal || parsed.goal.trim().length < 5) {
            errors.push("Goal is too short or missing");
        }
        if (parsed.confidence < 0.5) {
            warnings.push("Low confidence in parsing - consider rephrasing your request");
        }
        return {
            valid: errors.length === 0,
            warnings,
            errors
        };
    }
}
/**
 * Register the Autonomous Cascade Natural Language Interface
 */
export function registerAutonomousCascadeNl(server) {
    // Natural language interface tool with all advanced NLP functionality as sub-actions
    server.registerTool("ai_autonomous_cascade_nl", {
        description: "🗣️ **Autonomous Cascade Natural Language Interface** - Advanced natural language processing for autonomous cascade operations. Supports complex parsing, interactive building, template matching, and contextual suggestions.",
        inputSchema: z.object({
            action: z.enum(["parse_natural_language", "build_goal_interactive", "match_templates", "generate_suggestions"]).describe("NL action to perform: parse_natural_language (advanced parsing), build_goal_interactive (guided builder), match_templates (template matching), generate_suggestions (optimization suggestions)"),
            // Parse natural language parameters
            input: z.string().optional().describe("Natural language input to parse (required for parse_natural_language and match_templates actions)"),
            include_suggestions: z.boolean().optional().describe("Include contextual suggestions (default: true, for parse_natural_language action)"),
            validate_config: z.boolean().optional().describe("Validate the parsed configuration (default: true, for parse_natural_language action)"),
            // Interactive builder parameters
            partial_input: z.string().optional().describe("Partial input to start with (for build_goal_interactive action)"),
            step: z.enum(["goal", "risk", "time", "tools", "safety", "review"]).optional().describe("Current step in interactive builder (for build_goal_interactive action)"),
            previous_answers: z.record(z.string()).optional().describe("Previous answers from interactive session (for build_goal_interactive action)"),
            // Template matching parameters
            return_all_matches: z.boolean().optional().describe("Return all matches instead of top 3 (default: false, for match_templates action)"),
            // Suggestion generation parameters
            current_config: z.record(z.string()).optional().describe("Current cascade configuration to analyze (required for generate_suggestions action)"),
            context: z.string().optional().describe("Additional context for suggestions (for generate_suggestions action)"),
            focus_area: z.enum(["performance", "safety", "completeness", "efficiency"]).optional().describe("Focus area for suggestions (for generate_suggestions action)")
        }).shape
    }, async (args) => {
        try {
            const { action } = args;
            switch (action) {
                case "parse_natural_language": {
                    if (!args.input) {
                        return { success: false, error: "Input is required for parse_natural_language action" };
                    }
                    const include_suggestions = args.include_suggestions ?? true;
                    const validate_config = args.validate_config ?? true;
                    // Parse the natural language input
                    const parsed = CascadeNaturalLanguageProcessor.parseInput(args.input);
                    const result = {
                        parsed_config: parsed,
                        confidence: parsed.confidence,
                        reasoning: parsed.reasoning
                    };
                    // Add suggestions if requested
                    if (include_suggestions) {
                        result.suggestions = CascadeNaturalLanguageProcessor.generateSuggestions(parsed);
                    }
                    // Add validation if requested
                    if (validate_config) {
                        result.validation = CascadeNaturalLanguageProcessor.validateConfiguration(parsed);
                    }
                    return { success: true, result };
                }
                case "build_goal_interactive": {
                    const step = args.step || "goal";
                    const previous_answers = args.previous_answers || {};
                    const questions = {
                        goal: {
                            question: "What would you like to accomplish?",
                            examples: [
                                "Build a responsive website for my portfolio",
                                "Fix all TypeScript errors in my project",
                                "Research the latest trends in AI development",
                                "Optimize the performance of my database queries"
                            ]
                        },
                        risk: {
                            question: "What level of system access should be allowed?",
                            options: [
                                { value: "read_only", description: "Read-only access (safest)" },
                                { value: "write_fs", description: "File system write access" },
                                { value: "networked", description: "Network access (full capabilities)" }
                            ]
                        },
                        time: {
                            question: "How much time should be allocated?",
                            examples: ["10 minutes", "30 minutes", "1 hour", "2 hours"]
                        },
                        tools: {
                            question: "Are there specific tools you want to use or avoid?",
                            examples: [
                                "Only use web_search and fs_write_text",
                                "Avoid any destructive operations",
                                "Use development tools only"
                            ]
                        },
                        safety: {
                            question: "What safety measures should be enabled?",
                            options: [
                                { value: "safe_mode", description: "Enable safe mode (recommended)" },
                                { value: "dry_run", description: "Dry run only (preview actions)" },
                                { value: "normal", description: "Normal operation" }
                            ]
                        },
                        review: {
                            question: "Review your configuration:",
                            action: "generate_final_config"
                        }
                    };
                    const currentQuestion = questions[step];
                    if (step === "review") {
                        // Generate final configuration
                        const config = {
                            goal: previous_answers.goal,
                            risk: previous_answers.risk || "read_only",
                            hard_budget_seconds: previous_answers.time ? parseInt(previous_answers.time) * 60 : 600,
                            safe_mode: previous_answers.safety === "safe_mode",
                            dry_run: previous_answers.safety === "dry_run",
                            ...previous_answers
                        };
                        return {
                            success: true,
                            result: {
                                step: "complete",
                                final_config: config,
                                next_action: "Ready to start autonomous cascade"
                            }
                        };
                    }
                    return {
                        success: true,
                        result: {
                            step,
                            question: currentQuestion.question,
                            options: currentQuestion.options,
                            examples: currentQuestion.examples,
                            next_step: Object.keys(questions)[Object.keys(questions).indexOf(step) + 1]
                        }
                    };
                }
                case "match_templates": {
                    if (!args.input) {
                        return { success: false, error: "Input is required for match_templates action" };
                    }
                    const return_all_matches = args.return_all_matches || false;
                    const matches = [];
                    for (const [templateName, template] of Object.entries(GOAL_TEMPLATES)) {
                        const matchScore = template.patterns.reduce((score, pattern) => {
                            return pattern.test(args.input) ? score + 1 : score;
                        }, 0);
                        if (matchScore > 0) {
                            matches.push({
                                template: templateName,
                                score: matchScore,
                                config: template.config,
                                confidence: matchScore / template.patterns.length
                            });
                        }
                    }
                    // Sort by score (descending)
                    matches.sort((a, b) => b.score - a.score);
                    const result = return_all_matches ? matches : matches.slice(0, 3);
                    return { success: true, result };
                }
                case "generate_suggestions": {
                    if (!args.current_config) {
                        return { success: false, error: "Current config is required for generate_suggestions action" };
                    }
                    const { current_config, context, focus_area } = args;
                    const suggestions = [];
                    // Performance suggestions
                    if (!focus_area || focus_area === "performance") {
                        if (parseInt(current_config.max_rounds || "0") > 30) {
                            suggestions.push({
                                type: "performance",
                                suggestion: "Consider reducing max_rounds for faster execution",
                                impact: "medium"
                            });
                        }
                    }
                    // Safety suggestions
                    if (!focus_area || focus_area === "safety") {
                        if (current_config.risk === "networked" && current_config.safe_mode !== "true") {
                            suggestions.push({
                                type: "safety",
                                suggestion: "Enable safe_mode for networked operations",
                                impact: "high"
                            });
                        }
                    }
                    // Completeness suggestions
                    if (!focus_area || focus_area === "completeness") {
                        if (!current_config.goal || current_config.goal.length < 10) {
                            suggestions.push({
                                type: "completeness",
                                suggestion: "Provide a more detailed goal description",
                                impact: "high"
                            });
                        }
                    }
                    return { success: true, result: suggestions };
                }
                default:
                    return { success: false, error: `Unknown action: ${action}` };
            }
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : String(error)
            };
        }
    });
}
