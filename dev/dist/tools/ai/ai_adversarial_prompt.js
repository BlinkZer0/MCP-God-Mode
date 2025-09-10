/**
 * AI Adversarial Prompting Tool Registration
 * ==========================================
 *
 * Registers the AI Adversarial Prompting Tool with the MCP server
 */
import { z } from "zod";
import { AiAdversarialPromptTool, parseNaturalLanguageCommand } from "../../tools/aiAdversarialPrompt.js";
/**
 * Register the AI Adversarial Prompting Tool
 * @param server - The MCP server instance
 */
export function registerAiAdversarialPrompt(server) {
    const tool = new AiAdversarialPromptTool({
        openai_key: process.env.OPENAI_API_KEY,
        mcp_ai_endpoint: process.env.MCP_AI_ENDPOINT || 'http://localhost:3000/api/mcp-ai',
        log_dir: process.env.LOG_DIR || './logs',
        confirmation_required: process.env.CONFIRM_JAILBREAK !== 'NO',
        log_all_interactions: process.env.LOG_ALL_INTERACTIONS !== 'NO'
    });
    server.registerTool("ai_adversarial_prompt", {
        description: "🤖 **AI Adversarial Prompting Tool** - Advanced AI security testing with jailbreaking, poisoning, and hallucination capabilities. Supports self-targeting the MCP AI and external models. Cross-platform support with ethical safeguards and comprehensive logging.",
        inputSchema: {
            mode: z.enum(["jailbreaking", "poisoning", "hallucinations"]).describe("Adversarial prompting mode: jailbreaking (bypass safety filters), poisoning (inject biased data), hallucinations (induce false outputs)"),
            target_model: z.string().default("self").describe("Target model: 'self' (MCP AI), 'gpt-3.5-turbo', 'gpt-4', 'gpt2', 'local', etc."),
            topic: z.string().default("general").describe("Topic or subject for the adversarial prompt"),
            iterations: z.number().default(3).describe("Number of prompt variations (especially for poisoning mode)"),
            api_key: z.string().optional().describe("OpenAI API key (if not set in environment)"),
            use_local: z.boolean().default(false).describe("Use local model instead of API (not applicable for 'self' target)"),
            mcp_ai_endpoint: z.string().optional().describe("MCP AI endpoint for self-targeting (defaults to http://localhost:3000/api/mcp-ai)")
        }
    }, async (params) => {
        try {
            const result = await tool.execute(params);
            return {
                content: [
                    {
                        type: "text",
                        text: `# AI Adversarial Prompting Results\n\n` +
                            `**Status:** ${result.status}\n` +
                            `**Details:** ${result.details}\n` +
                            `**Platform:** ${result.platform}\n` +
                            `**Timestamp:** ${result.timestamp}\n\n` +
                            `## Generated Prompt\n\`\`\`\n${result.prompt}\n\`\`\`\n\n` +
                            `## AI Response\n\`\`\`\n${result.ai_response}\n\`\`\`\n\n` +
                            `## Analysis\n${result.analysis}\n\n` +
                            `⚠️ **Ethical Notice:** This tool is for AI security research only. All interactions are logged for audit purposes.`
                    }
                ]
            };
        }
        catch (error) {
            return {
                content: [
                    {
                        type: "text",
                        text: `❌ **Error executing AI adversarial prompt:** ${error.message}\n\n` +
                            `Please check your configuration and try again.`
                    }
                ]
            };
        }
    });
    // Register natural language processing tool for AI adversarial commands
    server.registerTool("ai_adversarial_nlp", {
        description: "🧠 **AI Adversarial Natural Language Processor** - Parse natural language commands for AI adversarial prompting. Converts commands like 'Jailbreak the server AI about climate change' into structured parameters.",
        inputSchema: {
            command: z.string().describe("Natural language command for AI adversarial prompting (e.g., 'Jailbreak the server AI about climate change', 'Poison the AI with false historical facts')")
        }
    }, async ({ command }) => {
        try {
            const parsed = parseNaturalLanguageCommand(command);
            return {
                content: [
                    {
                        type: "text",
                        text: `# Natural Language Command Parsed\n\n` +
                            `**Original Command:** ${command}\n\n` +
                            `**Parsed Parameters:**\n` +
                            `- Mode: ${parsed.mode}\n` +
                            `- Target Model: ${parsed.target_model}\n` +
                            `- Topic: ${parsed.topic}\n` +
                            `- Iterations: ${parsed.iterations}\n\n` +
                            `You can now use these parameters with the ai_adversarial_prompt tool.`
                    }
                ]
            };
        }
        catch (error) {
            return {
                content: [
                    {
                        type: "text",
                        text: `❌ **Error parsing natural language command:** ${error.message}`
                    }
                ]
            };
        }
    });
    // Register platform info tool
    server.registerTool("ai_adversarial_platform_info", {
        description: "📱 **AI Adversarial Platform Information** - Get platform-specific information and supported models for AI adversarial prompting.",
        inputSchema: {}
    }, async () => {
        try {
            const platformInfo = tool.getPlatformInfo();
            const supportedModels = tool.getSupportedModels();
            return {
                content: [
                    {
                        type: "text",
                        text: `# AI Adversarial Platform Information\n\n` +
                            `**Platform:** ${platformInfo.platform}\n` +
                            `**Mobile:** ${platformInfo.is_mobile ? 'Yes' : 'No'}\n` +
                            `**OpenAI Available:** ${platformInfo.openai_available ? 'Yes' : 'No'}\n` +
                            `**Local Model Available:** ${platformInfo.local_model_available ? 'Yes' : 'No'}\n` +
                            `**Axios Available:** ${platformInfo.axios_available ? 'Yes' : 'No'}\n\n` +
                            `## Supported Models\n${supportedModels.map(model => `- ${model}`).join('\n')}\n\n` +
                            `## Configuration\n` +
                            `- MCP AI Endpoint: ${tool['mcpAiEndpoint']}\n` +
                            `- Confirmation Required: ${tool['confirmationRequired']}\n` +
                            `- Log All Interactions: ${tool['logAllInteractions']}`
                    }
                ]
            };
        }
        catch (error) {
            return {
                content: [
                    {
                        type: "text",
                        text: `❌ **Error getting platform information:** ${error.message}`
                    }
                ]
            };
        }
    });
    // Register ethics and compliance tools
    server.registerTool("ai_adversarial_ethics", {
        description: "🔒 **AI Adversarial Ethics & Compliance** - Advanced ethics monitoring, compliance reporting, and audit trail management for AI adversarial operations.",
        inputSchema: {
            action: z.enum(["compliance_report", "audit_statistics", "ethics_config"]).describe("Ethics action to perform"),
            framework: z.string().optional().describe("Compliance framework (GDPR, CCPA, SOX, HIPAA)"),
            start_date: z.string().optional().describe("Start date for compliance report (ISO format)"),
            end_date: z.string().optional().describe("End date for compliance report (ISO format)")
        }
    }, async ({ action, framework, start_date, end_date }) => {
        try {
            const ethics = tool.getEthicsModule();
            switch (action) {
                case 'compliance_report':
                    if (!framework) {
                        return {
                            content: [{ type: "text", text: "❌ Framework parameter required for compliance report" }]
                        };
                    }
                    const report = await ethics.generateComplianceReport(framework, start_date, end_date);
                    return {
                        content: [
                            {
                                type: "text",
                                text: `# Compliance Report: ${framework}\n\n` +
                                    `**Compliance Status:** ${report.compliance ? '✅ Compliant' : '❌ Non-Compliant'}\n\n` +
                                    `## Violations\n${report.violations.length > 0 ? report.violations.map(v => `- ${v}`).join('\n') : 'None detected'}\n\n` +
                                    `## Recommendations\n${report.recommendations.map(r => `- ${r}`).join('\n')}\n\n` +
                                    `## Audit Entries\n${report.auditTrail.length} entries found`
                            }
                        ]
                    };
                case 'audit_statistics':
                    const stats = await ethics.getAuditStatistics();
                    return {
                        content: [
                            {
                                type: "text",
                                text: `# Audit Statistics\n\n` +
                                    `**Total Operations:** ${stats.totalOperations}\n` +
                                    `**Successful Operations:** ${stats.successfulOperations}\n` +
                                    `**Failed Operations:** ${stats.failedOperations}\n` +
                                    `**Self-Targeting Operations:** ${stats.selfTargetingOperations}\n` +
                                    `**Confirmation Required Operations:** ${stats.confirmationRequiredOperations}\n` +
                                    `**Blocked Operations:** ${stats.blockedOperations}`
                            }
                        ]
                    };
                case 'ethics_config':
                    const config = ethics.getConfig();
                    return {
                        content: [
                            {
                                type: "text",
                                text: `# Ethics Configuration\n\n` +
                                    `**Enabled:** ${config.enabled}\n` +
                                    `**Require Confirmation:** ${config.requireConfirmation}\n` +
                                    `**Log All Interactions:** ${config.logAllInteractions}\n` +
                                    `**Audit Trail:** ${config.auditTrail}\n` +
                                    `**Rate Limiting:** ${config.rateLimiting}\n` +
                                    `**Max Requests Per Hour:** ${config.maxRequestsPerHour}\n` +
                                    `**Compliance Frameworks:** ${config.complianceFrameworks.join(', ')}\n` +
                                    `**Legal Jurisdiction:** ${config.legalJurisdiction}`
                            }
                        ]
                    };
                default:
                    return {
                        content: [{ type: "text", text: `❌ Unknown action: ${action}` }]
                    };
            }
        }
        catch (error) {
            return {
                content: [
                    {
                        type: "text",
                        text: `❌ **Error in ethics operation:** ${error.message}`
                    }
                ]
            };
        }
    });
    console.log("✅ AI Adversarial Prompting Tool registered successfully");
}
