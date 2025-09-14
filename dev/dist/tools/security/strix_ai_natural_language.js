import { z } from "zod";
export function registerStrixAINaturalLanguage(server) {
    server.registerTool("strix_ai_natural_language", {
        description: "🤖 **Strix AI Natural Language Interface** - Process natural language commands for Strix AI dynamic code analysis and exploitation operations. Converts conversational requests like 'analyze this codebase for vulnerabilities' into structured Strix AI commands.",
        inputSchema: {
            command: z.string().describe("Natural language command for Strix AI operations (e.g., 'analyze this codebase for vulnerabilities', 'validate exploits in the target', 'generate auto-fixes for the code', 'integrate with CI/CD pipeline')")
        },
        outputSchema: {
            success: z.boolean(),
            message: z.string(),
            parsed_command: z.object({
                action: z.string(),
                target: z.string(),
                analysisDepth: z.string().optional(),
                vulnerabilityType: z.string().optional(),
                autoExploit: z.boolean().optional(),
                fixSuggestions: z.boolean().optional(),
                integrationType: z.string().optional(),
                sandboxMode: z.boolean().optional(),
                safeMode: z.boolean().optional()
            })
        }
    }, async ({ command }) => {
        try {
            const parsed = processNaturalLanguageCommand(command);
            return {
                success: true,
                message: `Strix AI natural language command processed: ${command}`,
                parsed_command: parsed
            };
        }
        catch (error) {
            return {
                success: false,
                message: `Failed to process natural language command: ${error instanceof Error ? error.message : String(error)}`,
                parsed_command: {
                    action: "dynamic_code_analysis",
                    target: "",
                    safeMode: true
                }
            };
        }
    });
}
function processNaturalLanguageCommand(command) {
    const lowerCommand = command.toLowerCase();
    // Extract target from command
    const targetMatch = command.match(/(?:for|on|in|analyze|scan|test)\s+([a-zA-Z0-9\-_\.\/\s]+?)(?:\s+(?:for|with|using|in|on)|$)/i);
    const target = targetMatch ? targetMatch[1].trim() : "target_codebase";
    // Determine action based on keywords
    let action = "dynamic_code_analysis";
    let analysisDepth = "comprehensive";
    let vulnerabilityType = "all";
    let autoExploit = false;
    let fixSuggestions = false;
    let integrationType = "github_actions";
    let sandboxMode = true;
    let safeMode = false;
    // Action detection
    if (lowerCommand.includes("analyze") || lowerCommand.includes("analysis")) {
        if (lowerCommand.includes("dynamic") || lowerCommand.includes("runtime")) {
            action = "dynamic_analysis";
        }
        else if (lowerCommand.includes("static") || lowerCommand.includes("code inspection")) {
            action = "static_analysis";
        }
        else {
            action = "dynamic_code_analysis";
        }
    }
    else if (lowerCommand.includes("scan") || lowerCommand.includes("vulnerability")) {
        action = "vulnerability_scan";
    }
    else if (lowerCommand.includes("exploit") || lowerCommand.includes("validate")) {
        action = "exploitation_validation";
    }
    else if (lowerCommand.includes("fix") || lowerCommand.includes("remediation")) {
        action = "auto_fix_suggestion";
    }
    else if (lowerCommand.includes("ci/cd") || lowerCommand.includes("pipeline") || lowerCommand.includes("integration")) {
        action = "ci_cd_integration";
    }
    else if (lowerCommand.includes("sandbox") || lowerCommand.includes("execute")) {
        action = "sandbox_execution";
    }
    // Analysis depth
    if (lowerCommand.includes("basic") || lowerCommand.includes("quick")) {
        analysisDepth = "basic";
    }
    else if (lowerCommand.includes("comprehensive") || lowerCommand.includes("thorough")) {
        analysisDepth = "comprehensive";
    }
    else if (lowerCommand.includes("deep") || lowerCommand.includes("extensive")) {
        analysisDepth = "deep";
    }
    // Vulnerability type
    if (lowerCommand.includes("sql injection") || lowerCommand.includes("sqli")) {
        vulnerabilityType = "sql_injection";
    }
    else if (lowerCommand.includes("xss") || lowerCommand.includes("cross-site")) {
        vulnerabilityType = "xss";
    }
    else if (lowerCommand.includes("buffer overflow") || lowerCommand.includes("overflow")) {
        vulnerabilityType = "buffer_overflow";
    }
    else if (lowerCommand.includes("rce") || lowerCommand.includes("remote code")) {
        vulnerabilityType = "rce";
    }
    else if (lowerCommand.includes("path traversal") || lowerCommand.includes("directory traversal")) {
        vulnerabilityType = "path_traversal";
    }
    // Auto-exploit
    if (lowerCommand.includes("auto exploit") || lowerCommand.includes("automatically exploit")) {
        autoExploit = true;
    }
    // Fix suggestions
    if (lowerCommand.includes("fix") || lowerCommand.includes("remediation") || lowerCommand.includes("patch")) {
        fixSuggestions = true;
    }
    // Integration type
    if (lowerCommand.includes("github")) {
        integrationType = "github_actions";
    }
    else if (lowerCommand.includes("jenkins")) {
        integrationType = "jenkins";
    }
    else if (lowerCommand.includes("gitlab")) {
        integrationType = "gitlab_ci";
    }
    else if (lowerCommand.includes("azure")) {
        integrationType = "azure_devops";
    }
    // Sandbox mode
    if (lowerCommand.includes("sandbox") || lowerCommand.includes("isolated")) {
        sandboxMode = true;
    }
    // Safe mode
    if (lowerCommand.includes("safe mode") || lowerCommand.includes("simulation") || lowerCommand.includes("test")) {
        safeMode = true;
    }
    return {
        action,
        target,
        analysisDepth,
        vulnerabilityType,
        autoExploit,
        fixSuggestions,
        integrationType,
        sandboxMode,
        safeMode
    };
}
