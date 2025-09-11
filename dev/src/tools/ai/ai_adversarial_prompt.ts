/**
 * AI Adversarial Prompting Tool Registration
 * ==========================================
 * 
 * Registers the AI Adversarial Prompting Tool with the MCP server
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { AiAdversarialPromptTool, parseNaturalLanguageCommand } from "../../tools/aiAdversarialPrompt.js";

/**
 * Register the AI Adversarial Prompting Tool
 * @param server - The MCP server instance
 */
export function registerAiAdversarialPrompt(server: McpServer): void {
  const tool = new AiAdversarialPromptTool({
    openai_key: process.env.OPENAI_API_KEY,
    mcp_ai_endpoint: process.env.MCP_AI_ENDPOINT || 'http://localhost:3000/api/mcp-ai',
    log_dir: process.env.LOG_DIR || './logs'
  });

  server.registerTool("ai_adversarial_prompt", {
    description: "🤖 **AI Adversarial Prompting Tool** - Advanced AI testing with jailbreaking, poisoning, and hallucination capabilities. Supports self-targeting the MCP AI and external models. Cross-platform support.",
    inputSchema: {
      mode: z.enum(["jailbreaking", "poisoning", "hallucinations"]).describe("Adversarial prompting mode: jailbreaking (bypass restrictions), poisoning (inject biased data), hallucinations (induce creative outputs)"),
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
                  `## Analysis\n${result.analysis}`
          }
        ]
      };
    } catch (error: any) {
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
    } catch (error: any) {
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
                  `- MCP AI Endpoint: ${tool['mcpAiEndpoint']}`
          }
        ]
      };
    } catch (error: any) {
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


  console.log("✅ AI Adversarial Prompting Tool registered successfully");
}
