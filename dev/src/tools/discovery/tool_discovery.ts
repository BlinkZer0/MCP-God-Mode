import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { enhancedToolDiscovery } from "../../utils/natural-language-router.js";

export function registerToolDiscovery(server: McpServer) {
  server.registerTool("tool_discovery", {
    description: "Discover and explore all available tools using natural language queries",
    inputSchema: {
      query: z.string().describe("Natural language query to find relevant tools"),
      category: z.string().optional().describe("Optional tool category to focus on"),
      capability: z.string().optional().describe("Specific capability or feature to search for")
    },
    outputSchema: {
      tools: z.array(z.object({
        name: z.string(),
        description: z.string(),
        category: z.string(),
        capabilities: z.array(z.string())
      })),
      total_found: z.number(),
      query: z.string(),
      natural_language_routing: z.object({
        suggested_tools: z.array(z.string()),
        confidence: z.number(),
        reasoning: z.string()
      }).optional(),
      suggested_tools: z.array(z.string()).optional(),
      confidence: z.number().optional()
    }
  }, async ({ query, category, capability }) => {
    // Use enhanced natural language routing for comprehensive tool discovery
    const result = enhancedToolDiscovery(query, category, capability);
    
    return {
      content: [{
        type: "text",
        text: `Found ${result.total_found} tools matching your query "${query}". ${result.natural_language_routing.reasoning}`
      }],
      structuredContent: result
    };
  });
}