import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PLATFORM } from "../../config/environment.js";

export function registerDataAnalyzer(server: McpServer) {
  server.registerTool("data_analyzer", {
    description: "Data analysis and statistical processing",
    inputSchema: {
      action: z.enum(["analyze", "statistics", "correlation", "trend_analysis", "outlier_detection"]).describe("Data analysis action to perform"),
      data: z.array(z.number()).describe("Array of numerical data to analyze"),
      analysis_type: z.enum(["descriptive", "inferential", "predictive"]).optional().describe("Type of analysis to perform"),
      options: z.object({
        confidence_level: z.number().optional(),
        outlier_threshold: z.number().optional()
      }).optional().describe("Analysis options and parameters")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string(),
      results: z.object({
        mean: z.number().optional(),
        median: z.number().optional(),
        standard_deviation: z.number().optional(),
        min: z.number().optional(),
        max: z.number().optional(),
        outliers: z.array(z.number()).optional()
      }).optional()
    }
  }, async ({ action, data, analysis_type, options }) => {
    try {
      // Data analysis implementation
      const mean = data.reduce((sum, val) => sum + val, 0) / data.length;
      const sortedData = [...data].sort((a, b) => a - b);
      const median = sortedData[Math.floor(sortedData.length / 2)];
      const min = Math.min(...data);
      const max = Math.max(...data);
      
      // Calculate standard deviation
      const variance = data.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / data.length;
      const standardDeviation = Math.sqrt(variance);
      
      // Detect outliers (values beyond 2 standard deviations)
      const outlierThreshold = options?.outlier_threshold || 2;
      const outliers = data.filter(val => Math.abs(val - mean) > outlierThreshold * standardDeviation);
      
      const results = {
        mean,
        median,
        standard_deviation: standardDeviation,
        min,
        max,
        outliers
      };
      
      return { 
        content: [], 
        structuredContent: { 
          success: true, 
          message: `Data analysis completed successfully for ${data.length} data points`,
          results 
        } 
      };
    } catch (error) {
      return { content: [], structuredContent: { success: false, message: `Data analysis failed: ${(error as Error).message}` } };
    }
  });
}
