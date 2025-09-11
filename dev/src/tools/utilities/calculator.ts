import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PLATFORM } from "../../config/environment.js";

export function registerCalculator(server: McpServer) {
  server.registerTool("calculator", {
    description: "Basic mathematical calculator with standard operations",
    inputSchema: {
      operation: z.enum(["add", "subtract", "multiply", "divide", "power", "sqrt", "percentage"]).describe("Mathematical operation to perform"),
      a: z.number().describe("First number for calculation"),
      b: z.number().optional().describe("Second number for calculation (not needed for sqrt)"),
      precision: z.number().optional().describe("Decimal precision for result")
    },
    outputSchema: {
      success: z.boolean(),
      result: z.number(),
      operation: z.string(),
      message: z.string().describe("Calculation result message")
    }
  }, async ({ operation, a, b, precision }) => {
    try {
      let result: number;
      
      switch (operation) {
        case "add":
          result = a + (b || 0);
          break;
        case "subtract":
          result = a - (b || 0);
          break;
        case "multiply":
          result = a * (b || 1);
          break;
        case "divide":
          if (b === 0) throw new Error("Division by zero");
          result = b !== undefined && b !== 0 ? a / b : Infinity;
          break;
        case "power":
          result = Math.pow(a, b || 2);
          break;
        case "sqrt":
          if (a < 0) throw new Error("Cannot calculate square root of negative number");
          result = Math.sqrt(a);
          break;
        case "percentage":
          result = (a * (b || 100)) / 100;
          break;
        default:
          throw new Error(`Unknown operation: ${operation}`);
      }
      
      if (precision !== undefined) {
        result = Number(result.toFixed(precision));
      }
      
      return { 
        content: [], 
        structuredContent: { 
          success: true, 
          result,
          operation,
          message: `Calculation completed: ${operation}(${a}${b !== undefined ? `, ${b}` : ''}) = ${result}`
        } 
      };
    } catch (error) {
      return { content: [], structuredContent: { success: false, result: 0, operation, message: `Calculation failed: ${(error as Error).message}` } };
    }
  });
}
