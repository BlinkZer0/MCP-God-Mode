import { z } from "zod";
import * as math from "mathjs";
export function registerMathCalculate(server) {
    server.registerTool("math_calculate", {
        description: "Advanced mathematical calculations and scientific computing",
        inputSchema: {
            expression: z.string().describe("Mathematical expression to evaluate"),
            precision: z.number().optional().describe("Decimal precision for results"),
            variables: z.record(z.number()).optional().describe("Variables to substitute in expression"),
            format: z.enum(["decimal", "fraction", "scientific"]).optional().describe("Output format for results")
        },
        outputSchema: {
            success: z.boolean(),
            result: z.number().optional(),
            formatted_result: z.string().optional(),
            error: z.string().optional()
        }
    }, async ({ expression, precision, variables, format }) => {
        try {
            // Math calculation implementation
            let result;
            if (variables) {
                // Substitute variables
                let processedExpression = expression;
                for (const [varName, varValue] of Object.entries(variables)) {
                    processedExpression = processedExpression.replace(new RegExp(varName, 'g'), varValue.toString());
                }
                result = math.evaluate(processedExpression);
            }
            else {
                result = math.evaluate(expression);
            }
            // Apply precision
            if (precision !== undefined) {
                result = Number(result.toFixed(precision));
            }
            // Format result
            let formatted_result = result.toString();
            if (format === "scientific") {
                formatted_result = result.toExponential();
            }
            else if (format === "fraction" && Number.isInteger(result)) {
                formatted_result = result.toString();
            }
            return {
                content: [],
                structuredContent: {
                    success: true,
                    result,
                    formatted_result
                }
            };
        }
        catch (error) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    error: error instanceof Error ? error.message : 'Unknown error'
                }
            };
        }
    });
}
