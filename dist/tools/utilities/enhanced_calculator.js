import { z } from "zod";
import * as math from "mathjs";
export function registerEnhancedCalculator(server) {
    server.registerTool("enhanced_calculator", {
        description: "🔢 **Enhanced Mathematical Calculator** - Comprehensive mathematical operations combining basic arithmetic, advanced scientific computing, expression evaluation, and statistical functions. Supports both simple operations (add, subtract, multiply, divide) and complex mathematical expressions with variables, precision control, and multiple output formats.",
        inputSchema: {
            mode: z.enum(["basic", "advanced", "expression"]).default("basic").describe("Calculation mode: 'basic' for simple operations, 'advanced' for scientific functions, 'expression' for mathematical expressions"),
            // Basic mode parameters
            operation: z.enum(["add", "subtract", "multiply", "divide", "power", "sqrt", "percentage", "factorial", "abs", "round", "floor", "ceil"]).optional().describe("Mathematical operation to perform (for basic mode)"),
            a: z.number().optional().describe("First number for calculation (for basic mode)"),
            b: z.number().optional().describe("Second number for calculation (for basic mode, not needed for unary operations)"),
            // Advanced/Expression mode parameters
            expression: z.string().optional().describe("Mathematical expression to evaluate (for advanced/expression modes). Supports variables, functions, and complex operations"),
            variables: z.record(z.number()).optional().describe("Variables to substitute in expression (for advanced/expression modes)"),
            // Common parameters
            precision: z.number().min(0).max(15).optional().describe("Decimal precision for results (0-15 digits)"),
            format: z.enum(["decimal", "fraction", "scientific", "engineering"]).default("decimal").describe("Output format for results"),
            // Advanced function parameters
            function_name: z.enum(["sin", "cos", "tan", "asin", "acos", "atan", "sinh", "cosh", "tanh", "log", "ln", "exp", "gcd", "lcm"]).optional().describe("Advanced mathematical function to apply"),
            angle_unit: z.enum(["degrees", "radians"]).default("radians").describe("Angle unit for trigonometric functions")
        },
        outputSchema: {
            success: z.boolean(),
            result: z.number().optional(),
            formatted_result: z.string().optional(),
            operation: z.string().optional(),
            mode: z.string(),
            message: z.string(),
            error: z.string().optional()
        }
    }, async ({ mode, operation, a, b, expression, variables, precision, format, function_name, angle_unit }) => {
        try {
            let result;
            let operationDescription;
            let resultMessage;
            switch (mode) {
                case "basic":
                    if (!operation || a === undefined) {
                        throw new Error("Operation and first number (a) are required for basic mode");
                    }
                    switch (operation) {
                        case "add":
                            if (b === undefined)
                                throw new Error("Second number (b) is required for addition");
                            result = a + b;
                            operationDescription = `Addition: ${a} + ${b}`;
                            break;
                        case "subtract":
                            if (b === undefined)
                                throw new Error("Second number (b) is required for subtraction");
                            result = a - b;
                            operationDescription = `Subtraction: ${a} - ${b}`;
                            break;
                        case "multiply":
                            if (b === undefined)
                                throw new Error("Second number (b) is required for multiplication");
                            result = a * b;
                            operationDescription = `Multiplication: ${a} × ${b}`;
                            break;
                        case "divide":
                            if (b === undefined)
                                throw new Error("Second number (b) is required for division");
                            if (b === 0)
                                throw new Error("Division by zero is not allowed");
                            result = a / b;
                            operationDescription = `Division: ${a} ÷ ${b}`;
                            break;
                        case "power":
                            if (b === undefined)
                                b = 2; // Default to square
                            result = Math.pow(a, b);
                            operationDescription = `Power: ${a}^${b}`;
                            break;
                        case "sqrt":
                            if (a < 0)
                                throw new Error("Cannot calculate square root of negative number");
                            result = Math.sqrt(a);
                            operationDescription = `Square root: √${a}`;
                            break;
                        case "percentage":
                            if (b === undefined)
                                b = 100; // Default to 100%
                            result = (a * b) / 100;
                            operationDescription = `Percentage: ${a}% of ${b}`;
                            break;
                        case "factorial":
                            if (a < 0 || !Number.isInteger(a))
                                throw new Error("Factorial is only defined for non-negative integers");
                            result = factorial(a);
                            operationDescription = `Factorial: ${a}!`;
                            break;
                        case "abs":
                            result = Math.abs(a);
                            operationDescription = `Absolute value: |${a}|`;
                            break;
                        case "round":
                            result = Math.round(a);
                            operationDescription = `Round: round(${a})`;
                            break;
                        case "floor":
                            result = Math.floor(a);
                            operationDescription = `Floor: floor(${a})`;
                            break;
                        case "ceil":
                            result = Math.ceil(a);
                            operationDescription = `Ceiling: ceil(${a})`;
                            break;
                        default:
                            throw new Error(`Unknown operation: ${operation}`);
                    }
                    resultMessage = `${operationDescription} = ${result}`;
                    break;
                case "advanced":
                    if (!function_name || a === undefined) {
                        throw new Error("Function name and input value are required for advanced mode");
                    }
                    let inputValue = a;
                    // Convert degrees to radians for trigonometric functions
                    if (["sin", "cos", "tan", "asin", "acos", "atan"].includes(function_name) && angle_unit === "degrees") {
                        inputValue = (inputValue * Math.PI) / 180;
                    }
                    switch (function_name) {
                        case "sin":
                            result = Math.sin(inputValue);
                            operationDescription = `Sine: sin(${a}${angle_unit === "degrees" ? "°" : " rad"})`;
                            break;
                        case "cos":
                            result = Math.cos(inputValue);
                            operationDescription = `Cosine: cos(${a}${angle_unit === "degrees" ? "°" : " rad"})`;
                            break;
                        case "tan":
                            result = Math.tan(inputValue);
                            operationDescription = `Tangent: tan(${a}${angle_unit === "degrees" ? "°" : " rad"})`;
                            break;
                        case "asin":
                            result = Math.asin(inputValue);
                            operationDescription = `Arcsine: arcsin(${a})`;
                            break;
                        case "acos":
                            result = Math.acos(inputValue);
                            operationDescription = `Arccosine: arccos(${a})`;
                            break;
                        case "atan":
                            result = Math.atan(inputValue);
                            operationDescription = `Arctangent: arctan(${a})`;
                            break;
                        case "sinh":
                            result = Math.sinh(inputValue);
                            operationDescription = `Hyperbolic sine: sinh(${a})`;
                            break;
                        case "cosh":
                            result = Math.cosh(inputValue);
                            operationDescription = `Hyperbolic cosine: cosh(${a})`;
                            break;
                        case "tanh":
                            result = Math.tanh(inputValue);
                            operationDescription = `Hyperbolic tangent: tanh(${a})`;
                            break;
                        case "log":
                            if (a <= 0)
                                throw new Error("Logarithm is only defined for positive numbers");
                            result = Math.log10(a);
                            operationDescription = `Logarithm base 10: log(${a})`;
                            break;
                        case "ln":
                            if (a <= 0)
                                throw new Error("Natural logarithm is only defined for positive numbers");
                            result = Math.log(a);
                            operationDescription = `Natural logarithm: ln(${a})`;
                            break;
                        case "exp":
                            result = Math.exp(a);
                            operationDescription = `Exponential: e^${a}`;
                            break;
                        case "gcd":
                            if (b === undefined)
                                throw new Error("Second number (b) is required for GCD calculation");
                            result = gcd(Math.abs(a), Math.abs(b));
                            operationDescription = `Greatest Common Divisor: gcd(${a}, ${b})`;
                            break;
                        case "lcm":
                            if (b === undefined)
                                throw new Error("Second number (b) is required for LCM calculation");
                            result = lcm(Math.abs(a), Math.abs(b));
                            operationDescription = `Least Common Multiple: lcm(${a}, ${b})`;
                            break;
                        default:
                            throw new Error(`Unknown function: ${function_name}`);
                    }
                    resultMessage = `${operationDescription} = ${result}`;
                    break;
                case "expression":
                    if (!expression) {
                        throw new Error("Expression is required for expression mode");
                    }
                    let processedExpression = expression;
                    // Substitute variables if provided
                    if (variables) {
                        for (const [varName, varValue] of Object.entries(variables)) {
                            processedExpression = processedExpression.replace(new RegExp(`\\b${varName}\\b`, 'g'), varValue.toString());
                        }
                    }
                    try {
                        result = math.evaluate(processedExpression);
                        operationDescription = `Expression: ${expression}`;
                        resultMessage = `${operationDescription} = ${result}`;
                    }
                    catch (mathError) {
                        throw new Error(`Invalid mathematical expression: ${mathError instanceof Error ? mathError.message : 'Unknown error'}`);
                    }
                    break;
                default:
                    throw new Error(`Unknown mode: ${mode}`);
            }
            // Apply precision
            if (precision !== undefined) {
                result = Number(result.toFixed(precision));
            }
            // Format result
            let formatted_result = formatResult(result, format);
            return {
                content: [{
                        type: "text",
                        text: resultMessage
                    }],
                structuredContent: {
                    success: true,
                    result,
                    formatted_result,
                    operation: operationDescription,
                    mode,
                    message: resultMessage
                }
            };
        }
        catch (error) {
            return {
                content: [{
                        type: "text",
                        text: `Calculation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                    }],
                structuredContent: {
                    success: false,
                    mode: mode || "unknown",
                    message: `Calculation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
                    error: error instanceof Error ? error.message : 'Unknown error'
                }
            };
        }
    });
}
// Helper functions
function factorial(n) {
    if (n === 0 || n === 1)
        return 1;
    let result = 1;
    for (let i = 2; i <= n; i++) {
        result *= i;
    }
    return result;
}
function gcd(a, b) {
    while (b !== 0) {
        let temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}
function lcm(a, b) {
    return Math.abs(a * b) / gcd(a, b);
}
function formatResult(result, format) {
    switch (format) {
        case "scientific":
            return result.toExponential();
        case "engineering":
            return result.toExponential().replace(/e([+-]?\d+)/, 'e$1');
        case "fraction":
            // Simple fraction approximation for common decimals
            const tolerance = 1e-6;
            const numerator = Math.round(result / tolerance);
            const denominator = Math.round(1 / tolerance);
            const gcd_value = gcd(numerator, denominator);
            const simplified_num = numerator / gcd_value;
            const simplified_den = denominator / gcd_value;
            if (simplified_den === 1) {
                return simplified_num.toString();
            }
            else if (Math.abs(result - simplified_num / simplified_den) < tolerance) {
                return `${simplified_num}/${simplified_den}`;
            }
            else {
                return result.toString();
            }
        case "decimal":
        default:
            return result.toString();
    }
}
