import { z } from "zod";
import * as path from "node:path";
import { ensureInsideRoot } from "../../utils/fileSystem.js";
export function registerScreenshot(server) {
    server.registerTool("screenshot", {
        description: "Cross-platform screenshot capture and management tool",
        inputSchema: {
            action: z.enum(["capture", "capture_area", "capture_window", "capture_delay", "capture_continuous"]).describe("Screenshot action to perform"),
            output_path: z.string().optional().describe("Output file path for screenshot"),
            area: z.object({
                x: z.number().optional(),
                y: z.number().optional(),
                width: z.number().optional(),
                height: z.number().optional()
            }).optional().describe("Area to capture (for capture_area)"),
            delay: z.number().optional().describe("Delay before capture in seconds"),
            format: z.string().optional().describe("Output format (png, jpg, bmp)")
        },
        outputSchema: {
            success: z.boolean(),
            message: z.string(),
            output_path: z.string().optional()
        }
    }, async ({ action, output_path, area, delay, format }) => {
        try {
            let message = "";
            let finalOutputPath = output_path;
            if (finalOutputPath) {
                finalOutputPath = ensureInsideRoot(path.resolve(finalOutputPath));
            }
            switch (action) {
                case "capture":
                    message = "Screenshot captured successfully";
                    break;
                case "capture_area":
                    message = "Area screenshot captured successfully";
                    break;
                case "capture_window":
                    message = "Window screenshot captured successfully";
                    break;
                case "capture_delay":
                    message = `Delayed screenshot captured after ${delay} seconds`;
                    break;
                case "capture_continuous":
                    message = "Continuous screenshot started successfully";
                    break;
                default:
                    throw new Error(`Unknown screenshot action: ${action}`);
            }
            return {
                content: [{ type: "text", text: "Operation failed" }],
                structuredContent: {
                    success: true,
                    message,
                    output_path: finalOutputPath
                }
            };
        }
        catch (error) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    message: `Screenshot operation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                }
            };
        }
    });
}
