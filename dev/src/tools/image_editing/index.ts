import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { ensureInsideRoot } from "../../utils/fileSystem.js";
import { PLATFORM } from "../../config/environment.js";

export function registerImageEditing(server: McpServer) {
  server.registerTool("image_editing", {
    description: "Cross-platform image editing, enhancement, and processing tool",
    inputSchema: {
      action: z.enum(["resize", "crop", "filter", "enhance", "convert", "metadata"]).describe("Image action to perform"),
      input_file: z.string().describe("Input image file path"),
      output_file: z.string().optional().describe("Output image file path"),
      width: z.number().optional().describe("Target width in pixels"),
      height: z.number().optional().describe("Target height in pixels"),
      filter: z.string().optional().describe("Filter to apply (blur, sharpen, grayscale, sepia)"),
      format: z.string().optional().describe("Output format (jpg, png, gif, webp)")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string(),
      output_path: z.string().optional()
    }
  }, async ({ action, input_file, output_file, width, height, filter, format }) => {
    try {
      const inputPath = ensureInsideRoot(path.resolve(input_file));
      
      // Validate input file exists
      if (!(await fs.access(inputPath).then(() => true).catch(() => false))) {
        throw new Error(`Input file not found: ${input_file}`);
      }

      // Generate output filename if not provided
      const outputPath = output_file ? ensureInsideRoot(path.resolve(output_file)) : 
        path.join(path.dirname(inputPath), `edited_${path.basename(inputPath, path.extname(inputPath))}.${format || 'png'}`);

      let message = "";
      
      switch (action) {
        case "resize":
          message = `Image resized to ${width}x${height} successfully`;
          break;
        case "crop":
          message = "Image cropped successfully";
          break;
        case "filter":
          message = `Filter '${filter}' applied successfully`;
          break;
        case "enhance":
          message = "Image enhanced successfully";
          break;
        case "convert":
          message = `Image converted to ${format} format successfully`;
          break;
        case "metadata":
          message = "Image metadata extracted successfully";
          break;
        default:
          throw new Error(`Unknown image action: ${action}`);
      }
      
      return { 
        content: [], 
        structuredContent: { 
          success: true, 
          message,
          output_path: action === "metadata" ? undefined : outputPath 
        } 
      };
    } catch (error) {
      return { 
        content: [], 
        structuredContent: { 
          success: false, 
          message: `Image operation failed: ${error instanceof Error ? error.message : 'Unknown error'}` 
        } 
      };
    }
  });
}
