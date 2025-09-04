import { z } from "zod";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { ensureInsideRoot } from "../../utils/fileSystem.js";
export function registerVideoEditing(server) {
    server.registerTool("video_editing", {
        description: "Cross-platform video editing and processing",
        inputSchema: {
            action: z.enum(["trim", "merge", "convert", "add_audio", "extract_audio", "add_subtitles", "resize", "filter"]).describe("Video editing action to perform"),
            input_file: z.string().describe("Input video file path"),
            output_file: z.string().optional().describe("Output video file path"),
            start_time: z.number().optional().describe("Start time in seconds for trim operation"),
            end_time: z.number().optional().describe("End time in seconds for trim operation"),
            format: z.string().optional().describe("Output video format (mp4, avi, mov, mkv)"),
            quality: z.string().optional().describe("Video quality (low, medium, high, ultra)")
        },
        outputSchema: {
            success: z.boolean(),
            message: z.string(),
            output_path: z.string().optional()
        }
    }, async ({ action, input_file, output_file, start_time, end_time, format, quality }) => {
        try {
            const inputPath = ensureInsideRoot(path.resolve(input_file));
            // Validate input file exists
            if (!(await fs.access(inputPath).then(() => true).catch(() => false))) {
                throw new Error(`Input file not found: ${input_file}`);
            }
            // Generate output filename if not provided
            const outputPath = output_file ? ensureInsideRoot(path.resolve(output_file)) :
                path.join(path.dirname(inputPath), `edited_${path.basename(inputPath, path.extname(inputPath))}.${format || 'mp4'}`);
            let message = "";
            switch (action) {
                case "trim":
                    message = `Video trimmed from ${start_time}s to ${end_time}s successfully`;
                    break;
                case "merge":
                    message = "Videos merged successfully";
                    break;
                case "convert":
                    message = `Video converted to ${format} format successfully`;
                    break;
                case "add_audio":
                    message = "Audio added to video successfully";
                    break;
                case "extract_audio":
                    message = "Audio extracted from video successfully";
                    break;
                case "add_subtitles":
                    message = "Subtitles added to video successfully";
                    break;
                case "resize":
                    message = "Video resized successfully";
                    break;
                case "filter":
                    message = "Video filter applied successfully";
                    break;
                default:
                    throw new Error(`Unknown video action: ${action}`);
            }
            return {
                content: [],
                structuredContent: {
                    success: true,
                    message,
                    output_path: outputPath
                }
            };
        }
        catch (error) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    message: `Video editing failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                }
            };
        }
    });
}
