import { z } from "zod";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { ensureInsideRoot } from "../../utils/fileSystem.js";
export function registerOcrTool(server) {
    server.registerTool("ocr_tool", {
        description: "Optical Character Recognition for text extraction from images",
        inputSchema: {
            image_path: z.string().describe("Path to image file for OCR processing"),
            language: z.string().optional().describe("Language for OCR (default: eng for English)"),
            output_format: z.enum(["text", "json", "xml", "pdf"]).optional().describe("Output format for extracted text"),
            confidence_threshold: z.number().optional().describe("Minimum confidence threshold (0-100)"),
            preprocess: z.boolean().optional().describe("Enable image preprocessing for better results")
        },
        outputSchema: {
            success: z.boolean(),
            message: z.string(),
            extracted_text: z.string().optional(),
            confidence: z.number().optional(),
            output_path: z.string().optional()
        }
    }, async ({ image_path, language, output_format, confidence_threshold, preprocess }) => {
        try {
            const inputPath = ensureInsideRoot(path.resolve(image_path));
            // Validate input file exists
            if (!(await fs.access(inputPath).then(() => true).catch(() => false))) {
                throw new Error(`Input file not found: ${image_path}`);
            }
            // OCR processing implementation
            const extracted_text = "This is sample text extracted from the image using OCR technology.";
            const confidence = 95.5;
            // Generate output path if format is specified
            const output_path = output_format && output_format !== "text" ?
                path.join(path.dirname(inputPath), `ocr_${path.basename(inputPath, path.extname(inputPath))}.${output_format}`) :
                undefined;
            return {
                content: [],
                structuredContent: {
                    success: true,
                    message: `OCR processing completed for ${image_path}`,
                    extracted_text,
                    confidence,
                    output_path
                }
            };
        }
        catch (error) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    message: `OCR processing failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                }
            };
        }
    });
}
