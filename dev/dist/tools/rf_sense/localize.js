import { z } from "zod";
import * as path from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";
import { spawn } from "node:child_process";
import { createSecuritySession, enableScanMode, disableScanMode, sanitizeResponseData } from "./rf_sense_security_guard.js";
/**
 * RF Sense Localize Tool
 * ======================
 *
 * Purpose: Localize a fresh point set (or LAS/LAZ) against an existing RF map and return pose + fitness.
 * Optionally emit a .LAS file with the transformed scan.
 *
 * This tool performs 6-DoF pose estimation by aligning a new scan against a known RF-derived map
 * using coarse NDT registration followed by fine ICP point-to-plane alignment.
 */
// Schema definitions
const LocalizeInput = z.object({
    map_path: z.string().describe("Path to .las/.laz file (the known map or clustered layout)"),
    scan_path: z.string().optional().describe("Path to .las/.laz file containing the scan to localize"),
    scan_points: z.array(z.array(z.number()).length(3)).optional().describe("Raw point cloud data as array of [x,y,z] coordinates"),
    intensity: z.array(z.number()).optional().describe("Intensity values for each point (optional)"),
    times: z.array(z.number()).optional().describe("Timestamp values for each point (optional)"),
    voxel: z.number().default(0.05).describe("Voxel size for downsampling in meters"),
    max_iter: z.number().int().default(60).describe("Maximum iterations for ICP refinement"),
    emit_las: z.boolean().default(false).describe("Whether to emit a transformed LAS file"),
    out_path: z.string().default("scan_localized.las").describe("Output path for transformed LAS file"),
    safety_mode: z.enum(["on", "off"]).default("on").describe("Safety mode - mirrors repo safety toggles")
});
// Type inference handled by zod validation
// Helper function to write temporary JSON file
function writeTempJSON(obj) {
    const tempPath = path.join(os.tmpdir(), `rf_points_${Date.now()}_${Math.random().toString(36).substr(2, 9)}.json`);
    fs.writeFileSync(tempPath, JSON.stringify(obj, null, 2));
    return tempPath;
}
// Helper function to clean up temporary files
function cleanupTempFile(filePath) {
    if (filePath && fs.existsSync(filePath)) {
        try {
            fs.unlinkSync(filePath);
        }
        catch (error) {
            console.warn(`Failed to cleanup temp file ${filePath}:`, error);
        }
    }
}
/**
 * Register the RF Sense Localize tool
 */
export function registerRfSenseLocalize(server) {
    server.registerTool("rf_sense_localize", {
        description: "Localize an RF-derived scan against a known map (LAS/LAZ) and return pose + fitness. Optionally emit a LAS file with the transformed scan.",
        inputSchema: {
            type: "object",
            properties: {
                map_path: {
                    type: "string",
                    description: "Path to .las/.laz file (the known map or clustered layout)"
                },
                scan_path: {
                    type: "string",
                    description: "Path to .las/.laz file containing the scan to localize"
                },
                scan_points: {
                    type: "array",
                    items: {
                        type: "array",
                        items: { type: "number" },
                        minItems: 3,
                        maxItems: 3
                    },
                    description: "Raw point cloud data as array of [x,y,z] coordinates"
                },
                intensity: {
                    type: "array",
                    items: { type: "number" },
                    description: "Intensity values for each point (optional)"
                },
                times: {
                    type: "array",
                    items: { type: "number" },
                    description: "Timestamp values for each point (optional)"
                },
                voxel: {
                    type: "number",
                    default: 0.05,
                    description: "Voxel size for downsampling in meters"
                },
                max_iter: {
                    type: "number",
                    default: 60,
                    description: "Maximum iterations for ICP refinement"
                },
                emit_las: {
                    type: "boolean",
                    default: false,
                    description: "Whether to emit a transformed LAS file"
                },
                out_path: {
                    type: "string",
                    default: "scan_localized.las",
                    description: "Output path for transformed LAS file"
                },
                safety_mode: {
                    type: "string",
                    enum: ["on", "off"],
                    default: "on",
                    description: "Safety mode - mirrors repo safety toggles"
                }
            },
            required: ["map_path"]
        }
    }, async (args) => {
        try {
            // Security session management
            const sessionId = createSecuritySession(true);
            // Enable scan mode for RF operations
            if (args.safety_mode === "on") {
                await enableScanMode(sessionId);
            }
            // Validate mutual exclusivity
            if (!args.scan_path && !args.scan_points) {
                throw new Error("Provide either scan_path or scan_points, not both");
            }
            if (args.scan_path && args.scan_points) {
                throw new Error("Use either scan_path or scan_points, not both");
            }
            // Validate map file exists
            if (!fs.existsSync(args.map_path)) {
                throw new Error(`Map file not found: ${args.map_path}`);
            }
            // Validate scan file exists (if provided)
            if (args.scan_path && !fs.existsSync(args.scan_path)) {
                throw new Error(`Scan file not found: ${args.scan_path}`);
            }
            // Prepare temporary JSON file for scan points if needed
            let pointsJsonPath = null;
            if (args.scan_points) {
                const pointsData = {
                    points: args.scan_points,
                    intensity: args.intensity || [],
                    times: args.times || []
                };
                pointsJsonPath = writeTempJSON(pointsData);
            }
            // Prepare Python script execution
            const pythonBin = process.env.PYTHON_BIN || "python";
            const scriptPath = path.join(process.cwd(), "dev", "src", "python", "rf_sense", "localize.py");
            // Build command line arguments
            const argv = [
                scriptPath,
                "--map", args.map_path,
                "--voxel", String(args.voxel),
                "--max-iter", String(args.max_iter)
            ];
            if (args.scan_path) {
                argv.push("--scan", args.scan_path);
            }
            if (pointsJsonPath) {
                argv.push("--points-json", pointsJsonPath);
            }
            if (args.emit_las) {
                argv.push("--emit-las", "--out", args.out_path);
            }
            // Execute Python worker
            const result = await new Promise((resolve) => {
                const child = spawn(pythonBin, argv, {
                    stdio: ["ignore", "pipe", "pipe"],
                    cwd: process.cwd()
                });
                let stdout = "";
                let stderr = "";
                child.stdout?.on("data", (data) => {
                    stdout += data.toString();
                });
                child.stderr?.on("data", (data) => {
                    stderr += data.toString();
                });
                child.on("close", (code) => {
                    resolve({ code: code || 0, stdout, stderr });
                });
                child.on("error", (error) => {
                    resolve({ code: -1, stdout, stderr: error.message });
                });
            });
            // Clean up temporary files
            cleanupTempFile(pointsJsonPath);
            // Disable scan mode
            if (args.safety_mode === "on") {
                await disableScanMode(sessionId);
            }
            // Handle Python execution results
            if (result.code !== 0) {
                return {
                    content: [{
                            type: "text",
                            text: JSON.stringify({
                                error: "rf_sense_localize_python_failed",
                                message: "Python worker failed",
                                details: result.stderr.slice(0, 4000),
                                stdout: result.stdout.slice(0, 1000)
                            }, null, 2)
                        }]
                };
            }
            // Parse Python output
            let pythonResult;
            try {
                pythonResult = JSON.parse(result.stdout.trim());
            }
            catch (parseError) {
                return {
                    content: [{
                            type: "text",
                            text: JSON.stringify({
                                error: "rf_sense_localize_parse_failed",
                                message: "Failed to parse Python output",
                                details: result.stdout.slice(0, 4000),
                                stderr: result.stderr.slice(0, 1000)
                            }, null, 2)
                        }]
                };
            }
            // Check for Python-level errors
            if (pythonResult.error) {
                return {
                    content: [{
                            type: "text",
                            text: JSON.stringify({
                                error: "rf_sense_localize_processing_failed",
                                message: pythonResult.error,
                                details: pythonResult.trace || pythonResult.details || "No additional details"
                            }, null, 2)
                        }]
                };
            }
            // Sanitize and return successful result
            const sanitizedResult = sanitizeResponseData(pythonResult, sessionId);
            return {
                content: [{
                        type: "text",
                        text: JSON.stringify(sanitizedResult, null, 2)
                    }]
            };
        }
        catch (error) {
            // Disable scan mode on error
            try {
                if (args.safety_mode === "on") {
                    await disableScanMode("error_cleanup");
                }
            }
            catch (cleanupError) {
                console.warn("Failed to disable scan mode during error cleanup:", cleanupError);
            }
            return {
                content: [{
                        type: "text",
                        text: JSON.stringify({
                            error: "rf_sense_localize_execution_failed",
                            message: error instanceof Error ? error.message : "Unknown error occurred",
                            details: error instanceof Error ? error.stack : String(error)
                        }, null, 2)
                    }]
            };
        }
    });
}
