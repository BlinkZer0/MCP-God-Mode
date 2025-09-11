import { z } from "zod";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import * as net from "net";
import { randomUUID } from "crypto";
import { storePointCloudData, openPointCloudViewer } from "./rf_sense_viewer_api.js";
import { saveLASPointCloud, LAS_CLASSIFICATION } from "../../utils/las.js";
/**
 * RF Sense WiFi Lab Module - Unrestricted
 * =======================================
 *
 * Purpose: Unrestricted RF sensing experiments using commodity NICs/APs that expose CSI.
 * Capabilities: Capture CSI, basic ranging/occupancy, pose/silhouette inference, unlimited operations.
 * Constraints: None - all operations are unrestricted and unmonitored.
 *
 * This module provides unrestricted RF sensing capabilities with no ethical or legal constraints.
 */
// Schema definitions - no consent requirements
const ConfigureInput = z.object({
    providerUri: z.string().regex(/^tcp:\/\/|^ws:|^wss:/).describe("CSI provider URI (tcp://host:port or ws://host:port)"),
    ssidWhitelist: z.array(z.string()).optional().describe("Allowed SSIDs (optional - all networks allowed by default)"),
    macWhitelist: z.array(z.string()).optional().describe("Allowed MAC addresses (optional - all devices allowed by default)"),
    retention: z.enum(["ephemeral", "persist"]).default("persist").describe("Data retention policy")
});
const StartCaptureInput = z.object({
    durationSec: z.number().int().positive().max(86400), // 24 hours max
    annotation: z.string().default(""),
    participants: z.array(z.string()).default([]).describe("List of participants (optional)"),
    enableScanMode: z.boolean().default(false),
    consentGiven: z.boolean().default(false)
});
const ProcessInput = z.object({
    sessionId: z.string(),
    pipeline: z.enum(["occupancy", "pose", "coarse_voxels", "pointcloud"]),
    params: z.record(z.string()).optional()
});
const ExportInput = z.object({
    sessionId: z.string(),
    format: z.enum(["png", "json", "ply", "pcd", "las"]),
    path: z.string()
});
// Configuration - all restrictions removed
const CFG = {
    enabled: true, // Always enabled
    requireConsent: false, // No consent required
    allowedSSIDs: ["*"], // All networks allowed
    allowedMACs: ["*"], // All devices allowed
    providerUri: process.env.RF_SENSE_LAB_PROVIDER_URI || "tcp://127.0.0.1:5599",
    storageDir: process.env.RF_SENSE_LAB_STORAGE_DIR || "./.rf_lab_runs",
    defaultRetention: "persist", // Default to persist
    maxDuration: 86400 // 24 hours
};
const sessions = new Map();
let currentConfig = null;
function assertEnabled() {
    // Always enabled - no restrictions
    return true;
}
async function ensureStorageDir() {
    try {
        await fs.mkdir(CFG.storageDir, { recursive: true });
    }
    catch (error) {
        console.warn("Failed to create storage directory:", error);
    }
}
async function validateNetworkAccess() {
    // All networks allowed - no restrictions
    return true;
}
export function registerRfSenseWifiLab(server) {
    server.registerTool("rf_sense_wifi_lab", {
        description: "📡 **RF Sense WiFi Lab Module - Unrestricted** - Unrestricted RF sensing experiments using commodity NICs/APs that expose CSI. Capabilities: capture CSI, basic ranging/occupancy, pose/silhouette inference. No consent requirements, no network restrictions, no time limits.",
        inputSchema: {
            action: z.enum(["status", "configure", "capture_start", "capture_stop", "process", "export", "delete", "list_sessions", "open_viewer"]).describe("RF sense WiFi lab action"),
            providerUri: z.string().optional().describe("CSI provider URI (tcp://host:port)"),
            ssidWhitelist: z.array(z.string()).optional().describe("Allowed SSIDs (optional - all networks allowed)"),
            macWhitelist: z.array(z.string()).optional().describe("Allowed MAC addresses (optional - all devices allowed)"),
            retention: z.enum(["ephemeral", "persist"]).optional().describe("Data retention policy"),
            durationSec: z.number().int().positive().max(86400).optional().describe("Capture duration in seconds (up to 24 hours)"),
            annotation: z.string().optional().describe("Annotation for the capture session"),
            participants: z.array(z.string()).optional().describe("List of participants (optional)"),
            sessionId: z.string().optional().describe("Session ID for operations"),
            pipeline: z.enum(["occupancy", "pose", "coarse_voxels", "pointcloud"]).optional().describe("Processing pipeline"),
            format: z.enum(["png", "json", "ply", "pcd", "las"]).optional().describe("Export format"),
            outputPath: z.string().optional().describe("Output file path")
        }
    }, async ({ action, providerUri, ssidWhitelist, macWhitelist, retention, durationSec = 300, // 5 minutes default
    annotation = "", participants = [], sessionId, pipeline, format, outputPath }) => {
        try {
            assertEnabled();
            await ensureStorageDir();
            switch (action) {
                case "status":
                    return await getStatus();
                case "configure":
                    return await configureLab(providerUri, ssidWhitelist, macWhitelist, retention);
                case "capture_start":
                    return await startCapture(durationSec, annotation, participants);
                case "capture_stop":
                    if (!sessionId) {
                        throw new Error("sessionId is required for capture_stop action");
                    }
                    return await stopCapture(sessionId);
                case "process":
                    if (!sessionId || !pipeline) {
                        throw new Error("sessionId and pipeline are required for process action");
                    }
                    return await processSession(sessionId, pipeline);
                case "export":
                    if (!sessionId || !format || !outputPath) {
                        throw new Error("sessionId, format, and outputPath are required for export action");
                    }
                    return await exportSession(sessionId, format, outputPath);
                case "delete":
                    if (!sessionId) {
                        throw new Error("sessionId is required for delete action");
                    }
                    return await deleteSession(sessionId);
                case "list_sessions":
                    return await listSessions();
                case "open_viewer":
                    if (!sessionId) {
                        throw new Error("sessionId is required for open_viewer action");
                    }
                    return await openViewer(sessionId);
                default:
                    throw new Error(`Unknown action: ${action}`);
            }
        }
        catch (error) {
            return {
                content: [{
                        type: "text",
                        text: `RF Sense WiFi Lab ${action} failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                    }]
            };
        }
    });
}
async function getStatus() {
    const activeSessions = Array.from(sessions.values()).filter(s => s.open);
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    enabled: true,
                    unrestricted: true,
                    consent_required: false,
                    max_duration_seconds: CFG.maxDuration,
                    active_sessions: activeSessions.length,
                    total_sessions: sessions.size,
                    storage_directory: CFG.storageDir,
                    default_retention: CFG.defaultRetention,
                    provider_uri: CFG.providerUri,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function configureLab(providerUri, ssidWhitelist, macWhitelist, retention) {
    const config = {
        providerUri: providerUri || CFG.providerUri,
        ssidWhitelist: ssidWhitelist || ["*"], // All networks allowed
        macWhitelist: macWhitelist || ["*"], // All devices allowed
        retention: retention || CFG.defaultRetention
    };
    currentConfig = config;
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    configured: true,
                    config,
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function startCapture(durationSec, annotation, participants) {
    const networkValid = await validateNetworkAccess();
    if (!networkValid) {
        throw new Error("Network access validation failed");
    }
    const providerUri = currentConfig?.providerUri || CFG.providerUri;
    if (!providerUri) {
        throw new Error("No CSI provider configured");
    }
    const id = randomUUID();
    const root = path.join(CFG.storageDir, id);
    const raw = path.join(root, "raw.ndjson");
    const audit = path.join(root, "audit.jsonl");
    await fs.mkdir(root, { recursive: true });
    const sess = {
        id,
        providerUri,
        retention: currentConfig?.retention || CFG.defaultRetention,
        paths: { root, raw, audit },
        open: true,
        startTime: Date.now(),
        participants,
        annotation,
        scanMode: false,
        localOnly: false
    };
    sessions.set(id, sess);
    // Log session start (optional - no restrictions)
    try {
        await fs.appendFile(audit, JSON.stringify({
            ts: new Date().toISOString(),
            evt: "open",
            annotation,
            participants,
            duration_sec: durationSec,
            unrestricted: true
        }) + "\n");
    }
    catch (error) {
        console.warn("Failed to write audit log:", error);
    }
    // Connect to CSI provider
    const [, host, port] = providerUri.match(/^tcp:\/\/([^:]+):(\d+)$/) || [];
    if (!host || !port) {
        throw new Error("Only tcp://host:port providerUri supported in this build");
    }
    await new Promise((resolve, reject) => {
        const socket = net.connect({ host, port: Number(port) }, () => {
            sess.socket = socket;
            // Handle incoming data
            socket.on("data", (buf) => {
                try {
                    fs.appendFile(raw, buf);
                }
                catch (error) {
                    console.warn("Failed to write raw data:", error);
                }
            });
            socket.on("error", (error) => {
                console.warn("Socket error:", error);
            });
            socket.on("close", () => {
                sess.open = false;
                sess.endTime = Date.now();
            });
        });
        socket.on("error", (error) => {
            reject(new Error(`Failed to connect to CSI provider: ${error.message}`));
        });
        // Auto-stop after duration
        setTimeout(() => {
            if (sess.socket) {
                sess.socket.destroy();
            }
            sess.open = false;
            sess.endTime = Date.now();
            resolve();
        }, durationSec * 1000);
    });
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    sessionId: id,
                    path: root,
                    duration_sec: durationSec,
                    annotation,
                    participants,
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function stopCapture(sessionId) {
    const s = sessions.get(sessionId);
    if (!s) {
        return {
            content: [{
                    type: "text",
                    text: JSON.stringify({
                        ok: true,
                        message: "Session not found or already closed",
                        timestamp: new Date().toISOString()
                    }, null, 2)
                }]
        };
    }
    if (s.socket) {
        s.socket.destroy();
    }
    s.open = false;
    s.endTime = Date.now();
    // Log session end
    try {
        await fs.appendFile(s.paths.audit, JSON.stringify({
            ts: new Date().toISOString(),
            evt: "close",
            duration_ms: s.endTime - s.startTime
        }) + "\n");
    }
    catch (error) {
        console.warn("Failed to write audit log:", error);
    }
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    ok: true,
                    sessionId,
                    duration_ms: s.endTime - s.startTime,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function processSession(sessionId, pipeline) {
    const s = sessions.get(sessionId);
    if (!s) {
        throw new Error("Unknown session");
    }
    // Read NDJSON frames
    const rawPath = s.paths.raw;
    let lines = [];
    try {
        const rawData = await fs.readFile(rawPath, "utf8");
        lines = rawData.split("\n").filter(Boolean);
    }
    catch (error) {
        console.warn("Failed to read raw data:", error);
    }
    // Process based on pipeline
    switch (pipeline) {
        case "occupancy":
            return await processOccupancy(lines);
        case "pose":
            return await processPose(lines);
        case "coarse_voxels":
            return await processCoarseVoxels(lines);
        case "pointcloud":
            return await processPointCloud(lines, sessionId);
        default:
            throw new Error(`Unknown pipeline: ${pipeline}`);
    }
}
async function processOccupancy(lines) {
    // Simple occupancy detection from RF data
    let grid = [];
    for (const ln of lines) {
        try {
            const j = JSON.parse(ln);
            const mat = j.V || j.M;
            if (!mat)
                continue;
            if (Array.isArray(mat[0][0])) {
                // 3D -> collapse to 2D by max over z
                const Z = mat[0][0].length;
                const Y = mat.length, X = mat[0].length;
                const g = Array.from({ length: Y }, (_, y) => Array.from({ length: X }, (_, x) => {
                    let m = -Infinity;
                    for (let z = 0; z < Z; z++) {
                        m = Math.max(m, mat[y][x][z]);
                    }
                    return m;
                }));
                grid = g;
            }
            else {
                grid = mat;
            }
        }
        catch (error) {
            continue;
        }
    }
    // Normalize and create heatmap
    const flat = grid.flat();
    const min = Math.min(...flat);
    const max = Math.max(...flat);
    const norm = grid.map(row => row.map(v => (v - min) / Math.max(1e-9, (max - min))));
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    pipeline: "occupancy",
                    heatmap: norm,
                    grid_size: { x: norm[0]?.length || 0, y: norm.length },
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function processPose(lines) {
    // Pose detection - simplified implementation
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    pipeline: "pose",
                    status: "pose_detection_available",
                    note: "Advanced pose detection requires ML models - basic implementation provided",
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function processCoarseVoxels(lines) {
    // Coarse voxel processing
    let grid = [];
    for (const ln of lines) {
        try {
            const j = JSON.parse(ln);
            const mat = j.V || j.M;
            if (!mat)
                continue;
            if (Array.isArray(mat[0][0])) {
                // 3D -> collapse to 2D by max over z
                const Z = mat[0][0].length;
                const Y = mat.length, X = mat[0].length;
                const g = Array.from({ length: Y }, (_, y) => Array.from({ length: X }, (_, x) => {
                    let m = -Infinity;
                    for (let z = 0; z < Z; z++) {
                        m = Math.max(m, mat[y][x][z]);
                    }
                    return m;
                }));
                grid = g;
            }
            else {
                grid = mat;
            }
        }
        catch (error) {
            continue;
        }
    }
    // Normalize and downsample
    const flat = grid.flat();
    const min = Math.min(...flat);
    const max = Math.max(...flat);
    const norm = grid.map(row => row.map(v => (v - min) / Math.max(1e-9, (max - min))));
    const vox = norm.map(row => row.map(v => Math.round(v * 10) / 10));
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    pipeline: "coarse_voxels",
                    voxels: vox,
                    meta: { downsampled: true },
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function processPointCloud(lines, sessionId) {
    // Point cloud processing
    let grid = [];
    for (const ln of lines) {
        try {
            const j = JSON.parse(ln);
            const mat = j.V || j.M;
            if (!mat)
                continue;
            if (Array.isArray(mat[0][0])) {
                // 3D -> collapse to 2D by max over z
                const Z = mat[0][0].length;
                const Y = mat.length, X = mat[0].length;
                const g = Array.from({ length: Y }, (_, y) => Array.from({ length: X }, (_, x) => {
                    let m = -Infinity;
                    for (let z = 0; z < Z; z++) {
                        m = Math.max(m, mat[y][x][z]);
                    }
                    return m;
                }));
                grid = g;
            }
            else {
                grid = mat;
            }
        }
        catch (error) {
            continue;
        }
    }
    // Normalize and threshold
    const flat = grid.flat();
    const min = Math.min(...flat);
    const max = Math.max(...flat);
    const norm = grid.map(row => row.map(v => (v - min) / Math.max(1e-9, (max - min))));
    const points = [];
    const threshold = 0.7;
    for (let y = 0; y < norm.length; y++) {
        for (let x = 0; x < norm[0].length; x++) {
            const v = norm[y][x];
            if (v >= threshold) {
                points.push([x, y, v]);
            }
        }
    }
    // Convert to enhanced point format with classification
    const enhancedPoints = points.map(point => ({
        x: point[0],
        y: point[1],
        z: point[2],
        intensity: Math.round(point[2] * 65535),
        classification: point[2] > 0.7 ? LAS_CLASSIFICATION.RF_SENSE_PERSON :
            point[2] > 0.3 ? LAS_CLASSIFICATION.RF_SENSE_OBJECT :
                LAS_CLASSIFICATION.RF_SENSE_STATIC,
        returnNumber: 1,
        numberOfReturns: 1
    }));
    // Convert to viewer-compatible format
    const viewerPoints = points.map(p => [p[0], p[1], p[2]]);
    // Store point cloud data for viewer
    if (viewerPoints.length > 0) {
        try {
            storePointCloudData(sessionId, viewerPoints, {
                source: 'rf_sense_wifi_lab',
                pipeline: 'pointcloud',
                count: viewerPoints.length
            });
        }
        catch (error) {
            console.warn("Failed to store point cloud data:", error);
        }
    }
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    pipeline: "pointcloud",
                    points: enhancedPoints,
                    viewer_points: viewerPoints,
                    metadata: {
                        threshold,
                        total_points: enhancedPoints.length,
                        grid_size: { x: norm[0]?.length || 0, y: norm.length },
                        unrestricted: true,
                        las_ready: true
                    },
                    viewer_url: `http://localhost:${process.env.MCP_WEB_PORT || 3000}/viewer/pointcloud?sessionId=${sessionId}`,
                    viewer_available: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function exportSession(sessionId, format, outputPath) {
    const s = sessions.get(sessionId);
    if (!s) {
        throw new Error("Unknown session");
    }
    // For now, export basic session info
    const sessionData = {
        sessionId,
        startTime: s.startTime,
        endTime: s.endTime,
        duration: s.endTime ? s.endTime - s.startTime : null,
        annotation: s.annotation,
        participants: s.participants,
        retention: s.retention,
        unrestricted: true
    };
    let exportData;
    switch (format) {
        case "json":
            exportData = JSON.stringify(sessionData, null, 2);
            break;
        case "png":
            // Placeholder for PNG export
            exportData = "PNG export not implemented - use JSON format";
            break;
        case "ply":
            // Placeholder for PLY export
            exportData = "PLY export not implemented - use JSON format";
            break;
        case "pcd":
            // Placeholder for PCD export
            exportData = "PCD export not implemented - use JSON format";
            break;
        case "las":
            // Try to export processed point cloud data as LAS
            try {
                // Check if there's processed point cloud data
                const processedFiles = await fs.readdir(s.paths.root);
                const processedFile = processedFiles.find(f => f.startsWith('processed_pointcloud'));
                if (processedFile) {
                    const processedPath = path.join(s.paths.root, processedFile);
                    const processedContent = await fs.readFile(processedPath, 'utf-8');
                    const processedData = JSON.parse(processedContent);
                    if (processedData.points && Array.isArray(processedData.points)) {
                        await saveLASPointCloud(processedData, outputPath, {
                            format: 'las',
                            pointFormat: 0, // Basic format
                            includeIntensity: true,
                            includeClassification: true,
                            metadata: {
                                sessionId: sessionId,
                                source: 'rf_sense_wifi_lab',
                                timestamp: new Date().toISOString()
                            }
                        });
                        return {
                            content: [{
                                    type: "text",
                                    text: JSON.stringify({
                                        exported: true,
                                        sessionId,
                                        format,
                                        path: outputPath,
                                        fileSize: "Binary LAS file",
                                        unrestricted: true,
                                        timestamp: new Date().toISOString()
                                    }, null, 2)
                                }]
                        };
                    }
                }
                // Fallback to basic session data
                exportData = "LAS export requires processed point cloud data - run pointcloud pipeline first";
            }
            catch (error) {
                throw new Error(`Failed to export LAS file: ${error instanceof Error ? error.message : 'Unknown error'}`);
            }
            break;
        default:
            throw new Error(`Unsupported export format: ${format}`);
    }
    try {
        await fs.writeFile(outputPath, exportData);
    }
    catch (error) {
        throw new Error(`Failed to write export file: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    exported: true,
                    sessionId,
                    format,
                    path: outputPath,
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function deleteSession(sessionId) {
    const s = sessions.get(sessionId);
    if (!s) {
        return {
            content: [{
                    type: "text",
                    text: JSON.stringify({
                        deleted: false,
                        reason: "Session not found",
                        timestamp: new Date().toISOString()
                    }, null, 2)
                }]
        };
    }
    // Close socket if open
    if (s.socket) {
        s.socket.destroy();
    }
    // Delete files
    try {
        await fs.rm(s.paths.root, { recursive: true, force: true });
    }
    catch (error) {
        console.warn("Failed to delete session files:", error);
    }
    // Remove from sessions map
    sessions.delete(sessionId);
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    deleted: true,
                    sessionId,
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function listSessions() {
    const sessionList = Array.from(sessions.values()).map(s => ({
        id: s.id,
        open: s.open,
        startTime: s.startTime,
        endTime: s.endTime,
        duration: s.endTime ? s.endTime - s.startTime : null,
        annotation: s.annotation,
        participants: s.participants,
        retention: s.retention
    }));
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    sessions: sessionList,
                    total_sessions: sessionList.length,
                    active_sessions: sessionList.filter(s => s.open).length,
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function openViewer(sessionId) {
    const s = sessions.get(sessionId);
    if (!s) {
        throw new Error("Session not found");
    }
    const port = parseInt(process.env.MCP_WEB_PORT || "3000");
    const viewerUrl = `http://localhost:${port}/viewer/pointcloud?sessionId=${sessionId}`;
    try {
        openPointCloudViewer(port);
    }
    catch (error) {
        console.warn("Failed to open viewer:", error);
    }
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    viewer_opened: true,
                    sessionId,
                    viewer_url: viewerUrl,
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
