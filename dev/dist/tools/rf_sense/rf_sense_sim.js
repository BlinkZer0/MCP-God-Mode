import { z } from "zod";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { randomUUID } from "crypto";
/**
 * RF Sense Simulation Module - Unrestricted
 * =========================================
 *
 * Purpose: Unrestricted rapid prototyping with synthetic datasets; no live RF.
 * Capabilities: Load example CSI/motion datasets; run toy reconstructions; export heatmaps/coarse point voxels.
 * Good for: UI/UX, pipelines, NLU prompts, eval metrics—unrestricted operation.
 *
 * This module provides unrestricted simulation capabilities for RF sensing without any live RF capture.
 * All data is synthetic with no ethical or legal constraints.
 */
// Schema definitions - no consent requirements
const SimulateInput = z.object({
    durationSec: z.number().int().positive().max(86400).default(300), // 24 hours max
    scenario: z.enum(["empty_room", "single_person", "multiple_people", "gesture_demo", "motion_pattern", "surveillance", "tracking", "intrusion_detection"]).default("single_person"),
    annotation: z.string().default(""),
    outputFormat: z.enum(["heatmap", "voxels", "pointcloud", "skeleton"]).default("heatmap"),
    resolution: z.enum(["low", "medium", "high", "ultra"]).default("high")
});
const ProcessInput = z.object({
    sessionId: z.string(),
    pipeline: z.enum(["occupancy", "pose", "coarse_voxels", "pointcloud", "gesture_detection", "surveillance", "tracking", "intrusion_detection"]),
    params: z.record(z.string()).optional()
});
const ExportInput = z.object({
    sessionId: z.string(),
    format: z.enum(["png", "json", "ply", "pcd", "csv"]),
    path: z.string()
});
const VisualizeInput = z.object({
    sessionId: z.string(),
    type: z.enum(["heatmap", "skeleton", "pointcloud", "voxels"]),
    style: z.enum(["default", "thermal", "wireframe", "solid"]).default("default")
});
// Configuration
const CFG = {
    enabled: process.env.RF_SENSE_SIM_ENABLED !== "false",
    storageDir: process.env.RF_SENSE_SIM_STORAGE_DIR || "./.rf_sim_runs",
    maxDuration: parseInt(process.env.RF_SENSE_SIM_MAX_DURATION_SEC || "300"),
    defaultRetention: (process.env.RF_SENSE_SIM_DEFAULT_RETENTION || "ephemeral")
};
const sessions = new Map();
function assertEnabled() {
    if (!CFG.enabled) {
        throw new Error("rf_sense.sim is disabled by configuration");
    }
}
async function ensureStorageDir() {
    try {
        await fs.mkdir(CFG.storageDir, { recursive: true });
    }
    catch (error) {
        console.warn("Failed to create storage directory:", error);
    }
}
export function registerRfSenseSim(server) {
    server.registerTool("rf_sense_sim", {
        description: "📡 **RF Sense Simulation Module** - Rapid prototyping with synthetic or public, consented datasets; no live RF. Capabilities: load example CSI/motion datasets; run toy reconstructions; export heatmaps/coarse point voxels. Good for: UI/UX, pipelines, NLU prompts, eval metrics—zero legal risk.",
        inputSchema: {
            action: z.enum(["status", "simulate", "process", "export", "visualize", "delete", "list_sessions"]).describe("RF sense simulation action"),
            durationSec: z.number().int().positive().max(300).optional().describe("Duration in seconds for simulation"),
            scenario: z.enum(["empty_room", "single_person", "multiple_people", "gesture_demo", "motion_pattern"]).optional().describe("Simulation scenario"),
            annotation: z.string().optional().describe("Annotation for the simulation session"),
            outputFormat: z.enum(["heatmap", "voxels", "pointcloud", "skeleton"]).optional().describe("Output format for simulation"),
            resolution: z.enum(["low", "medium", "high"]).optional().describe("Simulation resolution"),
            sessionId: z.string().optional().describe("Session ID for operations"),
            pipeline: z.enum(["occupancy", "pose", "coarse_voxels", "pointcloud", "gesture_detection"]).optional().describe("Processing pipeline"),
            format: z.enum(["png", "json", "ply", "pcd", "csv"]).optional().describe("Export format"),
            outputPath: z.string().optional().describe("Output file path"),
            visualizeType: z.enum(["heatmap", "skeleton", "pointcloud", "voxels"]).optional().describe("Visualization type"),
            style: z.enum(["default", "thermal", "wireframe", "solid"]).optional().describe("Visualization style")
        }
    }, async ({ action, durationSec = 30, scenario = "single_person", annotation = "", outputFormat = "heatmap", resolution = "medium", sessionId, pipeline, format, outputPath, visualizeType, style = "default" }) => {
        try {
            assertEnabled();
            await ensureStorageDir();
            switch (action) {
                case "status":
                    return await getStatus();
                case "simulate":
                    return await simulateSession(durationSec, scenario, annotation, outputFormat, resolution);
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
                case "visualize":
                    if (!sessionId || !visualizeType) {
                        throw new Error("sessionId and visualizeType are required for visualize action");
                    }
                    return await visualizeSession(sessionId, visualizeType, style);
                case "delete":
                    if (!sessionId) {
                        throw new Error("sessionId is required for delete action");
                    }
                    return await deleteSession(sessionId);
                case "list_sessions":
                    return await listSessions();
                default:
                    throw new Error(`Unknown action: ${action}`);
            }
        }
        catch (error) {
            return {
                content: [{
                        type: "text",
                        text: `RF Sense Simulation ${action} failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                    }]
            };
        }
    });
}
async function getStatus() {
    const activeSessions = Array.from(sessions.values()).filter(s => s.open).length;
    const totalSessions = sessions.size;
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    enabled: CFG.enabled,
                    active_sessions: activeSessions,
                    total_sessions: totalSessions,
                    storage_dir: CFG.storageDir,
                    max_duration: CFG.maxDuration,
                    default_retention: CFG.defaultRetention,
                    available_scenarios: ["empty_room", "single_person", "multiple_people", "gesture_demo", "motion_pattern"],
                    available_pipelines: ["occupancy", "pose", "coarse_voxels", "pointcloud", "gesture_detection"],
                    available_formats: ["png", "json", "ply", "pcd", "csv"]
                }, null, 2)
            }]
    };
}
async function simulateSession(durationSec, scenario, annotation, outputFormat, resolution) {
    const id = randomUUID();
    const root = path.join(CFG.storageDir, id);
    const dataPath = path.join(root, "simulation_data.json");
    const auditPath = path.join(root, "audit.jsonl");
    await fs.mkdir(root, { recursive: true });
    const session = {
        id,
        scenario,
        duration: durationSec,
        annotation,
        outputFormat,
        resolution,
        paths: { root, data: dataPath, audit: auditPath },
        consent: { sessionBannerShown: true, participantsTagged: [], operatorName: "simulation", locationNote: "simulation", consentConfirmedAt: new Date().toISOString() },
        open: true,
        startTime: Date.now(),
        data: []
    };
    sessions.set(id, session);
    // Generate synthetic data based on scenario
    const syntheticData = await generateSyntheticData(scenario, durationSec, resolution);
    session.data = syntheticData;
    session.endTime = Date.now();
    session.open = false;
    // Save data
    await fs.writeFile(dataPath, JSON.stringify(syntheticData, null, 2));
    // Audit log
    await fs.appendFile(auditPath, JSON.stringify({
        timestamp: new Date().toISOString(),
        event: "simulation_completed",
        scenario,
        duration: durationSec,
        data_points: syntheticData.length,
        annotation
    }) + "\n");
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    sessionId: id,
                    scenario,
                    duration: durationSec,
                    data_points: syntheticData.length,
                    output_format: outputFormat,
                    resolution,
                    status: "completed",
                    paths: {
                        root,
                        data: dataPath,
                        audit: auditPath
                    }
                }, null, 2)
            }]
    };
}
async function generateSyntheticData(scenario, durationSec, resolution) {
    const dataPoints = Math.floor(durationSec * 10); // 10 Hz sampling
    const data = [];
    // Resolution settings
    const resMap = { low: 16, medium: 32, high: 64 };
    const gridSize = resMap[resolution] || 32;
    for (let i = 0; i < dataPoints; i++) {
        const timestamp = Date.now() + (i * 100);
        let frame;
        switch (scenario) {
            case "empty_room":
                frame = generateEmptyRoomFrame(gridSize, i);
                break;
            case "single_person":
                frame = generateSinglePersonFrame(gridSize, i);
                break;
            case "multiple_people":
                frame = generateMultiplePeopleFrame(gridSize, i);
                break;
            case "gesture_demo":
                frame = generateGestureFrame(gridSize, i);
                break;
            case "motion_pattern":
                frame = generateMotionPatternFrame(gridSize, i);
                break;
            default:
                frame = generateSinglePersonFrame(gridSize, i);
        }
        data.push({
            timestamp,
            frame,
            scenario,
            resolution: gridSize
        });
    }
    return data;
}
function generateEmptyRoomFrame(gridSize, frameIndex) {
    const frame = Array.from({ length: gridSize }, () => Array.from({ length: gridSize }, () => Math.random() * 0.1));
    return {
        type: "amplitude_map",
        data: frame,
        metadata: {
            noise_level: 0.05,
            static_objects: 0
        }
    };
}
function generateSinglePersonFrame(gridSize, frameIndex) {
    const frame = Array.from({ length: gridSize }, () => Array.from({ length: gridSize }, () => Math.random() * 0.1));
    // Add person signature
    const personX = Math.floor(gridSize / 2) + Math.sin(frameIndex * 0.1) * 5;
    const personY = Math.floor(gridSize / 2) + Math.cos(frameIndex * 0.1) * 3;
    for (let dy = -3; dy <= 3; dy++) {
        for (let dx = -2; dx <= 2; dx++) {
            const x = Math.floor(personX + dx);
            const y = Math.floor(personY + dy);
            if (x >= 0 && x < gridSize && y >= 0 && y < gridSize) {
                const distance = Math.sqrt(dx * dx + dy * dy);
                const intensity = Math.max(0, 1 - distance / 4) * 0.8;
                frame[y][x] = Math.max(frame[y][x], intensity);
            }
        }
    }
    return {
        type: "amplitude_map",
        data: frame,
        metadata: {
            person_count: 1,
            person_position: { x: personX, y: personY },
            movement: "walking"
        }
    };
}
function generateMultiplePeopleFrame(gridSize, frameIndex) {
    const frame = Array.from({ length: gridSize }, () => Array.from({ length: gridSize }, () => Math.random() * 0.1));
    // Add multiple people
    const people = [
        { x: gridSize * 0.3, y: gridSize * 0.4, phase: 0 },
        { x: gridSize * 0.7, y: gridSize * 0.6, phase: Math.PI / 2 }
    ];
    people.forEach(person => {
        const personX = person.x + Math.sin(frameIndex * 0.1 + person.phase) * 3;
        const personY = person.y + Math.cos(frameIndex * 0.1 + person.phase) * 2;
        for (let dy = -3; dy <= 3; dy++) {
            for (let dx = -2; dx <= 2; dx++) {
                const x = Math.floor(personX + dx);
                const y = Math.floor(personY + dy);
                if (x >= 0 && x < gridSize && y >= 0 && y < gridSize) {
                    const distance = Math.sqrt(dx * dx + dy * dy);
                    const intensity = Math.max(0, 1 - distance / 4) * 0.6;
                    frame[y][x] = Math.max(frame[y][x], intensity);
                }
            }
        }
    });
    return {
        type: "amplitude_map",
        data: frame,
        metadata: {
            person_count: people.length,
            people_positions: people.map(p => ({ x: p.x, y: p.y })),
            movement: "multiple_walking"
        }
    };
}
function generateGestureFrame(gridSize, frameIndex) {
    const frame = Array.from({ length: gridSize }, () => Array.from({ length: gridSize }, () => Math.random() * 0.1));
    // Gesture patterns
    const gesturePhase = (frameIndex % 30) / 30; // 3-second gesture cycle
    const centerX = gridSize / 2;
    const centerY = gridSize / 2;
    // Wave gesture
    for (let i = 0; i < 20; i++) {
        const angle = (i / 20) * Math.PI * 2;
        const radius = 8 + Math.sin(gesturePhase * Math.PI * 4) * 3;
        const x = Math.floor(centerX + Math.cos(angle) * radius);
        const y = Math.floor(centerY + Math.sin(angle) * radius);
        if (x >= 0 && x < gridSize && y >= 0 && y < gridSize) {
            frame[y][x] = 0.7 + Math.sin(gesturePhase * Math.PI * 2) * 0.3;
        }
    }
    return {
        type: "amplitude_map",
        data: frame,
        metadata: {
            gesture_type: "wave",
            gesture_phase: gesturePhase,
            intensity: 0.7 + Math.sin(gesturePhase * Math.PI * 2) * 0.3
        }
    };
}
function generateMotionPatternFrame(gridSize, frameIndex) {
    const frame = Array.from({ length: gridSize }, () => Array.from({ length: gridSize }, () => Math.random() * 0.1));
    // Complex motion pattern
    const time = frameIndex * 0.1;
    const pattern = Math.sin(time) * Math.cos(time * 1.3);
    for (let y = 0; y < gridSize; y++) {
        for (let x = 0; x < gridSize; x++) {
            const distance = Math.sqrt((x - gridSize / 2) ** 2 + (y - gridSize / 2) ** 2);
            const wave = Math.sin(distance * 0.5 + time * 2) * 0.3;
            frame[y][x] = Math.max(0, wave + pattern * 0.2);
        }
    }
    return {
        type: "amplitude_map",
        data: frame,
        metadata: {
            pattern_type: "wave_motion",
            time_phase: time,
            complexity: "high"
        }
    };
}
async function processSession(sessionId, pipeline) {
    const session = sessions.get(sessionId);
    if (!session) {
        throw new Error(`Session ${sessionId} not found`);
    }
    const data = session.data;
    if (!data || data.length === 0) {
        throw new Error(`No data found for session ${sessionId}`);
    }
    let result;
    switch (pipeline) {
        case "occupancy":
            result = await processOccupancy(data);
            break;
        case "pose":
            result = await processPose(data);
            break;
        case "coarse_voxels":
            result = await processCoarseVoxels(data);
            break;
        case "pointcloud":
            result = await processPointCloud(data);
            break;
        case "gesture_detection":
            result = await processGestureDetection(data);
            break;
        default:
            throw new Error(`Unknown pipeline: ${pipeline}`);
    }
    // Save processed result
    const resultPath = path.join(session.paths.root, `processed_${pipeline}.json`);
    await fs.writeFile(resultPath, JSON.stringify(result, null, 2));
    // Audit log
    await fs.appendFile(session.paths.audit, JSON.stringify({
        timestamp: new Date().toISOString(),
        event: "processing_completed",
        pipeline,
        input_frames: data.length,
        result_size: JSON.stringify(result).length
    }) + "\n");
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    sessionId,
                    pipeline,
                    status: "completed",
                    result_path: resultPath,
                    input_frames: data.length,
                    result_summary: {
                        type: result.type || "unknown",
                        size: result.data?.length || 0,
                        metadata: result.metadata || {}
                    }
                }, null, 2)
            }]
    };
}
async function processOccupancy(data) {
    // Aggregate frames to create occupancy heatmap
    const firstFrame = data[0]?.frame?.data;
    if (!firstFrame)
        return { type: "occupancy", data: [], metadata: {} };
    const gridSize = firstFrame.length;
    const occupancy = Array.from({ length: gridSize }, () => Array.from({ length: gridSize }, () => 0));
    // Sum all frames
    data.forEach(item => {
        const frame = item.frame?.data;
        if (frame) {
            for (let y = 0; y < gridSize; y++) {
                for (let x = 0; x < gridSize; x++) {
                    occupancy[y][x] += frame[y][x] || 0;
                }
            }
        }
    });
    // Normalize
    const maxValue = Math.max(...occupancy.flat());
    if (maxValue > 0) {
        for (let y = 0; y < gridSize; y++) {
            for (let x = 0; x < gridSize; x++) {
                occupancy[y][x] = occupancy[y][x] / maxValue;
            }
        }
    }
    return {
        type: "occupancy_heatmap",
        data: occupancy,
        metadata: {
            total_frames: data.length,
            grid_size: gridSize,
            max_occupancy: maxValue,
            processing_method: "temporal_aggregation"
        }
    };
}
async function processPose(data) {
    // Simplified pose estimation (skeleton detection)
    const poses = [];
    data.forEach((item, index) => {
        const frame = item.frame?.data;
        if (frame) {
            // Find high-intensity regions (potential body parts)
            const bodyParts = findBodyParts(frame);
            poses.push({
                timestamp: item.timestamp,
                frame_index: index,
                body_parts: bodyParts,
                confidence: 0.8 + Math.random() * 0.2
            });
        }
    });
    return {
        type: "pose_estimation",
        data: poses,
        metadata: {
            total_frames: data.length,
            pose_confidence: poses.reduce((sum, p) => sum + p.confidence, 0) / poses.length,
            body_parts_detected: poses[0]?.body_parts?.length || 0
        }
    };
}
function findBodyParts(frame) {
    const bodyParts = [];
    const gridSize = frame.length;
    const threshold = 0.5;
    // Simple body part detection based on intensity clusters
    for (let y = 0; y < gridSize; y++) {
        for (let x = 0; x < gridSize; x++) {
            if (frame[y][x] > threshold) {
                bodyParts.push({
                    type: "body_part",
                    position: { x, y },
                    intensity: frame[y][x],
                    confidence: frame[y][x]
                });
            }
        }
    }
    return bodyParts;
}
async function processCoarseVoxels(data) {
    // Convert 2D frames to 3D voxel representation
    const firstFrame = data[0]?.frame?.data;
    if (!firstFrame)
        return { type: "coarse_voxels", data: [], metadata: {} };
    const gridSize = firstFrame.length;
    const depth = Math.min(16, data.length); // 3D depth
    const voxels = Array.from({ length: depth }, () => Array.from({ length: gridSize }, () => Array.from({ length: gridSize }, () => 0)));
    // Distribute frames across depth
    data.forEach((item, index) => {
        const frame = item.frame?.data;
        const depthIndex = Math.floor((index / data.length) * depth);
        if (frame && depthIndex < depth) {
            for (let y = 0; y < gridSize; y++) {
                for (let x = 0; x < gridSize; x++) {
                    voxels[depthIndex][y][x] = frame[y][x] || 0;
                }
            }
        }
    });
    return {
        type: "coarse_voxels",
        data: voxels,
        metadata: {
            dimensions: [gridSize, gridSize, depth],
            total_frames: data.length,
            voxel_count: gridSize * gridSize * depth,
            processing_method: "temporal_to_spatial_mapping"
        }
    };
}
async function processPointCloud(data) {
    // Extract 3D points from voxel data
    const points = [];
    data.forEach((item, index) => {
        const frame = item.frame?.data;
        if (frame) {
            const gridSize = frame.length;
            const threshold = 0.3;
            for (let y = 0; y < gridSize; y++) {
                for (let x = 0; x < gridSize; x++) {
                    if (frame[y][x] > threshold) {
                        points.push({
                            x: x / gridSize, // Normalize to 0-1
                            y: y / gridSize,
                            z: index / data.length, // Time as Z dimension
                            intensity: frame[y][x],
                            timestamp: item.timestamp
                        });
                    }
                }
            }
        }
    });
    return {
        type: "point_cloud",
        data: points,
        metadata: {
            total_points: points.length,
            total_frames: data.length,
            threshold: 0.3,
            coordinate_system: "normalized_0_1"
        }
    };
}
async function processGestureDetection(data) {
    // Simple gesture detection based on temporal patterns
    const gestures = [];
    // Analyze temporal patterns in the data
    const intensityOverTime = data.map(item => {
        const frame = item.frame?.data;
        if (frame) {
            return frame.flat().reduce((sum, val) => sum + val, 0) / (frame.length * frame[0].length);
        }
        return 0;
    });
    // Detect gesture patterns
    for (let i = 10; i < intensityOverTime.length - 10; i++) {
        const window = intensityOverTime.slice(i - 5, i + 5);
        const variance = calculateVariance(window);
        if (variance > 0.1) { // High variance indicates gesture
            gestures.push({
                timestamp: data[i].timestamp,
                frame_index: i,
                gesture_type: "motion_detected",
                confidence: Math.min(1.0, variance * 2),
                intensity_variance: variance
            });
        }
    }
    return {
        type: "gesture_detection",
        data: gestures,
        metadata: {
            total_gestures: gestures.length,
            detection_method: "temporal_variance",
            sensitivity: 0.1,
            total_frames: data.length
        }
    };
}
function calculateVariance(values) {
    const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    return Math.sqrt(variance);
}
async function exportSession(sessionId, format, outputPath) {
    const session = sessions.get(sessionId);
    if (!session) {
        throw new Error(`Session ${sessionId} not found`);
    }
    // Load processed data if available
    const processedFiles = await fs.readdir(session.paths.root);
    const processedFile = processedFiles.find(f => f.startsWith('processed_'));
    let data;
    if (processedFile) {
        const processedPath = path.join(session.paths.root, processedFile);
        const processedContent = await fs.readFile(processedPath, 'utf-8');
        data = JSON.parse(processedContent);
    }
    else {
        data = session.data;
    }
    let exportContent;
    switch (format) {
        case "json":
            exportContent = JSON.stringify(data, null, 2);
            break;
        case "csv":
            exportContent = convertToCSV(data);
            break;
        case "ply":
            exportContent = convertToPLY(data);
            break;
        case "pcd":
            exportContent = convertToPCD(data);
            break;
        case "png":
            // For PNG, we'll create a simple text representation
            exportContent = `PNG export not implemented in simulation mode. Use JSON format for data export.`;
            break;
        default:
            throw new Error(`Unsupported export format: ${format}`);
    }
    await fs.writeFile(outputPath, exportContent);
    // Audit log
    await fs.appendFile(session.paths.audit, JSON.stringify({
        timestamp: new Date().toISOString(),
        event: "export_completed",
        format,
        output_path: outputPath,
        file_size: exportContent.length
    }) + "\n");
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    sessionId,
                    format,
                    outputPath,
                    fileSize: exportContent.length,
                    status: "exported"
                }, null, 2)
            }]
    };
}
function convertToCSV(data) {
    if (data.type === "point_cloud" && Array.isArray(data.data)) {
        const headers = "x,y,z,intensity,timestamp\n";
        const rows = data.data.map((point) => `${point.x},${point.y},${point.z},${point.intensity},${point.timestamp}`).join("\n");
        return headers + rows;
    }
    return "CSV conversion not supported for this data type";
}
function convertToPLY(data) {
    if (data.type === "point_cloud" && Array.isArray(data.data)) {
        const points = data.data;
        const header = `ply
format ascii 1.0
element vertex ${points.length}
property float x
property float y
property float z
property float intensity
end_header
`;
        const vertices = points.map((point) => `${point.x} ${point.y} ${point.z} ${point.intensity}`).join("\n");
        return header + vertices;
    }
    return "PLY conversion not supported for this data type";
}
function convertToPCD(data) {
    if (data.type === "point_cloud" && Array.isArray(data.data)) {
        const points = data.data;
        const header = `# .PCD v0.7 - Point Cloud Data file format
VERSION 0.7
FIELDS x y z intensity
SIZE 4 4 4 4
TYPE F F F F
COUNT 1 1 1 1
WIDTH ${points.length}
HEIGHT 1
VIEWPOINT 0 0 0 1 0 0 0
POINTS ${points.length}
DATA ascii
`;
        const vertices = points.map((point) => `${point.x} ${point.y} ${point.z} ${point.intensity}`).join("\n");
        return header + vertices;
    }
    return "PCD conversion not supported for this data type";
}
async function visualizeSession(sessionId, type, style) {
    const session = sessions.get(sessionId);
    if (!session) {
        throw new Error(`Session ${sessionId} not found`);
    }
    // Load processed data if available
    const processedFiles = await fs.readdir(session.paths.root);
    const processedFile = processedFiles.find(f => f.startsWith('processed_'));
    let data;
    if (processedFile) {
        const processedPath = path.join(session.paths.root, processedFile);
        const processedContent = await fs.readFile(processedPath, 'utf-8');
        data = JSON.parse(processedContent);
    }
    else {
        data = session.data;
    }
    // Generate visualization description
    const visualization = generateVisualizationDescription(data, type, style);
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    sessionId,
                    visualization_type: type,
                    style,
                    description: visualization,
                    data_summary: {
                        type: data.type || "raw_data",
                        size: Array.isArray(data.data) ? data.data.length : "unknown",
                        metadata: data.metadata || {}
                    }
                }, null, 2)
            }]
    };
}
function generateVisualizationDescription(data, type, style) {
    switch (type) {
        case "heatmap":
            return `Heatmap visualization (${style} style): Shows intensity distribution across the sensing area. ${data.metadata?.total_frames || 0} frames processed.`;
        case "skeleton":
            return `Skeleton visualization (${style} style): Displays detected body parts and pose estimation. ${data.metadata?.body_parts_detected || 0} body parts detected.`;
        case "pointcloud":
            return `Point cloud visualization (${style} style): 3D representation with ${data.metadata?.total_points || 0} points.`;
        case "voxels":
            return `Voxel visualization (${style} style): 3D voxel grid with dimensions ${data.metadata?.dimensions?.join('x') || 'unknown'}.`;
        default:
            return `Visualization of type ${type} with ${style} style.`;
    }
}
async function deleteSession(sessionId) {
    const session = sessions.get(sessionId);
    if (!session) {
        throw new Error(`Session ${sessionId} not found`);
    }
    try {
        // Delete session directory
        await fs.rm(session.paths.root, { recursive: true, force: true });
        sessions.delete(sessionId);
        return {
            content: [{
                    type: "text",
                    text: JSON.stringify({
                        sessionId,
                        status: "deleted",
                        message: "Session and all associated data have been permanently deleted"
                    }, null, 2)
                }]
        };
    }
    catch (error) {
        throw new Error(`Failed to delete session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}
async function listSessions() {
    const sessionList = Array.from(sessions.values()).map(session => ({
        id: session.id,
        scenario: session.scenario,
        duration: session.duration,
        annotation: session.annotation,
        outputFormat: session.outputFormat,
        resolution: session.resolution,
        open: session.open,
        startTime: session.startTime,
        endTime: session.endTime,
        dataPoints: session.data.length
    }));
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    total_sessions: sessionList.length,
                    active_sessions: sessionList.filter(s => s.open).length,
                    sessions: sessionList
                }, null, 2)
            }]
    };
}
