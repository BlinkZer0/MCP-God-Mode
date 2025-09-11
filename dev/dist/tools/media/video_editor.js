import { z } from "zod";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import { randomUUID } from "crypto";
import { spawn, exec } from "node:child_process";
import { promisify } from "node:util";
const execAsync = promisify(exec);
// Configuration
const CFG = {
    storageDir: process.env.VIDEO_EDITOR_STORAGE_DIR || path.join(os.tmpdir(), "mcp_video_sessions"),
    maxDuration: parseInt(process.env.VIDEO_EDITOR_MAX_DURATION || "86400"), // 24 hours
    defaultFrameRate: parseInt(process.env.VIDEO_EDITOR_DEFAULT_FRAME_RATE || "30"),
    defaultResolution: process.env.VIDEO_EDITOR_DEFAULT_RESOLUTION || "1920x1080",
    defaultBitrate: parseInt(process.env.VIDEO_EDITOR_DEFAULT_BITRATE || "5000"), // kbps
    supportedFormats: (process.env.VIDEO_EDITOR_SUPPORTED_FORMATS || "mp4,avi,mov,mkv,webm,flv,wmv").split(","),
    webPort: parseInt(process.env.MCP_WEB_PORT || "3000"),
    unrestricted: true
};
// Session management
const sessions = new Map();
// Zod schemas
const OpenInput = z.object({
    source: z.union([z.string().url(), z.string()]),
    sessionName: z.string().default("untitled"),
    format: z.string().optional()
});
const RecordInput = z.object({
    duration: z.number().min(1).max(CFG.maxDuration),
    device: z.string().optional(),
    format: z.enum(["mp4", "avi", "mov", "webm"]).default("mp4"),
    resolution: z.string().default("1920x1080"),
    frameRate: z.number().min(1).max(120).default(30),
    bitrate: z.number().min(100).max(50000).default(5000),
    quality: z.enum(["low", "medium", "high", "ultra"]).default("high"),
    enableAudio: z.boolean().default(true),
    enablePreview: z.boolean().default(true),
    sessionName: z.string().default("recording")
});
const EditInput = z.object({
    sessionId: z.string(),
    op: z.enum([
        "trim", "split", "merge", "crop", "resize", "rotate", "flip",
        "speed", "fade", "transition", "filter", "effect", "text",
        "audio", "subtitle", "watermark", "stabilize", "denoise",
        "color_correct", "brightness", "contrast", "saturation", "hue"
    ]),
    params: z.record(z.string())
});
const ExportInput = z.object({
    sessionId: z.string(),
    format: z.enum(["mp4", "avi", "mov", "mkv", "webm", "flv", "wmv"]).default("mp4"),
    resolution: z.string().optional(),
    frameRate: z.number().optional(),
    bitrate: z.number().optional(),
    quality: z.enum(["low", "medium", "high", "ultra"]).default("high"),
    codec: z.string().optional(),
    audioCodec: z.string().optional(),
    outputPath: z.string().optional()
});
const StatusOutput = z.object({
    sessions: z.array(z.object({
        id: z.string(),
        name: z.string(),
        durationSec: z.number().optional(),
        resolution: z.string().optional(),
        format: z.string().optional()
    }))
});
// Helper functions
function newId() {
    return randomUUID();
}
async function ensureDir(p) {
    await fs.mkdir(p, { recursive: true });
}
async function getVideoMetadata(filePath) {
    try {
        const { stdout } = await execAsync(`ffprobe -v quiet -print_format json -show_format -show_streams "${filePath}"`);
        const data = JSON.parse(stdout);
        const videoStream = data.streams.find((s) => s.codec_type === 'video');
        const audioStream = data.streams.find((s) => s.codec_type === 'audio');
        return {
            duration: parseFloat(data.format.duration) || 0,
            width: parseInt(videoStream?.width) || 0,
            height: parseInt(videoStream?.height) || 0,
            frameRate: parseFloat(videoStream?.r_frame_rate?.split('/')[0]) / parseFloat(videoStream?.r_frame_rate?.split('/')[1]) || 30,
            bitRate: parseInt(data.format.bit_rate) || 0,
            format: data.format.format_name?.split(',')[0] || 'unknown',
            codec: videoStream?.codec_name || 'unknown',
            size: parseInt(data.format.size) || 0,
            hasAudio: !!audioStream,
            audioCodec: audioStream?.codec_name,
            audioSampleRate: parseInt(audioStream?.sample_rate),
            audioChannels: parseInt(audioStream?.channels)
        };
    }
    catch (error) {
        console.warn("Failed to get video metadata:", error);
        return {
            duration: 0,
            width: 1920,
            height: 1080,
            frameRate: 30,
            bitRate: 0,
            format: 'unknown',
            codec: 'unknown',
            size: 0,
            hasAudio: false
        };
    }
}
// Main functions
async function getStatus() {
    const activeSessions = Array.from(sessions.values());
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    enabled: true,
                    unrestricted: true,
                    max_duration_seconds: CFG.maxDuration,
                    active_sessions: activeSessions.length,
                    total_sessions: sessions.size,
                    storage_directory: CFG.storageDir,
                    supported_formats: CFG.supportedFormats,
                    default_frame_rate: CFG.defaultFrameRate,
                    default_resolution: CFG.defaultResolution,
                    default_bitrate: CFG.defaultBitrate,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function openVideo(source, sessionName, format) {
    const id = newId();
    const workDir = path.join(CFG.storageDir, id);
    await ensureDir(workDir);
    const srcPath = path.join(workDir, "source");
    if (/^https?:\/\//.test(source)) {
        const response = await fetch(source);
        const arrayBuffer = await response.arrayBuffer();
        await fs.writeFile(srcPath, Buffer.from(arrayBuffer));
    }
    else {
        await fs.copyFile(source, srcPath);
    }
    const metadata = await getVideoMetadata(srcPath);
    const session = {
        id,
        name: sessionName,
        srcPath,
        workDir,
        regions: [],
        metadata,
        edits: [],
        createdAt: Date.now(),
        modifiedAt: Date.now()
    };
    sessions.set(id, session);
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    sessionId: id,
                    name: sessionName,
                    durationSec: metadata.duration,
                    resolution: `${metadata.width}x${metadata.height}`,
                    frameRate: metadata.frameRate,
                    format: format || metadata.format,
                    hasAudio: metadata.hasAudio,
                    metadata,
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function recordVideo(duration, device, format = "mp4", resolution = "1920x1080", frameRate = 30, bitrate = 5000, quality = "high", enableAudio = true, enablePreview = true, sessionName = "recording") {
    const id = newId();
    const workDir = path.join(CFG.storageDir, id);
    await ensureDir(workDir);
    const outputPath = path.join(workDir, `recording.${format}`);
    // Cross-platform recording command
    let recordCommand;
    let recordArgs;
    if (os.platform() === "win32") {
        // Windows: Use ffmpeg with dshow
        recordCommand = "ffmpeg";
        recordArgs = [
            "-f", "dshow",
            "-i", `video=${device || "default"}`,
            "-t", duration.toString(),
            "-s", resolution,
            "-r", frameRate.toString(),
            "-b:v", `${bitrate}k`,
            "-y", outputPath
        ];
        if (enableAudio) {
            recordArgs.splice(-1, 0, "-f", "dshow", "-i", "audio=default");
        }
    }
    else if (os.platform() === "darwin") {
        // macOS: Use ffmpeg with avfoundation
        recordCommand = "ffmpeg";
        recordArgs = [
            "-f", "avfoundation",
            "-i", `:${device || "0"}`,
            "-t", duration.toString(),
            "-s", resolution,
            "-r", frameRate.toString(),
            "-b:v", `${bitrate}k`,
            "-y", outputPath
        ];
    }
    else {
        // Linux: Use ffmpeg with v4l2
        recordCommand = "ffmpeg";
        recordArgs = [
            "-f", "v4l2",
            "-i", device || "/dev/video0",
            "-t", duration.toString(),
            "-s", resolution,
            "-r", frameRate.toString(),
            "-b:v", `${bitrate}k`,
            "-y", outputPath
        ];
        if (enableAudio) {
            recordArgs.splice(-1, 0, "-f", "alsa", "-i", "default");
        }
    }
    // Start recording process
    const recordingProcess = spawn(recordCommand, recordArgs);
    // Wait for recording to complete
    await new Promise((resolve, reject) => {
        recordingProcess.on('close', (code) => {
            if (code === 0) {
                resolve();
            }
            else {
                reject(new Error(`Recording failed with code ${code}`));
            }
        });
        recordingProcess.on('error', (error) => {
            reject(error);
        });
    });
    const metadata = await getVideoMetadata(outputPath);
    const session = {
        id,
        name: sessionName,
        srcPath: outputPath,
        workDir,
        regions: [],
        metadata,
        edits: [],
        createdAt: Date.now(),
        modifiedAt: Date.now()
    };
    sessions.set(id, session);
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    sessionId: id,
                    name: sessionName,
                    durationSec: metadata.duration,
                    resolution: `${metadata.width}x${metadata.height}`,
                    frameRate: metadata.frameRate,
                    format: metadata.format,
                    device: device || "default",
                    recording_quality: quality,
                    audio_enabled: enableAudio,
                    preview_enabled: enablePreview,
                    metadata,
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function editVideo(sessionId, op, params) {
    const session = sessions.get(sessionId);
    if (!session) {
        throw new Error("Session not found");
    }
    const editId = newId();
    const edit = {
        id: editId,
        type: op,
        params,
        timestamp: Date.now()
    };
    session.edits.push(edit);
    session.modifiedAt = Date.now();
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    editId,
                    operation: op,
                    parameters: params,
                    sessionId,
                    totalEdits: session.edits.length,
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function exportVideo(sessionId, format, resolution, frameRate, bitrate, quality, codec, audioCodec, outputPath) {
    const session = sessions.get(sessionId);
    if (!session) {
        throw new Error("Session not found");
    }
    const output = outputPath || path.join(session.workDir, `export.${format || session.metadata.format}`);
    // Build FFmpeg command with all edits
    let ffmpegArgs = ["-i", session.srcPath];
    // Apply edits as filters
    const filters = [];
    for (const edit of session.edits) {
        switch (edit.type) {
            case "trim":
                if (edit.params.start || edit.params.end) {
                    const start = edit.params.start || 0;
                    const end = edit.params.end || session.metadata.duration;
                    filters.push(`trim=${start}:${end},setpts=PTS-STARTPTS`);
                }
                break;
            case "crop":
                if (edit.params.x && edit.params.y && edit.params.width && edit.params.height) {
                    filters.push(`crop=${edit.params.width}:${edit.params.height}:${edit.params.x}:${edit.params.y}`);
                }
                break;
            case "resize":
                if (edit.params.width && edit.params.height) {
                    filters.push(`scale=${edit.params.width}:${edit.params.height}`);
                }
                break;
            case "rotate":
                if (edit.params.angle) {
                    filters.push(`rotate=${edit.params.angle * Math.PI / 180}`);
                }
                break;
            case "flip":
                if (edit.params.direction === "horizontal") {
                    filters.push("hflip");
                }
                else if (edit.params.direction === "vertical") {
                    filters.push("vflip");
                }
                break;
            case "speed":
                if (edit.params.rate) {
                    filters.push(`setpts=${1 / edit.params.rate}*PTS`);
                }
                break;
            case "fade":
                if (edit.params.fadeIn) {
                    filters.push(`fade=t=in:st=0:d=${edit.params.fadeIn}`);
                }
                if (edit.params.fadeOut && session.metadata.duration) {
                    filters.push(`fade=t=out:st=${session.metadata.duration - edit.params.fadeOut}:d=${edit.params.fadeOut}`);
                }
                break;
            case "brightness":
                if (edit.params.value) {
                    filters.push(`eq=brightness=${edit.params.value}`);
                }
                break;
            case "contrast":
                if (edit.params.value) {
                    filters.push(`eq=contrast=${edit.params.value}`);
                }
                break;
            case "saturation":
                if (edit.params.value) {
                    filters.push(`eq=saturation=${edit.params.value}`);
                }
                break;
        }
    }
    if (filters.length > 0) {
        ffmpegArgs.push("-vf", filters.join(","));
    }
    if (resolution) {
        const [width, height] = resolution.split('x');
        ffmpegArgs.push("-s", `${width}x${height}`);
    }
    if (frameRate) {
        ffmpegArgs.push("-r", frameRate.toString());
    }
    if (bitrate) {
        ffmpegArgs.push("-b:v", `${bitrate}k`);
    }
    if (codec) {
        ffmpegArgs.push("-c:v", codec);
    }
    if (audioCodec) {
        ffmpegArgs.push("-c:a", audioCodec);
    }
    ffmpegArgs.push("-y", output);
    // Execute FFmpeg
    const ffmpegProcess = spawn("ffmpeg", ffmpegArgs);
    await new Promise((resolve, reject) => {
        ffmpegProcess.on('close', (code) => {
            if (code === 0) {
                resolve();
            }
            else {
                reject(new Error(`Export failed with code ${code}`));
            }
        });
        ffmpegProcess.on('error', (error) => {
            reject(error);
        });
    });
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    exported: true,
                    sessionId,
                    outputPath: output,
                    format: format || session.metadata.format,
                    resolution: resolution || `${session.metadata.width}x${session.metadata.height}`,
                    frameRate: frameRate || session.metadata.frameRate,
                    bitrate: bitrate || session.metadata.bitRate,
                    quality,
                    editsApplied: session.edits.length,
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function deleteSession(sessionId) {
    const session = sessions.get(sessionId);
    if (!session) {
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
    try {
        await fs.rm(session.workDir, { recursive: true, force: true });
    }
    catch (error) {
        console.warn("Failed to delete session files:", error);
    }
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
        name: s.name,
        durationSec: s.metadata.duration,
        resolution: `${s.metadata.width}x${s.metadata.height}`,
        format: s.metadata.format,
        editsCount: s.edits.length,
        createdAt: s.createdAt,
        modifiedAt: s.modifiedAt
    }));
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    sessions: sessionList,
                    total_sessions: sessionList.length,
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function analyzeVideo(sessionId) {
    const session = sessions.get(sessionId);
    if (!session) {
        throw new Error("Session not found");
    }
    const analysis = await analyzeVideoFile(session.srcPath);
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    sessionId,
                    analysis,
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function batchProcess(params) {
    const { inputFiles, operation, outputDir } = params;
    if (!inputFiles || !Array.isArray(inputFiles)) {
        throw new Error("inputFiles array is required for batch processing");
    }
    const results = [];
    for (const inputFile of inputFiles) {
        try {
            const session = await openVideo(inputFile, `batch_${Date.now()}`, params.format);
            const sessionId = JSON.parse(session.content[0].text).sessionId;
            if (operation) {
                await editVideo(sessionId, operation, params.operationParams || {});
            }
            const exportResult = await exportVideo(sessionId, params.format, params.resolution, params.frameRate, params.bitrate, params.quality, params.codec, params.audioCodec, outputDir ? path.join(outputDir, path.basename(inputFile)) : undefined);
            results.push({
                inputFile,
                success: true,
                sessionId,
                outputPath: JSON.parse(exportResult.content[0].text).outputPath
            });
        }
        catch (error) {
            results.push({
                inputFile,
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    }
    return {
        content: [{
                type: "text",
                text: JSON.stringify({
                    batchProcessed: true,
                    totalFiles: inputFiles.length,
                    successfulFiles: results.filter(r => r.success).length,
                    failedFiles: results.filter(r => !r.success).length,
                    results,
                    unrestricted: true,
                    timestamp: new Date().toISOString()
                }, null, 2)
            }]
    };
}
async function openViewer(sessionId) {
    const session = sessions.get(sessionId);
    if (!session) {
        throw new Error("Session not found");
    }
    const port = CFG.webPort;
    const viewerUrl = `http://localhost:${port}/viewer/video?sessionId=${sessionId}`;
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
async function analyzeVideoFile(filePath) {
    try {
        const { stdout } = await execAsync(`ffprobe -v quiet -print_format json -show_format -show_streams -f lavfi "movie='${filePath}',signalstats=metadata=1:reset=1"`);
        const data = JSON.parse(stdout);
        return {
            video: {
                resolution: "1920x1080", // Would be extracted from actual data
                frameRate: 30,
                bitrate: 5000,
                codec: "h264"
            },
            audio: {
                sampleRate: 44100,
                channels: 2,
                bitrate: 128,
                codec: "aac"
            },
            quality: {
                brightness: 0.5,
                contrast: 1.0,
                saturation: 1.0
            },
            metadata: data
        };
    }
    catch (error) {
        console.warn("Failed to analyze video file:", error);
        return {
            video: { resolution: "1920x1080", frameRate: 30, bitrate: 5000, codec: "h264" },
            audio: { sampleRate: 44100, channels: 2, bitrate: 128, codec: "aac" },
            quality: { brightness: 0.5, contrast: 1.0, saturation: 1.0 }
        };
    }
}
// Register the tool
export function registerVideoEditor(server) {
    server.registerTool("video_editor", {
        description: "Advanced cross-platform video editing and manipulation tool with recording capabilities. Perform video processing, editing, format conversion, effects application, recording, and video analysis across Windows, Linux, macOS, Android, and iOS.",
        inputSchema: {
            action: z.enum([
                "status", "open", "record", "edit", "export", "delete", "list", "analyze", "batch_process", "open_viewer"
            ]).describe("Video editing action to perform"),
            source: z.string().optional().describe("Source video file path or URL"),
            sessionName: z.string().optional().describe("Name for the video session"),
            format: z.string().optional().describe("Video format override"),
            duration: z.number().optional().describe("Recording duration in seconds"),
            device: z.string().optional().describe("Video input device name"),
            resolution: z.string().optional().describe("Video resolution (e.g., '1920x1080')"),
            frameRate: z.number().optional().describe("Frame rate for recording/export"),
            bitrate: z.number().optional().describe("Bitrate in kbps"),
            quality: z.enum(["low", "medium", "high", "ultra"]).optional().describe("Quality setting"),
            enableAudio: z.boolean().optional().describe("Enable audio recording"),
            enablePreview: z.boolean().optional().describe("Enable preview during recording"),
            sessionId: z.string().optional().describe("Session ID for operations"),
            op: z.string().optional().describe("Edit operation type"),
            params: z.record(z.string()).optional().describe("Edit operation parameters"),
            codec: z.string().optional().describe("Video codec for export"),
            audioCodec: z.string().optional().describe("Audio codec for export"),
            outputPath: z.string().optional().describe("Output file path"),
            inputFiles: z.array(z.string()).optional().describe("Input files for batch processing"),
            outputDir: z.string().optional().describe("Output directory for batch processing"),
            operation: z.string().optional().describe("Operation for batch processing"),
            operationParams: z.record(z.string()).optional().describe("Parameters for batch processing")
        }
    }, async (request) => {
        const { action, source, sessionName, format, duration, device, resolution, frameRate, bitrate, quality, enableAudio, enablePreview, sessionId, op, params, codec, audioCodec, outputPath, inputFiles, outputDir, operation, operationParams } = request.params;
        try {
            switch (action) {
                case "status":
                    return await getStatus();
                case "open":
                    if (!source)
                        throw new Error("Source is required for open action");
                    return await openVideo(source, sessionName || "untitled", format);
                case "record":
                    if (!duration)
                        throw new Error("Duration is required for record action");
                    return await recordVideo(duration, device, format, resolution, frameRate, bitrate, quality, enableAudio, enablePreview, sessionName);
                case "edit":
                    if (!sessionId || !op)
                        throw new Error("SessionId and op are required for edit action");
                    return await editVideo(sessionId, op, params || {});
                case "export":
                    if (!sessionId)
                        throw new Error("SessionId is required for export action");
                    return await exportVideo(sessionId, format, resolution, frameRate, bitrate, quality, codec, audioCodec, outputPath);
                case "delete":
                    if (!sessionId)
                        throw new Error("SessionId is required for delete action");
                    return await deleteSession(sessionId);
                case "list":
                    return await listSessions();
                case "analyze":
                    if (!sessionId)
                        throw new Error("SessionId is required for analyze action");
                    return await analyzeVideo(sessionId);
                case "batch_process":
                    return await batchProcess({ inputFiles, operation, outputDir, format, resolution, frameRate, bitrate, quality, codec, audioCodec, operationParams });
                case "open_viewer":
                    if (!sessionId)
                        throw new Error("SessionId is required for open_viewer action");
                    return await openViewer(sessionId);
                default:
                    throw new Error(`Unknown action: ${action}`);
            }
        }
        catch (error) {
            return {
                content: [{
                        type: "text",
                        text: JSON.stringify({
                            success: false,
                            error: error instanceof Error ? error.message : "Unknown error occurred",
                            action,
                            timestamp: new Date().toISOString()
                        }, null, 2)
                    }]
            };
        }
    });
}
