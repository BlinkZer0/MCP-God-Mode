import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import sharp from "sharp";
import ffmpegPath from "ffmpeg-static";
import ffmpeg from "fluent-ffmpeg";
import { z } from "zod";
import { generateSVG, generateAIImage } from "./image_editor.js";
// Set FFmpeg path
ffmpeg.setFfmpegPath(ffmpegPath || "");
// Unified Multimedia Tool Schemas
export const MultimediaSession = z.object({
    id: z.string(),
    name: z.string(),
    type: z.enum(["audio", "image", "video"]),
    sourcePath: z.string(),
    workDir: z.string(),
    metadata: z.object({}).passthrough().optional(),
    layers: z.array(z.object({}).passthrough()).default([]),
    createdAt: z.string().datetime().default(() => new Date().toISOString()),
    modifiedAt: z.string().datetime().default(() => new Date().toISOString())
});
export const OpenInput = z.object({
    source: z.union([z.string().url(), z.string()]),
    sessionName: z.string().default("untitled"),
    type: z.enum(["audio", "image", "video"]).describe("Media type to open")
});
export const EditInput = z.object({
    sessionId: z.string(),
    operation: z.enum([
        // Audio operations
        "trim", "normalize", "fade", "gain", "reverse", "time_stretch", "pitch_shift",
        // Image operations  
        "resize", "crop", "rotate", "flip", "filter", "enhance", "adjust", "vignette", "border", "generate_svg", "generate_ai_image",
        // Video operations
        "cut", "merge", "convert", "resize_video", "add_audio", "add_subtitles", "apply_effects",
        // Universal operations
        "composite", "watermark", "batch_process"
    ]),
    params: z.object({}).passthrough()
});
export const ExportInput = z.object({
    sessionId: z.string(),
    format: z.string().optional(),
    quality: z.number().min(1).max(100).optional(),
    path: z.string().optional(),
    options: z.object({}).passthrough().optional()
});
export const BatchProcessInput = z.object({
    sessionIds: z.array(z.string()),
    operations: z.array(z.object({
        name: z.string(),
        operation: z.string(),
        params: z.object({}).passthrough()
    })),
    outputDir: z.string()
});
export const CreateProjectInput = z.object({
    name: z.string(),
    type: z.enum(["audio", "image", "video", "mixed"]),
    sessions: z.array(z.string()).optional()
});
const sessions = new Map();
const projects = new Map();
// Utility Functions
function newId() {
    return crypto.randomUUID();
}
function ensureDir(p) {
    fs.mkdirSync(p, { recursive: true });
}
function updateSessionModified(sessionId) {
    const session = sessions.get(sessionId);
    if (session) {
        session.modifiedAt = new Date().toISOString();
    }
}
// Media Type Detection
async function detectMediaType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const audioExts = ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.wma'];
    const imageExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.tiff', '.bmp', '.svg'];
    const videoExts = ['.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv', '.m4v'];
    if (audioExts.includes(ext))
        return "audio";
    if (imageExts.includes(ext))
        return "image";
    if (videoExts.includes(ext))
        return "video";
    // Try to detect by file content
    try {
        const image = sharp(filePath);
        await image.metadata();
        return "image";
    }
    catch {
        // Not an image, assume video for now
        return "video";
    }
}
// Cross-Platform Audio Device Detection
async function getAudioDevices() {
    const devices = { input: [], output: [] };
    try {
        // Use FFmpeg to list audio devices
        const { exec } = await import('child_process');
        const { promisify } = await import('util');
        const execAsync = promisify(exec);
        const platform = os.platform();
        if (platform === 'win32') {
            // Windows: List DirectSound devices
            try {
                const { stdout } = await execAsync('ffmpeg -f dshow -list_devices true -i dummy 2>&1');
                const lines = stdout.split('\n');
                let currentSection = '';
                for (const line of lines) {
                    if (line.includes('[dshow @')) {
                        if (line.includes('DirectShow video devices')) {
                            currentSection = 'video';
                        }
                        else if (line.includes('DirectShow audio devices')) {
                            currentSection = 'audio';
                        }
                    }
                    else if (currentSection === 'audio' && line.includes('"')) {
                        const match = line.match(/"([^"]+)"/);
                        if (match) {
                            const deviceName = match[1];
                            if (deviceName.toLowerCase().includes('stereo mix') ||
                                deviceName.toLowerCase().includes('what u hear') ||
                                deviceName.toLowerCase().includes('loopback')) {
                                devices.input.push({
                                    name: deviceName,
                                    id: `dshow:audio=${deviceName}`,
                                    type: 'stereo_mix',
                                    platform: 'windows'
                                });
                            }
                            else {
                                devices.input.push({
                                    name: deviceName,
                                    id: `dshow:audio=${deviceName}`,
                                    type: 'microphone',
                                    platform: 'windows'
                                });
                            }
                        }
                    }
                }
            }
            catch (error) {
                console.warn('Failed to detect Windows audio devices:', error);
            }
        }
        else if (platform === 'darwin') {
            // macOS: List CoreAudio devices
            try {
                const { stdout } = await execAsync('ffmpeg -f avfoundation -list_devices true -i "" 2>&1');
                const lines = stdout.split('\n');
                let inAudioSection = false;
                for (const line of lines) {
                    if (line.includes('AVFoundation audio devices:')) {
                        inAudioSection = true;
                        continue;
                    }
                    else if (line.includes('AVFoundation video devices:')) {
                        inAudioSection = false;
                        continue;
                    }
                    if (inAudioSection && line.includes('[')) {
                        const match = line.match(/\[(\d+)\] (.+)/);
                        if (match) {
                            const deviceId = match[1];
                            const deviceName = match[2];
                            if (deviceName.toLowerCase().includes('stereo mix') ||
                                deviceName.toLowerCase().includes('loopback') ||
                                deviceName.toLowerCase().includes('system audio')) {
                                devices.input.push({
                                    name: deviceName,
                                    id: deviceId,
                                    type: 'stereo_mix',
                                    platform: 'macos'
                                });
                            }
                            else {
                                devices.input.push({
                                    name: deviceName,
                                    id: deviceId,
                                    type: 'microphone',
                                    platform: 'macos'
                                });
                            }
                        }
                    }
                }
            }
            catch (error) {
                console.warn('Failed to detect macOS audio devices:', error);
            }
        }
        else if (platform === 'linux') {
            // Linux: List ALSA/PulseAudio devices
            try {
                // Try PulseAudio first
                const { stdout: pulseOut } = await execAsync('pactl list sources short 2>/dev/null || echo "no pulse"');
                if (!pulseOut.includes('no pulse')) {
                    const lines = pulseOut.split('\n').filter(line => line.trim());
                    for (const line of lines) {
                        const parts = line.split('\t');
                        if (parts.length >= 2) {
                            const deviceId = parts[0];
                            const deviceName = parts[1];
                            if (deviceName.toLowerCase().includes('monitor') ||
                                deviceName.toLowerCase().includes('loopback') ||
                                deviceName.toLowerCase().includes('stereo mix')) {
                                devices.input.push({
                                    name: deviceName,
                                    id: deviceId,
                                    type: 'stereo_mix',
                                    platform: 'linux'
                                });
                            }
                            else {
                                devices.input.push({
                                    name: deviceName,
                                    id: deviceId,
                                    type: 'microphone',
                                    platform: 'linux'
                                });
                            }
                        }
                    }
                }
                else {
                    // Fallback to ALSA
                    const { stdout: alsaOut } = await execAsync('arecord -l 2>/dev/null || echo "no alsa"');
                    if (!alsaOut.includes('no alsa')) {
                        const lines = alsaOut.split('\n');
                        for (const line of lines) {
                            if (line.includes('card')) {
                                const match = line.match(/card (\d+): (.+), device (\d+): (.+)/);
                                if (match) {
                                    const cardId = match[1];
                                    const cardName = match[2];
                                    const deviceId = match[3];
                                    const deviceName = match[4];
                                    devices.input.push({
                                        name: `${cardName} - ${deviceName}`,
                                        id: `hw:${cardId},${deviceId}`,
                                        type: 'microphone',
                                        platform: 'linux'
                                    });
                                }
                            }
                        }
                    }
                }
            }
            catch (error) {
                console.warn('Failed to detect Linux audio devices:', error);
            }
        }
    }
    catch (error) {
        console.warn('Failed to detect audio devices:', error);
    }
    return devices;
}
// Cross-Platform Audio Recording
async function recordAudio(input) {
    const { deviceId, deviceType = 'auto', duration = 30, format = 'wav', quality = 80, sessionName = `Recording_${new Date().toISOString().replace(/[:.]/g, '-')}` } = input;
    const sessionId = newId();
    const workDir = path.join(os.tmpdir(), "mcp_multimedia", sessionId);
    ensureDir(workDir);
    const outputPath = path.join(workDir, `recording.${format}`);
    const platform = os.platform();
    let ffmpegInput = '';
    let ffmpegOptions = [];
    // Determine recording source
    if (deviceId) {
        // Use specified device
        ffmpegInput = deviceId;
    }
    else {
        // Auto-detect best device
        const devices = await getAudioDevices();
        const stereoMixDevice = devices.input.find((d) => d.type === 'stereo_mix');
        const micDevice = devices.input.find((d) => d.type === 'microphone');
        if (deviceType === 'stereo_mix' && stereoMixDevice) {
            ffmpegInput = stereoMixDevice.id;
        }
        else if (deviceType === 'microphone' && micDevice) {
            ffmpegInput = micDevice.id;
        }
        else if (deviceType === 'auto') {
            // Prefer stereo mix for "what's playing" recording
            ffmpegInput = stereoMixDevice?.id || micDevice?.id || '';
        }
    }
    if (!ffmpegInput) {
        throw new Error('No suitable audio input device found');
    }
    // Configure FFmpeg based on platform
    if (platform === 'win32') {
        ffmpegOptions = [
            '-f', 'dshow',
            '-i', ffmpegInput,
            '-t', duration.toString(),
            '-ac', '2', // Stereo
            '-ar', '44100', // Sample rate
            '-acodec', format === 'wav' ? 'pcm_s16le' : 'libmp3lame',
            '-y' // Overwrite output file
        ];
    }
    else if (platform === 'darwin') {
        ffmpegOptions = [
            '-f', 'avfoundation',
            '-i', `:${ffmpegInput}`,
            '-t', duration.toString(),
            '-ac', '2',
            '-ar', '44100',
            '-acodec', format === 'wav' ? 'pcm_s16le' : 'libmp3lame',
            '-y'
        ];
    }
    else if (platform === 'linux') {
        // Try PulseAudio first, then ALSA
        if (ffmpegInput.includes('pulse')) {
            ffmpegOptions = [
                '-f', 'pulse',
                '-i', ffmpegInput,
                '-t', duration.toString(),
                '-ac', '2',
                '-ar', '44100',
                '-acodec', format === 'wav' ? 'pcm_s16le' : 'libmp3lame',
                '-y'
            ];
        }
        else {
            ffmpegOptions = [
                '-f', 'alsa',
                '-i', ffmpegInput,
                '-t', duration.toString(),
                '-ac', '2',
                '-ar', '44100',
                '-acodec', format === 'wav' ? 'pcm_s16le' : 'libmp3lame',
                '-y'
            ];
        }
    }
    // Add quality settings for compressed formats
    if (format === 'mp3') {
        ffmpegOptions.push('-b:a', `${quality}k`);
    }
    else if (format === 'aac') {
        ffmpegOptions.push('-b:a', `${quality}k`);
    }
    // Execute recording
    return new Promise((resolve, reject) => {
        const { spawn } = require('child_process');
        const ffmpegProcess = spawn('ffmpeg', ffmpegOptions.concat([outputPath]));
        let stderr = '';
        ffmpegProcess.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        ffmpegProcess.on('close', (code) => {
            if (code === 0) {
                // Create session for the recorded audio
                const session = {
                    id: sessionId,
                    name: sessionName,
                    type: "audio",
                    sourcePath: outputPath,
                    workDir,
                    metadata: {
                        recording: true,
                        deviceType: deviceType,
                        duration: duration,
                        format: format,
                        quality: quality,
                        recordedAt: new Date().toISOString()
                    },
                    layers: [],
                    createdAt: new Date().toISOString(),
                    modifiedAt: new Date().toISOString()
                };
                sessions.set(sessionId, session);
                resolve({
                    sessionId,
                    path: outputPath,
                    duration
                });
            }
            else {
                reject(new Error(`Recording failed: ${stderr}`));
            }
        });
        ffmpegProcess.on('error', (error) => {
            reject(new Error(`Failed to start recording: ${error.message}`));
        });
    });
}
// Media Metadata Extraction
async function extractMetadata(filePath, type) {
    try {
        switch (type) {
            case "image":
                const image = sharp(filePath);
                const imageMeta = await image.metadata();
                return {
                    width: imageMeta.width,
                    height: imageMeta.height,
                    format: imageMeta.format,
                    channels: imageMeta.channels,
                    density: imageMeta.density,
                    hasAlpha: imageMeta.hasAlpha,
                    ...imageMeta
                };
            case "audio":
                return new Promise((resolve) => {
                    ffmpeg.ffprobe(filePath, (err, data) => {
                        if (err) {
                            resolve({ error: err.message });
                        }
                        else {
                            const audioStream = data.streams.find(s => s.codec_type === 'audio');
                            resolve({
                                duration: data.format.duration,
                                bitrate: data.format.bit_rate,
                                sampleRate: audioStream?.sample_rate,
                                channels: audioStream?.channels,
                                codec: audioStream?.codec_name,
                                ...data.format
                            });
                        }
                    });
                });
            case "video":
                return new Promise((resolve) => {
                    ffmpeg.ffprobe(filePath, (err, data) => {
                        if (err) {
                            resolve({ error: err.message });
                        }
                        else {
                            const videoStream = data.streams.find(s => s.codec_type === 'video');
                            const audioStream = data.streams.find(s => s.codec_type === 'audio');
                            resolve({
                                duration: data.format.duration,
                                bitrate: data.format.bit_rate,
                                width: videoStream?.width,
                                height: videoStream?.height,
                                fps: videoStream?.r_frame_rate,
                                videoCodec: videoStream?.codec_name,
                                audioCodec: audioStream?.codec_name,
                                ...data.format
                            });
                        }
                    });
                });
        }
    }
    catch (error) {
        return { error: error.message };
    }
}
// Core Multimedia Functions
export async function status() {
    const sessionList = Array.from(sessions.values()).map(s => ({
        id: s.id,
        name: s.name,
        type: s.type,
        metadata: s.metadata,
        layers: s.layers.length,
        createdAt: s.createdAt,
        modifiedAt: s.modifiedAt
    }));
    const projectList = Array.from(projects.values()).map(p => ({
        name: p.name,
        type: p.type,
        sessionCount: p.sessions.length
    }));
    return {
        sessions: sessionList,
        projects: projectList,
        totalSessions: sessions.size,
        totalProjects: projects.size
    };
}
export async function open(input) {
    const { source, sessionName, type } = OpenInput.parse(input);
    const id = newId();
    const workDir = path.join(os.tmpdir(), "mcp_multimedia", id);
    ensureDir(workDir);
    // Download or copy source file
    const sourcePath = path.join(workDir, "source");
    if (/^https?:\/\//.test(source)) {
        const data = await (await fetch(source)).arrayBuffer();
        fs.writeFileSync(sourcePath, Buffer.from(data));
    }
    else {
        fs.copyFileSync(source, sourcePath);
    }
    // Detect media type if not specified
    const detectedType = type || await detectMediaType(sourcePath);
    // Extract metadata
    const metadata = await extractMetadata(sourcePath, detectedType);
    const session = {
        id,
        name: sessionName,
        type: detectedType,
        sourcePath,
        workDir,
        metadata,
        layers: [],
        createdAt: new Date().toISOString(),
        modifiedAt: new Date().toISOString()
    };
    sessions.set(id, session);
    return {
        sessionId: id,
        name: sessionName,
        type: detectedType,
        metadata
    };
}
export async function edit(input) {
    const { sessionId, operation, params } = EditInput.parse(input);
    const session = sessions.get(sessionId);
    if (!session)
        throw new Error("Unknown session");
    const operationRecord = {
        id: newId(),
        operation,
        params,
        timestamp: Date.now()
    };
    session.layers.push(operationRecord);
    updateSessionModified(sessionId);
    return {
        operationId: operationRecord.id,
        layers: session.layers
    };
}
export async function exportMedia(input) {
    const { sessionId, format, quality, path: outPath, options } = ExportInput.parse(input);
    const session = sessions.get(sessionId);
    if (!session)
        throw new Error("Unknown session");
    const outputPath = outPath || path.join(session.workDir, `export.${format || 'original'}`);
    try {
        switch (session.type) {
            case "image":
                await exportImage(session, outputPath, format, quality, options);
                break;
            case "audio":
                await exportAudio(session, outputPath, format, quality, options);
                break;
            case "video":
                await exportVideo(session, outputPath, format, quality, options);
                break;
        }
        return {
            success: true,
            path: outputPath,
            format: format || 'original'
        };
    }
    catch (error) {
        throw new Error(`Export failed: ${error.message}`);
    }
}
// Image Export
async function exportImage(session, outputPath, format, quality, options) {
    let pipeline = sharp(session.sourcePath);
    // Apply all operations
    for (const layer of session.layers) {
        const { operation, params } = layer;
        switch (operation) {
            case "resize":
                if (params.width || params.height) {
                    pipeline = pipeline.resize(params.width, params.height, {
                        fit: params.fit || 'cover',
                        position: params.position || 'center'
                    });
                }
                break;
            case "crop":
                if (params.x !== undefined && params.y !== undefined && params.width && params.height) {
                    pipeline = pipeline.extract({
                        left: params.x,
                        top: params.y,
                        width: params.width,
                        height: params.height
                    });
                }
                break;
            case "rotate":
                if (params.angle) {
                    pipeline = pipeline.rotate(params.angle);
                }
                break;
            case "flip":
                if (params.direction === 'horizontal') {
                    pipeline = pipeline.flip();
                }
                else if (params.direction === 'vertical') {
                    pipeline = pipeline.flop();
                }
                break;
            case "filter":
                if (params.type === 'blur') {
                    pipeline = pipeline.blur(params.radius || 1);
                }
                else if (params.type === 'sharpen') {
                    pipeline = pipeline.sharpen({ sigma: params.sigma || 1 });
                }
                else if (params.type === 'grayscale') {
                    pipeline = pipeline.grayscale();
                }
                else if (params.type === 'negate') {
                    pipeline = pipeline.negate();
                }
                break;
            case "enhance":
                if (params.brightness !== undefined) {
                    pipeline = pipeline.modulate({
                        brightness: params.brightness,
                        saturation: params.saturation || 1,
                        hue: params.hue || 0
                    });
                }
                break;
        }
    }
    // Apply format-specific options
    const outputFormat = format || path.extname(outputPath).slice(1);
    switch (outputFormat) {
        case 'jpg':
        case 'jpeg':
            pipeline = pipeline.jpeg({ quality: quality || 80 });
            break;
        case 'png':
            pipeline = pipeline.png({ compressionLevel: 6 });
            break;
        case 'webp':
            pipeline = pipeline.webp({ quality: quality || 80 });
            break;
    }
    await pipeline.toFile(outputPath);
}
// Audio Export
async function exportAudio(session, outputPath, format, quality, options) {
    return new Promise((resolve, reject) => {
        let command = ffmpeg(session.sourcePath);
        // Apply operations
        for (const layer of session.layers) {
            const { operation, params } = layer;
            switch (operation) {
                case "trim":
                    if (params.start !== undefined || params.end !== undefined) {
                        command = command.seekInput(params.start || 0);
                        if (params.end !== undefined) {
                            command = command.duration(params.end - (params.start || 0));
                        }
                    }
                    break;
                case "normalize":
                    command = command.audioFilters('loudnorm');
                    break;
                case "fade":
                    if (params.fadeIn) {
                        command = command.audioFilters(`afade=t=in:d=${params.fadeIn}`);
                    }
                    if (params.fadeOut) {
                        command = command.audioFilters(`afade=t=out:d=${params.fadeOut}`);
                    }
                    break;
                case "gain":
                    if (params.gainDb) {
                        command = command.audioFilters(`volume=${Math.pow(10, params.gainDb / 20)}dB`);
                    }
                    break;
                case "reverse":
                    command = command.audioFilters('areverse');
                    break;
            }
        }
        // Set output format and quality
        const outputFormat = format || path.extname(outputPath).slice(1);
        switch (outputFormat) {
            case 'mp3':
                command = command.audioCodec('libmp3lame').audioBitrate(quality ? `${quality}k` : '128k');
                break;
            case 'wav':
                command = command.audioCodec('pcm_s16le');
                break;
            case 'flac':
                command = command.audioCodec('flac');
                break;
        }
        command
            .output(outputPath)
            .on('end', () => resolve())
            .on('error', (err) => reject(err))
            .run();
    });
}
// Video Export
async function exportVideo(session, outputPath, format, quality, options) {
    return new Promise((resolve, reject) => {
        let command = ffmpeg(session.sourcePath);
        // Apply operations
        for (const layer of session.layers) {
            const { operation, params } = layer;
            switch (operation) {
                case "cut":
                    if (params.start !== undefined || params.end !== undefined) {
                        command = command.seekInput(params.start || 0);
                        if (params.end !== undefined) {
                            command = command.duration(params.end - (params.start || 0));
                        }
                    }
                    break;
                case "resize_video":
                    if (params.width || params.height) {
                        command = command.size(`${params.width || '?'}x${params.height || '?'}`);
                    }
                    break;
                case "add_audio":
                    if (params.audioPath) {
                        command = command.input(params.audioPath);
                    }
                    break;
            }
        }
        // Set output format and quality
        const outputFormat = format || path.extname(outputPath).slice(1);
        switch (outputFormat) {
            case 'mp4':
                command = command.videoCodec('libx264').audioCodec('aac');
                if (quality) {
                    command = command.videoBitrate(`${quality}k`);
                }
                break;
            case 'webm':
                command = command.videoCodec('libvpx').audioCodec('libvorbis');
                break;
        }
        command
            .output(outputPath)
            .on('end', () => resolve())
            .on('error', (err) => reject(err))
            .run();
    });
}
export async function batchProcess(input) {
    const { sessionIds, operations, outputDir } = BatchProcessInput.parse(input);
    ensureDir(outputDir);
    const results = [];
    for (const sessionId of sessionIds) {
        const session = sessions.get(sessionId);
        if (!session)
            continue;
        for (const op of operations) {
            const outputPath = path.join(outputDir, `${session.name}_${op.name}.${op.params.format || 'original'}`);
            try {
                // Apply the operation
                const tempSession = { ...session, layers: [{ operation: op.operation, params: op.params }] };
                switch (session.type) {
                    case "image":
                        await exportImage(tempSession, outputPath, op.params.format, op.params.quality);
                        break;
                    case "audio":
                        await exportAudio(tempSession, outputPath, op.params.format, op.params.quality);
                        break;
                    case "video":
                        await exportVideo(tempSession, outputPath, op.params.format, op.params.quality);
                        break;
                }
                results.push({ name: op.name, path: outputPath, success: true });
            }
            catch (error) {
                results.push({ name: op.name, path: outputPath, success: false, error: error.message });
            }
        }
    }
    return { results };
}
export async function createProject(input) {
    const { name, type, sessions: sessionIds } = CreateProjectInput.parse(input);
    const projectId = newId();
    const project = {
        name,
        type,
        sessions: sessionIds || []
    };
    projects.set(projectId, project);
    return {
        projectId,
        name,
        type,
        sessionCount: project.sessions.length
    };
}
export async function getSession(sessionId) {
    const session = sessions.get(sessionId);
    if (!session)
        throw new Error("Session not found");
    return {
        id: session.id,
        name: session.name,
        type: session.type,
        metadata: session.metadata,
        layers: session.layers,
        createdAt: session.createdAt,
        modifiedAt: session.modifiedAt
    };
}
export async function deleteSession(sessionId) {
    const session = sessions.get(sessionId);
    if (!session)
        throw new Error("Session not found");
    // Clean up files
    try {
        fs.rmSync(session.workDir, { recursive: true, force: true });
    }
    catch (error) {
        console.warn(`Failed to clean up session directory: ${error}`);
    }
    sessions.delete(sessionId);
    return { success: true };
}
// Audio Recording Functions
export async function recordAudioSession(input) {
    const { deviceId, deviceType, duration, format, quality, sessionName } = z.object({
        deviceId: z.string().optional(),
        deviceType: z.enum(['microphone', 'stereo_mix', 'auto']).default('auto'),
        duration: z.number().min(1).max(3600).default(30),
        format: z.enum(['wav', 'mp3', 'flac', 'aac']).default('wav'),
        quality: z.number().min(1).max(100).default(80),
        sessionName: z.string().optional()
    }).parse(input);
    return await recordAudio({
        deviceId,
        deviceType,
        duration,
        format,
        quality,
        sessionName
    });
}
export async function getAudioDevicesList() {
    return await getAudioDevices();
}
export async function startRecording(input) {
    const { deviceType, duration, format, quality, sessionName } = z.object({
        deviceType: z.enum(['microphone', 'stereo_mix', 'auto']).default('auto'),
        duration: z.number().min(1).max(3600).default(30),
        format: z.enum(['wav', 'mp3', 'flac', 'aac']).default('wav'),
        quality: z.number().min(1).max(100).default(80),
        sessionName: z.string().optional()
    }).parse(input);
    // Start recording in background
    const recordingPromise = recordAudio({
        deviceType,
        duration,
        format,
        quality,
        sessionName
    });
    return {
        recording: true,
        message: `Started recording ${deviceType} for ${duration} seconds`,
        promise: recordingPromise
    };
}
// Register the unified multimedia tool
export function registerMultimediaTool(server) {
    server.registerTool("multimedia_tool", {
        description: "Unified multimedia editing tool combining audio, image, and video processing capabilities. Supports comprehensive editing operations across all media types with session management, batch processing, and project organization.",
        inputSchema: {
            action: z.enum([
                "status", "open", "edit", "export", "batch_process", "create_project",
                "get_session", "delete_session", "record_audio", "get_audio_devices", "start_recording", "generate_svg", "generate_ai_image"
            ]).describe("Multimedia tool action to perform"),
            source: z.string().optional().describe("Media source path or URL"),
            sessionName: z.string().optional().describe("Name for the editing session"),
            type: z.enum(["audio", "image", "video"]).optional().describe("Media type"),
            sessionId: z.string().optional().describe("Session ID"),
            operation: z.enum([
                "trim", "normalize", "fade", "gain", "reverse", "time_stretch", "pitch_shift",
                "resize", "crop", "rotate", "flip", "filter", "enhance", "adjust", "vignette", "border",
                "cut", "merge", "convert", "resize_video", "add_audio", "add_subtitles", "apply_effects",
                "composite", "watermark", "batch_process"
            ]).optional().describe("Editing operation"),
            params: z.object({}).passthrough().optional().describe("Operation parameters"),
            format: z.string().optional().describe("Output format"),
            quality: z.number().min(1).max(100).optional().describe("Output quality"),
            path: z.string().optional().describe("Output path"),
            options: z.object({}).passthrough().optional().describe("Additional options"),
            sessionIds: z.array(z.string()).optional().describe("Array of session IDs"),
            operations: z.array(z.object({
                name: z.string(),
                operation: z.string(),
                params: z.object({}).passthrough()
            })).optional().describe("Batch operations"),
            outputDir: z.string().optional().describe("Output directory"),
            name: z.string().optional().describe("Project or session name"),
            sessions: z.array(z.string()).optional().describe("Array of session IDs for project"),
            deviceId: z.string().optional().describe("Audio device ID for recording"),
            deviceType: z.enum(['microphone', 'stereo_mix', 'auto']).optional().describe("Audio device type for recording"),
            duration: z.number().min(1).max(3600).optional().describe("Recording duration in seconds"),
            recordingFormat: z.enum(['wav', 'mp3', 'flac', 'aac']).optional().describe("Recording format"),
            // SVG and AI Image Generation parameters
            prompt: z.string().optional().describe("Description of the SVG/image to generate"),
            width: z.number().optional().describe("Width in pixels"),
            height: z.number().optional().describe("Height in pixels"),
            style: z.enum(["minimal", "detailed", "geometric", "organic", "technical", "artistic", "realistic", "cartoon", "abstract", "photographic", "digital_art"]).optional().describe("Generation style"),
            colors: z.array(z.string()).optional().describe("Color palette (hex codes)"),
            elements: z.array(z.string()).optional().describe("Specific elements to include"),
            model: z.string().optional().describe("AI model to use (auto-detect if not specified)"),
            fallbackToSVG: z.boolean().optional().describe("Fallback to SVG if model not supported"),
            generationQuality: z.enum(["low", "medium", "high"]).optional().describe("Generation quality")
        },
        outputSchema: {
            success: z.boolean(),
            message: z.string().optional(),
            sessionId: z.string().optional(),
            projectId: z.string().optional(),
            name: z.string().optional(),
            type: z.string().optional(),
            metadata: z.object({}).passthrough().optional(),
            operationId: z.string().optional(),
            layers: z.array(z.object({}).passthrough()).optional(),
            path: z.string().optional(),
            format: z.string().optional(),
            results: z.array(z.object({
                name: z.string(),
                path: z.string(),
                success: z.boolean(),
                error: z.string().optional()
            })).optional(),
            sessions: z.array(z.object({
                id: z.string(),
                name: z.string(),
                type: z.string(),
                metadata: z.object({}).passthrough().optional(),
                layers: z.number(),
                createdAt: z.string(),
                modifiedAt: z.string()
            })).optional(),
            projects: z.array(z.object({
                name: z.string(),
                type: z.string(),
                sessionCount: z.number()
            })).optional(),
            totalSessions: z.number().optional(),
            totalProjects: z.number().optional()
        }
    }, async (params) => {
        try {
            const { action, ...restParams } = params;
            switch (action) {
                case "status":
                    const statusResult = await status();
                    return {
                        content: [{ type: "text", text: `Multimedia tool status: ${JSON.stringify(statusResult, null, 2)}` }],
                        structuredContent: {
                            success: true,
                            message: "Status retrieved successfully",
                            ...statusResult
                        }
                    };
                case "open":
                    const openResult = await open(restParams);
                    return {
                        content: [{ type: "text", text: `Media opened successfully: ${openResult.sessionId}` }],
                        structuredContent: {
                            success: true,
                            message: "Media opened successfully",
                            sessionId: openResult.sessionId,
                            name: openResult.name,
                            type: openResult.type,
                            metadata: openResult.metadata
                        }
                    };
                case "edit":
                    const editResult = await edit(restParams);
                    return {
                        content: [{ type: "text", text: `Operation applied successfully: ${editResult.operationId}` }],
                        structuredContent: {
                            success: true,
                            message: "Operation applied successfully",
                            operationId: editResult.operationId,
                            layers: editResult.layers
                        }
                    };
                case "export":
                    const exportResult = await exportMedia(restParams);
                    return {
                        content: [{ type: "text", text: `Media exported successfully: ${exportResult.path}` }],
                        structuredContent: {
                            success: true,
                            message: "Media exported successfully",
                            path: exportResult.path,
                            format: exportResult.format
                        }
                    };
                case "batch_process":
                    const batchResult = await batchProcess(restParams);
                    return {
                        content: [{ type: "text", text: `Batch processing completed: ${batchResult.results.length} operations` }],
                        structuredContent: {
                            success: true,
                            message: "Batch processing completed",
                            results: batchResult.results
                        }
                    };
                case "create_project":
                    const projectResult = await createProject(restParams);
                    return {
                        content: [{ type: "text", text: `Project created successfully: ${projectResult.projectId}` }],
                        structuredContent: {
                            success: true,
                            message: "Project created successfully",
                            projectId: projectResult.projectId,
                            name: projectResult.name,
                            type: projectResult.type,
                            sessionCount: projectResult.sessionCount
                        }
                    };
                case "get_session":
                    const sessionResult = await getSession(restParams.sessionId);
                    return {
                        content: [{ type: "text", text: `Session retrieved: ${JSON.stringify(sessionResult, null, 2)}` }],
                        structuredContent: {
                            success: true,
                            message: "Session retrieved successfully",
                            ...sessionResult
                        }
                    };
                case "delete_session":
                    const deleteResult = await deleteSession(restParams.sessionId);
                    return {
                        content: [{ type: "text", text: "Session deleted successfully" }],
                        structuredContent: {
                            success: true,
                            message: "Session deleted successfully"
                        }
                    };
                case "record_audio":
                    const recordResult = await recordAudioSession(restParams);
                    return {
                        content: [{ type: "text", text: `Audio recorded successfully: ${recordResult.sessionId}` }],
                        structuredContent: {
                            success: true,
                            message: "Audio recorded successfully",
                            sessionId: recordResult.sessionId,
                            path: recordResult.path,
                            duration: recordResult.duration
                        }
                    };
                case "get_audio_devices":
                    const devicesResult = await getAudioDevicesList();
                    return {
                        content: [{ type: "text", text: `Found ${devicesResult.input.length} audio input devices` }],
                        structuredContent: {
                            success: true,
                            message: "Audio devices retrieved successfully",
                            devices: devicesResult
                        }
                    };
                case "start_recording":
                    const startResult = await startRecording(restParams);
                    return {
                        content: [{ type: "text", text: startResult.message }],
                        structuredContent: {
                            success: true,
                            message: startResult.message,
                            recording: startResult.recording
                        }
                    };
                case "generate_svg":
                    const svgResult = await generateSVG(restParams);
                    return {
                        content: [{ type: "text", text: `SVG generated successfully: ${svgResult.sessionId}` }],
                        structuredContent: {
                            success: true,
                            message: "SVG generated successfully",
                            sessionId: svgResult.sessionId,
                            name: svgResult.name,
                            dimensions: svgResult.dimensions,
                            format: svgResult.format,
                            path: svgResult.path,
                            svgContent: svgResult.svgContent
                        }
                    };
                case "generate_ai_image":
                    const aiResult = await generateAIImage(restParams);
                    return {
                        content: [{ type: "text", text: `AI image generated successfully: ${aiResult.sessionId}` }],
                        structuredContent: {
                            success: true,
                            message: "AI image generated successfully",
                            sessionId: aiResult.sessionId,
                            name: aiResult.name,
                            dimensions: aiResult.dimensions,
                            format: aiResult.format,
                            path: aiResult.path,
                            model: aiResult.model
                        }
                    };
                default:
                    throw new Error(`Unknown action: ${action}`);
            }
        }
        catch (error) {
            return {
                content: [{ type: "text", text: `Multimedia operation failed: ${error.message}` }],
                structuredContent: {
                    success: false,
                    message: `Multimedia operation failed: ${error.message}`
                }
            };
        }
    });
}
export default {
    name: "multimedia_tool",
    commands: {
        status,
        open,
        edit,
        export: exportMedia,
        batchProcess,
        createProject,
        getSession,
        deleteSession
    }
};
