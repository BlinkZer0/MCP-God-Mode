import { z } from "zod";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import { exec } from "node:child_process";
import { promisify } from "node:util";
const execAsync = promisify(exec);
/**
 * Cross-Platform Audio Editor with Recording Capabilities
 * ======================================================
 *
 * Purpose: Comprehensive audio editing, processing, and recording with natural language interface.
 * Capabilities: Record, edit, process, convert, analyze audio with device selection and time specification.
 * Features: Web UI with waveform visualization, spectrogram, cross-platform support, PWA capabilities.
 *
 * This module provides unrestricted audio editing capabilities for any purpose.
 */
// Schema definitions
const OpenInput = z.object({
    source: z.union([z.string().url(), z.string()]).describe("Audio file path or URL"),
    sessionName: z.string().default("untitled").describe("Session name"),
    format: z.string().optional().describe("Audio format (wav, mp3, flac, etc.)")
});
const RecordInput = z.object({
    duration: z.number().positive().max(86400).describe("Recording duration in seconds (max 24 hours)"),
    device: z.string().optional().describe("Audio device name"),
    format: z.enum(["wav", "mp3", "flac", "ogg"]).default("wav").describe("Recording format"),
    sampleRate: z.number().int().min(8000).max(192000).default(44100).describe("Sample rate"),
    channels: z.number().int().min(1).max(8).default(2).describe("Number of channels"),
    bitDepth: z.number().int().min(16).max(32).default(16).describe("Bit depth"),
    quality: z.enum(["low", "medium", "high", "ultra"]).default("high").describe("Recording quality"),
    enableMonitoring: z.boolean().default(true).describe("Enable audio monitoring"),
    sessionName: z.string().default("recording").describe("Recording session name")
});
const EditInput = z.object({
    sessionId: z.string().describe("Session ID"),
    op: z.enum([
        "split", "trim", "delete", "insert", "move", "gain", "fade", "normalize",
        "time_stretch", "pitch_shift", "reverse", "compress", "equalize", "reverb",
        "echo", "noise_reduction", "silence_removal", "crossfade", "merge"
    ]).describe("Edit operation"),
    params: z.record(z.string()).describe("Operation parameters")
});
const ExportInput = z.object({
    sessionId: z.string().describe("Session ID"),
    format: z.enum(["wav", "mp3", "flac", "ogg", "aac", "m4a"]).default("wav").describe("Export format"),
    sampleRate: z.number().int().optional().describe("Sample rate"),
    bitRateKbps: z.number().int().optional().describe("Bit rate in kbps"),
    path: z.string().optional().describe("Output file path"),
    quality: z.enum(["low", "medium", "high", "ultra"]).default("high").describe("Export quality")
});
// Configuration
const CFG = {
    enabled: true,
    storageDir: process.env.AUDIO_EDITOR_STORAGE_DIR || "./.audio_sessions",
    maxDuration: 86400, // 24 hours
    supportedFormats: ["wav", "mp3", "flac", "ogg", "aac", "m4a"],
    defaultSampleRate: 44100,
    defaultChannels: 2,
    defaultBitDepth: 16
};
const sessions = new Map();
function assertEnabled() {
    if (!CFG.enabled) {
        throw new Error("Audio editor is disabled");
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
async function getAudioDevices() {
    // Cross-platform audio device detection
    const devices = [];
    try {
        if (os.platform() === "win32") {
            // Windows: Use PowerShell to get audio devices
            const { stdout } = await execAsync('powershell "Get-WmiObject -Class Win32_SoundDevice | Select-Object Name, DeviceID"');
            const lines = stdout.split('\n').filter(line => line.trim());
            lines.forEach((line, index) => {
                if (line.includes('Name') && line.includes('DeviceID'))
                    return;
                const parts = line.split(/\s+/);
                if (parts.length >= 2) {
                    devices.push({
                        name: parts.slice(0, -1).join(' '),
                        id: `win_${index}`,
                        type: "both",
                        channels: 2,
                        sampleRates: [44100, 48000, 96000],
                        isDefault: index === 0
                    });
                }
            });
        }
        else if (os.platform() === "darwin") {
            // macOS: Use system_profiler
            const { stdout } = await execAsync('system_profiler SPAudioDataType -json');
            const data = JSON.parse(stdout);
            if (data.SPAudioDataType) {
                data.SPAudioDataType.forEach((device, index) => {
                    devices.push({
                        name: device._name || `Audio Device ${index}`,
                        id: `mac_${index}`,
                        type: "both",
                        channels: 2,
                        sampleRates: [44100, 48000, 96000],
                        isDefault: index === 0
                    });
                });
            }
        }
        else {
            // Linux: Use arecord -l and aplay -l
            try {
                const { stdout: inputDevs } = await execAsync('arecord -l 2>/dev/null || echo "No input devices"');
                const { stdout: outputDevs } = await execAsync('aplay -l 2>/dev/null || echo "No output devices"');
                const inputLines = inputDevs.split('\n').filter(line => line.includes('card'));
                const outputLines = outputDevs.split('\n').filter(line => line.includes('card'));
                inputLines.forEach((line, index) => {
                    const match = line.match(/card (\d+): (.+?),/);
                    if (match) {
                        devices.push({
                            name: `Input: ${match[2]}`,
                            id: `linux_input_${match[1]}`,
                            type: "input",
                            channels: 2,
                            sampleRates: [44100, 48000, 96000],
                            isDefault: index === 0
                        });
                    }
                });
                outputLines.forEach((line, index) => {
                    const match = line.match(/card (\d+): (.+?),/);
                    if (match) {
                        devices.push({
                            name: `Output: ${match[2]}`,
                            id: `linux_output_${match[1]}`,
                            type: "output",
                            channels: 2,
                            sampleRates: [44100, 48000, 96000],
                            isDefault: index === 0
                        });
                    }
                });
            }
            catch (error) {
                // Fallback to default devices
                devices.push({
                    name: "Default Audio Device",
                    id: "default",
                    type: "both",
                    channels: 2,
                    sampleRates: [44100, 48000, 96000],
                    isDefault: true
                });
            }
        }
    }
    catch (error) {
        console.warn("Failed to detect audio devices:", error);
        // Fallback to default device
        devices.push({
            name: "Default Audio Device",
            id: "default",
            type: "both",
            channels: 2,
            sampleRates: [44100, 48000, 96000],
            isDefault: true
        });
    }
    return devices;
}
export function registerAudioEditor(server) {
    server.registerTool("audio_editor", {
        description: "🎵 **Cross-Platform Audio Editor with Recording** - Comprehensive audio editing, processing, and recording with natural language interface. Features: record with device selection, edit with waveform visualization, process with effects, convert formats, analyze audio. Cross-platform support for Windows, macOS, Linux, iOS, Android with PWA capabilities.",
        inputSchema: {
            action: z.enum([
                "status", "open", "record", "edit", "export", "delete", "list_sessions",
                "get_devices", "analyze", "batch_process", "open_viewer"
            ]).describe("Audio editor action"),
            source: z.string().optional().describe("Audio file path or URL"),
            sessionName: z.string().optional().describe("Session name"),
            format: z.string().optional().describe("Audio format"),
            duration: z.number().int().positive().max(86400).optional().describe("Recording duration in seconds"),
            device: z.string().optional().describe("Audio device name for recording"),
            sampleRate: z.number().int().min(8000).max(192000).optional().describe("Sample rate"),
            channels: z.number().int().min(1).max(8).optional().describe("Number of channels"),
            bitDepth: z.number().int().min(16).max(32).optional().describe("Bit depth"),
            quality: z.enum(["low", "medium", "high", "ultra"]).optional().describe("Quality setting"),
            enableMonitoring: z.boolean().optional().describe("Enable audio monitoring"),
            sessionId: z.string().optional().describe("Session ID for operations"),
            op: z.enum([
                "split", "trim", "delete", "insert", "move", "gain", "fade", "normalize",
                "time_stretch", "pitch_shift", "reverse", "compress", "equalize", "reverb",
                "echo", "noise_reduction", "silence_removal", "crossfade", "merge"
            ]).optional().describe("Edit operation"),
            params: z.record(z.string()).optional().describe("Operation parameters"),
            outputPath: z.string().optional().describe("Output file path"),
            bitRateKbps: z.number().int().optional().describe("Bit rate in kbps")
        }
    }, async ({ action, source, sessionName, format, duration, device, sampleRate, channels, bitDepth, quality, enableMonitoring, sessionId, op, params, outputPath, bitRateKbps }) => {
        try {
            assertEnabled();
            await ensureStorageDir();
            switch (action) {
                case "status":
                    return await getStatus();
                case "open":
                    if (!source) {
                        throw new Error("source is required for open action");
                    }
                    return await openAudio(source, sessionName || "untitled", format);
                case "record":
                    if (!duration) {
                        throw new Error("duration is required for record action");
                    }
                    return await recordAudio(duration, device, format, sampleRate, channels, bitDepth, quality, enableMonitoring, sessionName);
                case "edit":
                    if (!sessionId || !op) {
                        throw new Error("sessionId and op are required for edit action");
                    }
                    return await editAudio(sessionId, op, params || {});
                case "export":
                    if (!sessionId) {
                        throw new Error("sessionId is required for export action");
                    }
                    return await exportAudio(sessionId, format, sampleRate, bitRateKbps, outputPath, quality);
                case "delete":
                    if (!sessionId) {
                        throw new Error("sessionId is required for delete action");
                    }
                    return await deleteSession(sessionId);
                case "list_sessions":
                    return await listSessions();
                case "get_devices":
                    return await getAudioDevices();
                case "analyze":
                    if (!sessionId) {
                        throw new Error("sessionId is required for analyze action");
                    }
                    return await analyzeAudio(sessionId);
                case "batch_process":
                    return await batchProcess(params || {});
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
                        text: `Audio Editor ${action} failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                    }]
            };
        }
    });
}
// Implementation functions will be in the next part...
