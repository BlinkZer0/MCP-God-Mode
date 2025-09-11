import { z } from "zod";
/**
 * RF Sense Natural Language Interface
 * ==================================
 *
 * Purpose: Natural language command processing for RF sensing operations.
 * Capabilities: Parse natural language commands and route to appropriate RF sensing modules.
 * Supports: Simulation, WiFi lab, and mmWave operations with intelligent command parsing.
 *
 * This module provides a unified natural language interface for all RF sensing tools.
 */
// Natural language command patterns
const COMMAND_PATTERNS = {
    // Simulation commands
    simulate: [
        /start.*simulat.*rf.*session.*(\d+).*second/i,
        /run.*simulat.*for.*(\d+).*second/i,
        /create.*simulat.*scenario.*(\w+)/i,
        /generate.*synthetic.*data.*(\d+).*second/i
    ],
    // WiFi lab commands
    wifi_lab: [
        /start.*wifi.*lab.*capture.*(\d+).*second/i,
        /begin.*rf.*sens.*room.*(\w+).*(\d+).*second/i,
        /capture.*wifi.*csi.*(\d+).*second/i,
        /run.*wifi.*experiment.*(\d+).*second/i,
        /detect.*people.*through.*walls/i,
        /monitor.*occupancy.*across.*rooms/i,
        /track.*movement.*through.*building/i
    ],
    // mmWave commands
    mmwave: [
        /start.*mmwave.*capture.*(\d+).*second/i,
        /begin.*radar.*scan.*(\d+).*second/i,
        /capture.*point.*cloud.*(\d+).*second/i,
        /run.*mmwave.*experiment.*(\d+).*second/i,
        /detect.*objects.*through.*walls/i,
        /track.*through.*building.*materials/i,
        /penetrate.*walls.*with.*radar/i
    ],
    // Processing commands
    process: [
        /process.*last.*session/i,
        /analyze.*session.*(\w+)/i,
        /run.*pipeline.*(\w+)/i,
        /generate.*(\w+).*from.*session/i
    ],
    // Export commands
    export: [
        /export.*session.*(\w+).*format/i,
        /save.*session.*as.*(\w+)/i,
        /download.*session.*(\w+)/i,
        /convert.*session.*to.*(\w+)/i
    ],
    // Visualization commands
    visualize: [
        /visualize.*session/i,
        /show.*heatmap/i,
        /display.*point.*cloud/i,
        /render.*(\w+).*visualization/i
    ],
    // Status commands
    status: [
        /show.*status/i,
        /list.*sessions/i,
        /check.*rf.*sense/i,
        /get.*system.*status/i
    ]
};
// Scenario mappings
const SCENARIO_MAPPINGS = {
    "empty room": "empty_room",
    "single person": "single_person",
    "multiple people": "multiple_people",
    "gesture demo": "gesture_demo",
    "motion pattern": "motion_pattern",
    "walking": "single_person",
    "gestures": "gesture_demo",
    "crowd": "multiple_people"
};
// Pipeline mappings
const PIPELINE_MAPPINGS = {
    "occupancy": "occupancy",
    "pose": "pose",
    "skeleton": "pose",
    "voxels": "coarse_voxels",
    "point cloud": "pointcloud",
    "pointcloud": "pointcloud",
    "gesture": "gesture_detection",
    "tracking": "object_tracking",
    "clutter": "clutter_removal",
    "doppler": "doppler_analysis"
};
// Format mappings
const FORMAT_MAPPINGS = {
    "json": "json",
    "png": "png",
    "ply": "ply",
    "pcd": "pcd",
    "csv": "csv",
    "point cloud": "ply",
    "pointcloud": "ply"
};
// Capture mode mappings
const CAPTURE_MODE_MAPPINGS = {
    "point cloud": "point_cloud",
    "pointcloud": "point_cloud",
    "object tracking": "object_tracking",
    "gesture detection": "gesture_detection",
    "full scan": "full_scan",
    "radar": "point_cloud",
    "tracking": "object_tracking"
};
export function registerRfSenseNaturalLanguage(server) {
    server.registerTool("rf_sense_natural_language", {
        description: "🧠 **RF Sense Natural Language Interface** - Process natural language commands for RF sensing operations with intelligent parsing and routing to appropriate modules (simulation, WiFi lab, mmWave). Supports commands like 'Start a simulated RF session for 30s and render occupancy heatmap', 'Run wifi lab capture in Room A for 15s', 'With mmwave, capture 5s and export point cloud'.",
        inputSchema: {
            command: z.string().describe("Natural language command for RF sensing operations"),
            context: z.string().optional().describe("Additional context about the operation"),
            userIntent: z.string().optional().describe("User's intended goal or objective"),
            platform: z.enum(["windows", "linux", "macos", "android", "ios", "auto"]).optional().describe("Target platform preference")
        }
    }, async ({ command, context, userIntent, platform }) => {
        try {
            const parsedCommand = parseNaturalLanguageCommand(command, context, userIntent);
            if (!parsedCommand) {
                return {
                    content: [{
                            type: "text",
                            text: `Could not parse command: "${command}". Please try rephrasing your request. Available commands include:
            
**Simulation Commands:**
- "Start a simulated RF session for 30 seconds and render occupancy"
- "Run simulation with single person scenario for 15 seconds"
- "Generate synthetic data for gesture demo"

**WiFi Lab Commands:**
- "Start WiFi lab capture for 20 seconds in Room A"
- "Begin RF sensing experiment for 10 seconds"
- "Capture WiFi CSI data for 30 seconds"
- "Detect people through walls in adjacent rooms"
- "Monitor occupancy across multiple rooms"

**mmWave Commands:**
- "Start mmWave capture for 15 seconds"
- "Begin radar scan for point cloud generation"
- "Capture mmWave data for object tracking"
- "Detect objects through walls with mmWave radar"
- "Track movement through building materials"

**Processing Commands:**
- "Process last session into occupancy heatmap"
- "Analyze session with pose estimation"
- "Generate point cloud from session data"

**Export Commands:**
- "Export session as PLY format"
- "Save session data as JSON"
- "Download point cloud as PCD"

**Visualization Commands:**
- "Visualize session as heatmap"
- "Show point cloud visualization"
- "Display occupancy map"

**Status Commands:**
- "Show RF sense status"
- "List all sessions"
- "Check system status"`
                        }]
                };
            }
            // Execute the parsed command
            const result = await executeParsedCommand(parsedCommand, platform);
            return {
                content: [{
                        type: "text",
                        text: JSON.stringify({
                            original_command: command,
                            parsed_command: parsedCommand,
                            execution_result: result,
                            platform: platform || "auto"
                        }, null, 2)
                    }]
            };
        }
        catch (error) {
            return {
                content: [{
                        type: "text",
                        text: `Natural language processing failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                    }]
            };
        }
    });
}
function parseNaturalLanguageCommand(command, context, userIntent) {
    const normalizedCommand = command.toLowerCase().trim();
    // Check for simulation commands
    for (const pattern of COMMAND_PATTERNS.simulate) {
        const match = normalizedCommand.match(pattern);
        if (match) {
            const duration = parseInt(match[1]) || 30;
            const scenario = extractScenario(normalizedCommand) || "single_person";
            const outputFormat = extractOutputFormat(normalizedCommand) || "heatmap";
            return {
                module: "rf_sense_sim",
                action: "simulate",
                parameters: {
                    durationSec: duration,
                    scenario: scenario,
                    outputFormat: outputFormat,
                    annotation: context || `Simulation: ${scenario} for ${duration}s`
                }
            };
        }
    }
    // Check for WiFi lab commands
    for (const pattern of COMMAND_PATTERNS.wifi_lab) {
        const match = normalizedCommand.match(pattern);
        if (match) {
            const duration = parseInt(match[1]) || 30;
            const room = match[2] || "Lab";
            const participants = extractParticipants(normalizedCommand);
            return {
                module: "rf_sense_wifi_lab",
                action: "capture_start",
                parameters: {
                    durationSec: duration,
                    annotation: `WiFi Lab: ${room} for ${duration}s`,
                    participants: participants
                }
            };
        }
    }
    // Check for mmWave commands
    for (const pattern of COMMAND_PATTERNS.mmwave) {
        const match = normalizedCommand.match(pattern);
        if (match) {
            const duration = parseInt(match[1]) || 30;
            const captureMode = extractCaptureMode(normalizedCommand) || "point_cloud";
            const participants = extractParticipants(normalizedCommand);
            return {
                module: "rf_sense_mmwave",
                action: "capture_start",
                parameters: {
                    durationSec: duration,
                    captureMode: captureMode,
                    annotation: `mmWave: ${captureMode} for ${duration}s`,
                    participants: participants
                }
            };
        }
    }
    // Check for processing commands
    for (const pattern of COMMAND_PATTERNS.process) {
        const match = normalizedCommand.match(pattern);
        if (match) {
            const pipeline = extractPipeline(normalizedCommand) || "occupancy";
            const sessionId = extractSessionId(normalizedCommand) || "last";
            return {
                module: "auto", // Will be determined by session type
                action: "process",
                parameters: {
                    sessionId: sessionId,
                    pipeline: pipeline
                }
            };
        }
    }
    // Check for export commands
    for (const pattern of COMMAND_PATTERNS.export) {
        const match = normalizedCommand.match(pattern);
        if (match) {
            const format = extractFormat(normalizedCommand) || "json";
            const sessionId = extractSessionId(normalizedCommand) || "last";
            const outputPath = generateOutputPath(format, sessionId);
            return {
                module: "auto", // Will be determined by session type
                action: "export",
                parameters: {
                    sessionId: sessionId,
                    format: format,
                    outputPath: outputPath
                }
            };
        }
    }
    // Check for visualization commands
    for (const pattern of COMMAND_PATTERNS.visualize) {
        const match = normalizedCommand.match(pattern);
        if (match) {
            const visualizeType = extractVisualizeType(normalizedCommand) || "heatmap";
            const sessionId = extractSessionId(normalizedCommand) || "last";
            return {
                module: "auto", // Will be determined by session type
                action: "visualize",
                parameters: {
                    sessionId: sessionId,
                    visualizeType: visualizeType,
                    style: "default"
                }
            };
        }
    }
    // Check for status commands
    for (const pattern of COMMAND_PATTERNS.status) {
        const match = normalizedCommand.match(pattern);
        if (match) {
            return {
                module: "all",
                action: "status",
                parameters: {}
            };
        }
    }
    return null;
}
function extractScenario(command) {
    for (const [key, value] of Object.entries(SCENARIO_MAPPINGS)) {
        if (command.includes(key)) {
            return value;
        }
    }
    return "single_person";
}
function extractPipeline(command) {
    for (const [key, value] of Object.entries(PIPELINE_MAPPINGS)) {
        if (command.includes(key)) {
            return value;
        }
    }
    return "occupancy";
}
function extractFormat(command) {
    for (const [key, value] of Object.entries(FORMAT_MAPPINGS)) {
        if (command.includes(key)) {
            return value;
        }
    }
    return "json";
}
function extractCaptureMode(command) {
    for (const [key, value] of Object.entries(CAPTURE_MODE_MAPPINGS)) {
        if (command.includes(key)) {
            return value;
        }
    }
    return "point_cloud";
}
function extractOutputFormat(command) {
    for (const [key, value] of Object.entries(FORMAT_MAPPINGS)) {
        if (command.includes(key)) {
            return value;
        }
    }
    return "heatmap";
}
function extractVisualizeType(command) {
    if (command.includes("heatmap"))
        return "heatmap";
    if (command.includes("point cloud") || command.includes("pointcloud"))
        return "pointcloud";
    if (command.includes("skeleton"))
        return "skeleton";
    if (command.includes("voxel"))
        return "voxels";
    return "heatmap";
}
function extractParticipants(command) {
    const participants = [];
    // Look for participant mentions
    if (command.includes("participant")) {
        const match = command.match(/participant[s]?\s+(\w+)/i);
        if (match) {
            participants.push(match[1]);
        }
    }
    if (command.includes("person")) {
        const match = command.match(/person[s]?\s+(\w+)/i);
        if (match) {
            participants.push(match[1]);
        }
    }
    return participants;
}
function extractSessionId(command) {
    if (command.includes("last"))
        return "last";
    if (command.includes("current"))
        return "current";
    // Look for session ID patterns
    const match = command.match(/session\s+(\w+)/i);
    if (match) {
        return match[1];
    }
    return "last";
}
function generateOutputPath(format, sessionId) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `rf_sense_${sessionId}_${timestamp}.${format}`;
    return `./exports/${filename}`;
}
async function executeParsedCommand(parsedCommand, platform) {
    const { module, action, parameters } = parsedCommand;
    // Simulate command execution
    // In a real implementation, this would call the appropriate RF sensing modules
    const executionResult = {
        module: module,
        action: action,
        parameters: parameters,
        status: "executed",
        timestamp: new Date().toISOString(),
        platform: platform || "auto",
        simulated: true,
        details: {}
    };
    // Add module-specific execution details
    switch (module) {
        case "rf_sense_sim":
            executionResult.details = {
                simulation_type: parameters.scenario,
                duration: parameters.durationSec,
                output_format: parameters.outputFormat,
                data_points: Math.floor(parameters.durationSec * 10) // 10 Hz sampling
            };
            break;
        case "rf_sense_wifi_lab":
            executionResult.details = {
                capture_type: "wifi_csi",
                duration: parameters.durationSec,
                participants: parameters.participants,
                consent_required: true,
                network_restricted: true
            };
            break;
        case "rf_sense_mmwave":
            executionResult.details = {
                capture_type: "mmwave_radar",
                duration: parameters.durationSec,
                capture_mode: parameters.captureMode,
                participants: parameters.participants,
                sdk_required: true,
                dev_kit_required: true
            };
            break;
        case "auto":
            executionResult.details = {
                auto_detection: "session_type_determined_at_runtime",
                action: action,
                parameters: parameters
            };
            break;
        case "all":
            executionResult.details = {
                status_check: "all_modules",
                modules: ["rf_sense_sim", "rf_sense_wifi_lab", "rf_sense_mmwave"]
            };
            break;
    }
    return executionResult;
}
// Helper function to get available commands
export function getAvailableCommands() {
    return [
        "Start a simulated RF session for 30 seconds and render occupancy",
        "Run simulation with single person scenario for 15 seconds",
        "Generate synthetic data for gesture demo",
        "Start WiFi lab capture for 20 seconds in Room A",
        "Begin RF sensing experiment for 10 seconds",
        "Capture WiFi CSI data for 30 seconds",
        "Start mmWave capture for 15 seconds",
        "Begin radar scan for point cloud generation",
        "Capture mmWave data for object tracking",
        "Process last session into occupancy heatmap",
        "Analyze session with pose estimation",
        "Generate point cloud from session data",
        "Export session as PLY format",
        "Save session data as JSON",
        "Download point cloud as PCD",
        "Visualize session as heatmap",
        "Show point cloud visualization",
        "Display occupancy map",
        "Show RF sense status",
        "List all sessions",
        "Check system status"
    ];
}
// Helper function to get command examples by category
export function getCommandExamples() {
    return {
        simulation: [
            "Start a simulated RF session for 30 seconds and render occupancy",
            "Run simulation with single person scenario for 15 seconds",
            "Generate synthetic data for gesture demo",
            "Create simulation with multiple people for 20 seconds"
        ],
        wifi_lab: [
            "Start WiFi lab capture for 20 seconds in Room A",
            "Begin RF sensing experiment for 10 seconds",
            "Capture WiFi CSI data for 30 seconds",
            "Run WiFi lab experiment with participants for 15 seconds",
            "Detect people through walls in adjacent rooms",
            "Monitor occupancy across multiple rooms using WiFi CSI"
        ],
        mmwave: [
            "Start mmWave capture for 15 seconds",
            "Begin radar scan for point cloud generation",
            "Capture mmWave data for object tracking",
            "Run mmWave experiment for gesture detection",
            "Detect objects through walls with mmWave radar",
            "Track movement through building materials"
        ],
        processing: [
            "Process last session into occupancy heatmap",
            "Analyze session with pose estimation",
            "Generate point cloud from session data",
            "Run clutter removal on session data"
        ],
        export: [
            "Export session as PLY format",
            "Save session data as JSON",
            "Download point cloud as PCD",
            "Convert session to CSV format"
        ],
        visualization: [
            "Visualize session as heatmap",
            "Show point cloud visualization",
            "Display occupancy map",
            "Render skeleton visualization"
        ],
        status: [
            "Show RF sense status",
            "List all sessions",
            "Check system status",
            "Get module information"
        ]
    };
}
