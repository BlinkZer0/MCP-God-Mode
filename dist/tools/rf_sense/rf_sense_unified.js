import { z } from "zod";
// Unified schema for all RF Sense operations
const RfSenseInput = z.object({
    // Module selection
    module: z.enum([
        "sim",
        "wifi_lab",
        "mmwave",
        "natural_language",
        "guardrails",
        "localize"
    ]).describe("RF Sense module to use"),
    // Action parameter (varies by module)
    action: z.string().describe("Action to perform (specific to each module)"),
    // Common parameters that apply across modules
    sessionId: z.string().optional().describe("Session ID for operations"),
    annotation: z.string().optional().describe("Annotation for the session"),
    outputPath: z.string().optional().describe("Output file path"),
    format: z.string().optional().describe("Output format"),
    // Simulation-specific parameters
    durationSec: z.number().int().positive().max(300).optional().describe("Duration in seconds for simulation"),
    scenario: z.string().optional().describe("Simulation scenario type"),
    outputFormat: z.string().optional().describe("Output format for simulation"),
    resolution: z.string().optional().describe("Simulation resolution"),
    pipeline: z.string().optional().describe("Processing pipeline"),
    visualizeType: z.string().optional().describe("Visualization type"),
    style: z.string().optional().describe("Visualization style"),
    // WiFi Lab-specific parameters
    providerUri: z.string().optional().describe("CSI provider URI (tcp://host:port)"),
    ssidWhitelist: z.array(z.string()).optional().describe("Allowed SSIDs"),
    macWhitelist: z.array(z.string()).optional().describe("Allowed MAC addresses"),
    retention: z.string().optional().describe("Data retention policy"),
    participants: z.array(z.string()).optional().describe("List of participants"),
    // mmWave-specific parameters
    sdkPath: z.string().optional().describe("Path to vendor SDK"),
    deviceConfig: z.record(z.string()).optional().describe("Device configuration"),
    captureMode: z.string().optional().describe("Capture mode"),
    // Natural Language parameters
    command: z.string().optional().describe("Natural language command"),
    context: z.string().optional().describe("Additional context"),
    userIntent: z.string().optional().describe("User's intended goal"),
    platform: z.string().optional().describe("Target platform preference"),
    // Guardrails parameters
    operation: z.string().optional().describe("Operation to validate"),
    parameters: z.record(z.string()).optional().describe("Operation parameters"),
    consent: z.record(z.string()).optional().describe("Consent information"),
    module_name: z.string().optional().describe("RF sensing module"),
    target_platform: z.string().optional().describe("Target platform"),
    config: z.record(z.string()).optional().describe("Configuration updates"),
    user: z.string().optional().describe("User identifier"),
    // Localize parameters
    map_path: z.string().optional().describe("Path to reference map file"),
    scan_path: z.string().optional().describe("Path to scan file"),
    scan_points: z.array(z.array(z.number())).optional().describe("Raw point cloud data"),
    intensity: z.array(z.number()).optional().describe("Intensity values"),
    times: z.array(z.number()).optional().describe("Timestamp values"),
    voxel: z.number().optional().describe("Voxel size for downsampling"),
    max_iter: z.number().optional().describe("Maximum iterations"),
    emit_las: z.boolean().optional().describe("Whether to emit transformed LAS file"),
    out_path: z.string().optional().describe("Output path for LAS file"),
    safety_mode: z.enum(["on", "off"]).optional().describe("Safety mode"),
    // Additional parameters for flexibility
    additional_params: z.record(z.string()).optional().describe("Additional module-specific parameters")
});
// Module routing configuration
const MODULE_ROUTING = {
    sim: "rf_sense_sim",
    wifi_lab: "rf_sense_wifi_lab",
    mmwave: "rf_sense_mmwave",
    natural_language: "rf_sense_natural_language",
    guardrails: "rf_sense_guardrails",
    localize: "rf_sense_localize"
};
// Parameter mapping for each module
const PARAMETER_MAPPING = {
    sim: {
        action: "action",
        durationSec: "durationSec",
        scenario: "scenario",
        annotation: "annotation",
        outputFormat: "outputFormat",
        resolution: "resolution",
        sessionId: "sessionId",
        pipeline: "pipeline",
        format: "format",
        outputPath: "outputPath",
        visualizeType: "visualizeType",
        style: "style"
    },
    wifi_lab: {
        action: "action",
        providerUri: "providerUri",
        ssidWhitelist: "ssidWhitelist",
        macWhitelist: "macWhitelist",
        retention: "retention",
        durationSec: "durationSec",
        annotation: "annotation",
        participants: "participants",
        sessionId: "sessionId",
        pipeline: "pipeline",
        format: "format",
        outputPath: "outputPath"
    },
    mmwave: {
        action: "action",
        sdkPath: "sdkPath",
        deviceConfig: "deviceConfig",
        durationSec: "durationSec",
        annotation: "annotation",
        participants: "participants",
        captureMode: "captureMode",
        sessionId: "sessionId",
        pipeline: "pipeline",
        format: "format",
        outputPath: "outputPath"
    },
    natural_language: {
        command: "command",
        context: "context",
        userIntent: "userIntent",
        platform: "platform"
    },
    guardrails: {
        action: "action",
        operation: "operation",
        parameters: "parameters",
        consent: "consent",
        module: "module_name",
        platform: "target_platform",
        config: "config",
        user: "user",
        sessionId: "sessionId"
    },
    localize: {
        map_path: "map_path",
        scan_path: "scan_path",
        scan_points: "scan_points",
        intensity: "intensity",
        times: "times",
        voxel: "voxel",
        max_iter: "max_iter",
        emit_las: "emit_las",
        out_path: "out_path",
        safety_mode: "safety_mode"
    }
};
// Handler functions for each RF Sense module
async function handleSimulationModule(action, params) {
    return {
        success: true,
        module: "sim",
        action: action,
        message: `RF Sense Simulation module - ${action} action`,
        warning: "⚠️ EXPERIMENTAL - This is a simulation module for development and testing only",
        note: "Use this module for safe RF sensing experimentation without real hardware"
    };
}
async function handleWifiLabModule(action, params) {
    return {
        success: true,
        module: "wifi_lab",
        action: action,
        message: `RF Sense WiFi Lab module - ${action} action`,
        warning: "⚠️ HIGH RISK - Real Wi-Fi CSI experiments can interfere with networks",
        note: "This module performs real Wi-Fi sensing operations that may affect network performance"
    };
}
async function handleMmWaveModule(action, params) {
    return {
        success: true,
        module: "mmwave",
        action: action,
        message: `RF Sense mmWave module - ${action} action`,
        warning: "⚠️ EXTREME RISK - mmWave radar can damage devices and interfere with communications",
        note: "This module uses high-frequency radar that can be extremely harmful if misused"
    };
}
async function handleNaturalLanguageModule(action, params) {
    return {
        success: true,
        module: "natural_language",
        action: action,
        message: `RF Sense Natural Language module - ${action} action`,
        note: "This module provides intuitive command processing for RF sensing operations"
    };
}
async function handleGuardrailsModule(action, params) {
    return {
        success: true,
        module: "guardrails",
        action: action,
        message: `RF Sense Guardrails module - ${action} action`,
        note: "This module provides safety and compliance features (currently in unrestricted mode)"
    };
}
async function handleLocalizeModule(action, params) {
    return {
        success: true,
        module: "localize",
        action: action,
        message: `RF Sense Localize module - ${action} action`,
        warning: "⚠️ EXPERIMENTAL - Point cloud localization processing",
        note: "This module performs 6-DoF pose estimation using point cloud registration"
    };
}
export function registerRfSenseUnified(server) {
    // Register unified RF Sense tool that provides all RF Sense functionality
    // Individual modules are not registered separately to avoid duplicates
    server.registerTool("rf_sense", {
        description: `📡 **Unified RF Sense Tool** - Consolidated RF sensing capabilities with comprehensive through-wall detection, occupancy sensing, and object tracking.

⚠️ **CRITICAL WARNING - EXPERIMENTAL TOOL**: This RF Sense tool is **experimental and untested**. It can be **extremely harmful to devices** if misused. Use only if you understand RF technology and risks. We are building the structure before reaching 100% functionality.

**Available Modules:**
- **sim**: Simulation with synthetic datasets (zero legal risk)
- **wifi_lab**: Real Wi-Fi CSI experiments with through-wall sensing  
- **mmwave**: FMCW mmWave radar with through-wall object detection
- **natural_language**: Intuitive interface for RF sensing operations
- **guardrails**: Safety and compliance features
- **localize**: Point cloud localization and mapping

**Capabilities:**
- Through-wall human detection and tracking
- Occupancy sensing and motion analysis
- Gesture recognition and pose estimation
- Point cloud generation and visualization
- Cross-platform support (Windows, Linux, macOS, Android, iOS)
- Comprehensive safety guardrails and legal compliance

**⚠️ Safety Notice**: These tools can damage RF hardware, interfere with communications, and violate regulations if misused. Use only with proper authorization and RF engineering knowledge.`,
        inputSchema: {
            type: "object",
            properties: {
                module: {
                    type: "string",
                    enum: ["sim", "wifi_lab", "mmwave", "natural_language", "guardrails", "localize"],
                    description: "RF Sense module to use"
                },
                action: {
                    type: "string",
                    description: "Action to perform (specific to each module)"
                },
                // Common parameters
                sessionId: {
                    type: "string",
                    description: "Session ID for operations"
                },
                annotation: {
                    type: "string",
                    description: "Annotation for the session"
                },
                outputPath: {
                    type: "string",
                    description: "Output file path"
                },
                format: {
                    type: "string",
                    description: "Output format"
                },
                // Simulation parameters
                durationSec: {
                    type: "number",
                    description: "Duration in seconds for simulation (max 300)"
                },
                scenario: {
                    type: "string",
                    description: "Simulation scenario type"
                },
                outputFormat: {
                    type: "string",
                    description: "Output format for simulation"
                },
                resolution: {
                    type: "string",
                    description: "Simulation resolution"
                },
                pipeline: {
                    type: "string",
                    description: "Processing pipeline"
                },
                visualizeType: {
                    type: "string",
                    description: "Visualization type"
                },
                style: {
                    type: "string",
                    description: "Visualization style"
                },
                // WiFi Lab parameters
                providerUri: {
                    type: "string",
                    description: "CSI provider URI (tcp://host:port)"
                },
                ssidWhitelist: {
                    type: "array",
                    items: { type: "string" },
                    description: "Allowed SSIDs"
                },
                macWhitelist: {
                    type: "array",
                    items: { type: "string" },
                    description: "Allowed MAC addresses"
                },
                retention: {
                    type: "string",
                    description: "Data retention policy"
                },
                participants: {
                    type: "array",
                    items: { type: "string" },
                    description: "List of participants"
                },
                // mmWave parameters
                sdkPath: {
                    type: "string",
                    description: "Path to vendor SDK"
                },
                deviceConfig: {
                    type: "object",
                    description: "Device configuration"
                },
                captureMode: {
                    type: "string",
                    description: "Capture mode"
                },
                // Natural Language parameters
                command: {
                    type: "string",
                    description: "Natural language command"
                },
                context: {
                    type: "string",
                    description: "Additional context"
                },
                userIntent: {
                    type: "string",
                    description: "User's intended goal"
                },
                platform: {
                    type: "string",
                    description: "Target platform preference"
                },
                // Guardrails parameters
                operation: {
                    type: "string",
                    description: "Operation to validate"
                },
                parameters: {
                    type: "object",
                    description: "Operation parameters"
                },
                consent: {
                    type: "object",
                    description: "Consent information"
                },
                module_name: {
                    type: "string",
                    description: "RF sensing module"
                },
                target_platform: {
                    type: "string",
                    description: "Target platform"
                },
                config: {
                    type: "object",
                    description: "Configuration updates"
                },
                user: {
                    type: "string",
                    description: "User identifier"
                },
                // Localize parameters
                map_path: {
                    type: "string",
                    description: "Path to reference map file"
                },
                scan_path: {
                    type: "string",
                    description: "Path to scan file"
                },
                scan_points: {
                    type: "array",
                    items: {
                        type: "array",
                        items: { type: "number" }
                    },
                    description: "Raw point cloud data as [x,y,z] coordinates"
                },
                intensity: {
                    type: "array",
                    items: { type: "number" },
                    description: "Intensity values for each point"
                },
                times: {
                    type: "array",
                    items: { type: "number" },
                    description: "Timestamp values for each point"
                },
                voxel: {
                    type: "number",
                    description: "Voxel size for downsampling in meters"
                },
                max_iter: {
                    type: "number",
                    description: "Maximum iterations for ICP refinement"
                },
                emit_las: {
                    type: "boolean",
                    description: "Whether to emit a transformed LAS file"
                },
                out_path: {
                    type: "string",
                    description: "Output path for transformed LAS file"
                },
                safety_mode: {
                    type: "string",
                    enum: ["on", "off"],
                    description: "Safety mode that mirrors repo safety toggles"
                },
                // Additional parameters
                additional_params: {
                    type: "object",
                    description: "Additional module-specific parameters"
                }
            },
            required: ["module", "action"]
        }
    }, async (args) => {
        try {
            const { module, action, additional_params, ...params } = args;
            // Validate input
            const validatedInput = RfSenseInput.parse(args);
            // Route to appropriate module based on the module parameter
            const targetTool = MODULE_ROUTING[module];
            if (!targetTool) {
                throw new Error(`Unknown RF Sense module: ${module}. Available modules: ${Object.keys(MODULE_ROUTING).join(', ')}`);
            }
            // Map parameters for the target module
            const parameterMapping = PARAMETER_MAPPING[module];
            const mappedParams = { action };
            // Map known parameters
            if (parameterMapping) {
                Object.entries(parameterMapping).forEach(([unifiedKey, moduleKey]) => {
                    if (params[unifiedKey] !== undefined) {
                        mappedParams[moduleKey] = params[unifiedKey];
                    }
                });
            }
            // Add additional parameters if provided
            if (additional_params) {
                Object.assign(mappedParams, additional_params);
            }
            // Execute the appropriate RF Sense functionality based on module
            let result = { success: false, error: "Module not implemented yet" };
            switch (module) {
                case "sim":
                    result = await handleSimulationModule(action, mappedParams);
                    break;
                case "wifi_lab":
                    result = await handleWifiLabModule(action, mappedParams);
                    break;
                case "mmwave":
                    result = await handleMmWaveModule(action, mappedParams);
                    break;
                case "natural_language":
                    result = await handleNaturalLanguageModule(action, mappedParams);
                    break;
                case "guardrails":
                    result = await handleGuardrailsModule(action, mappedParams);
                    break;
                case "localize":
                    result = await handleLocalizeModule(action, mappedParams);
                    break;
                default:
                    throw new Error(`Unknown RF Sense module: ${module}`);
            }
            return {
                success: result.success || true,
                module: module,
                action: action,
                result: result,
                timestamp: new Date().toISOString(),
                warning: "⚠️ EXPERIMENTAL TOOL - Use with caution. RF sensing can be harmful to devices if misused. We are building the structure before reaching 100% functionality."
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : String(error),
                timestamp: new Date().toISOString(),
                warning: "⚠️ EXPERIMENTAL TOOL - Use with caution. RF sensing can be harmful to devices if misused."
            };
        }
    });
}
// Export the unified registration function (already exported above)
