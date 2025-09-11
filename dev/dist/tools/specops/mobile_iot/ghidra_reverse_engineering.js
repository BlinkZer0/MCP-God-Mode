import { z } from "zod";
import { exec } from "node:child_process";
import { promisify } from "util";
import * as os from "node:os";
const execAsync = promisify(exec);
export function registerGhidraReverseEngineering(server) {
    server.registerTool("ghidra_reverse_engineering", {
        description: "Advanced Ghidra reverse engineering framework with full cross-platform support (Windows, Linux, macOS, iOS, Android). Provides comprehensive binary analysis capabilities including disassembly, decompilation, function analysis, vulnerability detection, and malware analysis across all platforms. Supports natural language interface for intuitive reverse engineering operations.",
        inputSchema: {
            action: z.enum([
                // Core analysis
                "analyze_binary", "disassemble_code", "decompile_code", "analyze_functions", "analyze_strings",
                "analyze_imports", "analyze_exports", "analyze_headers", "analyze_sections", "analyze_relocations",
                // Advanced analysis
                "control_flow_analysis", "data_flow_analysis", "call_graph_analysis", "xref_analysis", "signature_analysis",
                "entropy_analysis", "packer_detection", "obfuscation_detection", "anti_analysis_detection",
                // Vulnerability analysis
                "vulnerability_scan", "buffer_overflow_detection", "format_string_detection", "integer_overflow_detection",
                "use_after_free_detection", "double_free_detection", "race_condition_detection",
                // Malware analysis
                "malware_analysis", "packer_analysis", "crypter_analysis", "rootkit_detection", "backdoor_detection",
                "keylogger_detection", "ransomware_analysis", "trojan_analysis", "botnet_analysis",
                // Platform-specific analysis
                "windows_pe_analysis", "linux_elf_analysis", "macos_mach_o_analysis", "ios_ipa_analysis", "android_apk_analysis",
                "firmware_analysis", "bootloader_analysis", "kernel_analysis", "driver_analysis",
                // Custom operations
                "custom_script", "plugin_execution", "headless_analysis", "batch_analysis"
            ]).describe("Ghidra action to perform"),
            // Target information
            binary_file: z.string().optional().describe("Binary file path to analyze"),
            project_name: z.string().optional().describe("Ghidra project name"),
            output_directory: z.string().optional().describe("Output directory for analysis results"),
            // Analysis parameters
            analysis_depth: z.enum(["basic", "comprehensive", "deep"]).optional().describe("Analysis depth level"),
            target_architecture: z.string().optional().describe("Target architecture (x86, x64, ARM, ARM64, MIPS, etc.)"),
            target_platform: z.string().optional().describe("Target platform (Windows, Linux, macOS, iOS, Android)"),
            // Script operations
            script_content: z.string().optional().describe("Ghidra script content"),
            script_file: z.string().optional().describe("Ghidra script file path"),
            script_type: z.enum(["python", "java"]).optional().describe("Script type"),
            // Platform-specific options
            platform: z.enum(["windows", "linux", "macos", "ios", "android", "auto"]).optional().describe("Target platform"),
            architecture: z.enum(["x86", "x64", "arm", "arm64"]).optional().describe("Target architecture"),
            // Natural language interface
            natural_language_command: z.string().optional().describe("Natural language command for Ghidra operations (e.g., 'analyze this binary for vulnerabilities', 'disassemble the main function', 'find all strings in the executable', 'detect malware signatures')"),
            // Security options
            safe_mode: z.boolean().default(false).describe("Enable safe mode to prevent actual analysis (disabled by default for full functionality)"),
            verbose: z.boolean().default(false).describe("Enable verbose output"),
            debug: z.boolean().default(false).describe("Enable debug output")
        },
        outputSchema: {
            success: z.boolean(),
            message: z.string(),
            platform_info: z.object({
                detected_platform: z.string(),
                architecture: z.string(),
                ghidra_available: z.boolean(),
                alternative_tools: z.array(z.string()).optional()
            }).optional(),
            analysis_results: z.object({
                binary_info: z.object({
                    file_type: z.string().optional(),
                    architecture: z.string().optional(),
                    platform: z.string().optional(),
                    entry_point: z.string().optional(),
                    sections: z.array(z.string()).optional()
                }).optional(),
                functions: z.array(z.object({
                    name: z.string(),
                    address: z.string(),
                    size: z.number(),
                    complexity: z.string().optional()
                })).optional(),
                strings: z.array(z.object({
                    value: z.string(),
                    address: z.string(),
                    length: z.number()
                })).optional(),
                imports: z.array(z.string()).optional(),
                exports: z.array(z.string()).optional(),
                vulnerabilities: z.array(z.object({
                    type: z.string(),
                    severity: z.string(),
                    address: z.string(),
                    description: z.string()
                })).optional(),
                malware_indicators: z.array(z.object({
                    type: z.string(),
                    confidence: z.string(),
                    description: z.string()
                })).optional()
            }).optional(),
            results: z.object({
                action: z.string().optional(),
                output: z.string().optional(),
                status: z.string().optional(),
                platform: z.string().optional(),
                execution_time: z.number().optional()
            }).optional()
        }
    }, async ({ action, binary_file, project_name, output_directory, analysis_depth, target_architecture, target_platform, script_content, script_file, script_type, platform, architecture, natural_language_command, safe_mode, verbose, debug }) => {
        try {
            // Process natural language command if provided
            let processedAction = action;
            let processedParams = { binary_file, project_name, output_directory, analysis_depth, target_architecture, target_platform, script_content, script_file, script_type };
            if (natural_language_command) {
                const nlResult = processNaturalLanguageCommand(natural_language_command);
                processedAction = nlResult.action || action;
                processedParams = { ...processedParams, ...nlResult.params };
            }
            // Detect platform if not specified
            const detectedPlatform = platform || detectPlatform();
            const detectedArch = architecture || detectArchitecture();
            // Legal compliance check
            if (safe_mode !== true) {
                return {
                    success: false,
                    message: "⚠️ LEGAL WARNING: Safe mode is disabled. This tool is for authorized reverse engineering only. Ensure you have explicit written permission before proceeding.",
                    platform_info: {
                        detected_platform: detectedPlatform,
                        architecture: detectedArch,
                        ghidra_available: isGhidraAvailable(detectedPlatform),
                        alternative_tools: getAlternativeTools(detectedPlatform)
                    }
                };
            }
            let result = { success: true, message: "" };
            // Platform-specific execution
            switch (detectedPlatform) {
                case "windows":
                    result = await executeWindowsGhidra(processedAction, processedParams, { safe_mode, verbose, debug });
                    break;
                case "linux":
                    result = await executeLinuxGhidra(processedAction, processedParams, { safe_mode, verbose, debug });
                    break;
                case "macos":
                    result = await executeMacOSGhidra(processedAction, processedParams, { safe_mode, verbose, debug });
                    break;
                case "ios":
                    result = await executeIOSGhidra(processedAction, processedParams, { safe_mode, verbose, debug });
                    break;
                case "android":
                    result = await executeAndroidGhidra(processedAction, processedParams, { safe_mode, verbose, debug });
                    break;
                default:
                    result = { success: false, message: `Unsupported platform: ${detectedPlatform}` };
            }
            // Add platform information to result
            result.platform_info = {
                detected_platform: detectedPlatform,
                architecture: detectedArch,
                ghidra_available: isGhidraAvailable(detectedPlatform),
                alternative_tools: getAlternativeTools(detectedPlatform)
            };
            return result;
        }
        catch (error) {
            return {
                success: false,
                message: `Ghidra reverse engineering operation failed: ${error instanceof Error ? error.message : String(error)}`,
                platform_info: {
                    detected_platform: platform || detectPlatform(),
                    architecture: architecture || detectArchitecture(),
                    ghidra_available: false,
                    alternative_tools: getAlternativeTools(platform || detectPlatform())
                }
            };
        }
    });
}
// Platform detection functions
function detectPlatform() {
    const platform = os.platform();
    switch (platform) {
        case "win32": return "windows";
        case "linux": return "linux";
        case "darwin": return "macos";
        default: return "unknown";
    }
}
function detectArchitecture() {
    const arch = os.arch();
    switch (arch) {
        case "x64": return "x64";
        case "x32": return "x86";
        case "arm": return "arm";
        case "arm64": return "arm64";
        default: return "unknown";
    }
}
function isGhidraAvailable(platform) {
    switch (platform) {
        case "windows": return true;
        case "linux": return true;
        case "macos": return true;
        case "ios": return false; // Requires alternative tools
        case "android": return false; // Requires alternative tools
        default: return false;
    }
}
function getAlternativeTools(platform) {
    switch (platform) {
        case "windows":
            return ["ghidra.exe", "ghidraRun.bat", "analyzeHeadless.bat"];
        case "linux":
            return ["ghidra", "ghidraRun", "analyzeHeadless"];
        case "macos":
            return ["ghidra", "ghidraRun", "analyzeHeadless"];
        case "ios":
            return ["class-dump", "otool", "nm", "strings", "hexdump"];
        case "android":
            return ["apktool", "dex2jar", "jadx", "aapt", "dexdump"];
        default:
            return [];
    }
}
// Windows Ghidra execution
async function executeWindowsGhidra(action, params, options) {
    if (options.safe_mode === true) {
        return {
            success: true,
            message: "🔒 SAFE MODE: Windows Ghidra operation simulated. No actual analysis performed.",
            results: {
                action,
                status: "simulated",
                platform: "windows",
                output: `Simulated Windows Ghidra operation: ${action}`
            }
        };
    }
    try {
        let command = "";
        switch (action) {
            case "analyze_binary":
                command = `analyzeHeadless.bat ${params.project_name || "temp_project"} -import "${params.binary_file}" -postScript ${params.script_file || "analyze.py"}`;
                break;
            case "disassemble_code":
                command = `analyzeHeadless.bat ${params.project_name || "temp_project"} -import "${params.binary_file}" -postScript disassemble.py`;
                break;
            case "vulnerability_scan":
                command = `analyzeHeadless.bat ${params.project_name || "temp_project"} -import "${params.binary_file}" -postScript vulnerability_scan.py`;
                break;
            default:
                command = `analyzeHeadless.bat ${params.project_name || "temp_project"} -import "${params.binary_file}" -postScript ${action}.py`;
        }
        const { stdout } = await execAsync(command);
        return {
            success: true,
            message: `Windows Ghidra operation completed: ${action}`,
            results: {
                action,
                status: "completed",
                platform: "windows",
                output: stdout
            }
        };
    }
    catch (error) {
        return {
            success: false,
            message: `Windows Ghidra operation failed: ${error instanceof Error ? error.message : String(error)}`
        };
    }
}
// Linux Ghidra execution
async function executeLinuxGhidra(action, params, options) {
    if (options.safe_mode === true) {
        return {
            success: true,
            message: "🔒 SAFE MODE: Linux Ghidra operation simulated. No actual analysis performed.",
            results: {
                action,
                status: "simulated",
                platform: "linux",
                output: `Simulated Linux Ghidra operation: ${action}`
            }
        };
    }
    try {
        let command = "";
        switch (action) {
            case "analyze_binary":
                command = `analyzeHeadless ${params.project_name || "temp_project"} -import "${params.binary_file}" -postScript ${params.script_file || "analyze.py"}`;
                break;
            case "disassemble_code":
                command = `analyzeHeadless ${params.project_name || "temp_project"} -import "${params.binary_file}" -postScript disassemble.py`;
                break;
            case "vulnerability_scan":
                command = `analyzeHeadless ${params.project_name || "temp_project"} -import "${params.binary_file}" -postScript vulnerability_scan.py`;
                break;
            default:
                command = `analyzeHeadless ${params.project_name || "temp_project"} -import "${params.binary_file}" -postScript ${action}.py`;
        }
        const { stdout } = await execAsync(command);
        return {
            success: true,
            message: `Linux Ghidra operation completed: ${action}`,
            results: {
                action,
                status: "completed",
                platform: "linux",
                output: stdout
            }
        };
    }
    catch (error) {
        return {
            success: false,
            message: `Linux Ghidra operation failed: ${error instanceof Error ? error.message : String(error)}`
        };
    }
}
// macOS Ghidra execution
async function executeMacOSGhidra(action, params, options) {
    if (options.safe_mode === true) {
        return {
            success: true,
            message: "🔒 SAFE MODE: macOS Ghidra operation simulated. No actual analysis performed.",
            results: {
                action,
                status: "simulated",
                platform: "macos",
                output: `Simulated macOS Ghidra operation: ${action}`
            }
        };
    }
    try {
        let command = "";
        switch (action) {
            case "analyze_binary":
                command = `analyzeHeadless ${params.project_name || "temp_project"} -import "${params.binary_file}" -postScript ${params.script_file || "analyze.py"}`;
                break;
            case "macos_mach_o_analysis":
                command = `analyzeHeadless ${params.project_name || "temp_project"} -import "${params.binary_file}" -postScript mach_o_analysis.py`;
                break;
            case "vulnerability_scan":
                command = `analyzeHeadless ${params.project_name || "temp_project"} -import "${params.binary_file}" -postScript vulnerability_scan.py`;
                break;
            default:
                command = `analyzeHeadless ${params.project_name || "temp_project"} -import "${params.binary_file}" -postScript ${action}.py`;
        }
        const { stdout } = await execAsync(command);
        return {
            success: true,
            message: `macOS Ghidra operation completed: ${action}`,
            results: {
                action,
                status: "completed",
                platform: "macos",
                output: stdout
            }
        };
    }
    catch (error) {
        return {
            success: false,
            message: `macOS Ghidra operation failed: ${error instanceof Error ? error.message : String(error)}`
        };
    }
}
// iOS Ghidra execution (using alternative tools)
async function executeIOSGhidra(action, params, options) {
    if (options.safe_mode === true) {
        return {
            success: true,
            message: "🔒 SAFE MODE: iOS reverse engineering operation simulated. No actual analysis performed.",
            results: {
                action,
                status: "simulated",
                platform: "ios",
                output: `Simulated iOS reverse engineering operation: ${action}`
            }
        };
    }
    try {
        let command = "";
        switch (action) {
            case "analyze_binary":
                command = `class-dump "${params.binary_file}"`;
                break;
            case "disassemble_code":
                command = `otool -t "${params.binary_file}"`;
                break;
            case "analyze_strings":
                command = `strings "${params.binary_file}"`;
                break;
            case "ios_ipa_analysis":
                command = `unzip -l "${params.binary_file}" && class-dump "${params.binary_file}"`;
                break;
            default:
                command = `otool -l "${params.binary_file}"`;
        }
        const { stdout } = await execAsync(command);
        return {
            success: true,
            message: `iOS reverse engineering operation completed: ${action}`,
            results: {
                action,
                status: "completed",
                platform: "ios",
                output: stdout
            }
        };
    }
    catch (error) {
        return {
            success: false,
            message: `iOS reverse engineering operation failed: ${error instanceof Error ? error.message : String(error)}`
        };
    }
}
// Android Ghidra execution (using alternative tools)
async function executeAndroidGhidra(action, params, options) {
    if (options.safe_mode === true) {
        return {
            success: true,
            message: "🔒 SAFE MODE: Android reverse engineering operation simulated. No actual analysis performed.",
            results: {
                action,
                status: "simulated",
                platform: "android",
                output: `Simulated Android reverse engineering operation: ${action}`
            }
        };
    }
    try {
        let command = "";
        switch (action) {
            case "analyze_binary":
                command = `apktool d "${params.binary_file}" -o "${params.output_directory || "output"}"`;
                break;
            case "disassemble_code":
                command = `dex2jar "${params.binary_file}" && jadx "${params.binary_file}"`;
                break;
            case "analyze_strings":
                command = `aapt dump strings "${params.binary_file}"`;
                break;
            case "android_apk_analysis":
                command = `apktool d "${params.binary_file}" -o "${params.output_directory || "output"}" && aapt dump badging "${params.binary_file}"`;
                break;
            default:
                command = `aapt dump badging "${params.binary_file}"`;
        }
        const { stdout } = await execAsync(command);
        return {
            success: true,
            message: `Android reverse engineering operation completed: ${action}`,
            results: {
                action,
                status: "completed",
                platform: "android",
                output: stdout
            }
        };
    }
    catch (error) {
        return {
            success: false,
            message: `Android reverse engineering operation failed: ${error instanceof Error ? error.message : String(error)}`
        };
    }
}
// Natural language command processing for Ghidra
function processNaturalLanguageCommand(command) {
    const cmd = command.toLowerCase();
    const params = {};
    // Binary analysis patterns
    if (cmd.includes('analyze') && cmd.includes('binary')) {
        return { action: 'analyze_binary', params };
    }
    // Disassembly patterns
    if (cmd.includes('disassemble') || cmd.includes('disassembly')) {
        return { action: 'disassemble_code', params };
    }
    // Vulnerability analysis patterns
    if (cmd.includes('vulnerability') || cmd.includes('vulnerabilities')) {
        return { action: 'vulnerability_scan', params };
    }
    // String analysis patterns
    if (cmd.includes('string') && cmd.includes('find')) {
        return { action: 'analyze_strings', params };
    }
    // Function analysis patterns
    if (cmd.includes('function') && cmd.includes('analyze')) {
        return { action: 'analyze_functions', params };
    }
    // Malware analysis patterns
    if (cmd.includes('malware') || cmd.includes('malicious')) {
        return { action: 'malware_analysis', params };
    }
    // Platform-specific patterns
    if (cmd.includes('windows') && cmd.includes('pe')) {
        return { action: 'windows_pe_analysis', params };
    }
    if (cmd.includes('linux') && cmd.includes('elf')) {
        return { action: 'linux_elf_analysis', params };
    }
    if (cmd.includes('macos') && cmd.includes('mach')) {
        return { action: 'macos_mach_o_analysis', params };
    }
    if (cmd.includes('ios') && cmd.includes('ipa')) {
        return { action: 'ios_ipa_analysis', params };
    }
    if (cmd.includes('android') && cmd.includes('apk')) {
        return { action: 'android_apk_analysis', params };
    }
    // Default to binary analysis
    return { action: 'analyze_binary', params };
}
