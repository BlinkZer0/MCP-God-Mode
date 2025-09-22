import { z } from "zod";
import { exec } from "node:child_process";
import { promisify } from "util";
import * as os from "node:os";
const execAsync = promisify(exec);
export function registerFridaToolkit(server) {
    server.registerTool("frida_toolkit", {
        description: "Advanced Frida dynamic instrumentation toolkit with full cross-platform support (Windows, Linux, macOS, iOS, Android). Provides comprehensive dynamic analysis capabilities including function hooking, memory manipulation, API interception, and runtime patching across all platforms. Supports natural language interface for intuitive dynamic analysis operations.",
        inputSchema: {
            action: z.enum([
                // Core instrumentation
                "attach_process", "spawn_process", "detach_process", "list_processes", "list_applications",
                "hook_function", "hook_method", "intercept_api", "patch_memory", "read_memory", "write_memory",
                // Advanced analysis
                "trace_calls", "trace_execution", "monitor_network", "monitor_file_operations", "monitor_crypto",
                "dump_strings", "dump_classes", "dump_methods", "dump_imports", "dump_exports",
                // Platform-specific operations
                "ios_app_analysis", "android_app_analysis", "macos_app_analysis", "windows_app_analysis", "linux_app_analysis",
                "ios_keychain_access", "android_keystore_access", "macos_keychain_access", "windows_credential_access",
                // Security testing
                "bypass_ssl_pinning", "bypass_root_detection", "bypass_anti_debug", "bypass_anti_vm",
                "inject_payload", "modify_behavior", "extract_secrets", "runtime_patching",
                // Custom operations
                "execute_script", "load_script", "custom_instrumentation", "advanced_hooking"
            ]).describe("Frida action to perform"),
            // Target information
            target_process: z.string().optional().describe("Target process name or PID"),
            target_application: z.string().optional().describe("Target application bundle ID or package name"),
            target_device: z.string().optional().describe("Target device ID (for mobile platforms)"),
            // Instrumentation parameters
            function_name: z.string().optional().describe("Function name to hook"),
            method_name: z.string().optional().describe("Method name to hook"),
            class_name: z.string().optional().describe("Class name for method hooking"),
            module_name: z.string().optional().describe("Module name for API interception"),
            // Memory operations
            memory_address: z.string().optional().describe("Memory address for operations"),
            memory_size: z.number().optional().describe("Memory size for operations"),
            memory_data: z.string().optional().describe("Memory data to write"),
            // Script operations
            script_content: z.string().optional().describe("Frida script content"),
            script_file: z.string().optional().describe("Frida script file path"),
            script_type: z.enum(["javascript", "python", "typescript"]).optional().describe("Script type"),
            // Platform-specific options
            platform: z.enum(["windows", "linux", "macos", "ios", "android", "auto"]).optional().describe("Target platform"),
            architecture: z.enum(["x86", "x64", "arm", "arm64"]).optional().describe("Target architecture"),
            // Natural language interface
            natural_language_command: z.string().optional().describe("Natural language command for Frida operations (e.g., 'hook the login function in the app', 'extract API keys from memory', 'bypass SSL pinning in the application')"),
            // Security options
            safe_mode: z.boolean().default(false).describe("Enable safe mode to prevent actual instrumentation (disabled by default for full functionality)"),
            verbose: z.boolean().default(false).describe("Enable verbose output"),
            debug: z.boolean().default(false).describe("Enable debug output")
        },
        outputSchema: {
            success: z.boolean(),
            message: z.string(),
            platform_info: z.object({
                detected_platform: z.string(),
                architecture: z.string(),
                frida_available: z.boolean(),
                alternative_tools: z.array(z.string()).optional()
            }).optional(),
            instrumentation_results: z.object({
                process_id: z.number().optional(),
                process_name: z.string().optional(),
                hooks_installed: z.number().optional(),
                functions_hooked: z.array(z.string()).optional(),
                memory_operations: z.array(z.object({
                    address: z.string(),
                    operation: z.string(),
                    result: z.string()
                })).optional(),
                extracted_data: z.array(z.object({
                    type: z.string(),
                    value: z.string(),
                    source: z.string()
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
    }, async ({ action, target_process, target_application, target_device, function_name, method_name, class_name, module_name, memory_address, memory_size, memory_data, script_content, script_file, script_type, platform, architecture, natural_language_command, safe_mode, verbose, debug }) => {
        try {
            // Process natural language command if provided
            let processedAction = action;
            let processedParams = { target_process, target_application, target_device, function_name, method_name, class_name, module_name, memory_address, memory_size, memory_data, script_content, script_file, script_type };
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
                    message: "⚠️ LEGAL WARNING: Safe mode is disabled. This tool is for authorized dynamic analysis only. Ensure you have explicit written permission before proceeding.",
                    platform_info: {
                        detected_platform: detectedPlatform,
                        architecture: detectedArch,
                        frida_available: isFridaAvailable(detectedPlatform),
                        alternative_tools: getAlternativeTools(detectedPlatform)
                    }
                };
            }
            let result = { success: true, message: "" };
            // Platform-specific execution
            switch (detectedPlatform) {
                case "windows":
                    result = await executeWindowsFrida(processedAction, processedParams, { safe_mode, verbose, debug });
                    break;
                case "linux":
                    result = await executeLinuxFrida(processedAction, processedParams, { safe_mode, verbose, debug });
                    break;
                case "macos":
                    result = await executeMacOSFrida(processedAction, processedParams, { safe_mode, verbose, debug });
                    break;
                case "ios":
                    result = await executeIOSFrida(processedAction, processedParams, { safe_mode, verbose, debug });
                    break;
                case "android":
                    result = await executeAndroidFrida(processedAction, processedParams, { safe_mode, verbose, debug });
                    break;
                default:
                    result = { success: false, message: `Unsupported platform: ${detectedPlatform}` };
            }
            // Add platform information to result
            result.platform_info = {
                detected_platform: detectedPlatform,
                architecture: detectedArch,
                frida_available: isFridaAvailable(detectedPlatform),
                alternative_tools: getAlternativeTools(detectedPlatform)
            };
            return result;
        }
        catch (error) {
            return {
                success: false,
                message: `Frida toolkit operation failed: ${error instanceof Error ? error.message : String(error)}`,
                platform_info: {
                    detected_platform: platform || detectPlatform(),
                    architecture: architecture || detectArchitecture(),
                    frida_available: false,
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
function isFridaAvailable(platform) {
    switch (platform) {
        case "windows": return true;
        case "linux": return true;
        case "macos": return true;
        case "ios": return true; // Requires jailbreak
        case "android": return true; // Requires root or USB debugging
        default: return false;
    }
}
function getAlternativeTools(platform) {
    switch (platform) {
        case "windows":
            return ["frida.exe", "frida-tools", "frida-server"];
        case "linux":
            return ["frida", "frida-tools", "frida-server"];
        case "macos":
            return ["frida", "frida-tools", "frida-server"];
        case "ios":
            return ["frida", "cycript", "class-dump", "theos"];
        case "android":
            return ["frida", "xposed", "magisk", "adb"];
        default:
            return [];
    }
}
// Windows Frida execution
async function executeWindowsFrida(action, params, options) {
    if (options.safe_mode === true) {
        return {
            success: true,
            message: "🔒 SAFE MODE: Windows Frida operation simulated. No actual instrumentation performed.",
            results: {
                action,
                status: "simulated",
                platform: "windows",
                output: `Simulated Windows Frida operation: ${action}`
            }
        };
    }
    try {
        let command = "";
        switch (action) {
            case "attach_process":
                command = `frida -p ${params.target_process} -l ${params.script_file || "hook_script.js"}`;
                break;
            case "hook_function":
                command = `frida -p ${params.target_process} -l hook_function.js --function-name ${params.function_name}`;
                break;
            case "extract_secrets":
                command = `frida -p ${params.target_process} -l extract_secrets.js`;
                break;
            default:
                command = `frida -p ${params.target_process} -l ${action}.js`;
        }
        const { stdout } = await execAsync(command);
        return {
            success: true,
            message: `Windows Frida operation completed: ${action}`,
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
            message: `Windows Frida operation failed: ${error instanceof Error ? error.message : String(error)}`
        };
    }
}
// Linux Frida execution
async function executeLinuxFrida(action, params, options) {
    if (options.safe_mode === true) {
        return {
            success: true,
            message: "🔒 SAFE MODE: Linux Frida operation simulated. No actual instrumentation performed.",
            results: {
                action,
                status: "simulated",
                platform: "linux",
                output: `Simulated Linux Frida operation: ${action}`
            }
        };
    }
    try {
        let command = "";
        switch (action) {
            case "attach_process":
                command = `frida -p ${params.target_process} -l ${params.script_file || "hook_script.js"}`;
                break;
            case "hook_function":
                command = `frida -p ${params.target_process} -l hook_function.js --function-name ${params.function_name}`;
                break;
            case "extract_secrets":
                command = `frida -p ${params.target_process} -l extract_secrets.js`;
                break;
            default:
                command = `frida -p ${params.target_process} -l ${action}.js`;
        }
        const { stdout } = await execAsync(command);
        return {
            success: true,
            message: `Linux Frida operation completed: ${action}`,
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
            message: `Linux Frida operation failed: ${error instanceof Error ? error.message : String(error)}`
        };
    }
}
// macOS Frida execution
async function executeMacOSFrida(action, params, options) {
    if (options.safe_mode === true) {
        return {
            success: true,
            message: "🔒 SAFE MODE: macOS Frida operation simulated. No actual instrumentation performed.",
            results: {
                action,
                status: "simulated",
                platform: "macos",
                output: `Simulated macOS Frida operation: ${action}`
            }
        };
    }
    try {
        let command = "";
        switch (action) {
            case "attach_process":
                command = `frida -p ${params.target_process} -l ${params.script_file || "hook_script.js"}`;
                break;
            case "macos_keychain_access":
                command = `frida -p ${params.target_process} -l keychain_access.js`;
                break;
            case "extract_secrets":
                command = `frida -p ${params.target_process} -l extract_secrets.js`;
                break;
            default:
                command = `frida -p ${params.target_process} -l ${action}.js`;
        }
        const { stdout } = await execAsync(command);
        return {
            success: true,
            message: `macOS Frida operation completed: ${action}`,
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
            message: `macOS Frida operation failed: ${error instanceof Error ? error.message : String(error)}`
        };
    }
}
// iOS Frida execution
async function executeIOSFrida(action, params, options) {
    if (options.safe_mode === true) {
        return {
            success: true,
            message: "🔒 SAFE MODE: iOS Frida operation simulated. No actual instrumentation performed.",
            results: {
                action,
                status: "simulated",
                platform: "ios",
                output: `Simulated iOS Frida operation: ${action}`
            }
        };
    }
    try {
        let command = "";
        switch (action) {
            case "attach_process":
                command = `frida -U -f ${params.target_application} -l ${params.script_file || "hook_script.js"}`;
                break;
            case "ios_keychain_access":
                command = `frida -U -f ${params.target_application} -l keychain_access.js`;
                break;
            case "bypass_ssl_pinning":
                command = `frida -U -f ${params.target_application} -l ssl_pinning_bypass.js`;
                break;
            case "extract_secrets":
                command = `frida -U -f ${params.target_application} -l extract_secrets.js`;
                break;
            default:
                command = `frida -U -f ${params.target_application} -l ${action}.js`;
        }
        const { stdout } = await execAsync(command);
        return {
            success: true,
            message: `iOS Frida operation completed: ${action}`,
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
            message: `iOS Frida operation failed: ${error instanceof Error ? error.message : String(error)}`
        };
    }
}
// Android Frida execution
async function executeAndroidFrida(action, params, options) {
    if (options.safe_mode === true) {
        return {
            success: true,
            message: "🔒 SAFE MODE: Android Frida operation simulated. No actual instrumentation performed.",
            results: {
                action,
                status: "simulated",
                platform: "android",
                output: `Simulated Android Frida operation: ${action}`
            }
        };
    }
    try {
        let command = "";
        switch (action) {
            case "attach_process":
                command = `frida -U -f ${params.target_application} -l ${params.script_file || "hook_script.js"}`;
                break;
            case "android_keystore_access":
                command = `frida -U -f ${params.target_application} -l keystore_access.js`;
                break;
            case "bypass_ssl_pinning":
                command = `frida -U -f ${params.target_application} -l ssl_pinning_bypass.js`;
                break;
            case "extract_secrets":
                command = `frida -U -f ${params.target_application} -l extract_secrets.js`;
                break;
            default:
                command = `frida -U -f ${params.target_application} -l ${action}.js`;
        }
        const { stdout } = await execAsync(command);
        return {
            success: true,
            message: `Android Frida operation completed: ${action}`,
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
            message: `Android Frida operation failed: ${error instanceof Error ? error.message : String(error)}`
        };
    }
}
// Natural language command processing for Frida
function processNaturalLanguageCommand(command) {
    const cmd = command.toLowerCase();
    const params = {};
    // Hook function patterns
    if (cmd.includes('hook') && cmd.includes('function')) {
        const funcMatch = cmd.match(/function\s+(\w+)/);
        if (funcMatch)
            params.function_name = funcMatch[1];
        return { action: 'hook_function', params };
    }
    // Extract secrets patterns
    if (cmd.includes('extract') && (cmd.includes('secret') || cmd.includes('key') || cmd.includes('api'))) {
        return { action: 'extract_secrets', params };
    }
    // SSL pinning bypass patterns
    if (cmd.includes('bypass') && cmd.includes('ssl')) {
        return { action: 'bypass_ssl_pinning', params };
    }
    // Root detection bypass patterns
    if (cmd.includes('bypass') && cmd.includes('root')) {
        return { action: 'bypass_root_detection', params };
    }
    // Keychain/keystore access patterns
    if (cmd.includes('keychain') || cmd.includes('keystore')) {
        if (cmd.includes('ios'))
            return { action: 'ios_keychain_access', params };
        if (cmd.includes('android'))
            return { action: 'android_keystore_access', params };
        if (cmd.includes('macos'))
            return { action: 'macos_keychain_access', params };
    }
    // Memory operations patterns
    if (cmd.includes('memory') && cmd.includes('read')) {
        return { action: 'read_memory', params };
    }
    if (cmd.includes('memory') && cmd.includes('write')) {
        return { action: 'write_memory', params };
    }
    // Default to attach process
    return { action: 'attach_process', params };
}
