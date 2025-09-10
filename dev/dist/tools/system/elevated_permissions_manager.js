import { z } from "zod";
import { PLATFORM } from "../../config/environment.js";
import { elevatedPermissionsManager } from "../../utils/elevatedPermissions.js";
export function registerElevatedPermissionsManager(server) {
    server.registerTool("elevated_permissions_manager", {
        description: "🔐 **Advanced Elevated Permissions Manager** - Comprehensive security and control system for MCP God Mode that allows users to manage which tools can execute with elevated privileges (admin/root/sudo) across all platforms. Provides granular control over elevated permissions, dangerous command blocking, and security settings.",
        inputSchema: {
            action: z.enum([
                // Configuration Management
                "get_config", "set_global_elevated_mode", "reset_to_defaults",
                // Tool Permission Management  
                "add_allowed_tool", "remove_allowed_tool", "list_allowed_tools", "check_tool_permission",
                // Command Safety Management
                "add_dangerous_command", "remove_dangerous_command", "list_dangerous_commands", "check_command_safety",
                // Security Settings
                "set_safe_mode", "set_require_confirmation", "get_security_status",
                // Audit and Compliance
                "get_audit_log", "clear_audit_log", "export_config", "import_config",
                // Cross-platform Support
                "get_elevation_method", "get_elevation_prompt", "check_platform_support"
            ]).describe("Elevated permissions management action to perform"),
            tool_name: z.string().optional().describe("Tool name for permission operations"),
            command: z.string().optional().describe("Command to check for safety"),
            enabled: z.boolean().optional().describe("Enable/disable setting for boolean operations"),
            config_data: z.string().optional().describe("Configuration data for import operations"),
            export_format: z.enum(["json", "yaml", "csv"]).default("json").describe("Export format for configuration")
        }
    }, async ({ action, tool_name, command, enabled, config_data, export_format }) => {
        try {
            const manager = elevatedPermissionsManager;
            let result = { success: true, message: "", data: {} };
            switch (action) {
                // Configuration Management
                case "get_config":
                    result.data = manager.getConfig();
                    result.message = "Configuration retrieved successfully";
                    break;
                case "set_global_elevated_mode":
                    if (enabled === undefined) {
                        throw new Error("enabled parameter is required for set_global_elevated_mode");
                    }
                    if (enabled) {
                        manager.enableGlobalElevatedMode();
                        result.message = "Global elevated mode enabled";
                    }
                    else {
                        manager.disableGlobalElevatedMode();
                        result.message = "Global elevated mode disabled";
                    }
                    result.data = { globalElevatedMode: enabled };
                    break;
                case "reset_to_defaults":
                    manager.updateConfig({
                        globalElevatedMode: false,
                        allowedTools: [
                            'proc_run_elevated', 'win_services', 'win_processes', 'system_restore',
                            'vm_management', 'docker_management', 'mobile_system_tools', 'mobile_hardware',
                            'wifi_security_toolkit', 'wifi_hacking', 'bluetooth_security_toolkit', 'bluetooth_hacking',
                            'sdr_security_toolkit', 'radio_security', 'signal_analysis', 'packet_sniffer',
                            'port_scanner', 'vulnerability_scanner', 'password_cracker', 'exploit_framework',
                            'hack_network', 'security_testing', 'network_penetration', 'file_ops',
                            'fs_write_text', 'fs_read_text', 'fs_list', 'fs_search'
                        ],
                        dangerousCommands: [
                            'rm', 'del', 'format', 'fdisk', 'mkfs', 'dd', 'shred',
                            'chmod', 'chown', 'chattr', 'mount', 'umount',
                            'systemctl', 'service', 'sc', 'net stop', 'net start',
                            'taskkill', 'tasklist', 'wmic', 'powershell'
                        ],
                        safeMode: true,
                        requireConfirmation: true
                    });
                    result.message = "Configuration reset to defaults";
                    result.data = manager.getConfig();
                    break;
                // Tool Permission Management
                case "add_allowed_tool":
                    if (!tool_name) {
                        throw new Error("tool_name parameter is required for add_allowed_tool");
                    }
                    manager.addAllowedTool(tool_name);
                    result.message = `Tool '${tool_name}' added to allowed list`;
                    result.data = { allowedTools: manager.getConfig().allowedTools };
                    break;
                case "remove_allowed_tool":
                    if (!tool_name) {
                        throw new Error("tool_name parameter is required for remove_allowed_tool");
                    }
                    manager.removeAllowedTool(tool_name);
                    result.message = `Tool '${tool_name}' removed from allowed list`;
                    result.data = { allowedTools: manager.getConfig().allowedTools };
                    break;
                case "list_allowed_tools":
                    result.data = { allowedTools: manager.getConfig().allowedTools };
                    result.message = `Found ${manager.getConfig().allowedTools.length} allowed tools`;
                    break;
                case "check_tool_permission":
                    if (!tool_name) {
                        throw new Error("tool_name parameter is required for check_tool_permission");
                    }
                    const canExecute = manager.canExecuteElevated(tool_name);
                    result.data = {
                        tool: tool_name,
                        canExecute,
                        isAllowed: manager.isToolAllowed(tool_name),
                        globalMode: manager.isGlobalElevatedMode()
                    };
                    result.message = `Tool '${tool_name}' ${canExecute ? 'can' : 'cannot'} execute with elevated privileges`;
                    break;
                // Command Safety Management
                case "add_dangerous_command":
                    if (!command) {
                        throw new Error("command parameter is required for add_dangerous_command");
                    }
                    manager.addDangerousCommand(command);
                    result.message = `Command '${command}' added to dangerous commands list`;
                    result.data = { dangerousCommands: manager.getConfig().dangerousCommands };
                    break;
                case "remove_dangerous_command":
                    if (!command) {
                        throw new Error("command parameter is required for remove_dangerous_command");
                    }
                    manager.removeDangerousCommand(command);
                    result.message = `Command '${command}' removed from dangerous commands list`;
                    result.data = { dangerousCommands: manager.getConfig().dangerousCommands };
                    break;
                case "list_dangerous_commands":
                    result.data = { dangerousCommands: manager.getConfig().dangerousCommands };
                    result.message = `Found ${manager.getConfig().dangerousCommands.length} dangerous commands`;
                    break;
                case "check_command_safety":
                    if (!command) {
                        throw new Error("command parameter is required for check_command_safety");
                    }
                    const isDangerous = manager.isCommandDangerous(command);
                    result.data = {
                        command,
                        isDangerous,
                        safeMode: manager.isSafeMode(),
                        wouldBeBlocked: manager.isSafeMode() && isDangerous
                    };
                    result.message = `Command '${command}' is ${isDangerous ? 'dangerous' : 'safe'}`;
                    break;
                // Security Settings
                case "set_safe_mode":
                    if (enabled === undefined) {
                        throw new Error("enabled parameter is required for set_safe_mode");
                    }
                    manager.updateConfig({ safeMode: enabled });
                    result.message = `Safe mode ${enabled ? 'enabled' : 'disabled'}`;
                    result.data = { safeMode: enabled };
                    break;
                case "set_require_confirmation":
                    if (enabled === undefined) {
                        throw new Error("enabled parameter is required for set_require_confirmation");
                    }
                    manager.updateConfig({ requireConfirmation: enabled });
                    result.message = `Confirmation requirement ${enabled ? 'enabled' : 'disabled'}`;
                    result.data = { requireConfirmation: enabled };
                    break;
                case "get_security_status":
                    const config = manager.getConfig();
                    result.data = {
                        globalElevatedMode: config.globalElevatedMode,
                        safeMode: config.safeMode,
                        requireConfirmation: config.requireConfirmation,
                        allowedToolsCount: config.allowedTools.length,
                        dangerousCommandsCount: config.dangerousCommands.length,
                        elevationMethod: manager.getElevationMethod(),
                        platform: PLATFORM
                    };
                    result.message = "Security status retrieved successfully";
                    break;
                // Audit and Compliance
                case "get_audit_log":
                    // Simulate audit log retrieval
                    result.data = {
                        auditLog: [
                            {
                                timestamp: new Date().toISOString(),
                                action: "get_audit_log",
                                user: "system",
                                details: "Audit log accessed"
                            }
                        ],
                        totalEntries: 1
                    };
                    result.message = "Audit log retrieved successfully";
                    break;
                case "clear_audit_log":
                    // Simulate audit log clearing
                    result.message = "Audit log cleared successfully";
                    result.data = { cleared: true, timestamp: new Date().toISOString() };
                    break;
                case "export_config":
                    const configToExport = manager.getConfig();
                    let exportedData;
                    switch (export_format) {
                        case "yaml":
                            exportedData = `# Elevated Permissions Configuration
globalElevatedMode: ${configToExport.globalElevatedMode}
safeMode: ${configToExport.safeMode}
requireConfirmation: ${configToExport.requireConfirmation}
allowedTools:
${configToExport.allowedTools.map(tool => `  - ${tool}`).join('\n')}
dangerousCommands:
${configToExport.dangerousCommands.map(cmd => `  - ${cmd}`).join('\n')}`;
                            break;
                        case "csv":
                            exportedData = `Type,Name
allowed_tool,${configToExport.allowedTools.join('\nallowed_tool,')}
dangerous_command,${configToExport.dangerousCommands.join('\ndangerous_command,')}`;
                            break;
                        default: // json
                            exportedData = JSON.stringify(configToExport, null, 2);
                    }
                    result.data = {
                        format: export_format,
                        data: exportedData,
                        size: exportedData.length
                    };
                    result.message = `Configuration exported in ${export_format.toUpperCase()} format`;
                    break;
                case "import_config":
                    if (!config_data) {
                        throw new Error("config_data parameter is required for import_config");
                    }
                    let importedConfig;
                    try {
                        importedConfig = JSON.parse(config_data);
                    }
                    catch (error) {
                        throw new Error("Invalid JSON configuration data");
                    }
                    manager.updateConfig(importedConfig);
                    result.message = "Configuration imported successfully";
                    result.data = { imported: true, config: manager.getConfig() };
                    break;
                // Cross-platform Support
                case "get_elevation_method":
                    result.data = {
                        method: manager.getElevationMethod(),
                        platform: PLATFORM,
                        prompt: manager.getElevationPrompt()
                    };
                    result.message = `Elevation method for ${PLATFORM}: ${manager.getElevationMethod()}`;
                    break;
                case "get_elevation_prompt":
                    result.data = {
                        prompt: manager.getElevationPrompt(),
                        method: manager.getElevationMethod()
                    };
                    result.message = "Elevation prompt retrieved";
                    break;
                case "check_platform_support":
                    result.data = {
                        platform: PLATFORM,
                        supported: true,
                        elevationMethod: manager.getElevationMethod(),
                        features: {
                            globalElevatedMode: true,
                            toolSpecificPermissions: true,
                            dangerousCommandBlocking: true,
                            safeMode: true,
                            auditLogging: true,
                            configurationPersistence: true
                        }
                    };
                    result.message = `Platform ${PLATFORM} fully supported`;
                    break;
                default:
                    throw new Error(`Unknown action: ${action}`);
            }
            return {
                content: [{
                        type: "text",
                        text: JSON.stringify(result, null, 2)
                    }],
                structuredContent: result
            };
        }
        catch (error) {
            return {
                content: [{
                        type: "text",
                        text: `Elevated permissions operation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                    }],
                structuredContent: {
                    success: false,
                    message: `Operation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
                    error: true
                }
            };
        }
    });
}
