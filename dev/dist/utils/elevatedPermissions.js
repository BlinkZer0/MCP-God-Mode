import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
// Use process.cwd() instead of import.meta.url for better compatibility
const CONFIG_FILE = join(process.cwd(), 'config', 'elevated_permissions.json');
// Default configuration
const DEFAULT_CONFIG = {
    globalElevatedMode: false,
    allowedTools: [
        'proc_run_elevated',
        'win_services',
        'win_processes',
        'system_restore',
        'vm_management',
        'docker_management',
        'mobile_system_tools',
        'mobile_hardware',
        'wifi_security_toolkit',
        'wifi_hacking',
        'bluetooth_security_toolkit',
        'bluetooth_hacking',
        'sdr_security_toolkit',
        'radio_security',
        'signal_analysis',
        'packet_sniffer',
        'port_scanner',
        'vulnerability_scanner',
        'password_cracker',
        'exploit_framework',
        'hack_network',
        'security_testing',
        'network_penetration',
        'flipper_zero',
        'file_ops',
        'fs_write_text',
        'fs_read_text',
        'fs_list',
        'fs_search'
    ],
    dangerousCommands: [
        'rm', 'del', 'format', 'fdisk', 'mkfs', 'dd', 'shred',
        'chmod', 'chown', 'chattr', 'mount', 'umount',
        'systemctl', 'service', 'sc', 'net stop', 'net start',
        'taskkill', 'tasklist', 'wmic', 'powershell'
    ],
    safeMode: true,
    requireConfirmation: true
};
export class ElevatedPermissionsManager {
    static instance;
    config;
    constructor() {
        this.config = this.loadConfig();
    }
    static getInstance() {
        if (!ElevatedPermissionsManager.instance) {
            ElevatedPermissionsManager.instance = new ElevatedPermissionsManager();
        }
        return ElevatedPermissionsManager.instance;
    }
    loadConfig() {
        try {
            if (existsSync(CONFIG_FILE)) {
                const configData = readFileSync(CONFIG_FILE, 'utf8');
                return { ...DEFAULT_CONFIG, ...JSON.parse(configData) };
            }
        }
        catch (error) {
            console.warn('Failed to load elevated permissions config, using defaults:', error);
        }
        // Create default config file
        this.saveConfig(DEFAULT_CONFIG);
        return DEFAULT_CONFIG;
    }
    saveConfig(config) {
        try {
            const configDir = dirname(CONFIG_FILE);
            if (!existsSync(configDir)) {
                // Create config directory if it doesn't exist
                mkdirSync(configDir, { recursive: true });
            }
            writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf8');
        }
        catch (error) {
            console.error('Failed to save elevated permissions config:', error);
        }
    }
    getConfig() {
        return { ...this.config };
    }
    updateConfig(updates) {
        this.config = { ...this.config, ...updates };
        this.saveConfig(this.config);
    }
    isGlobalElevatedMode() {
        return this.config.globalElevatedMode;
    }
    isToolAllowed(toolName) {
        return this.config.allowedTools.includes(toolName);
    }
    isCommandDangerous(command) {
        const lowerCommand = command.toLowerCase();
        return this.config.dangerousCommands.some(dangerous => lowerCommand.includes(dangerous.toLowerCase()));
    }
    isSafeMode() {
        return this.config.safeMode;
    }
    requiresConfirmation() {
        return this.config.requireConfirmation;
    }
    enableGlobalElevatedMode() {
        this.updateConfig({ globalElevatedMode: true });
    }
    disableGlobalElevatedMode() {
        this.updateConfig({ globalElevatedMode: false });
    }
    addAllowedTool(toolName) {
        if (!this.config.allowedTools.includes(toolName)) {
            this.config.allowedTools.push(toolName);
            this.saveConfig(this.config);
        }
    }
    removeAllowedTool(toolName) {
        this.config.allowedTools = this.config.allowedTools.filter(tool => tool !== toolName);
        this.saveConfig(this.config);
    }
    addDangerousCommand(command) {
        if (!this.config.dangerousCommands.includes(command)) {
            this.config.dangerousCommands.push(command);
            this.saveConfig(this.config);
        }
    }
    removeDangerousCommand(command) {
        this.config.dangerousCommands = this.config.dangerousCommands.filter(cmd => cmd !== command);
        this.saveConfig(this.config);
    }
    canExecuteElevated(toolName, command) {
        // Check if global elevated mode is enabled
        if (this.config.globalElevatedMode) {
            return true;
        }
        // Check if the specific tool is allowed
        if (!this.isToolAllowed(toolName)) {
            return false;
        }
        // If safe mode is enabled, block dangerous commands
        if (this.config.safeMode && command && this.isCommandDangerous(command)) {
            return false;
        }
        return true;
    }
    getElevationMethod() {
        if (process.platform === 'win32') {
            return 'runas'; // Windows UAC
        }
        else if (process.platform === 'darwin') {
            return 'sudo'; // macOS
        }
        else {
            return 'sudo'; // Linux/Unix
        }
    }
    getElevationPrompt() {
        const method = this.getElevationMethod();
        switch (method) {
            case 'runas':
                return 'This operation requires administrator privileges. Please confirm in the UAC dialog.';
            case 'sudo':
                return 'This operation requires elevated privileges. You may be prompted for your password.';
            default:
                return 'This operation requires elevated privileges.';
        }
    }
}
// Export singleton instance
export const elevatedPermissionsManager = ElevatedPermissionsManager.getInstance();
// Helper functions for easy access
export function isElevatedModeEnabled() {
    return elevatedPermissionsManager.isGlobalElevatedMode();
}
export function canExecuteElevated(toolName, command) {
    return elevatedPermissionsManager.canExecuteElevated(toolName, command);
}
export function getElevationMethod() {
    return elevatedPermissionsManager.getElevationMethod();
}
export function getElevationPrompt() {
    return elevatedPermissionsManager.getElevationPrompt();
}
