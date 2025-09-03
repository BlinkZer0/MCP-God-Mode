"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ELEVATED_TOOLS = void 0;
exports.requiresElevation = requiresElevation;
exports.hasElevatedPrivileges = hasElevatedPrivileges;
exports.getElevationCommand = getElevationCommand;
exports.executeElevated = executeElevated;
exports.executeInteractiveElevated = executeInteractiveElevated;
exports.isElevationAvailable = isElevationAvailable;
exports.getElevationMethod = getElevationMethod;
exports.canElevateCommand = canElevateCommand;
const node_child_process_1 = require("node:child_process");
const node_util_1 = require("node:util");
const environment_js_1 = require("../config/environment.js");
const execAsync = (0, node_util_1.promisify)(node_child_process_1.exec);
// Tools that require elevated permissions by category
exports.ELEVATED_TOOLS = {
    // System administration tools
    system: [
        "win_services", "win_processes", "system_monitor", "system_backup",
        "system_repair", "security_audit", "event_log_analyzer", "disk_management"
    ],
    // Network and security tools
    security: [
        "wifi_security_toolkit", "wifi_hacking", "packet_sniffer",
        "bluetooth_security_toolkit", "bluetooth_hacking", "sdr_security_toolkit",
        "radio_security", "signal_analysis", "hack_network", "security_testing",
        "wireless_security", "network_penetration"
    ],
    // Virtualization and container tools
    virtualization: [
        "vm_management", "docker_management"
    ],
    // Mobile system tools
    mobile: [
        "mobile_system_tools", "mobile_hardware"
    ],
    // File system operations that might need elevation
    filesystem: [
        "file_ops" // For operations like chmod, chown, system file access
    ]
};
// Check if a tool requires elevated permissions
function requiresElevation(toolName) {
    return Object.values(exports.ELEVATED_TOOLS).flat().includes(toolName);
}
// Check if current process has elevated privileges
async function hasElevatedPrivileges() {
    try {
        if (environment_js_1.IS_WINDOWS) {
            // Check if running as administrator on Windows
            const { stdout } = await execAsync('net session', { timeout: 5000 });
            return !stdout.includes('Access is denied');
        }
        else if (environment_js_1.IS_LINUX || environment_js_1.IS_MACOS) {
            // Check if running as root on Unix-like systems
            return process.getuid?.() === 0;
        }
        else if (environment_js_1.IS_ANDROID) {
            // Check if running as root on Android
            const { stdout } = await execAsync('id', { timeout: 5000 });
            return stdout.includes('uid=0');
        }
        else if (environment_js_1.IS_IOS) {
            // iOS has very limited elevated access
            return false;
        }
        return false;
    }
    catch {
        return false;
    }
}
// Get platform-specific elevation command
function getElevationCommand(command, args = []) {
    if (environment_js_1.IS_WINDOWS) {
        // Windows: Use runas or PowerShell elevation
        return `powershell -Command "Start-Process -FilePath '${command}' -ArgumentList '${args.join(' ')}' -Verb RunAs -Wait"`;
    }
    else if (environment_js_1.IS_LINUX || environment_js_1.IS_MACOS) {
        // Unix-like: Use sudo
        return `sudo ${command} ${args.join(' ')}`;
    }
    else if (environment_js_1.IS_ANDROID) {
        // Android: Use su if available
        return `su -c '${command} ${args.join(' ')}'`;
    }
    else if (environment_js_1.IS_IOS) {
        // iOS: No elevation available
        return `${command} ${args.join(' ')}`;
    }
    return `${command} ${args.join(' ')}`;
}
// Execute command with elevated privileges
async function executeElevated(command, args = [], cwd, timeout = 30000) {
    try {
        // Check if we already have elevated privileges
        const isElevated = await hasElevatedPrivileges();
        if (isElevated) {
            // Already elevated, run command directly
            const { stdout, stderr } = await execAsync(`${command} ${args.join(' ')}`, {
                cwd,
                timeout,
                maxBuffer: 1024 * 1024 // 1MB buffer
            });
            return { success: true, stdout, stderr, exitCode: 0 };
        }
        // Need to elevate - use platform-specific method
        const elevatedCommand = getElevationCommand(command, args);
        if (environment_js_1.IS_WINDOWS) {
            // Windows: Use PowerShell elevation
            const { stdout, stderr } = await execAsync(elevatedCommand, {
                cwd,
                timeout,
                maxBuffer: 1024 * 1024
            });
            return { success: true, stdout, stderr, exitCode: 0 };
        }
        else if (environment_js_1.IS_LINUX || environment_js_1.IS_MACOS) {
            // Unix-like: Use sudo with proper error handling
            const { stdout, stderr } = await execAsync(elevatedCommand, {
                cwd,
                timeout,
                maxBuffer: 1024 * 1024
            });
            return { success: true, stdout, stderr, exitCode: 0 };
        }
        else if (environment_js_1.IS_ANDROID) {
            // Android: Try su command
            try {
                const { stdout, stderr } = await execAsync(elevatedCommand, {
                    cwd,
                    timeout,
                    maxBuffer: 1024 * 1024
                });
                return { success: true, stdout, stderr, exitCode: 0 };
            }
            catch (error) {
                // Fallback to non-elevated execution
                const { stdout, stderr } = await execAsync(`${command} ${args.join(' ')}`, {
                    cwd,
                    timeout,
                    maxBuffer: 1024 * 1024
                });
                return { success: true, stdout, stderr, exitCode: 0 };
            }
        }
        else if (environment_js_1.IS_IOS) {
            // iOS: No elevation available, run normally
            const { stdout, stderr } = await execAsync(`${command} ${args.join(' ')}`, {
                cwd,
                timeout,
                maxBuffer: 1024 * 1024
            });
            return { success: true, stdout, stderr, exitCode: 0 };
        }
        // Fallback to normal execution
        const { stdout, stderr } = await execAsync(`${command} ${args.join(' ')}`, {
            cwd,
            timeout,
            maxBuffer: 1024 * 1024
        });
        return { success: true, stdout, stderr, exitCode: 0 };
    }
    catch (error) {
        const errorMessage = error?.message || String(error);
        const stdout = error?.stdout || undefined;
        const stderr = error?.stderr || undefined;
        const exitCode = error?.code || -1;
        return {
            success: false,
            stdout,
            stderr,
            exitCode,
            error: errorMessage
        };
    }
}
// Execute command with interactive elevation prompt
async function executeInteractiveElevated(command, args = [], cwd) {
    try {
        // Check if we already have elevated privileges
        const isElevated = await hasElevatedPrivileges();
        if (isElevated) {
            // Already elevated, run command directly
            const { stdout, stderr } = await execAsync(`${command} ${args.join(' ')}`, {
                cwd,
                maxBuffer: 1024 * 1024
            });
            return { success: true, stdout, stderr, exitCode: 0 };
        }
        // Need to elevate - use interactive method
        if (environment_js_1.IS_WINDOWS) {
            // Windows: Use runas with interactive prompt
            return new Promise((resolve) => {
                const elevatedCommand = `runas /user:Administrator "${command} ${args.join(' ')}"`;
                const child = (0, node_child_process_1.spawn)('cmd', ['/c', elevatedCommand], {
                    cwd,
                    stdio: ['pipe', 'pipe', 'pipe']
                });
                let stdout = '';
                let stderr = '';
                child.stdout?.on('data', (data) => {
                    stdout += data.toString();
                });
                child.stderr?.on('data', (data) => {
                    stderr += data.toString();
                });
                child.on('close', (code) => {
                    resolve({
                        success: code === 0,
                        stdout,
                        stderr,
                        exitCode: code || 0
                    });
                });
                child.on('error', (error) => {
                    resolve({
                        success: false,
                        error: error.message
                    });
                });
            });
        }
        else if (environment_js_1.IS_LINUX || environment_js_1.IS_MACOS) {
            // Unix-like: Use sudo with interactive prompt
            return new Promise((resolve) => {
                const child = (0, node_child_process_1.spawn)('sudo', [command, ...args], {
                    cwd,
                    stdio: ['pipe', 'pipe', 'pipe']
                });
                let stdout = '';
                let stderr = '';
                child.stdout?.on('data', (data) => {
                    stdout += data.toString();
                });
                child.stderr?.on('data', (data) => {
                    stderr += data.toString();
                });
                child.on('close', (code) => {
                    resolve({
                        success: code === 0,
                        stdout,
                        stderr,
                        exitCode: code || 0
                    });
                });
                child.on('error', (error) => {
                    resolve({
                        success: false,
                        error: error.message
                    });
                });
            });
        }
        else {
            // Other platforms: fallback to non-interactive
            return executeElevated(command, args, cwd);
        }
    }
    catch (error) {
        return {
            success: false,
            error: error?.message || String(error)
        };
    }
}
// Check if elevation is available on current platform
function isElevationAvailable() {
    if (environment_js_1.IS_WINDOWS) {
        return true; // Windows has UAC
    }
    else if (environment_js_1.IS_LINUX || environment_js_1.IS_MACOS) {
        return true; // Unix-like systems have sudo
    }
    else if (environment_js_1.IS_ANDROID) {
        return true; // Android can have root access
    }
    else if (environment_js_1.IS_IOS) {
        return false; // iOS has no elevation
    }
    return false;
}
// Get elevation method description for current platform
function getElevationMethod() {
    if (environment_js_1.IS_WINDOWS) {
        return "User Account Control (UAC) - Administrator privileges";
    }
    else if (environment_js_1.IS_LINUX) {
        return "sudo - Root privileges";
    }
    else if (environment_js_1.IS_MACOS) {
        return "sudo - Administrator privileges";
    }
    else if (environment_js_1.IS_ANDROID) {
        return "su - Root access (if available)";
    }
    else if (environment_js_1.IS_IOS) {
        return "No elevation available - iOS security restrictions";
    }
    return "Unknown platform";
}
// Validate if a command can be elevated
function canElevateCommand(command) {
    // Block dangerous commands from elevation
    const dangerousCommands = [
        'format', 'del', 'rmdir', 'shutdown', 'taskkill', 'rm', 'dd',
        'diskpart', 'reg', 'sc', 'wmic', 'powershell', 'cmd',
        'sudo', 'su', 'chmod', 'chown', 'mkfs', 'fdisk'
    ];
    return !dangerousCommands.some(cmd => command.toLowerCase().includes(cmd.toLowerCase()));
}
