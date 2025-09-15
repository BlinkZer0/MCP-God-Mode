import { spawn, exec } from "node:child_process";
import { promisify } from "node:util";
import { IS_WINDOWS, IS_LINUX, IS_MACOS, IS_ANDROID, IS_IOS } from "../config/environment.js";
const execAsync = promisify(exec);
// Tools that require elevated permissions by category
export const ELEVATED_TOOLS = {
    // System administration tools
    system: [
        "win_services", "win_processes", "system_monitor", "system_backup",
        "system_repair", "security_audit", "event_log_analyzer", "disk_management",
        "system_restore", "elevated_permissions_manager", "cron_job_manager"
    ],
    // Network and security tools
    security: [
        "wifi_security_toolkit", "wifi_hacking", "packet_sniffer",
        "bluetooth_security_toolkit", "bluetooth_hacking", "sdr_security_toolkit",
        "radio_security", "signal_analysis", "hack_network", "security_testing",
        "wireless_security", "network_penetration", "port_scanner", "vulnerability_scanner",
        "password_cracker", "exploit_framework", "network_security", "blockchain_security",
        "quantum_security", "iot_security", "threat_intelligence", "compliance_assessment",
        "social_network_ripper", "metadata_extractor", "siem_toolkit", "cloud_security_assessment",
        "api_security_testing", "email_security_suite", "database_security_toolkit",
        "hack_gpt", "hack_gpt_natural_language", "strix_ai", "strix_ai_natural_language",
        "pentest_plus_plus", "pentest_plus_plus_natural_language", "encryption_tool",
        "malware_analysis", "malware_analysis_toolkit", "advanced_security_assessment",
        "cross_platform_system_manager", "enterprise_integration_hub", "advanced_analytics_engine"
    ],
    // Penetration testing tools
    penetration: [
        "network_penetration", "penetration_testing_toolkit", "social_engineering_toolkit",
        "red_team_toolkit", "metasploit_framework", "cobalt_strike", "empire_powershell",
        "bloodhound_ad", "mimikatz_credentials", "mimikatz_enhanced", "hexstrike_ai",
        "hexstrike_ai_natural_language", "nmap_scanner", "frida_toolkit", "ghidra_reverse_engineering",
        "pacu_aws_exploitation", "exploit_framework", "zero_day_exploiter_unified"
    ],
    // Wireless and radio tools
    wireless: [
        "wireless_network_scanner", "wifi_disrupt", "cellular_triangulate"
    ],
    // Virtualization and container tools
    virtualization: [
        "vm_management", "docker_management"
    ],
    // Mobile system tools
    mobile: [
        "mobile_system_tools", "mobile_hardware", "mobile_device_management",
        "mobile_network_analyzer", "mobile_security_toolkit", "enhanced_mobile_app_toolkit",
        "mobile_app_unified"
    ],
    // File system operations that might need elevation
    filesystem: [
        "file_ops", "file_watcher" // For operations like chmod, chown, system file access
    ],
    // Process management tools
    process: [
        "proc_run_elevated", "proc_run_remote" // Tools that specifically need elevated execution
    ],
    // AI and advanced tools
    ai_tools: [
        "ai_adversarial_prompt", "ai_adversarial_nlp", "ai_adversarial_platform_info"
    ],
    // Advanced security operations
    advanced_security: [
        "advanced_threat_hunting", "cyber_deception_platform", "zero_trust_architect",
        "quantum_cryptography_suite", "ai_security_orchestrator", "blockchain_forensics",
        "supply_chain_security", "privacy_engineering", "incident_commander",
        "security_metrics_dashboard"
    ],
    // Specialized tools
    specialized: [
        "flipper_zero", "drone_unified", "rf_sense", "tool_burglar"
    ]
};
// Check if a tool requires elevated permissions
export function requiresElevation(toolName) {
    return Object.values(ELEVATED_TOOLS).flat().includes(toolName);
}
// Check if current process has elevated privileges
export async function hasElevatedPrivileges() {
    try {
        if (IS_WINDOWS) {
            // Check if running as administrator on Windows
            const { stdout } = await execAsync('net session', { timeout: 5000 });
            return !stdout.includes('Access is denied');
        }
        else if (IS_LINUX || IS_MACOS) {
            // Check if running as root on Unix-like systems
            return process.getuid?.() === 0;
        }
        else if (IS_ANDROID) {
            // Check if running as root on Android
            const { stdout } = await execAsync('id', { timeout: 5000 });
            return stdout.includes('uid=0');
        }
        else if (IS_IOS) {
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
export function getElevationCommand(command, args = []) {
    if (IS_WINDOWS) {
        // Windows: Use runas or PowerShell elevation
        return `powershell -Command "Start-Process -FilePath '${command}' -ArgumentList '${args.join(' ')}' -Verb RunAs -Wait"`;
    }
    else if (IS_LINUX || IS_MACOS) {
        // Unix-like: Use sudo
        return `sudo ${command} ${args.join(' ')}`;
    }
    else if (IS_ANDROID) {
        // Android: Use su if available
        return `su -c '${command} ${args.join(' ')}'`;
    }
    else if (IS_IOS) {
        // iOS: No elevation available
        return `${command} ${args.join(' ')}`;
    }
    return `${command} ${args.join(' ')}`;
}
// Execute command with elevated privileges
export async function executeElevated(command, args = [], cwd, timeout = 30000) {
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
        if (IS_WINDOWS) {
            // Windows: Use PowerShell elevation
            const { stdout, stderr } = await execAsync(elevatedCommand, {
                cwd,
                timeout,
                maxBuffer: 1024 * 1024
            });
            return { success: true, stdout, stderr, exitCode: 0 };
        }
        else if (IS_LINUX || IS_MACOS) {
            // Unix-like: Use sudo with proper error handling
            const { stdout, stderr } = await execAsync(elevatedCommand, {
                cwd,
                timeout,
                maxBuffer: 1024 * 1024
            });
            return { success: true, stdout, stderr, exitCode: 0 };
        }
        else if (IS_ANDROID) {
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
        else if (IS_IOS) {
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
export async function executeInteractiveElevated(command, args = [], cwd) {
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
        if (IS_WINDOWS) {
            // Windows: Use runas with interactive prompt
            return new Promise((resolve) => {
                const elevatedCommand = `runas /user:Administrator "${command} ${args.join(' ')}"`;
                const child = spawn('cmd', ['/c', elevatedCommand], {
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
        else if (IS_LINUX || IS_MACOS) {
            // Unix-like: Use sudo with interactive prompt
            return new Promise((resolve) => {
                const child = spawn('sudo', [command, ...args], {
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
export function isElevationAvailable() {
    if (IS_WINDOWS) {
        return true; // Windows has UAC
    }
    else if (IS_LINUX || IS_MACOS) {
        return true; // Unix-like systems have sudo
    }
    else if (IS_ANDROID) {
        return true; // Android can have root access
    }
    else if (IS_IOS) {
        return false; // iOS has no elevation
    }
    return false;
}
// Get elevation method description for current platform
export function getElevationMethod() {
    if (IS_WINDOWS) {
        return "User Account Control (UAC) - Administrator privileges";
    }
    else if (IS_LINUX) {
        return "sudo - Root privileges";
    }
    else if (IS_MACOS) {
        return "sudo - Administrator privileges";
    }
    else if (IS_ANDROID) {
        return "su - Root access (if available)";
    }
    else if (IS_IOS) {
        return "No elevation available - iOS security restrictions";
    }
    return "Unknown platform";
}
// Validate if a command can be elevated
export function canElevateCommand(command) {
    // Block dangerous commands from elevation
    const dangerousCommands = [
        'format', 'del', 'rmdir', 'shutdown', 'taskkill', 'rm', 'dd',
        'diskpart', 'reg', 'sc', 'wmic', 'powershell', 'cmd',
        'sudo', 'su', 'chmod', 'chown', 'mkfs', 'fdisk'
    ];
    return !dangerousCommands.some(cmd => command.toLowerCase().includes(cmd.toLowerCase()));
}
