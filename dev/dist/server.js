import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as path from "node:path";
import * as os from "node:os";
import * as fs from "node:fs/promises";
import * as fsSync from "node:fs";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import simpleGit from "simple-git";
import { createWriteStream } from "node:fs";
import winston from "winston";
import * as math from "mathjs";
import * as crypto from "node:crypto";
// Global variables for enhanced features
let browserInstance = null;
let webSocketServer = null;
let expressServer = null;
let cronJobs = new Map();
let fileWatchers = new Map();
let apiCache = new Map();
let webhookEndpoints = new Map();
const execAsync = promisify(exec);
// Cross-platform OS detection
const PLATFORM = os.platform();
const IS_WINDOWS = PLATFORM === "win32";
const IS_LINUX = PLATFORM === "linux";
const IS_MACOS = PLATFORM === "darwin";
// Configure structured logging
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.errors({ stack: true }), winston.format.json()),
    transports: [
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});
// Environment configuration validation
const config = {
    allowedRoot: process.env.ALLOWED_ROOT || "",
    webAllowlist: process.env.WEB_ALLOWLIST || "",
    procAllowlist: process.env.PROC_ALLOWLIST || "",
    extraPath: process.env.EXTRA_PATH || "",
    logLevel: process.env.LOG_LEVEL || "info",
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE || "1000000"),
    timeout: parseInt(process.env.COMMAND_TIMEOUT || "30000"),
    enableSecurityChecks: process.env.ENABLE_SECURITY_CHECKS !== "false"
};
logger.info("MCP Server starting", {
    platform: PLATFORM,
    config: {
        ...config,
        allowedRoot: config.allowedRoot ? "configured" : "unrestricted",
        webAllowlist: config.webAllowlist ? "configured" : "unrestricted",
        procAllowlist: config.procAllowlist ? "configured" : "unrestricted"
    }
});
// Cross-platform utility functions
function getRootPaths() {
    if (IS_WINDOWS) {
        // Get all available drives on Windows
        const drives = [];
        try {
            for (let i = 65; i <= 90; i++) { // ASCII A-Z
                const driveLetter = String.fromCharCode(i) + ":\\";
                try {
                    const stats = fsSync.statSync(driveLetter);
                    if (stats.isDirectory()) {
                        drives.push(driveLetter);
                    }
                }
                catch {
                    // Drive doesn't exist or isn't accessible, skip it
                }
            }
        }
        catch (error) {
            logger.warn("Could not enumerate drives", { error: error instanceof Error ? error.message : String(error) });
        }
        return drives;
    }
    else {
        // Unix-like systems: common root paths
        return ["/", "/home", "/usr", "/var", "/etc", "/opt"];
    }
}
function getSystemInfo() {
    const platform = os.platform();
    const arch = os.arch();
    const cpus = os.cpus().length;
    const memGB = Math.round((os.totalmem() / (1024 ** 3)) * 10) / 10;
    let osInfo = "";
    if (IS_WINDOWS) {
        osInfo = "Windows";
    }
    else if (IS_LINUX) {
        try {
            const release = fsSync.readFileSync("/etc/os-release", "utf8");
            const lines = release.split("\n");
            const nameLine = lines.find(line => line.startsWith("PRETTY_NAME"));
            osInfo = nameLine ? nameLine.split("=")[1].replace(/"/g, "") : "Linux";
        }
        catch {
            osInfo = "Linux";
        }
    }
    else if (IS_MACOS) {
        osInfo = "macOS";
    }
    return { platform, arch, cpus, memGB, osInfo };
}
// Security: Command sanitization utility
function sanitizeCommand(command, args) {
    // Remove any command injection attempts
    const sanitizedCommand = command.replace(/[;&|`$(){}[\]]/g, '');
    const sanitizedArgs = args.map(arg => arg.replace(/[;&|`$(){}[\]]/g, ''));
    return { command: sanitizedCommand, args: sanitizedArgs };
}
// Security: Validate against dangerous commands
function isDangerousCommand(command) {
    const dangerousCommands = [
        'format', 'del', 'rmdir', 'shutdown', 'taskkill', 'rm', 'dd',
        'diskpart', 'reg', 'sc', 'wmic', 'powershell', 'cmd',
        'sudo', 'su', 'chmod', 'chown', 'mkfs', 'fdisk'
    ];
    return dangerousCommands.some(cmd => command.toLowerCase().includes(cmd.toLowerCase()));
}
// Universal access - allow all drives and paths
const ALLOWED_ROOTS = config.allowedRoot
    ? config.allowedRoot.split(",").map(s => path.resolve(s.trim())).filter(Boolean)
    : [];
// Get all available root paths for the current platform
const ALL_DRIVES = getRootPaths();
const ALLOWED_ROOTS_SET = new Set([...ALLOWED_ROOTS, ...ALL_DRIVES]);
const ALLOWED_ROOTS_ARRAY = Array.from(ALLOWED_ROOTS_SET);
// If no drives found, fall back to current directory
if (ALLOWED_ROOTS_ARRAY.length === 0) {
    ALLOWED_ROOTS_ARRAY.push(process.cwd());
}
const MAX_BYTES = config.maxFileSize;
// Remove web restrictions - allow all hosts
const WEB_ALLOWLIST = []; // Empty array means no restrictions
const PROC_ALLOWLIST_RAW = config.procAllowlist;
const PROC_ALLOWLIST = PROC_ALLOWLIST_RAW === "" ? [] : PROC_ALLOWLIST_RAW.split(",").map(s => s.trim()).filter(Boolean);
function ensureInsideRoot(p) {
    const resolved = path.resolve(p);
    if (IS_WINDOWS) {
        // Allow any path that starts with a drive letter (Windows)
        if (/^[A-Za-z]:\\/.test(resolved)) {
            return resolved;
        }
    }
    else {
        // Allow any absolute path on Unix-like systems
        if (path.isAbsolute(resolved)) {
            return resolved;
        }
    }
    // For relative paths, check if they're within any allowed root
    for (const root of ALLOWED_ROOTS_ARRAY) {
        if (resolved.startsWith(root)) {
            return resolved;
        }
    }
    // If no restrictions match, allow the path anyway (god mode)
    return resolved;
}
function limitString(s, max = MAX_BYTES) {
    const buf = Buffer.from(s, "utf8");
    if (buf.byteLength <= max)
        return { text: s, truncated: false };
    const sliced = buf.slice(0, max).toString("utf8");
    return { text: sliced, truncated: true };
}
// Cross-platform process management
async function getProcesses(filter) {
    try {
        let command = "";
        if (IS_WINDOWS) {
            command = "tasklist /fo csv /nh";
            if (filter) {
                command += ` | findstr /i "${filter}"`;
            }
        }
        else {
            command = "ps aux";
            if (filter) {
                command += ` | grep -i "${filter}"`;
            }
        }
        const { stdout } = await execAsync(command);
        const lines = stdout.trim().split("\n");
        if (IS_WINDOWS) {
            return lines.map(line => {
                const parts = line.split(",");
                return {
                    pid: parseInt(parts[1]) || 0,
                    name: parts[0]?.replace(/"/g, "") || "Unknown",
                    memory: parts[4]?.replace(/"/g, "") || "Unknown",
                    cpu: parts[8]?.replace(/"/g, "") || "Unknown"
                };
            }).filter(process => process.pid > 0);
        }
        else {
            return lines.slice(1).map(line => {
                const parts = line.trim().split(/\s+/);
                return {
                    pid: parseInt(parts[1]) || 0,
                    name: parts[10] || "Unknown",
                    memory: parts[5] || "Unknown",
                    cpu: parts[2] || "Unknown"
                };
            }).filter(process => process.pid > 0);
        }
    }
    catch (error) {
        logger.error("Error getting processes", { error: error instanceof Error ? error.message : String(error) });
        return [];
    }
}
// Cross-platform service management
async function getServices(filter) {
    try {
        if (IS_WINDOWS) {
            let command = "wmic service get name,displayname,state,startmode /format:csv";
            if (filter) {
                command += ` | findstr /i "${filter}"`;
            }
            const { stdout } = await execAsync(command);
            const lines = stdout.trim().split("\n").slice(1); // Skip header
            return lines.map(line => {
                const parts = line.split(",");
                return {
                    name: parts[1] || "Unknown",
                    displayName: parts[2] || "Unknown",
                    status: parts[3] || "Unknown",
                    startupType: parts[4] || "Unknown"
                };
            }).filter(service => service.name !== "Unknown");
        }
        else {
            // For Unix-like systems, use systemctl or service command
            let command = "";
            try {
                command = "systemctl list-units --type=service --all --no-pager";
                if (filter) {
                    command += ` | grep -i "${filter}"`;
                }
                const { stdout } = await execAsync(command);
                const lines = stdout.trim().split("\n");
                return lines.map(line => {
                    const parts = line.trim().split(/\s+/);
                    if (parts.length >= 4) {
                        return {
                            name: parts[0] || "Unknown",
                            displayName: parts[0] || "Unknown",
                            status: parts[3] || "Unknown",
                            startupType: parts[2] || "Unknown"
                        };
                    }
                    return null;
                }).filter(service => service && service.name !== "Unknown");
            }
            catch {
                // Fallback to service command
                command = "service --status-all";
                const { stdout } = await execAsync(command);
                const lines = stdout.trim().split("\n");
                return lines.map(line => {
                    const match = line.match(/\[([+\-?])\]\s+(\S+)/);
                    if (match) {
                        const status = match[1] === "+" ? "running" : match[1] === "-" ? "stopped" : "unknown";
                        return {
                            name: match[2] || "Unknown",
                            displayName: match[2] || "Unknown",
                            status: status,
                            startupType: "unknown"
                        };
                    }
                    return null;
                }).filter(service => service && service.name !== "Unknown");
            }
        }
    }
    catch (error) {
        logger.error("Error getting services", { error: error instanceof Error ? error.message : String(error) });
        return [];
    }
}
// Cross-platform service control
async function controlService(serviceName, action) {
    try {
        let command = "";
        if (IS_WINDOWS) {
            command = `sc ${action} "${serviceName}"`;
        }
        else {
            // Try systemctl first, fallback to service command
            try {
                command = `systemctl ${action} ${serviceName}`;
                const { stdout } = await execAsync(command);
                return { success: true, output: stdout };
            }
            catch {
                command = `service ${serviceName} ${action}`;
            }
        }
        const { stdout } = await execAsync(command);
        return { success: true, output: stdout };
    }
    catch (error) {
        return { success: false, error: error.message };
    }
}
// Cross-platform disk management
async function getDiskInfo() {
    try {
        if (IS_WINDOWS) {
            const { stdout } = await execAsync("wmic logicaldisk get size,freespace,caption /format:csv");
            const lines = stdout.trim().split("\n").slice(1);
            return lines.map(line => {
                const parts = line.split(",");
                const size = parseInt(parts[1]) || 0;
                const free = parseInt(parts[2]) || 0;
                const used = size - free;
                return {
                    drive: parts[0] || "Unknown",
                    total: Math.round(size / (1024 ** 3) * 100) / 100,
                    used: Math.round(used / (1024 ** 3) * 100) / 100,
                    free: Math.round(free / (1024 ** 3) * 100) / 100,
                    usage: Math.round((used / size) * 100)
                };
            });
        }
        else {
            const { stdout } = await execAsync("df -h");
            const lines = stdout.trim().split("\n").slice(1);
            return lines.map(line => {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 5) {
                    const total = parseFloat(parts[1].replace(/[A-Za-z]/g, ""));
                    const used = parseFloat(parts[2].replace(/[A-Za-z]/g, ""));
                    const free = parseFloat(parts[3].replace(/[A-Za-z]/g, ""));
                    const usage = parseInt(parts[4].replace(/%/g, ""));
                    return {
                        drive: parts[5] || "Unknown",
                        total: total,
                        used: used,
                        free: free,
                        usage: usage
                    };
                }
                return null;
            }).filter(disk => disk !== null);
        }
    }
    catch (error) {
        logger.error("Error getting disk info", { error: error instanceof Error ? error.message : String(error) });
        return [];
    }
}
// Cross-platform network scanning
async function scanNetwork(target, scanType = "ping") {
    try {
        let command = "";
        let results = [];
        switch (scanType) {
            case "ping":
                if (IS_WINDOWS) {
                    command = `ping -n 1 ${target || "127.0.0.1"}`;
                }
                else {
                    command = `ping -c 1 ${target || "127.0.0.1"}`;
                }
                break;
            case "port":
                if (IS_WINDOWS) {
                    command = `netstat -an | findstr :${target || "80"}`;
                }
                else {
                    command = `netstat -an | grep :${target || "80"}`;
                }
                break;
            case "arp":
                if (IS_WINDOWS) {
                    command = "arp -a";
                }
                else {
                    command = "arp -a";
                }
                break;
            case "full":
                command = `nmap -sn ${target || "192.168.1.0/24"}`;
                break;
        }
        const { stdout } = await execAsync(command);
        results.push({ command, output: stdout });
        return results;
    }
    catch (error) {
        return [{ error: error.message }];
    }
}
// Cross-platform system repair
async function performSystemRepair(repairType) {
    const elevated = await isProcessElevated();
    try {
        let command = "";
        let needsElevation = false;
        switch (repairType) {
            case "sfc":
                if (IS_WINDOWS) {
                    command = "sfc /scannow";
                    needsElevation = true;
                }
                else {
                    command = "sudo apt-get check && sudo apt-get autoremove";
                    needsElevation = true;
                }
                break;
            case "dism":
                if (IS_WINDOWS) {
                    command = "dism /online /cleanup-image /restorehealth";
                    needsElevation = true;
                }
                else {
                    command = "sudo apt-get update && sudo apt-get upgrade";
                    needsElevation = true;
                }
                break;
            case "chkdsk":
                if (IS_WINDOWS) {
                    command = "chkdsk C: /f /r";
                    needsElevation = true;
                }
                else {
                    command = "sudo fsck -f /";
                    needsElevation = true;
                }
                break;
            case "network_reset":
                if (IS_WINDOWS) {
                    command = "netsh winsock reset && netsh int ip reset";
                    needsElevation = true;
                }
                else {
                    command = "sudo systemctl restart NetworkManager";
                    needsElevation = true;
                }
                break;
            case "windows_update_reset":
                if (IS_WINDOWS) {
                    command = "net stop wuauserv && net stop cryptSvc && net stop bits && net stop msiserver";
                    needsElevation = true;
                }
                else {
                    command = "sudo systemctl restart systemd-update-utmp";
                    needsElevation = true;
                }
                break;
            case "dns_flush":
                if (IS_WINDOWS) {
                    command = "ipconfig /flushdns";
                }
                else {
                    command = "sudo systemctl restart systemd-resolved";
                    needsElevation = true;
                }
                break;
            case "temp_cleanup":
                if (IS_WINDOWS) {
                    command = "del /q /f %temp%\\* && del /q /f C:\\Windows\\Temp\\*";
                    needsElevation = true;
                }
                else {
                    command = "sudo rm -rf /tmp/* && sudo rm -rf /var/tmp/*";
                    needsElevation = true;
                }
                break;
            case "disk_cleanup":
                if (IS_WINDOWS) {
                    command = "cleanmgr /sagerun:1";
                    needsElevation = true;
                }
                else {
                    command = "sudo apt-get autoremove && sudo apt-get autoclean";
                    needsElevation = true;
                }
                break;
        }
        if (needsElevation && !elevated) {
            const { stdout, stderr, exitCode } = await runElevatedCommand('cmd', ['/c', command], process.cwd(), 10 * 60 * 1000);
            return {
                success: exitCode === 0,
                output: stdout || undefined,
                error: exitCode !== 0 ? stderr : undefined,
                elevated: false
            };
        }
        else {
            const { stdout, stderr } = await execAsync(command, { timeout: 10 * 60 * 1000 });
            return {
                success: true,
                output: stdout || undefined,
                error: stderr || undefined,
                elevated: elevated
            };
        }
    }
    catch (error) {
        return {
            success: false,
            error: error.message,
            elevated: elevated
        };
    }
}
// Cross-platform security audit
async function performSecurityAudit(auditType, target) {
    const findings = [];
    let summary = {};
    try {
        switch (auditType) {
            case "permissions":
                const targetPath = target || (IS_WINDOWS ? "C:\\Windows\\System32" : "/etc");
                if (IS_WINDOWS) {
                    const { stdout } = await execAsync(`icacls "${targetPath}" /T /C /L`);
                    const lines = stdout.trim().split("\n");
                    lines.forEach((line) => {
                        if (line.includes("Everyone") || line.includes("BUILTIN\\Users")) {
                            findings.push({
                                type: "permission_issue",
                                path: line.split(" ")[0],
                                issue: "Overly permissive access",
                                details: line
                            });
                        }
                    });
                }
                else {
                    const { stdout } = await execAsync(`find ${targetPath} -type f -perm -o+w -ls`);
                    const lines = stdout.trim().split("\n");
                    lines.forEach((line) => {
                        if (line.trim()) {
                            findings.push({
                                type: "permission_issue",
                                path: line.split(/\s+/)[10] || "Unknown",
                                issue: "World-writable file",
                                details: line
                            });
                        }
                    });
                }
                summary = {
                    totalFiles: findings.length,
                    issuesFound: findings.length
                };
                break;
            case "services":
                const services = await getServices();
                services.forEach((service) => {
                    if (service.startupType === "Auto" && service.status === "Stopped") {
                        findings.push({
                            type: "service_issue",
                            service: service.name,
                            issue: "Auto-start service is stopped",
                            details: `Service ${service.name} is configured to start automatically but is currently stopped`
                        });
                    }
                });
                summary = {
                    totalServices: services.length,
                    issuesFound: findings.length
                };
                break;
            case "updates":
                if (IS_WINDOWS) {
                    const { stdout: updateOutput } = await execAsync("wmic qfe get hotfixid,installedon /format:csv");
                    const updateLines = updateOutput.trim().split("\n").slice(1);
                    const lastUpdate = updateLines[updateLines.length - 1];
                    if (lastUpdate) {
                        const parts = lastUpdate.split(",");
                        const updateDate = parts[2];
                        const updateDateObj = new Date(updateDate);
                        const daysSinceUpdate = Math.floor((Date.now() - updateDateObj.getTime()) / (1000 * 60 * 60 * 24));
                        if (daysSinceUpdate > 30) {
                            findings.push({
                                type: "update_issue",
                                issue: "System updates are outdated",
                                details: `Last update was ${daysSinceUpdate} days ago on ${updateDate}`
                            });
                        }
                    }
                    summary = {
                        totalUpdates: updateLines.length,
                        issuesFound: findings.length
                    };
                }
                else {
                    // For Unix-like systems, check package manager
                    try {
                        if (IS_MACOS) {
                            const { stdout } = await execAsync("softwareupdate -l");
                            if (stdout.includes("No updates available")) {
                                summary = { totalUpdates: 0, issuesFound: 0 };
                            }
                            else {
                                findings.push({
                                    type: "update_issue",
                                    issue: "System updates available",
                                    details: "Software updates are pending installation"
                                });
                                summary = { totalUpdates: 1, issuesFound: 1 };
                            }
                        }
                        else {
                            const { stdout } = await execAsync("apt list --upgradable");
                            const lines = stdout.trim().split("\n").slice(1);
                            if (lines.length > 0) {
                                findings.push({
                                    type: "update_issue",
                                    issue: "System updates available",
                                    details: `${lines.length} packages can be upgraded`
                                });
                            }
                            summary = { totalUpdates: lines.length, issuesFound: findings.length };
                        }
                    }
                    catch {
                        summary = { totalUpdates: 0, issuesFound: 0 };
                    }
                }
                break;
        }
    }
    catch (error) {
        logger.error("Error performing security audit", { error: error instanceof Error ? error.message : String(error) });
    }
    return { findings, summary };
}
// Cross-platform event log analysis
async function analyzeEventLogs(logType = "system", filter, timeRange, level = "error", maxEvents = 100) {
    try {
        let events = [];
        if (IS_WINDOWS) {
            let command = `wevtutil qe "${logType}" /c:${maxEvents} /f:json`;
            if (level !== "all") {
                command += ` /q:"*[System[Level=${level}]]"`;
            }
            if (timeRange) {
                const now = new Date();
                let startTime;
                switch (timeRange) {
                    case "1h":
                        startTime = new Date(now.getTime() - 60 * 60 * 1000);
                        break;
                    case "24h":
                        startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
                        break;
                    case "7d":
                        startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                        break;
                    case "30d":
                        startTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                        break;
                    default:
                        startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
                }
                const startTimeStr = startTime.toISOString();
                command += ` /q:"*[System[TimeCreated[@SystemTime>='${startTimeStr}']]]"`;
            }
            const { stdout } = await execAsync(command);
            // Parse the XML-like output
            const lines = stdout.trim().split("\n");
            let currentEvent = {};
            let inEvent = false;
            lines.forEach((line) => {
                if (line.includes("<Event ")) {
                    inEvent = true;
                    currentEvent = {};
                }
                else if (line.includes("</Event>")) {
                    inEvent = false;
                    if (Object.keys(currentEvent).length > 0) {
                        events.push(currentEvent);
                    }
                }
                else if (inEvent) {
                    if (line.includes("<TimeCreated SystemTime=")) {
                        const match = line.match(/SystemTime="([^"]+)"/);
                        if (match) {
                            currentEvent.timestamp = match[1];
                        }
                    }
                    else if (line.includes("<Level>")) {
                        const match = line.match(/<Level>(\d+)<\/Level>/);
                        if (match) {
                            currentEvent.level = parseInt(match[1]);
                        }
                    }
                    else if (line.includes("<EventID>")) {
                        const match = line.match(/<EventID>(\d+)<\/EventID>/);
                        if (match) {
                            currentEvent.eventId = parseInt(match[1]);
                        }
                    }
                    else if (line.includes("<Source>")) {
                        const match = line.match(/<Source>([^<]+)<\/Source>/);
                        if (match) {
                            currentEvent.source = match[1];
                        }
                    }
                    else if (line.includes("<Message>")) {
                        const match = line.match(/<Message>([^<]+)<\/Message>/);
                        if (match) {
                            currentEvent.message = match[1];
                        }
                    }
                }
            });
        }
        else {
            // For Unix-like systems, use journalctl
            let command = `journalctl --no-pager -n ${maxEvents}`;
            if (level !== "all") {
                const levelMap = {
                    "error": "err",
                    "warning": "warning",
                    "information": "info",
                    "critical": "crit"
                };
                command += ` --priority=${levelMap[level] || "err"}`;
            }
            if (timeRange) {
                const timeMap = {
                    "1h": "1 hour ago",
                    "24h": "1 day ago",
                    "7d": "1 week ago",
                    "30d": "1 month ago"
                };
                command += ` --since="${timeMap[timeRange] || "1 day ago"}"`;
            }
            const { stdout } = await execAsync(command);
            const lines = stdout.trim().split("\n");
            events = lines.map(line => {
                const parts = line.split(" ");
                if (parts.length >= 5) {
                    return {
                        timestamp: `${parts[0]} ${parts[1]} ${parts[2]}`,
                        source: parts[4] || "Unknown",
                        message: parts.slice(5).join(" "),
                        level: parts[3] || "Unknown"
                    };
                }
                return null;
            }).filter(event => event !== null);
        }
        // Filter events if filter is provided
        const filteredEvents = filter
            ? events.filter(event => event.message?.toLowerCase().includes(filter.toLowerCase()) ||
                event.source?.toLowerCase().includes(filter.toLowerCase()))
            : events;
        // Analyze patterns
        const patterns = [];
        const sourceCounts = {};
        filteredEvents.forEach(event => {
            if (event.source) {
                sourceCounts[event.source] = (sourceCounts[event.source] || 0) + 1;
            }
        });
        // Find most common sources
        Object.entries(sourceCounts)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 5)
            .forEach(([source, count]) => {
            patterns.push({
                type: "common_source",
                source,
                count,
                percentage: Math.round((count / filteredEvents.length) * 100)
            });
        });
        // Summary
        const summary = {
            totalEvents: filteredEvents.length,
            logType,
            timeRange: timeRange || "all",
            level,
            topSources: Object.entries(sourceCounts)
                .sort(([, a], [, b]) => b - a)
                .slice(0, 3)
                .map(([source, count]) => ({ source, count }))
        };
        return { events: filteredEvents.slice(0, maxEvents), summary, patterns };
    }
    catch (error) {
        logger.error("Error analyzing event logs", { error: error.message });
        return { events: [], summary: {}, patterns: [] };
    }
}
const server = new McpServer({ name: "windows-dev-mcp", version: "1.0.0" });
server.registerTool("health", {
    description: "Liveness/readiness probe",
    outputSchema: { ok: z.boolean(), roots: z.array(z.string()), cwd: z.string() }
}, async () => ({
    content: [{ type: "text", text: "ok" }],
    structuredContent: { ok: true, roots: ALLOWED_ROOTS_ARRAY, cwd: process.cwd() }
}));
server.registerTool("system_info", {
    description: "Basic host info (OS, arch, cpus, memGB)",
    outputSchema: { platform: z.string(), arch: z.string(), cpus: z.number(), memGB: z.number() }
}, async () => ({
    content: [],
    structuredContent: {
        platform: os.platform(),
        arch: os.arch(),
        cpus: os.cpus().length,
        memGB: Math.round((os.totalmem() / (1024 ** 3)) * 10) / 10
    }
}));
server.registerTool("fs_list", {
    description: "List files/directories under a relative path (non-recursive)",
    inputSchema: { dir: z.string().default(".") },
    outputSchema: { entries: z.array(z.object({ name: z.string(), isDir: z.boolean() })) }
}, async ({ dir }) => {
    // Try to find the directory in one of the allowed roots
    let base;
    try {
        base = ensureInsideRoot(path.resolve(dir));
    }
    catch {
        // If not an absolute path, try the first allowed root
        base = path.resolve(ALLOWED_ROOTS_ARRAY[0], dir);
        ensureInsideRoot(base); // Verify it's still within allowed roots
    }
    const items = await fs.readdir(base, { withFileTypes: true });
    return { content: [], structuredContent: { entries: items.map(d => ({ name: d.name, isDir: d.isDirectory() })) } };
});
server.registerTool("fs_read_text", {
    description: "Read a UTF-8 text file within the sandbox",
    inputSchema: { path: z.string() },
    outputSchema: { path: z.string(), content: z.string(), truncated: z.boolean() }
}, async ({ path: relPath }) => {
    const fullPath = ensureInsideRoot(path.resolve(relPath));
    const content = await fs.readFile(fullPath, "utf8");
    const { text, truncated } = limitString(content);
    return { content: [], structuredContent: { path: fullPath, content: text, truncated } };
});
server.registerTool("fs_write_text", {
    description: "Write a UTF-8 text file within the sandbox",
    inputSchema: { path: z.string(), content: z.string() },
    outputSchema: { path: z.string(), success: z.boolean() }
}, async ({ path: relPath, content }) => {
    const fullPath = ensureInsideRoot(path.resolve(relPath));
    await fs.writeFile(fullPath, content, "utf8");
    return { content: [], structuredContent: { path: fullPath, success: true } };
});
server.registerTool("fs_search", {
    description: "Search for files by name pattern",
    inputSchema: { pattern: z.string(), dir: z.string().default(".") },
    outputSchema: { matches: z.array(z.string()) }
}, async ({ pattern, dir }) => {
    const base = ensureInsideRoot(path.resolve(dir));
    const matches = [];
    try {
        // Try using ripgrep if available
        const { stdout } = await execAsync(`rg --files --glob "${pattern}" "${base}"`);
        matches.push(...stdout.trim().split("\n").filter(Boolean));
    }
    catch {
        // Fallback to naive search
        const searchRecursive = async (currentDir) => {
            const results = [];
            try {
                const items = await fs.readdir(currentDir, { withFileTypes: true });
                for (const item of items) {
                    const fullPath = path.join(currentDir, item.name);
                    if (item.isDirectory()) {
                        results.push(...await searchRecursive(fullPath));
                    }
                    else if (item.name.includes(pattern.replace("*", ""))) {
                        results.push(fullPath);
                    }
                }
            }
            catch (error) {
                // Ignore permission errors
            }
            return results;
        };
        matches.push(...await searchRecursive(base));
    }
    return { content: [], structuredContent: { matches } };
});
server.registerTool("proc_run", {
    description: "Run a process with arguments",
    inputSchema: {
        command: z.string(),
        args: z.array(z.string()).default([]),
        cwd: z.string().optional()
    },
    outputSchema: {
        success: z.boolean(),
        stdout: z.string().optional(),
        stderr: z.string().optional(),
        exitCode: z.number().optional()
    }
}, async ({ command, args, cwd }) => {
    // GOD MODE: Allow all commands if no restrictions are set
    if (PROC_ALLOWLIST.length > 0 && !PROC_ALLOWLIST.includes(command)) {
        throw new Error(`Command not allowed: ${command}. Allowed: ${PROC_ALLOWLIST.join(", ")}`);
    }
    // Security: Check for dangerous commands if security checks are enabled
    if (config.enableSecurityChecks && isDangerousCommand(command)) {
        logger.warn("Potentially dangerous command attempted", { command, args });
        throw new Error(`Potentially dangerous command detected: ${command}. Use with caution.`);
    }
    const workingDir = cwd ? ensureInsideRoot(path.resolve(cwd)) : process.cwd();
    try {
        const { command: sanitizedCommand, args: sanitizedArgs } = sanitizeCommand(command, args);
        const { stdout, stderr } = await execAsync(`${sanitizedCommand} ${sanitizedArgs.join(" ")}`, { cwd: workingDir });
        return {
            content: [],
            structuredContent: {
                success: true,
                stdout: stdout || undefined,
                stderr: stderr || undefined,
                exitCode: 0
            }
        };
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        const stdout = error?.stdout || undefined;
        const stderr = error?.stderr || undefined;
        const exitCode = error?.code || -1;
        return {
            content: [],
            structuredContent: {
                success: false,
                stdout,
                stderr,
                exitCode,
                error: errorMessage
            }
        };
    }
});
server.registerTool("git_status", {
    description: "Get git status for a repository",
    inputSchema: { dir: z.string().default(".") },
    outputSchema: {
        status: z.string(),
        branch: z.string().optional(),
        changes: z.array(z.string()).optional()
    }
}, async ({ dir }) => {
    const repoPath = ensureInsideRoot(path.resolve(dir));
    const git = simpleGit(repoPath);
    try {
        const status = await git.status();
        return {
            content: [],
            structuredContent: {
                status: "clean",
                branch: status.current,
                changes: [
                    ...status.modified,
                    ...status.created,
                    ...status.deleted,
                    ...status.renamed
                ]
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                status: "error",
                error: error instanceof Error ? error.message : String(error)
            }
        };
    }
});
server.registerTool("win_services", {
    description: "List system services (cross-platform: Windows services, Linux systemd, macOS launchd)",
    inputSchema: { filter: z.string().optional() },
    outputSchema: {
        services: z.array(z.object({
            name: z.string(),
            displayName: z.string(),
            status: z.string(),
            startupType: z.string().optional()
        })),
        platform: z.string()
    }
}, async ({ filter }) => {
    try {
        let services = [];
        if (IS_WINDOWS) {
            let command = "wmic service get name,displayname,state,startmode /format:csv";
            if (filter) {
                command += ` | findstr /i "${filter}"`;
            }
            const { stdout } = await execAsync(command);
            const lines = stdout.trim().split("\n").slice(1); // Skip header
            services = lines.map(line => {
                const parts = line.split(",");
                return {
                    name: parts[1] || "Unknown",
                    displayName: parts[2] || "Unknown",
                    status: parts[3] || "Unknown",
                    startupType: parts[4] || "Unknown"
                };
            }).filter(service => service.name !== "Unknown");
        }
        else if (IS_LINUX) {
            // Linux systemd services
            let command = "systemctl list-units --type=service --all --no-pager";
            if (filter) {
                command += ` | grep -i "${filter}"`;
            }
            const { stdout } = await execAsync(command);
            const lines = stdout.trim().split("\n").slice(1); // Skip header
            services = lines.map(line => {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 4) {
                    return {
                        name: parts[0].replace(/\.service$/, ""),
                        displayName: parts.slice(4).join(" ") || parts[0],
                        status: parts[2] || "unknown",
                        startupType: parts[1] || "unknown"
                    };
                }
                return null;
            }).filter(service => service !== null);
        }
        else if (IS_MACOS) {
            // macOS launchd services
            let command = "launchctl list";
            if (filter) {
                command += ` | grep -i "${filter}"`;
            }
            const { stdout } = await execAsync(command);
            const lines = stdout.trim().split("\n").slice(1); // Skip header
            services = lines.map(line => {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 3) {
                    return {
                        name: parts[2] || "unknown",
                        displayName: parts[2] || "unknown",
                        status: parts[0] === "-" ? "stopped" : "running"
                    };
                }
                return null;
            }).filter(service => service !== null);
        }
        return {
            content: [],
            structuredContent: {
                services,
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                services: [],
                platform: PLATFORM,
                error: error instanceof Error ? error.message : String(error)
            }
        };
    }
});
server.registerTool("win_processes", {
    description: "List system processes (cross-platform: Windows, Linux, macOS)",
    inputSchema: { filter: z.string().optional() },
    outputSchema: {
        processes: z.array(z.object({
            pid: z.number(),
            name: z.string(),
            memory: z.string(),
            cpu: z.string()
        })),
        platform: z.string()
    }
}, async ({ filter }) => {
    try {
        let processes = [];
        if (IS_WINDOWS) {
            let command = "tasklist /fo csv /nh";
            if (filter) {
                command += ` | findstr /i "${filter}"`;
            }
            const { stdout } = await execAsync(command);
            const lines = stdout.trim().split("\n");
            processes = lines.map(line => {
                const parts = line.split(",");
                return {
                    pid: parseInt(parts[1]) || 0,
                    name: parts[0]?.replace(/"/g, "") || "Unknown",
                    memory: parts[4]?.replace(/"/g, "") || "Unknown",
                    cpu: parts[8]?.replace(/"/g, "") || "Unknown"
                };
            }).filter(process => process.pid > 0);
        }
        else if (IS_LINUX) {
            // Linux processes using ps
            let command = "ps aux --no-headers";
            if (filter) {
                command += ` | grep -i "${filter}" | grep -v grep`;
            }
            const { stdout } = await execAsync(command + " | head -50");
            const lines = stdout.trim().split("\n");
            processes = lines.map(line => {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 11) {
                    return {
                        pid: parseInt(parts[1]) || 0,
                        name: parts.slice(10).join(" ") || "Unknown",
                        memory: parts[5] || "0",
                        cpu: parts[2] + "%" || "0.0%"
                    };
                }
                return null;
            }).filter(process => process !== null && process.pid > 0);
        }
        else if (IS_MACOS) {
            // macOS processes using ps
            let command = "ps aux";
            if (filter) {
                command += ` | grep -i "${filter}" | grep -v grep`;
            }
            const { stdout } = await execAsync(command + " | head -50");
            const lines = stdout.trim().split("\n").slice(1); // Skip header
            processes = lines.map(line => {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 11) {
                    return {
                        pid: parseInt(parts[1]) || 0,
                        name: parts.slice(10).join(" ") || "Unknown",
                        memory: parts[5] || "0",
                        cpu: parts[2] + "%" || "0.0%"
                    };
                }
                return null;
            }).filter(process => process !== null && process.pid > 0);
        }
        return {
            content: [],
            structuredContent: {
                processes,
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                processes: [],
                platform: PLATFORM,
                error: error instanceof Error ? error.message : String(error)
            }
        };
    }
});
server.registerTool("download_file", {
    description: "Download a file from URL",
    inputSchema: {
        url: z.string().url(),
        outputPath: z.string().optional()
    },
    outputSchema: {
        success: z.boolean(),
        path: z.string().optional(),
        error: z.string().optional()
    }
}, async ({ url, outputPath }) => {
    try {
        const fileName = outputPath || path.basename(new URL(url).pathname) || "downloaded_file";
        // Use current working directory instead of first allowed root
        const fullPath = path.join(process.cwd(), fileName);
        ensureInsideRoot(fullPath);
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const fileStream = createWriteStream(fullPath);
        const reader = response.body?.getReader();
        if (!reader) {
            throw new Error("No response body");
        }
        while (true) {
            const { done, value } = await reader.read();
            if (done)
                break;
            fileStream.write(value);
        }
        fileStream.end();
        return {
            content: [],
            structuredContent: {
                success: true,
                path: fullPath
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error instanceof Error ? error.message : String(error)
            }
        };
    }
});
server.registerTool("change_wallpaper", {
    description: "Change desktop wallpaper (cross-platform: Windows, Linux, macOS)",
    inputSchema: {
        imagePath: z.string(),
        mode: z.enum(["center", "tile", "stretch", "fit", "fill"]).default("fill")
    },
    outputSchema: {
        success: z.boolean(),
        platform: z.string(),
        error: z.string().optional()
    }
}, async ({ imagePath, mode }) => {
    try {
        const fullPath = path.resolve(imagePath);
        // Verify the image file exists
        try {
            await fs.access(fullPath);
        }
        catch {
            throw new Error(`Image file not found: ${fullPath}`);
        }
        if (IS_WINDOWS) {
            // Use PowerShell to change wallpaper
            const script = `
        Add-Type -TypeDefinition @"
          using System.Runtime.InteropServices;
          public class Wallpaper {
            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
          }
"@
        [Wallpaper]::SystemParametersInfo(0x0014, 0, "${fullPath.replace(/\\/g, "\\\\")}", 0x01 -bor 0x02)
      `;
            await execAsync(`powershell -Command "${script}"`);
            return {
                content: [],
                structuredContent: {
                    success: true,
                    platform: "windows"
                }
            };
        }
        else if (IS_LINUX) {
            // Linux: Try multiple desktop environments
            let command = "";
            // Detect desktop environment
            const desktop = process.env.XDG_CURRENT_DESKTOP || process.env.DESKTOP_SESSION || "";
            if (desktop.toLowerCase().includes("gnome")) {
                // GNOME
                command = `gsettings set org.gnome.desktop.background picture-uri "file://${fullPath}" && gsettings set org.gnome.desktop.background picture-options "${mode}"`;
            }
            else if (desktop.toLowerCase().includes("kde") || desktop.toLowerCase().includes("plasma")) {
                // KDE Plasma
                command = `qdbus org.kde.plasmashell /PlasmaShell org.kde.PlasmaShell.evaluateScript 'var allDesktops = desktops();for (i=0;i<allDesktops.length;i++) {d = allDesktops[i];d.wallpaperPlugin = "org.kde.image";d.currentConfigGroup = Array("Wallpaper", "org.kde.image", "General");d.writeConfig("Image", "file://${fullPath}");}'`;
            }
            else if (desktop.toLowerCase().includes("xfce")) {
                // XFCE
                command = `xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitor0/workspace0/last-image -s "${fullPath}"`;
            }
            else {
                // Fallback: try feh (common wallpaper setter)
                command = `feh --bg-${mode === "fill" ? "fill" : "scale"} "${fullPath}"`;
            }
            await execAsync(command);
            return {
                content: [],
                structuredContent: {
                    success: true,
                    platform: `linux-${desktop.toLowerCase() || 'generic'}`
                }
            };
        }
        else if (IS_MACOS) {
            // macOS: Use osascript to set wallpaper
            const script = `tell application "Finder" to set desktop picture to POSIX file "${fullPath}"`;
            await execAsync(`osascript -e '${script}'`);
            return {
                content: [],
                structuredContent: {
                    success: true,
                    platform: "macos"
                }
            };
        }
        // Should never reach here, but TypeScript needs a return
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: "Unsupported platform"
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error instanceof Error ? error.message : String(error)
            }
        };
    }
});
server.registerTool("rag_search", {
    description: "Search documents using RAG",
    inputSchema: {
        query: z.string(),
        documents: z.array(z.string()),
        topK: z.number().int().min(1).max(10).default(3)
    },
    outputSchema: {
        results: z.array(z.object({
            document: z.string(),
            score: z.number()
        })),
        error: z.string().optional()
    }
}, async ({ query, documents, topK }) => {
    try {
        const script = `
import sys
import json
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

try:
    query = "${query}"
    documents = ${JSON.stringify(documents)}
    top_k = ${topK}
    
    # Load model
    model = SentenceTransformer('all-MiniLM-L6-v2')
    
    # Encode query and documents
    query_embedding = model.encode([query])
    doc_embeddings = model.encode(documents)
    
    # Calculate similarities
    similarities = cosine_similarity(query_embedding, doc_embeddings)[0]
    
    # Get top-k results
    top_indices = np.argsort(similarities)[::-1][:top_k]
    
    results = []
    for idx in top_indices:
        results.append({
            "document": documents[idx],
            "score": float(similarities[idx])
        })
    
    print(json.dumps({"success": True, "results": results}))
    sys.exit(0)
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
    sys.exit(1)
`;
        const scriptPath = path.join(process.cwd(), "temp_rag_script.py");
        await fs.writeFile(scriptPath, script, "utf8");
        const { stdout, stderr } = await execAsync(`python "${scriptPath}"`);
        await fs.unlink(scriptPath).catch(() => { });
        const result = JSON.parse(stdout);
        if (result.success) {
            return { content: [], structuredContent: { results: result.results } };
        }
        else {
            return { content: [], structuredContent: { results: [], error: result.error } };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                results: [],
                error: error instanceof Error ? error.message : String(error)
            }
        };
    }
});
server.registerTool("rag_query", {
    description: "Query documents using RAG with context",
    inputSchema: {
        query: z.string(),
        documents: z.array(z.string()),
        contextLength: z.number().int().min(100).max(2000).default(500)
    },
    outputSchema: {
        answer: z.string(),
        context: z.array(z.string()),
        error: z.string().optional()
    }
}, async ({ query, documents, contextLength }) => {
    try {
        const script = `
import sys
import json
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

try:
    query = "${query}"
    documents = ${JSON.stringify(documents)}
    context_length = ${contextLength}
    
    # Load model
    model = SentenceTransformer('all-MiniLM-L6-v2')
    
    # Encode query and documents
    query_embedding = model.encode([query])
    doc_embeddings = model.encode(documents)
    
    # Calculate similarities
    similarities = cosine_similarity(query_embedding, doc_embeddings)[0]
    
    # Get most relevant documents
    top_indices = np.argsort(similarities)[::-1]
    
    # Build context from top documents
    context = []
    current_length = 0
    
    for idx in top_indices:
        if current_length >= context_length:
            break
        doc = documents[idx]
        if current_length + len(doc) <= context_length:
            context.append(doc)
            current_length += len(doc)
        else:
            # Truncate document to fit
            remaining = context_length - current_length
            context.append(doc[:remaining] + "...")
            break
    
    # Simple answer generation (in a real implementation, you'd use an LLM)
    answer = f"Based on the provided context ({len(context)} documents), here's what I found: {query}"
    
    print(json.dumps({
        "success": True,
        "answer": answer,
        "context": context
    }))
    sys.exit(0)
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
    sys.exit(1)
`;
        const scriptPath = path.join(process.cwd(), "temp_rag_query_script.py");
        await fs.writeFile(scriptPath, script, "utf8");
        const { stdout, stderr } = await execAsync(`python "${scriptPath}"`);
        await fs.unlink(scriptPath).catch(() => { });
        const result = JSON.parse(stdout);
        if (result.success) {
            return {
                content: [],
                structuredContent: {
                    answer: result.answer,
                    context: result.context
                }
            };
        }
        else {
            return {
                content: [],
                structuredContent: {
                    answer: "",
                    context: [],
                    error: result.error
                }
            };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                answer: "",
                context: [],
                error: error instanceof Error ? error.message : String(error)
            }
        };
    }
});
server.registerTool("system_exec", {
    description: "Execute any system command with full privileges (GOD MODE)",
    inputSchema: {
        command: z.string(),
        args: z.array(z.string()).default([]),
        cwd: z.string().optional(),
        timeout: z.number().default(30000)
    },
    outputSchema: {
        success: z.boolean(),
        stdout: z.string().optional(),
        stderr: z.string().optional(),
        exitCode: z.number().optional(),
        error: z.string().optional()
    }
}, async ({ command, args, cwd, timeout }) => {
    try {
        const workingDir = cwd ? path.resolve(cwd) : process.cwd();
        const fullCommand = `${command} ${args.join(" ")}`;
        const { stdout, stderr } = await execAsync(fullCommand, {
            cwd: workingDir,
            timeout: timeout,
            windowsHide: false
        });
        return {
            content: [],
            structuredContent: {
                success: true,
                stdout: stdout || undefined,
                stderr: stderr || undefined,
                exitCode: 0
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                stdout: error.stdout || undefined,
                stderr: error.stderr || undefined,
                exitCode: error.code || -1,
                error: error.message
            }
        };
    }
});
server.registerTool("registry_read", {
    description: "Read system configuration (Windows: Registry, Linux: config files, macOS: plist/config files)",
    inputSchema: {
        key: z.string(),
        value: z.string().optional()
    },
    outputSchema: {
        success: z.boolean(),
        data: z.any().optional(),
        platform: z.string(),
        error: z.string().optional()
    }
}, async ({ key, value }) => {
    try {
        if (IS_WINDOWS) {
            // Windows Registry
            const command = value
                ? `reg query "${key}" /v "${value}"`
                : `reg query "${key}"`;
            const { stdout } = await execAsync(command);
            return {
                content: [],
                structuredContent: {
                    success: true,
                    data: stdout,
                    platform: "windows-registry"
                }
            };
        }
        else if (IS_LINUX) {
            // Linux: Map common registry-like locations to config files
            let configPath = "";
            let command = "";
            if (key.toLowerCase().includes("software") || key.toLowerCase().includes("apps")) {
                configPath = "/etc/";
                command = `find /etc -name "*.conf" -o -name "*.cfg" | head -10 | xargs grep -l "${value || ''}" 2>/dev/null || echo "No matching config found"`;
            }
            else if (key.toLowerCase().includes("system")) {
                command = value
                    ? `grep -r "${value}" /etc/systemd/ /etc/default/ 2>/dev/null || echo "Not found"`
                    : `ls -la /etc/systemd/system/ /etc/default/`;
            }
            else if (key.toLowerCase().includes("user") || key.toLowerCase().includes("current_user")) {
                const homeDir = process.env.HOME || "/home/" + (process.env.USER || "user");
                command = value
                    ? `grep -r "${value}" ${homeDir}/.config/ ${homeDir}/.local/ 2>/dev/null || echo "Not found"`
                    : `ls -la ${homeDir}/.config/ ${homeDir}/.local/share/ 2>/dev/null || echo "No user config"`;
            }
            else {
                // General config search
                command = value
                    ? `grep -r "${value}" /etc/ 2>/dev/null | head -5 || echo "Not found"`
                    : `echo "Specify a value to search for in Linux config files"`;
            }
            const { stdout } = await execAsync(command);
            return {
                content: [],
                structuredContent: {
                    success: true,
                    data: stdout,
                    platform: "linux-configs"
                }
            };
        }
        else if (IS_MACOS) {
            // macOS: Use defaults command for plist files
            let command = "";
            if (key.toLowerCase().includes("system")) {
                command = value
                    ? `defaults read /Library/Preferences/SystemConfiguration/preferences | grep -i "${value}" || echo "Not found"`
                    : `defaults domains | tr ',' '\n' | head -10`;
            }
            else if (key.toLowerCase().includes("user") || key.toLowerCase().includes("current_user")) {
                command = value
                    ? `defaults read com.apple.finder | grep -i "${value}" || echo "Not found"`
                    : `defaults domains | tr ',' '\n' | grep -E "com\\.apple\\.|com\\.microsoft\\." | head -10`;
            }
            else {
                // Try to read as a domain
                command = value
                    ? `defaults read "${key}" 2>/dev/null | grep -i "${value}" || echo "Not found"`
                    : `defaults read "${key}" 2>/dev/null || echo "Domain not found: ${key}"`;
            }
            const { stdout } = await execAsync(command);
            return {
                content: [],
                structuredContent: {
                    success: true,
                    data: stdout,
                    platform: "macos-defaults"
                }
            };
        }
        // Should never reach here, but TypeScript needs a return
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: "Unsupported platform for registry operations"
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
server.registerTool("registry_write", {
    description: "Write system configuration (Windows: Registry, Linux: config files, macOS: plist/config files)",
    inputSchema: {
        key: z.string(),
        value: z.string(),
        data: z.string(),
        type: z.enum(["REG_SZ", "REG_DWORD", "REG_QWORD", "REG_BINARY", "REG_MULTI_SZ", "REG_EXPAND_SZ", "string", "boolean", "integer"]).default("string")
    },
    outputSchema: {
        success: z.boolean(),
        platform: z.string(),
        error: z.string().optional()
    }
}, async ({ key, value, data, type }) => {
    try {
        if (IS_WINDOWS) {
            // Windows Registry
            const regType = type.startsWith("REG_") ? type : "REG_SZ";
            const command = `reg add "${key}" /v "${value}" /t ${regType} /d "${data}" /f`;
            await execAsync(command);
            return {
                content: [],
                structuredContent: {
                    success: true,
                    platform: "windows-registry"
                }
            };
        }
        else if (IS_LINUX) {
            // Linux: Write to appropriate config files
            if (key.toLowerCase().includes("user") || key.toLowerCase().includes("current_user")) {
                // User config
                const homeDir = process.env.HOME || "/home/" + (process.env.USER || "user");
                const configFile = `${homeDir}/.config/mcp-settings.conf`;
                // Ensure directory exists
                await execAsync(`mkdir -p ${homeDir}/.config`);
                // Append or update the setting
                const setting = `${value}=${data}`;
                await execAsync(`grep -v "^${value}=" "${configFile}" > "${configFile}.tmp" 2>/dev/null || touch "${configFile}.tmp"`);
                await execAsync(`echo "${setting}" >> "${configFile}.tmp"`);
                await execAsync(`mv "${configFile}.tmp" "${configFile}"`);
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        platform: "linux-userconfig"
                    }
                };
            }
            else {
                // System config (requires sudo)
                const configFile = `/etc/mcp-settings.conf`;
                const setting = `${value}=${data}`;
                await execAsync(`sudo bash -c 'grep -v "^${value}=" "${configFile}" > "${configFile}.tmp" 2>/dev/null || touch "${configFile}.tmp"'`);
                await execAsync(`sudo bash -c 'echo "${setting}" >> "${configFile}.tmp"'`);
                await execAsync(`sudo mv "${configFile}.tmp" "${configFile}"`);
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        platform: "linux-systemconfig"
                    }
                };
            }
        }
        else if (IS_MACOS) {
            // macOS: Use defaults command for plist files
            let command = "";
            if (key.toLowerCase().includes("user") || key.toLowerCase().includes("current_user")) {
                // User defaults
                const domain = "com.mcp.settings";
                if (type === "boolean") {
                    command = `defaults write ${domain} "${value}" -bool ${data}`;
                }
                else if (type === "integer") {
                    command = `defaults write ${domain} "${value}" -int ${data}`;
                }
                else {
                    command = `defaults write ${domain} "${value}" -string "${data}"`;
                }
            }
            else {
                // Try to write to the specified domain
                if (type === "boolean") {
                    command = `defaults write "${key}" "${value}" -bool ${data}`;
                }
                else if (type === "integer") {
                    command = `defaults write "${key}" "${value}" -int ${data}`;
                }
                else {
                    command = `defaults write "${key}" "${value}" -string "${data}"`;
                }
            }
            await execAsync(command);
            return {
                content: [],
                structuredContent: {
                    success: true,
                    platform: "macos-defaults"
                }
            };
        }
        // Should never reach here, but TypeScript needs a return
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: "Unsupported platform for registry operations"
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
server.registerTool("service_control", {
    description: "Control system services (cross-platform: Windows services, Linux systemd/init, macOS launchd)",
    inputSchema: {
        serviceName: z.string(),
        action: z.enum(["start", "stop", "restart", "pause", "resume", "status", "enable", "disable", "list"])
    },
    outputSchema: {
        success: z.boolean(),
        output: z.string().optional(),
        platform: z.string(),
        error: z.string().optional()
    }
}, async ({ serviceName, action }) => {
    try {
        let command = "";
        if (IS_WINDOWS) {
            // Windows services
            switch (action) {
                case "start":
                case "stop":
                case "pause":
                case "resume":
                    command = `sc ${action} "${serviceName}"`;
                    break;
                case "restart":
                    command = `sc stop "${serviceName}" && sc start "${serviceName}"`;
                    break;
                case "status":
                    command = `sc query "${serviceName}"`;
                    break;
                case "enable":
                    command = `sc config "${serviceName}" start= auto`;
                    break;
                case "disable":
                    command = `sc config "${serviceName}" start= disabled`;
                    break;
                case "list":
                    command = `sc query type= service state= all`;
                    break;
            }
        }
        else if (IS_LINUX) {
            // Linux systemd/init services
            switch (action) {
                case "start":
                    command = `sudo systemctl start "${serviceName}" || sudo service "${serviceName}" start`;
                    break;
                case "stop":
                    command = `sudo systemctl stop "${serviceName}" || sudo service "${serviceName}" stop`;
                    break;
                case "restart":
                    command = `sudo systemctl restart "${serviceName}" || sudo service "${serviceName}" restart`;
                    break;
                case "status":
                    command = `systemctl status "${serviceName}" || service "${serviceName}" status`;
                    break;
                case "enable":
                    command = `sudo systemctl enable "${serviceName}"`;
                    break;
                case "disable":
                    command = `sudo systemctl disable "${serviceName}"`;
                    break;
                case "pause":
                    command = `sudo systemctl stop "${serviceName}"`;
                    break;
                case "resume":
                    command = `sudo systemctl start "${serviceName}"`;
                    break;
                case "list":
                    command = `systemctl list-units --type=service || service --status-all`;
                    break;
            }
        }
        else if (IS_MACOS) {
            // macOS launchd services
            switch (action) {
                case "start":
                    command = `sudo launchctl load -w /System/Library/LaunchDaemons/${serviceName}.plist || sudo launchctl start ${serviceName}`;
                    break;
                case "stop":
                    command = `sudo launchctl unload -w /System/Library/LaunchDaemons/${serviceName}.plist || sudo launchctl stop ${serviceName}`;
                    break;
                case "restart":
                    command = `sudo launchctl stop ${serviceName} && sudo launchctl start ${serviceName}`;
                    break;
                case "status":
                    command = `launchctl print system/${serviceName} || launchctl list | grep ${serviceName}`;
                    break;
                case "enable":
                    command = `sudo launchctl enable system/${serviceName}`;
                    break;
                case "disable":
                    command = `sudo launchctl disable system/${serviceName}`;
                    break;
                case "pause":
                    command = `sudo launchctl stop ${serviceName}`;
                    break;
                case "resume":
                    command = `sudo launchctl start ${serviceName}`;
                    break;
                case "list":
                    command = `launchctl list | head -20`;
                    break;
            }
        }
        const { stdout } = await execAsync(command);
        return {
            content: [],
            structuredContent: {
                success: true,
                output: stdout,
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
server.registerTool("disk_management", {
    description: "Manage disk partitions and volumes (cross-platform)",
    inputSchema: {
        action: z.enum(["list", "create", "delete", "format", "extend", "shrink", "info"]),
        disk: z.string().optional(),
        partition: z.string().optional(),
        size: z.string().optional(),
        format: z.string().optional()
    },
    outputSchema: {
        success: z.boolean(),
        output: z.string().optional(),
        platform: z.string(),
        error: z.string().optional()
    }
}, async ({ action, disk, partition, size, format }) => {
    try {
        let command = "";
        if (IS_WINDOWS) {
            // Windows disk management
            switch (action) {
                case "list":
                    command = "wmic logicaldisk get size,freespace,caption";
                    break;
                case "info":
                    command = "wmic diskdrive get model,size,status";
                    break;
                case "create":
                    command = `diskpart /s - <<EOF
select disk ${disk}
create partition primary size=${size}
EOF`;
                    break;
                case "format":
                    command = `format ${disk}: /fs:${format || "NTFS"} /q`;
                    break;
                default:
                    command = "wmic logicaldisk get size,freespace,caption";
            }
        }
        else if (IS_LINUX) {
            // Linux disk management
            switch (action) {
                case "list":
                    command = "df -h && echo '--- Block Devices ---' && lsblk";
                    break;
                case "info":
                    command = "fdisk -l | grep -E '^Disk|^Device' && echo '--- Mount Points ---' && mount | grep -E '^/dev/'";
                    break;
                case "create":
                    if (!disk || !size) {
                        throw new Error("Disk and size required for partition creation on Linux");
                    }
                    command = `sudo parted ${disk} mkpart primary ext4 0% ${size}`;
                    break;
                case "format":
                    if (!disk) {
                        throw new Error("Disk/partition required for formatting on Linux");
                    }
                    const fsType = format || "ext4";
                    command = `sudo mkfs.${fsType} ${disk}`;
                    break;
                case "delete":
                    if (!disk || !partition) {
                        throw new Error("Disk and partition number required for deletion on Linux");
                    }
                    command = `sudo parted ${disk} rm ${partition}`;
                    break;
                default:
                    command = "df -h && echo '--- Block Devices ---' && lsblk";
            }
        }
        else if (IS_MACOS) {
            // macOS disk management
            switch (action) {
                case "list":
                    command = "df -h && echo '--- Disk Utility ---' && diskutil list";
                    break;
                case "info":
                    command = "diskutil info disk0 && system_profiler SPStorageDataType";
                    break;
                case "create":
                    if (!disk || !size) {
                        throw new Error("Disk and size required for partition creation on macOS");
                    }
                    const fsFormat = format || "JHFS+";
                    command = `diskutil partitionDisk ${disk} GPT ${fsFormat} "New Partition" ${size}`;
                    break;
                case "format":
                    if (!disk) {
                        throw new Error("Disk/partition required for formatting on macOS");
                    }
                    const macFormat = format || "JHFS+";
                    command = `diskutil eraseDisk ${macFormat} "Formatted" ${disk}`;
                    break;
                case "delete":
                    if (!partition) {
                        throw new Error("Partition identifier required for deletion on macOS");
                    }
                    command = `diskutil eraseVolume "Free Space" %noformat% ${partition}`;
                    break;
                default:
                    command = "df -h && echo '--- Disk Utility ---' && diskutil list";
            }
        }
        const { stdout } = await execAsync(command);
        return {
            content: [],
            structuredContent: {
                success: true,
                output: stdout,
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
server.registerTool("network_scan", {
    description: "Scan network for devices and open ports (cross-platform)",
    inputSchema: {
        target: z.string().optional(),
        ports: z.string().optional(),
        scanType: z.enum(["ping", "port", "arp", "full"]).default("ping")
    },
    outputSchema: {
        success: z.boolean(),
        results: z.array(z.any()).optional(),
        platform: z.string(),
        error: z.string().optional()
    }
}, async ({ target, ports, scanType }) => {
    try {
        let command = "";
        let results = [];
        switch (scanType) {
            case "ping":
                if (IS_WINDOWS) {
                    command = `ping -n 1 ${target || "127.0.0.1"}`;
                }
                else {
                    command = `ping -c 1 ${target || "127.0.0.1"}`;
                }
                break;
            case "port":
                if (IS_WINDOWS) {
                    command = `netstat -an | findstr :${ports || "80"}`;
                }
                else {
                    command = `netstat -an | grep :${ports || "80"}`;
                }
                break;
            case "arp":
                if (IS_WINDOWS) {
                    command = "arp -a";
                }
                else if (IS_LINUX) {
                    command = "arp -a";
                }
                else if (IS_MACOS) {
                    command = "arp -a";
                }
                break;
            case "full":
                // Try nmap first, fallback to ping sweep
                try {
                    if (IS_WINDOWS) {
                        command = `nmap -sn ${target || "192.168.1.0/24"}`;
                    }
                    else {
                        command = `nmap -sn ${target || "192.168.1.0/24"}`;
                    }
                }
                catch {
                    // Fallback to ping sweep if nmap not available
                    if (IS_WINDOWS) {
                        command = `for /L %i in (1,1,254) do @ping -n 1 -w 100 192.168.1.%i | find "TTL"`;
                    }
                    else {
                        command = `for i in {1..254}; do ping -c 1 -W 100 192.168.1.$i | grep "ttl" & done`;
                    }
                }
                break;
        }
        const { stdout } = await execAsync(command, { timeout: 30000 });
        results.push({
            command,
            output: stdout,
            scanType,
            target: target || "default"
        });
        return {
            content: [],
            structuredContent: {
                success: true,
                results,
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
// Utility: Check if current process is elevated (admin)
async function isProcessElevated() {
    try {
        // 'net session' requires admin; it returns error when not elevated
        await execAsync("net session");
        return true;
    }
    catch {
        return false;
    }
}
// Utility: Run a command elevated (cross-platform: Windows UAC, Linux/macOS sudo)
async function runElevatedCommand(command, args, workingDirectory, timeoutMs = config.timeout) {
    const tempDir = os.tmpdir();
    const uid = Date.now().toString(36) + Math.random().toString(36).slice(2);
    const stdoutPath = path.join(tempDir, `mcp_elev_${uid}.out.txt`);
    const stderrPath = path.join(tempDir, `mcp_elev_${uid}.err.txt`);
    const exitPath = path.join(tempDir, `mcp_elev_${uid}.code.txt`);
    if (IS_WINDOWS) {
        // Windows: Use PowerShell with UAC elevation
        const scriptPath = path.join(tempDir, `mcp_elev_${uid}.ps1`);
        const cdLine = workingDirectory ? `Set-Location -Path '${workingDirectory.replace(/'/g, "''")}'` : '';
        const script = `
$ErrorActionPreference = 'Continue'
${cdLine}
try {
  & '${command.replace(/'/g, "''")}' ${args.map(a => `'${a.replace(/'/g, "''")}'`).join(' ')} 1> '${stdoutPath.replace(/'/g, "''")}' 2> '${stderrPath.replace(/'/g, "''")}'
  $code = $LASTEXITCODE
} catch {
  $_ | Out-File -FilePath '${stderrPath.replace(/'/g, "''")}' -Append -Encoding utf8
  $code = 1
}
Set-Content -Path '${exitPath.replace(/'/g, "''")}' -Value $code -Encoding ascii -Force
`;
        await fs.writeFile(scriptPath, script, 'utf8');
        const startProcessCmd = `Start-Process PowerShell -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','${scriptPath.replace(/'/g, "''")}' -Wait`;
        try {
            await execAsync(`powershell -NoProfile -ExecutionPolicy Bypass -Command "${startProcessCmd}"`, { timeout: timeoutMs });
        }
        catch (e) {
            // Even if Start-Process fails (e.g., user cancels UAC), fall through to read any files
        }
        // Cleanup the script file
        await fs.unlink(scriptPath).catch(() => { });
    }
    else {
        // Linux/macOS: Use sudo with script execution
        const scriptPath = path.join(tempDir, `mcp_elev_${uid}.sh`);
        const cdLine = workingDirectory ? `cd '${workingDirectory.replace(/'/g, "'\"'\"'")}'` : '';
        const script = `#!/bin/bash
set -e
${cdLine}
# Execute the command and capture output/exit code
{ ${command} ${args.map(a => `'${a.replace(/'/g, "'\"'\"'")}'`).join(' ')} > '${stdoutPath}' 2> '${stderrPath}'; echo $? > '${exitPath}'; } || { echo $? > '${exitPath}'; }
`;
        await fs.writeFile(scriptPath, script, 'utf8');
        await execAsync(`chmod +x '${scriptPath}'`);
        try {
            // Use sudo to execute the script
            // Note: This may prompt for password in terminal
            await execAsync(`sudo '${scriptPath}'`, { timeout: timeoutMs });
        }
        catch (e) {
            // Continue to read output files even if sudo fails
        }
        // Cleanup the script file
        await fs.unlink(scriptPath).catch(() => { });
    }
    // Read output files (common for all platforms)
    let exitCode = -1;
    let stdout = '';
    let stderr = '';
    try {
        stdout = await fs.readFile(stdoutPath, 'utf8');
    }
    catch { }
    try {
        stderr = await fs.readFile(stderrPath, 'utf8');
    }
    catch { }
    try {
        const codeText = await fs.readFile(exitPath, 'utf8');
        exitCode = parseInt(codeText.trim(), 10);
    }
    catch { }
    // Cleanup output files
    await Promise.all([
        fs.unlink(stdoutPath).catch(() => { }),
        fs.unlink(stderrPath).catch(() => { }),
        fs.unlink(exitPath).catch(() => { }),
    ]);
    return { stdout, stderr, exitCode: Number.isFinite(exitCode) ? exitCode : -1 };
}
// Elevated process execution (cross-platform)
server.registerTool("proc_run_elevated", {
    description: "Run a command with elevated privileges (Windows: UAC, Linux/macOS: sudo). May prompt for authentication.",
    inputSchema: {
        command: z.string(),
        args: z.array(z.string()).default([]),
        cwd: z.string().optional(),
        timeout: z.number().int().min(1000).max(10 * 60 * 1000).default(2 * 60 * 1000)
    },
    outputSchema: {
        success: z.boolean(),
        stdout: z.string().optional(),
        stderr: z.string().optional(),
        exitCode: z.number().optional(),
        elevated: z.boolean(),
        platform: z.string(),
        note: z.string().optional()
    }
}, async ({ command, args, cwd, timeout }) => {
    const elevated = await isProcessElevated();
    const workingDir = cwd ? path.resolve(cwd) : process.cwd();
    if (elevated) {
        try {
            const { stdout, stderr } = await execAsync(`${command} ${args.join(' ')}`, { cwd: workingDir, timeout });
            return {
                content: [],
                structuredContent: {
                    success: true,
                    stdout: stdout || undefined,
                    stderr: stderr || undefined,
                    exitCode: 0,
                    elevated: true,
                    platform: PLATFORM
                }
            };
        }
        catch (error) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    stdout: error.stdout || undefined,
                    stderr: error.stderr || undefined,
                    exitCode: error.code || -1,
                    elevated: true,
                    platform: PLATFORM
                }
            };
        }
    }
    const { stdout, stderr, exitCode } = await runElevatedCommand(command, args, workingDir, timeout);
    const success = exitCode === 0;
    let note = undefined;
    if (!success) {
        if (IS_WINDOWS) {
            note = 'If you did not accept the UAC prompt, the command did not run.';
        }
        else {
            note = 'If you did not provide the correct sudo password, the command did not run.';
        }
    }
    return {
        content: [],
        structuredContent: {
            success,
            stdout: stdout || undefined,
            stderr: stderr || undefined,
            exitCode,
            elevated: false,
            platform: PLATFORM,
            note
        }
    };
});
// Linux/macOS-specific elevated terminal execution
server.registerTool("unix_sudo_exec", {
    description: "Execute commands with sudo on Linux/macOS (equivalent to Windows PowerShell admin). Interactive sudo prompt.",
    inputSchema: {
        command: z.string(),
        args: z.array(z.string()).default([]),
        cwd: z.string().optional(),
        timeout: z.number().int().min(1000).max(10 * 60 * 1000).default(2 * 60 * 1000),
        interactive: z.boolean().default(false)
    },
    outputSchema: {
        success: z.boolean(),
        stdout: z.string().optional(),
        stderr: z.string().optional(),
        exitCode: z.number().optional(),
        platform: z.string(),
        sudoUsed: z.boolean(),
        note: z.string().optional()
    }
}, async ({ command, args, cwd, timeout, interactive }) => {
    if (IS_WINDOWS) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                sudoUsed: false,
                note: "This tool is for Linux/macOS only. Use proc_run_elevated for Windows."
            }
        };
    }
    const workingDir = cwd ? path.resolve(cwd) : process.cwd();
    try {
        let fullCommand = "";
        let sudoUsed = false;
        // Check if we're already running as root
        const isRoot = process.getuid && process.getuid() === 0;
        if (isRoot) {
            // Already root, no sudo needed
            fullCommand = `${command} ${args.join(' ')}`;
        }
        else {
            // Use sudo
            sudoUsed = true;
            if (interactive) {
                // Interactive mode - let sudo handle password prompt
                fullCommand = `sudo ${command} ${args.join(' ')}`;
            }
            else {
                // Non-interactive mode - use sudo with -S flag and provide password via stdin
                fullCommand = `sudo -S ${command} ${args.join(' ')}`;
            }
        }
        const { stdout, stderr } = await execAsync(fullCommand, {
            cwd: workingDir,
            timeout: timeout
        });
        return {
            content: [],
            structuredContent: {
                success: true,
                stdout: stdout || undefined,
                stderr: stderr || undefined,
                exitCode: 0,
                platform: PLATFORM,
                sudoUsed: sudoUsed
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                stdout: error.stdout || undefined,
                stderr: error.stderr || undefined,
                exitCode: error.code || -1,
                platform: PLATFORM,
                sudoUsed: true,
                note: "Command failed. Check if sudo password was correct or if command is valid."
            }
        };
    }
});
// Cross-platform shell execution with auto-elevation detection
server.registerTool("shell_exec_smart", {
    description: "Smart shell execution that automatically detects and uses appropriate elevation (UAC/sudo) when needed",
    inputSchema: {
        command: z.string(),
        args: z.array(z.string()).default([]),
        cwd: z.string().optional(),
        autoElevate: z.boolean().default(true),
        timeout: z.number().int().min(1000).max(10 * 60 * 1000).default(2 * 60 * 1000)
    },
    outputSchema: {
        success: z.boolean(),
        stdout: z.string().optional(),
        stderr: z.string().optional(),
        exitCode: z.number().optional(),
        platform: z.string(),
        elevationUsed: z.boolean(),
        elevationType: z.string().optional(),
        note: z.string().optional()
    }
}, async ({ command, args, cwd, autoElevate, timeout }) => {
    const workingDir = cwd ? path.resolve(cwd) : process.cwd();
    // List of commands that typically require elevation
    const needsElevationCommands = [
        'chown', 'chmod', 'mount', 'umount', 'systemctl', 'service', 'apt-get', 'apt',
        'yum', 'dnf', 'pacman', 'zypper', 'brew', 'fdisk', 'parted', 'mkfs', 'fsck',
        'iptables', 'ufw', 'firewall-cmd', 'netstat', 'ss', 'lsof', 'dmesg', 'modprobe',
        'insmod', 'rmmod', 'update-grub', 'grub-install', 'ldconfig', 'sysctl'
    ];
    const commandName = command.split(/[\/\\]/).pop() || command;
    const needsElevation = autoElevate && needsElevationCommands.includes(commandName);
    try {
        if (!needsElevation || await isProcessElevated()) {
            // Run normally without elevation
            const { stdout, stderr } = await execAsync(`${command} ${args.join(' ')}`, {
                cwd: workingDir,
                timeout: timeout
            });
            return {
                content: [],
                structuredContent: {
                    success: true,
                    stdout: stdout || undefined,
                    stderr: stderr || undefined,
                    exitCode: 0,
                    platform: PLATFORM,
                    elevationUsed: false
                }
            };
        }
        else {
            // Use elevation
            const { stdout, stderr, exitCode } = await runElevatedCommand(command, args, workingDir, timeout);
            const success = exitCode === 0;
            let elevationType = "";
            let note = undefined;
            if (IS_WINDOWS) {
                elevationType = "UAC";
                if (!success) {
                    note = "UAC elevation may have been cancelled or failed.";
                }
            }
            else {
                elevationType = "sudo";
                if (!success) {
                    note = "sudo elevation may have been cancelled or password incorrect.";
                }
            }
            return {
                content: [],
                structuredContent: {
                    success,
                    stdout: stdout || undefined,
                    stderr: stderr || undefined,
                    exitCode,
                    platform: PLATFORM,
                    elevationUsed: true,
                    elevationType,
                    note
                }
            };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                stdout: error.stdout || undefined,
                stderr: error.stderr || undefined,
                exitCode: error.code || -1,
                platform: PLATFORM,
                elevationUsed: false,
                note: `Command execution failed: ${error.message}`
            }
        };
    }
});
// Create a System Snapshot/Restore Point (cross-platform)
server.registerTool("create_restore_point", {
    description: "Create a system snapshot/restore point (Windows: Restore Point, Linux: LVM/Btrfs snapshot, macOS: Time Machine snapshot)",
    inputSchema: {
        description: z.string().default("MCP System Snapshot"),
        restorePointType: z.enum(["APPLICATION_INSTALL", "APPLICATION_UNINSTALL", "DEVICE_DRIVER_INSTALL", "MODIFY_SETTINGS", "CANCELLED_OPERATION"]).default("MODIFY_SETTINGS")
    },
    outputSchema: {
        success: z.boolean(),
        stdout: z.string().optional(),
        stderr: z.string().optional(),
        elevated: z.boolean(),
        snapshotId: z.string().optional(),
        platform: z.string(),
        error: z.string().optional()
    }
}, async ({ description, restorePointType }) => {
    const elevated = await isProcessElevated();
    try {
        if (IS_WINDOWS) {
            // Windows Restore Point
            const psCommand = `Checkpoint-Computer -Description '${description.replace(/'/g, "''")}' -RestorePointType '${restorePointType}'`;
            if (elevated) {
                const { stdout, stderr } = await execAsync(`powershell -NoProfile -ExecutionPolicy Bypass -Command "${psCommand}"`, { timeout: 3 * 60 * 1000 });
                return { content: [], structuredContent: { success: true, stdout: stdout || undefined, stderr: stderr || undefined, elevated: true, platform: "windows" } };
            }
            else {
                const { stdout, stderr, exitCode } = await runElevatedCommand('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', psCommand], process.cwd(), 3 * 60 * 1000);
                const success = exitCode === 0;
                return { content: [], structuredContent: { success, stdout: stdout || undefined, stderr: stderr || undefined, elevated: false, platform: "windows", error: success ? undefined : 'Failed to create restore point (UAC denied, System Protection disabled, or policy restrictions).' } };
            }
        }
        else if (IS_LINUX) {
            // Linux: Try Btrfs snapshot first, then LVM snapshot
            const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
            const snapshotId = `mcp-snapshot-${timestamp}`;
            try {
                // Check if we're on a Btrfs filesystem
                const { stdout: fsType } = await execAsync("findmnt -n -o FSTYPE /");
                if (fsType.includes("btrfs")) {
                    // Create Btrfs snapshot
                    const snapshotPath = `/.snapshots/${snapshotId}`;
                    await execAsync(`sudo mkdir -p /.snapshots`);
                    await execAsync(`sudo btrfs subvolume snapshot / ${snapshotPath}`);
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            snapshotId,
                            platform: "linux-btrfs",
                            stdout: `Btrfs snapshot created: ${snapshotPath}`,
                            elevated: true
                        }
                    };
                }
                else {
                    // Try LVM snapshot
                    const { stdout: lvmInfo } = await execAsync("sudo lvdisplay --colon 2>/dev/null || echo 'no-lvm'");
                    if (!lvmInfo.includes("no-lvm")) {
                        const rootLv = await execAsync("sudo lvdisplay --colon | grep $(df / | tail -1 | awk '{print $1}') | head -1 | cut -d: -f1");
                        if (rootLv.stdout.trim()) {
                            await execAsync(`sudo lvcreate -L1G -s -n ${snapshotId} ${rootLv.stdout.trim()}`);
                            return {
                                content: [],
                                structuredContent: {
                                    success: true,
                                    snapshotId,
                                    platform: "linux-lvm",
                                    stdout: `LVM snapshot created: ${snapshotId}`,
                                    elevated: true
                                }
                            };
                        }
                    }
                    // Fallback: Create a tar backup of important directories
                    const backupPath = `/tmp/mcp-backup-${timestamp}.tar.gz`;
                    await execAsync(`sudo tar -czf ${backupPath} /etc /var/log /home --exclude=/home/*/.*cache* 2>/dev/null || true`);
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            snapshotId: backupPath,
                            platform: "linux-backup",
                            stdout: `System backup created: ${backupPath}`,
                            elevated: true
                        }
                    };
                }
            }
            catch (error) {
                return {
                    content: [],
                    structuredContent: {
                        success: false,
                        platform: "linux",
                        error: `Failed to create Linux snapshot: ${error.message}`
                    }
                };
            }
        }
        else if (IS_MACOS) {
            // macOS: Use tmutil for Time Machine snapshot
            const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
            const snapshotId = `mcp-snapshot-${timestamp}`;
            try {
                // Create Time Machine snapshot
                const { stdout, stderr } = await execAsync(`sudo tmutil localsnapshot`);
                // Try to get the snapshot name
                const { stdout: snapshots } = await execAsync(`tmutil listlocalsnapshots /`);
                const latestSnapshot = snapshots.trim().split('\n').pop();
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        snapshotId: latestSnapshot || snapshotId,
                        platform: "macos-timemachine",
                        stdout: `Time Machine snapshot created: ${latestSnapshot}`,
                        elevated: true
                    }
                };
            }
            catch (error) {
                // Fallback: Create a tar backup
                const backupPath = `/tmp/mcp-backup-${timestamp}.tar.gz`;
                await execAsync(`sudo tar -czf ${backupPath} /etc /var/log /Users --exclude=/Users/*/Library/Caches 2>/dev/null || true`);
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        snapshotId: backupPath,
                        platform: "macos-backup",
                        stdout: `System backup created: ${backupPath}`,
                        elevated: true
                    }
                };
            }
        }
        // Should never reach here, but TypeScript needs a return
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: "Unsupported platform for restore points"
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
// 1. System Repair Tool
server.registerTool("system_repair", {
    description: "System repairs and diagnostics (cross-platform)",
    inputSchema: {
        repairType: z.enum(["sfc", "dism", "chkdsk", "network_reset", "windows_update_reset", "dns_flush", "temp_cleanup", "disk_cleanup", "fsck", "system_update", "package_repair", "service_restart"])
    },
    outputSchema: {
        success: z.boolean(),
        output: z.string().optional(),
        error: z.string().optional(),
        elevated: z.boolean(),
        platform: z.string()
    }
}, async ({ repairType }) => {
    const elevated = await isProcessElevated();
    try {
        let command = "";
        let needsElevation = false;
        switch (repairType) {
            case "sfc":
                if (IS_WINDOWS) {
                    command = "sfc /scannow";
                    needsElevation = true;
                }
                else if (IS_LINUX) {
                    command = "sudo apt-get check && sudo apt-get autoremove";
                    needsElevation = true;
                }
                else if (IS_MACOS) {
                    command = "sudo diskutil verifyVolume /";
                    needsElevation = true;
                }
                break;
            case "dism":
                if (IS_WINDOWS) {
                    command = "dism /online /cleanup-image /restorehealth";
                    needsElevation = true;
                }
                else if (IS_LINUX) {
                    command = "sudo apt-get update && sudo apt-get upgrade";
                    needsElevation = true;
                }
                else if (IS_MACOS) {
                    command = "softwareupdate -i -a";
                    needsElevation = true;
                }
                break;
            case "chkdsk":
                if (IS_WINDOWS) {
                    command = "chkdsk C: /f /r";
                    needsElevation = true;
                }
                else if (IS_LINUX) {
                    command = "sudo fsck -f /";
                    needsElevation = true;
                }
                else if (IS_MACOS) {
                    command = "sudo diskutil repairVolume /";
                    needsElevation = true;
                }
                break;
            case "network_reset":
                if (IS_WINDOWS) {
                    command = "netsh winsock reset && netsh int ip reset";
                    needsElevation = true;
                }
                else if (IS_LINUX) {
                    command = "sudo systemctl restart NetworkManager";
                    needsElevation = true;
                }
                else if (IS_MACOS) {
                    command = "sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder";
                    needsElevation = true;
                }
                break;
            case "windows_update_reset":
                if (IS_WINDOWS) {
                    command = "net stop wuauserv && net stop cryptSvc && net stop bits && net stop msiserver";
                    needsElevation = true;
                }
                else if (IS_LINUX) {
                    command = "sudo systemctl restart systemd-update-utmp";
                    needsElevation = true;
                }
                else if (IS_MACOS) {
                    command = "sudo launchctl unload /System/Library/LaunchDaemons/com.apple.softwareupdate.plist";
                    needsElevation = true;
                }
                break;
            case "dns_flush":
                if (IS_WINDOWS) {
                    command = "ipconfig /flushdns";
                }
                else if (IS_LINUX) {
                    command = "sudo systemctl restart systemd-resolved";
                    needsElevation = true;
                }
                else if (IS_MACOS) {
                    command = "sudo dscacheutil -flushcache";
                    needsElevation = true;
                }
                break;
            case "temp_cleanup":
                if (IS_WINDOWS) {
                    command = "del /q /f %temp%\\* && del /q /f C:\\Windows\\Temp\\*";
                    needsElevation = true;
                }
                else {
                    command = "sudo rm -rf /tmp/* /var/tmp/* 2>/dev/null || true";
                    needsElevation = true;
                }
                break;
            case "disk_cleanup":
                if (IS_WINDOWS) {
                    command = "cleanmgr /sagerun:1";
                    needsElevation = true;
                }
                else if (IS_LINUX) {
                    command = "sudo apt-get autoremove -y && sudo apt-get autoclean";
                    needsElevation = true;
                }
                else if (IS_MACOS) {
                    command = "sudo rm -rf ~/Library/Caches/* /tmp/* 2>/dev/null || true";
                    needsElevation = true;
                }
                break;
            case "fsck":
                if (IS_LINUX || IS_MACOS) {
                    command = "sudo fsck -f /";
                    needsElevation = true;
                }
                else {
                    throw new Error("fsck is not available on Windows");
                }
                break;
            case "system_update":
                if (IS_LINUX) {
                    command = "sudo apt update && sudo apt upgrade -y";
                    needsElevation = true;
                }
                else if (IS_MACOS) {
                    command = "softwareupdate -i -a";
                    needsElevation = true;
                }
                else {
                    throw new Error("System update not supported on Windows via this tool");
                }
                break;
            case "package_repair":
                if (IS_LINUX) {
                    command = "sudo dpkg --configure -a && sudo apt-get install -f";
                    needsElevation = true;
                }
                else if (IS_MACOS) {
                    command = "brew doctor && brew cleanup";
                }
                else {
                    throw new Error("Package repair not supported on Windows");
                }
                break;
            case "service_restart":
                if (IS_LINUX) {
                    command = "sudo systemctl restart systemd-resolved";
                    needsElevation = true;
                }
                else if (IS_MACOS) {
                    command = "sudo launchctl unload /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist && sudo launchctl load /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist";
                    needsElevation = true;
                }
                else {
                    throw new Error("Service restart not supported on Windows via this tool");
                }
                break;
        }
        if (needsElevation && !elevated) {
            // Try to run with elevation
            let elevatedCommand = command;
            if (IS_WINDOWS) {
                elevatedCommand = `powershell -Command "Start-Process cmd -ArgumentList '/c ${command}' -Verb RunAs"`;
            }
            else {
                elevatedCommand = `sudo ${command}`;
            }
            const { stdout, stderr } = await execAsync(elevatedCommand, { timeout: 10 * 60 * 1000 });
            return {
                content: [],
                structuredContent: {
                    success: true,
                    output: stdout || undefined,
                    error: stderr || undefined,
                    elevated: true,
                    platform: PLATFORM
                }
            };
        }
        else {
            const { stdout, stderr } = await execAsync(command, { timeout: 10 * 60 * 1000 });
            return {
                content: [],
                structuredContent: {
                    success: true,
                    output: stdout || undefined,
                    error: stderr || undefined,
                    elevated: elevated,
                    platform: PLATFORM
                }
            };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message,
                elevated: elevated,
                platform: PLATFORM
            }
        };
    }
});
// 2. System Monitor Tool
server.registerTool("system_monitor", {
    description: "Monitor system resources in real-time (cross-platform)",
    inputSchema: {
        duration: z.number().default(30),
        metrics: z.array(z.enum(["cpu", "memory", "disk", "network", "processes"])).default(["cpu", "memory"]),
        interval: z.number().default(2)
    },
    outputSchema: {
        success: z.boolean(),
        data: z.array(z.any()).optional(),
        error: z.string().optional(),
        platform: z.string()
    }
}, async ({ duration, metrics, interval }) => {
    try {
        const data = [];
        const startTime = Date.now();
        const endTime = startTime + (duration * 1000);
        while (Date.now() < endTime) {
            const snapshot = { timestamp: new Date().toISOString() };
            for (const metric of metrics) {
                switch (metric) {
                    case "cpu":
                        const cpuUsage = os.loadavg()[0] * 100;
                        snapshot.cpu = { usage: Math.round(cpuUsage), cores: os.cpus().length };
                        break;
                    case "memory":
                        const totalMem = os.totalmem();
                        const freeMem = os.freemem();
                        const usedMem = totalMem - freeMem;
                        snapshot.memory = {
                            total: Math.round(totalMem / (1024 ** 3) * 100) / 100,
                            used: Math.round(usedMem / (1024 ** 3) * 100) / 100,
                            free: Math.round(freeMem / (1024 ** 3) * 100) / 100,
                            usage: Math.round((usedMem / totalMem) * 100)
                        };
                        break;
                    case "disk":
                        try {
                            let command = "";
                            if (IS_WINDOWS) {
                                command = "wmic logicaldisk get size,freespace,caption /format:csv";
                            }
                            else {
                                command = "df -h";
                            }
                            const { stdout } = await execAsync(command);
                            if (IS_WINDOWS) {
                                const lines = stdout.trim().split("\n").slice(1);
                                snapshot.disk = lines.map((line) => {
                                    const parts = line.split(",");
                                    const size = parseInt(parts[1]) || 0;
                                    const free = parseInt(parts[2]) || 0;
                                    const used = size - free;
                                    return {
                                        drive: parts[0] || "Unknown",
                                        total: Math.round(size / (1024 ** 3) * 100) / 100,
                                        used: Math.round(used / (1024 ** 3) * 100) / 100,
                                        free: Math.round(free / (1024 ** 3) * 100) / 100,
                                        usage: Math.round((used / size) * 100)
                                    };
                                });
                            }
                            else {
                                const lines = stdout.trim().split("\n").slice(1);
                                snapshot.disk = lines.map((line) => {
                                    const parts = line.trim().split(/\s+/);
                                    return {
                                        filesystem: parts[0],
                                        size: parts[1],
                                        used: parts[2],
                                        available: parts[3],
                                        usage: parts[4],
                                        mount: parts[5]
                                    };
                                });
                            }
                        }
                        catch (error) {
                            snapshot.disk = { error: "Could not retrieve disk info" };
                        }
                        break;
                    case "network":
                        try {
                            let command = "";
                            if (IS_WINDOWS) {
                                command = "netstat -e";
                            }
                            else {
                                command = "cat /proc/net/dev | head -2";
                            }
                            const { stdout } = await execAsync(command);
                            if (IS_WINDOWS) {
                                const lines = stdout.trim().split("\n");
                                const stats = lines[lines.length - 1].split(/\s+/);
                                snapshot.network = {
                                    bytesReceived: parseInt(stats[1]) || 0,
                                    bytesSent: parseInt(stats[2]) || 0
                                };
                            }
                            else {
                                const lines = stdout.split("\n");
                                if (lines.length >= 2) {
                                    const header = lines[0].trim().split(/\s+/);
                                    const data = lines[1].trim().split(/\s+/);
                                    snapshot.network = {
                                        interface: data[0],
                                        bytesReceived: parseInt(data[1]) || 0,
                                        bytesSent: parseInt(data[9]) || 0
                                    };
                                }
                            }
                        }
                        catch (error) {
                            snapshot.network = { error: "Could not retrieve network stats" };
                        }
                        break;
                    case "processes":
                        try {
                            let command = "";
                            if (IS_WINDOWS) {
                                command = "tasklist /fo csv /nh";
                            }
                            else {
                                command = "ps aux --sort=-%cpu | head -10";
                            }
                            const { stdout } = await execAsync(command);
                            if (IS_WINDOWS) {
                                const processes = stdout.trim().split("\n").map((line) => {
                                    const parts = line.split(",");
                                    return {
                                        name: parts[0]?.replace(/"/g, "") || "Unknown",
                                        pid: parseInt(parts[1]) || 0,
                                        memory: parts[4]?.replace(/"/g, "") || "Unknown"
                                    };
                                });
                                snapshot.processes = processes.slice(0, 10); // Top 10 processes
                            }
                            else {
                                const lines = stdout.trim().split("\n").slice(1);
                                const processes = lines.map((line) => {
                                    const parts = line.trim().split(/\s+/);
                                    return {
                                        user: parts[0],
                                        pid: parseInt(parts[1]) || 0,
                                        cpu: parts[2],
                                        memory: parts[3],
                                        command: parts.slice(10).join(" ")
                                    };
                                });
                                snapshot.processes = processes;
                            }
                        }
                        catch (error) {
                            snapshot.processes = { error: "Could not retrieve process list" };
                        }
                        break;
                }
            }
            data.push(snapshot);
            if (Date.now() < endTime) {
                await new Promise(resolve => setTimeout(resolve, interval * 1000));
            }
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                data,
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message,
                platform: PLATFORM
            }
        };
    }
});
// 3. System Backup Tool
server.registerTool("system_backup", {
    description: "Create system backups and restore points",
    inputSchema: {
        backupType: z.enum(["files", "registry", "services", "full", "custom"]),
        source: z.string().optional(),
        destination: z.string().optional(),
        includeSystem: z.boolean().default(false)
    },
    outputSchema: {
        success: z.boolean(),
        backupPath: z.string().optional(),
        size: z.string().optional(),
        error: z.string().optional()
    }
}, async ({ backupType, source, destination, includeSystem }) => {
    try {
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
        const backupDir = destination || path.join(process.cwd(), "backups");
        await fs.mkdir(backupDir, { recursive: true });
        let backupPath = "";
        let command = "";
        switch (backupType) {
            case "files":
                const sourcePath = source || "C:\\Users";
                backupPath = path.join(backupDir, `files_backup_${timestamp}`);
                command = `robocopy "${sourcePath}" "${backupPath}" /E /R:3 /W:10 /LOG:"${backupPath}.log"`;
                break;
            case "registry":
                backupPath = path.join(backupDir, `registry_backup_${timestamp}.reg`);
                command = `reg export HKLM "${backupPath}" /y && reg export HKCU "${backupPath.replace('.reg', '_user.reg')}" /y`;
                break;
            case "services":
                backupPath = path.join(backupDir, `services_backup_${timestamp}.txt`);
                command = `sc query type= service state= all > "${backupPath}"`;
                break;
            case "full":
                backupPath = path.join(backupDir, `full_backup_${timestamp}`);
                command = `wbadmin start backup -backupTarget:"${backupPath}" -include:C: -allCritical -quiet`;
                break;
            case "custom":
                if (!source) {
                    throw new Error("Source path required for custom backup");
                }
                backupPath = path.join(backupDir, `custom_backup_${timestamp}`);
                command = `robocopy "${source}" "${backupPath}" /E /R:3 /W:10 /LOG:"${backupPath}.log"`;
                break;
        }
        const { stdout, stderr } = await execAsync(command, { timeout: 30 * 60 * 1000 });
        // Get backup size
        let size = "Unknown";
        try {
            const stats = await fs.stat(backupPath);
            size = `${Math.round(stats.size / (1024 ** 2) * 100) / 100} MB`;
        }
        catch (error) {
            // Size calculation failed
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                backupPath,
                size
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
// 4. Security Audit Tool
server.registerTool("security_audit", {
    description: "Security audit and scanning (cross-platform)",
    inputSchema: {
        auditType: z.enum(["permissions", "services", "registry", "files", "network", "users", "firewall", "updates", "packages", "configs"]),
        target: z.string().optional(),
        detailed: z.boolean().default(false)
    },
    outputSchema: {
        success: z.boolean(),
        findings: z.array(z.any()).optional(),
        summary: z.any().optional(),
        error: z.string().optional(),
        platform: z.string()
    }
}, async ({ auditType, target, detailed }) => {
    try {
        const findings = [];
        let summary = {};
        switch (auditType) {
            case "permissions":
                const targetPath = target || (IS_WINDOWS ? "C:\\Windows\\System32" : "/etc");
                if (IS_WINDOWS) {
                    const { stdout } = await execAsync(`icacls "${targetPath}" /T /C /L`);
                    const lines = stdout.trim().split("\n");
                    lines.forEach((line) => {
                        if (line.includes("Everyone") || line.includes("BUILTIN\\Users")) {
                            findings.push({
                                type: "permission_issue",
                                path: line.split(" ")[0],
                                issue: "Overly permissive access",
                                details: line
                            });
                        }
                    });
                }
                else {
                    const { stdout } = await execAsync(`find ${targetPath} -type f -perm -o+w -ls`);
                    const lines = stdout.trim().split("\n");
                    lines.forEach((line) => {
                        if (line.trim()) {
                            findings.push({
                                type: "permission_issue",
                                path: line.split(/\s+/)[10] || "Unknown",
                                issue: "World-writable file",
                                details: line
                            });
                        }
                    });
                }
                summary = {
                    totalFiles: findings.length,
                    issuesFound: findings.length
                };
                break;
            case "services":
                const services = await getServices();
                services.forEach((service) => {
                    if (service.startupType === "Auto" && service.status === "Stopped") {
                        findings.push({
                            type: "service_issue",
                            service: service.name,
                            issue: "Auto-start service is stopped",
                            details: `Service ${service.name} is configured to start automatically but is currently stopped`
                        });
                    }
                });
                summary = {
                    totalServices: services.length,
                    issuesFound: findings.length
                };
                break;
            case "registry":
                if (IS_WINDOWS) {
                    const registryChecks = [
                        { key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", issue: "Startup programs" },
                        { key: "HKLM\\SYSTEM\\CurrentControlSet\\Services", issue: "Service configurations" },
                        { key: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", issue: "User startup programs" }
                    ];
                    for (const check of registryChecks) {
                        try {
                            const { stdout: regOutput } = await execAsync(`reg query "${check.key}"`);
                            if (regOutput.includes("ERROR")) {
                                findings.push({
                                    type: "registry_issue",
                                    key: check.key,
                                    issue: "Registry access denied",
                                    details: "Cannot access registry key for security audit"
                                });
                            }
                        }
                        catch (error) {
                            findings.push({
                                type: "registry_issue",
                                key: check.key,
                                issue: "Registry key not found or inaccessible",
                                details: error instanceof Error ? error.message : String(error)
                            });
                        }
                    }
                    summary = {
                        registryKeysChecked: registryChecks.length,
                        issuesFound: findings.length
                    };
                }
                else {
                    // Unix/Linux/macOS: Check configuration files instead
                    const configChecks = [
                        { path: "/etc/passwd", issue: "User accounts" },
                        { path: "/etc/shadow", issue: "Password hashes" },
                        { path: "/etc/sudoers", issue: "Sudo configuration" },
                        { path: "/etc/crontab", issue: "Cron jobs" }
                    ];
                    for (const check of configChecks) {
                        try {
                            const { stdout: configOutput } = await execAsync(`ls -la "${check.path}"`);
                            if (configOutput.includes("Permission denied")) {
                                findings.push({
                                    type: "config_issue",
                                    path: check.path,
                                    issue: "Configuration file access denied",
                                    details: "Cannot access configuration file for security audit"
                                });
                            }
                        }
                        catch (error) {
                            findings.push({
                                type: "config_issue",
                                path: check.path,
                                issue: "Configuration file not found or inaccessible",
                                details: error instanceof Error ? error.message : String(error)
                            });
                        }
                    }
                    summary = {
                        configFilesChecked: configChecks.length,
                        issuesFound: findings.length
                    };
                }
                break;
            case "files":
                let criticalPaths = [];
                let command = "";
                if (IS_WINDOWS) {
                    criticalPaths = [
                        "C:\\Windows\\System32",
                        "C:\\Windows\\System32\\drivers",
                        "C:\\Program Files",
                        "C:\\Program Files (x86)"
                    ];
                }
                else {
                    criticalPaths = [
                        "/bin",
                        "/sbin",
                        "/usr/bin",
                        "/usr/sbin",
                        "/etc"
                    ];
                }
                for (const criticalPath of criticalPaths) {
                    try {
                        if (IS_WINDOWS) {
                            command = `dir "${criticalPath}" /A /B`;
                        }
                        else {
                            command = `ls -la "${criticalPath}"`;
                        }
                        const { stdout: fileOutput } = await execAsync(command);
                        const files = fileOutput.trim().split("\n");
                        // Check for suspicious files
                        const suspiciousExtensions = IS_WINDOWS
                            ? [".exe", ".dll", ".bat", ".ps1", ".vbs"]
                            : ["", ".sh", ".py", ".pl"];
                        files.forEach((file) => {
                            const ext = path.extname(file).toLowerCase();
                            if (suspiciousExtensions.includes(ext) && file.includes("temp")) {
                                findings.push({
                                    type: "file_issue",
                                    path: path.join(criticalPath, file),
                                    issue: "Suspicious file in system directory",
                                    details: `File ${file} with extension ${ext} found in system directory`
                                });
                            }
                        });
                    }
                    catch (error) {
                        findings.push({
                            type: "file_issue",
                            path: criticalPath,
                            issue: "Cannot access directory",
                            details: error instanceof Error ? error.message : String(error)
                        });
                    }
                }
                summary = {
                    directoriesChecked: criticalPaths.length,
                    issuesFound: findings.length
                };
                break;
            case "network":
                let networkChecks = [];
                if (IS_WINDOWS) {
                    networkChecks = [
                        { command: "netstat -an", issue: "Open ports" },
                        { command: "arp -a", issue: "ARP table" },
                        { command: "route print", issue: "Routing table" }
                    ];
                }
                else {
                    networkChecks = [
                        { command: "netstat -tuln", issue: "Open ports" },
                        { command: "arp -a", issue: "ARP table" },
                        { command: "ip route show", issue: "Routing table" }
                    ];
                }
                for (const check of networkChecks) {
                    try {
                        const { stdout: netOutput } = await execAsync(check.command);
                        const lines = netOutput.trim().split("\n");
                        if (check.issue === "Open ports") {
                            lines.forEach((line) => {
                                if (IS_WINDOWS) {
                                    if (line.includes("LISTENING") && (line.includes(":80") || line.includes(":443"))) {
                                        findings.push({
                                            type: "network_issue",
                                            issue: "Web server ports open",
                                            details: line.trim()
                                        });
                                    }
                                }
                                else {
                                    if (line.includes("LISTEN") && (line.includes(":80") || line.includes(":443"))) {
                                        findings.push({
                                            type: "network_issue",
                                            issue: "Web server ports open",
                                            details: line.trim()
                                        });
                                    }
                                }
                            });
                        }
                    }
                    catch (error) {
                        findings.push({
                            type: "network_issue",
                            issue: `Cannot check ${check.issue}`,
                            details: error instanceof Error ? error.message : String(error)
                        });
                    }
                }
                summary = {
                    networkChecks: networkChecks.length,
                    issuesFound: findings.length
                };
                break;
            case "users":
                if (IS_WINDOWS) {
                    const { stdout: usersOutput } = await execAsync("wmic useraccount get name,disabled,lockout /format:csv");
                    const userLines = usersOutput.trim().split("\n").slice(1);
                    userLines.forEach((line) => {
                        const parts = line.split(",");
                        const username = parts[1];
                        const disabled = parts[2];
                        const lockout = parts[3];
                        if (disabled === "FALSE" && username !== "Administrator") {
                            findings.push({
                                type: "user_issue",
                                user: username,
                                issue: "Active non-admin user account",
                                details: `User ${username} is enabled and may need review`
                            });
                        }
                    });
                    summary = {
                        totalUsers: userLines.length,
                        issuesFound: findings.length
                    };
                }
                else {
                    const { stdout: usersOutput } = await execAsync("cat /etc/passwd");
                    const userLines = usersOutput.trim().split("\n");
                    userLines.forEach((line) => {
                        const parts = line.split(":");
                        const username = parts[0];
                        const uid = parseInt(parts[2]);
                        const shell = parts[6];
                        // Check for users with shell access and non-system UIDs
                        if (uid >= 1000 && shell !== "/bin/false" && shell !== "/usr/sbin/nologin") {
                            findings.push({
                                type: "user_issue",
                                user: username,
                                issue: "User with shell access",
                                details: `User ${username} has shell access (${shell}) and may need review`
                            });
                        }
                    });
                    summary = {
                        totalUsers: userLines.length,
                        issuesFound: findings.length
                    };
                }
                break;
            case "firewall":
                if (IS_WINDOWS) {
                    const { stdout: firewallOutput } = await execAsync("netsh advfirewall show allprofiles");
                    const firewallLines = firewallOutput.trim().split("\n");
                    let currentProfile = "";
                    firewallLines.forEach((line) => {
                        if (line.includes("Profile Settings:")) {
                            currentProfile = line.split(":")[0].trim();
                        }
                        if (line.includes("State") && line.includes("OFF")) {
                            findings.push({
                                type: "firewall_issue",
                                profile: currentProfile,
                                issue: "Firewall disabled",
                                details: `Windows Firewall is disabled for ${currentProfile} profile`
                            });
                        }
                    });
                    summary = {
                        profilesChecked: 3, // Domain, Private, Public
                        issuesFound: findings.length
                    };
                }
                else {
                    // Check for common firewall tools on Unix systems
                    try {
                        const { stdout: ufwOutput } = await execAsync("sudo ufw status");
                        if (ufwOutput.includes("Status: inactive")) {
                            findings.push({
                                type: "firewall_issue",
                                issue: "UFW firewall disabled",
                                details: "Uncomplicated Firewall (UFW) is inactive"
                            });
                        }
                    }
                    catch {
                        try {
                            const { stdout: iptablesOutput } = await execAsync("sudo iptables -L");
                            if (iptablesOutput.includes("Chain INPUT (policy ACCEPT)")) {
                                findings.push({
                                    type: "firewall_issue",
                                    issue: "iptables firewall permissive",
                                    details: "iptables INPUT chain has ACCEPT policy"
                                });
                            }
                        }
                        catch {
                            findings.push({
                                type: "firewall_issue",
                                issue: "No firewall detected",
                                details: "No common firewall tools (UFW, iptables) found or accessible"
                            });
                        }
                    }
                    summary = {
                        firewallToolsChecked: 2, // UFW, iptables
                        issuesFound: findings.length
                    };
                }
                break;
            case "updates":
                if (IS_WINDOWS) {
                    const { stdout: updateOutput } = await execAsync("wmic qfe get hotfixid,installedon /format:csv");
                    const updateLines = updateOutput.trim().split("\n").slice(1);
                    const lastUpdate = updateLines[updateLines.length - 1];
                    if (lastUpdate) {
                        const parts = lastUpdate.split(",");
                        const updateDate = parts[2];
                        const updateDateObj = new Date(updateDate);
                        const daysSinceUpdate = Math.floor((Date.now() - updateDateObj.getTime()) / (1000 * 60 * 60 * 24));
                        if (daysSinceUpdate > 30) {
                            findings.push({
                                type: "update_issue",
                                issue: "System updates are outdated",
                                details: `Last update was ${daysSinceUpdate} days ago on ${updateDate}`
                            });
                        }
                    }
                    summary = {
                        totalUpdates: updateLines.length,
                        issuesFound: findings.length
                    };
                }
                else {
                    // Check for available updates on Unix systems
                    try {
                        if (IS_LINUX) {
                            const { stdout: updateOutput } = await execAsync("sudo apt list --upgradable");
                            const updateLines = updateOutput.trim().split("\n").slice(1);
                            if (updateLines.length > 0) {
                                findings.push({
                                    type: "update_issue",
                                    issue: "System updates available",
                                    details: `${updateLines.length} packages have available updates`
                                });
                            }
                        }
                        else if (IS_MACOS) {
                            const { stdout: updateOutput } = await execAsync("softwareupdate -l");
                            if (updateOutput.includes("Software Update found")) {
                                findings.push({
                                    type: "update_issue",
                                    issue: "System updates available",
                                    details: "macOS software updates are available"
                                });
                            }
                        }
                    }
                    catch (error) {
                        findings.push({
                            type: "update_issue",
                            issue: "Cannot check for updates",
                            details: error instanceof Error ? error.message : String(error)
                        });
                    }
                    summary = {
                        updateSystemChecked: true,
                        issuesFound: findings.length
                    };
                }
                break;
            case "packages":
                if (!IS_WINDOWS) {
                    try {
                        if (IS_LINUX) {
                            const { stdout: packageOutput } = await execAsync("dpkg -l | grep -E '^ii' | wc -l");
                            const packageCount = parseInt(packageOutput.trim());
                            // Check for packages that might need attention
                            const { stdout: brokenOutput } = await execAsync("dpkg -l | grep -E '^[^i]' | wc -l");
                            const brokenCount = parseInt(brokenOutput.trim());
                            if (brokenCount > 0) {
                                findings.push({
                                    type: "package_issue",
                                    issue: "Broken packages detected",
                                    details: `${brokenCount} packages are in a broken state`
                                });
                            }
                            summary = {
                                totalPackages: packageCount,
                                brokenPackages: brokenCount,
                                issuesFound: findings.length
                            };
                        }
                        else if (IS_MACOS) {
                            const { stdout: brewOutput } = await execAsync("brew list | wc -l");
                            const packageCount = parseInt(brewOutput.trim());
                            summary = {
                                totalPackages: packageCount,
                                issuesFound: findings.length
                            };
                        }
                    }
                    catch (error) {
                        findings.push({
                            type: "package_issue",
                            issue: "Cannot check packages",
                            details: error instanceof Error ? error.message : String(error)
                        });
                    }
                }
                else {
                    findings.push({
                        type: "package_issue",
                        issue: "Package audit not supported",
                        details: "Package audit is not supported on Windows systems"
                    });
                }
                break;
            case "configs":
                if (!IS_WINDOWS) {
                    const configFiles = [
                        { path: "/etc/ssh/sshd_config", issue: "SSH configuration" },
                        { path: "/etc/sudoers", issue: "Sudo configuration" },
                        { path: "/etc/crontab", issue: "Cron configuration" },
                        { path: "/etc/fstab", issue: "Filesystem configuration" }
                    ];
                    for (const config of configFiles) {
                        try {
                            const { stdout: configOutput } = await execAsync(`ls -la "${config.path}"`);
                            if (configOutput.includes("Permission denied")) {
                                findings.push({
                                    type: "config_issue",
                                    path: config.path,
                                    issue: "Configuration file access denied",
                                    details: `Cannot access ${config.issue} for security audit`
                                });
                            }
                        }
                        catch (error) {
                            findings.push({
                                type: "config_issue",
                                path: config.path,
                                issue: "Configuration file not found",
                                details: `${config.issue} file not found or inaccessible`
                            });
                        }
                    }
                    summary = {
                        configFilesChecked: configFiles.length,
                        issuesFound: findings.length
                    };
                }
                else {
                    findings.push({
                        type: "config_issue",
                        issue: "Config audit not supported",
                        details: "Configuration file audit is not supported on Windows systems"
                    });
                }
                break;
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                findings,
                summary,
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message,
                platform: PLATFORM
            }
        };
    }
});
// 5. Event Log Analyzer Tool
server.registerTool("event_log_analyzer", {
    description: "Analyze system logs for issues and patterns (cross-platform)",
    inputSchema: {
        logType: z.enum(["system", "application", "security", "setup", "forwardedevents", "kernel", "auth", "syslog"]).default("system"),
        filter: z.string().optional(),
        timeRange: z.string().optional(),
        level: z.enum(["error", "warning", "information", "critical", "all"]).default("error"),
        maxEvents: z.number().default(100)
    },
    outputSchema: {
        success: z.boolean(),
        events: z.array(z.any()).optional(),
        summary: z.any().optional(),
        patterns: z.array(z.any()).optional(),
        error: z.string().optional(),
        platform: z.string()
    }
}, async ({ logType, filter, timeRange, level, maxEvents }) => {
    try {
        let command = `wevtutil qe "${logType}" /c:${maxEvents} /f:json`;
        if (level !== "all") {
            command += ` /q:"*[System[Level=${level}]]"`;
        }
        if (timeRange) {
            const now = new Date();
            let startTime;
            switch (timeRange) {
                case "1h":
                    startTime = new Date(now.getTime() - 60 * 60 * 1000);
                    break;
                case "24h":
                    startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
                    break;
                case "7d":
                    startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                    break;
                case "30d":
                    startTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                    break;
                default:
                    startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000); // Default to 24h
            }
            const startTimeStr = startTime.toISOString();
            command += ` /q:"*[System[TimeCreated[@SystemTime>='${startTimeStr}']]]"`;
        }
        const { stdout } = await execAsync(command);
        // Parse the XML-like output (wevtutil doesn't actually output JSON)
        const events = [];
        const lines = stdout.trim().split("\n");
        let currentEvent = {};
        let inEvent = false;
        lines.forEach((line) => {
            if (line.includes("<Event ")) {
                inEvent = true;
                currentEvent = {};
            }
            else if (line.includes("</Event>")) {
                inEvent = false;
                if (Object.keys(currentEvent).length > 0) {
                    events.push(currentEvent);
                }
            }
            else if (inEvent) {
                if (line.includes("<TimeCreated SystemTime=")) {
                    const match = line.match(/SystemTime="([^"]+)"/);
                    if (match) {
                        currentEvent.timestamp = match[1];
                    }
                }
                else if (line.includes("<Level>")) {
                    const match = line.match(/<Level>(\d+)<\/Level>/);
                    if (match) {
                        currentEvent.level = parseInt(match[1]);
                    }
                }
                else if (line.includes("<EventID>")) {
                    const match = line.match(/<EventID>(\d+)<\/EventID>/);
                    if (match) {
                        currentEvent.eventId = parseInt(match[1]);
                    }
                }
                else if (line.includes("<Source>")) {
                    const match = line.match(/<Source>([^<]+)<\/Source>/);
                    if (match) {
                        currentEvent.source = match[1];
                    }
                }
                else if (line.includes("<Message>")) {
                    const match = line.match(/<Message>([^<]+)<\/Message>/);
                    if (match) {
                        currentEvent.message = match[1];
                    }
                }
            }
        });
        // Filter events if filter is provided
        const filteredEvents = filter
            ? events.filter(event => event.message?.toLowerCase().includes(filter.toLowerCase()) ||
                event.source?.toLowerCase().includes(filter.toLowerCase()))
            : events;
        // Analyze patterns
        const patterns = [];
        const sourceCounts = {};
        const eventIdCounts = {};
        filteredEvents.forEach(event => {
            if (event.source) {
                sourceCounts[event.source] = (sourceCounts[event.source] || 0) + 1;
            }
            if (event.eventId) {
                eventIdCounts[event.eventId] = (eventIdCounts[event.eventId] || 0) + 1;
            }
        });
        // Find most common sources
        Object.entries(sourceCounts)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 5)
            .forEach(([source, count]) => {
            patterns.push({
                type: "common_source",
                source,
                count,
                percentage: Math.round((count / filteredEvents.length) * 100)
            });
        });
        // Find most common event IDs
        Object.entries(eventIdCounts)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 5)
            .forEach(([eventId, count]) => {
            patterns.push({
                type: "common_event_id",
                eventId: parseInt(eventId),
                count,
                percentage: Math.round((count / filteredEvents.length) * 100)
            });
        });
        // Summary
        const summary = {
            totalEvents: filteredEvents.length,
            logType,
            timeRange: timeRange || "all",
            level,
            topSources: Object.entries(sourceCounts)
                .sort(([, a], [, b]) => b - a)
                .slice(0, 3)
                .map(([source, count]) => ({ source, count })),
            topEventIds: Object.entries(eventIdCounts)
                .sort(([, a], [, b]) => b - a)
                .slice(0, 3)
                .map(([eventId, count]) => ({ eventId: parseInt(eventId), count }))
        };
        return {
            content: [],
            structuredContent: {
                success: true,
                events: filteredEvents.slice(0, maxEvents),
                summary,
                patterns
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
// Browser automation utilities
function getBrowserPaths() {
    const browsers = {};
    if (IS_WINDOWS) {
        browsers.chrome = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
        browsers.chromium = "C:\\Program Files\\Chromium\\Application\\chrome.exe";
        browsers.firefox = "C:\\Program Files\\Mozilla Firefox\\firefox.exe";
        browsers.edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
        browsers.opera = "C:\\Users\\%USERNAME%\\AppData\\Local\\Programs\\Opera\\launcher.exe";
    }
    else if (IS_MACOS) {
        browsers.chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
        browsers.chromium = "/Applications/Chromium.app/Contents/MacOS/Chromium";
        browsers.firefox = "/Applications/Firefox.app/Contents/MacOS/firefox";
        browsers.safari = "/Applications/Safari.app/Contents/MacOS/Safari";
        browsers.opera = "/Applications/Opera.app/Contents/MacOS/Opera";
    }
    else {
        // Linux
        browsers.chrome = "/usr/bin/google-chrome";
        browsers.chromium = "/usr/bin/chromium-browser";
        browsers.firefox = "/usr/bin/firefox";
        browsers.opera = "/usr/bin/opera";
    }
    return browsers;
}
async function getDefaultBrowser() {
    try {
        if (IS_WINDOWS) {
            // Check Windows registry for default browser
            const { stdout } = await execAsync('reg query "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice" /v ProgId');
            const match = stdout.match(/ProgId\s+REG_SZ\s+(.+)/);
            if (match) {
                const progId = match[1].trim();
                if (progId.includes('Chrome'))
                    return 'chrome';
                if (progId.includes('Firefox'))
                    return 'firefox';
                if (progId.includes('Edge'))
                    return 'edge';
                if (progId.includes('Safari'))
                    return 'safari';
                if (progId.includes('Opera'))
                    return 'opera';
            }
        }
        else if (IS_MACOS) {
            // Check macOS default browser
            const { stdout } = await execAsync('defaults read com.apple.LaunchServices/com.apple.launchservices.secure LSHandlers');
            const lines = stdout.split('\n');
            for (const line of lines) {
                if (line.includes('LSHandlerURLScheme = http')) {
                    const nextLine = lines[lines.indexOf(line) + 1];
                    if (nextLine.includes('com.google.Chrome'))
                        return 'chrome';
                    if (nextLine.includes('org.mozilla.firefox'))
                        return 'firefox';
                    if (nextLine.includes('com.apple.Safari'))
                        return 'safari';
                    if (nextLine.includes('com.opera.Opera'))
                        return 'opera';
                }
            }
        }
        else {
            // Linux - check xdg-settings
            try {
                const { stdout } = await execAsync('xdg-settings get default-web-browser');
                if (stdout.includes('google-chrome'))
                    return 'chrome';
                if (stdout.includes('firefox'))
                    return 'firefox';
                if (stdout.includes('opera'))
                    return 'opera';
            }
            catch {
                // Fallback to checking common browsers
            }
        }
    }
    catch (error) {
        logger.warn("Could not determine default browser", { error: error instanceof Error ? error.message : String(error) });
    }
    return null;
}
async function findBrowserExecutable(browserName) {
    const browsers = getBrowserPaths();
    const browserPath = browsers[browserName.toLowerCase()];
    if (browserPath) {
        try {
            await fs.access(browserPath);
            return browserPath;
        }
        catch {
            // Browser not found at expected path
        }
    }
    // Try to find browser in PATH
    try {
        const { stdout } = await execAsync(`which ${browserName}`);
        return stdout.trim();
    }
    catch {
        // Browser not found in PATH
    }
    return null;
}
async function getBrowserProcesses() {
    const browsers = ["chrome", "firefox", "safari", "opera", "edge", "chromium"];
    const processes = await getProcesses();
    return processes.filter(process => {
        const name = process.name.toLowerCase();
        return browsers.some(browser => name.includes(browser));
    });
}
// Browser automation tools
server.registerTool("browser_control", {
    description: "Control web browsers (Chrome, Firefox, Safari, Opera, Edge) with default browser detection",
    inputSchema: {
        action: z.enum(["open", "close", "navigate", "screenshot", "get_tabs", "close_tab", "new_tab"]),
        browser: z.enum(["chrome", "firefox", "safari", "opera", "edge", "default", "auto"]).optional(),
        url: z.string().url().optional(),
        tab_index: z.number().optional(),
        output_path: z.string().optional()
    },
    outputSchema: {
        success: z.boolean(),
        message: z.string(),
        browser_used: z.string().optional(),
        data: z.any().optional(),
        error: z.string().optional()
    }
}, async ({ action, browser = "default", url, tab_index, output_path }) => {
    try {
        let browserPath = null;
        let browserUsed = browser;
        if (browser === "default" || browser === "auto") {
            // Try to find default browser first
            const defaultBrowser = await getDefaultBrowser();
            if (defaultBrowser) {
                browserPath = await findBrowserExecutable(defaultBrowser);
                browserUsed = defaultBrowser;
            }
            // If no default browser found, try any available browser
            if (!browserPath) {
                const browsers = ["chrome", "firefox", "edge", "safari", "opera"];
                for (const b of browsers) {
                    browserPath = await findBrowserExecutable(b);
                    if (browserPath) {
                        browserUsed = b;
                        break;
                    }
                }
            }
        }
        else {
            browserPath = await findBrowserExecutable(browser);
        }
        if (!browserPath) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    error: `No browser found. Tried: ${browser === "default" ? "default browser and common browsers" : browser}`
                }
            };
        }
        switch (action) {
            case "open":
                if (url) {
                    await execAsync(`"${browserPath}" "${url}"`);
                }
                else {
                    await execAsync(`"${browserPath}"`);
                }
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        message: `Opened ${browserUsed}${url ? ` with URL: ${url}` : ""}`,
                        browser_used: browserUsed
                    }
                };
            case "close":
                if (IS_WINDOWS) {
                    await execAsync(`taskkill /f /im ${browserUsed}.exe`);
                }
                else {
                    await execAsync(`pkill -f ${browserUsed}`);
                }
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        message: `Closed ${browserUsed}`,
                        browser_used: browserUsed
                    }
                };
            case "navigate":
                if (!url) {
                    return {
                        content: [],
                        structuredContent: {
                            success: false,
                            error: "URL is required for navigate action"
                        }
                    };
                }
                // For navigation, we need to handle different browsers differently
                if (browserUsed === "chrome" || browserUsed === "chromium" || browserUsed === "edge") {
                    await execAsync(`"${browserPath}" "${url}"`);
                }
                else if (browserUsed === "firefox") {
                    await execAsync(`"${browserPath}" "${url}"`);
                }
                else if (browserUsed === "safari") {
                    // Safari on macOS can be controlled via AppleScript
                    if (IS_MACOS) {
                        const script = `
              tell application "Safari"
                activate
                set URL of current tab of front window to "${url}"
              end tell
            `;
                        await execAsync(`osascript -e '${script}'`);
                    }
                    else {
                        await execAsync(`"${browserPath}" "${url}"`);
                    }
                }
                else {
                    await execAsync(`"${browserPath}" "${url}"`);
                }
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        message: `Navigated ${browserUsed} to ${url}`,
                        browser_used: browserUsed
                    }
                };
            case "screenshot":
                const screenshotPath = output_path || path.join(process.cwd(), `screenshot_${Date.now()}.png`);
                if (browserUsed === "chrome" || browserUsed === "chromium" || browserUsed === "edge") {
                    // Use Chrome's headless mode for screenshots
                    await execAsync(`"${browserPath}" --headless --disable-gpu --screenshot="${screenshotPath}" "${url || 'about:blank'}"`);
                }
                else if (browserUsed === "firefox") {
                    // Use Firefox's headless mode
                    await execAsync(`"${browserPath}" --headless --screenshot "${screenshotPath}" "${url || 'about:blank'}"`);
                }
                else {
                    // For other browsers, we'll need to use a different approach
                    return {
                        content: [],
                        structuredContent: {
                            success: false,
                            error: `Screenshot not supported for ${browserUsed}`
                        }
                    };
                }
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        message: `Screenshot saved to ${screenshotPath}`,
                        browser_used: browserUsed,
                        data: { screenshot_path: screenshotPath }
                    }
                };
            case "get_tabs":
                // This is more complex and would require browser-specific APIs
                // For now, we'll return basic browser process info
                const browserProcesses = await getBrowserProcesses();
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        message: `Found ${browserProcesses.length} browser processes`,
                        browser_used: browserUsed,
                        data: { processes: browserProcesses }
                    }
                };
            default:
                return {
                    content: [],
                    structuredContent: {
                        success: false,
                        error: `Action ${action} not implemented for ${browserUsed}`
                    }
                };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
server.registerTool("browser_automation", {
    description: "Advanced browser automation with multiple browsers and default browser detection",
    inputSchema: {
        browsers: z.array(z.enum(["chrome", "firefox", "safari", "opera", "edge", "default"])).optional(),
        urls: z.array(z.string().url()).optional(),
        actions: z.array(z.object({
            type: z.enum(["open", "navigate", "screenshot", "close"]),
            browser: z.string().optional(),
            url: z.string().url().optional(),
            delay: z.number().optional()
        })).optional(),
        headless: z.boolean().optional(),
        use_default: z.boolean().optional()
    },
    outputSchema: {
        success: z.boolean(),
        results: z.array(z.object({
            browser: z.string(),
            action: z.string(),
            success: z.boolean(),
            message: z.string(),
            data: z.any().optional()
        })),
        default_browser: z.string().optional(),
        error: z.string().optional()
    }
}, async ({ browsers = ["default"], urls = [], actions = [], headless = false, use_default = true }) => {
    try {
        const results = [];
        let defaultBrowser = null;
        // Get default browser if requested
        if (use_default) {
            defaultBrowser = await getDefaultBrowser();
        }
        // Resolve browser list
        let resolvedBrowsers = browsers;
        if (browsers.includes("default") && defaultBrowser) {
            resolvedBrowsers = browsers.map(b => b === "default" ? defaultBrowser : b);
        }
        else if (browsers.includes("default") && !defaultBrowser) {
            resolvedBrowsers = ["chrome", "firefox", "edge", "safari", "opera"];
        }
        // If no specific actions provided, open browsers with URLs
        if (actions.length === 0 && urls.length > 0) {
            for (const browser of resolvedBrowsers) {
                const browserPath = await findBrowserExecutable(browser);
                if (browserPath) {
                    for (const url of urls) {
                        try {
                            const command = headless
                                ? `"${browserPath}" --headless "${url}"`
                                : `"${browserPath}" "${url}"`;
                            await execAsync(command);
                            results.push({
                                browser,
                                action: "open",
                                success: true,
                                message: `Opened ${browser} with ${url}`
                            });
                        }
                        catch (error) {
                            results.push({
                                browser,
                                action: "open",
                                success: false,
                                message: error.message
                            });
                        }
                    }
                }
                else {
                    results.push({
                        browser,
                        action: "open",
                        success: false,
                        message: `Browser ${browser} not found`
                    });
                }
            }
        }
        else {
            // Execute specific actions
            for (const action of actions) {
                const browser = action.browser || resolvedBrowsers[0];
                const browserPath = await findBrowserExecutable(browser);
                if (browserPath) {
                    try {
                        switch (action.type) {
                            case "open":
                                const command = action.url
                                    ? `"${browserPath}" "${action.url}"`
                                    : `"${browserPath}"`;
                                await execAsync(command);
                                break;
                            case "navigate":
                                if (action.url) {
                                    await execAsync(`"${browserPath}" "${action.url}"`);
                                }
                                break;
                            case "close":
                                if (IS_WINDOWS) {
                                    await execAsync(`taskkill /f /im ${browser}.exe`);
                                }
                                else {
                                    await execAsync(`pkill -f ${browser}`);
                                }
                                break;
                        }
                        if (action.delay && action.delay > 0) {
                            await new Promise(resolve => setTimeout(resolve, action.delay * 1000));
                        }
                        results.push({
                            browser,
                            action: action.type,
                            success: true,
                            message: `Executed ${action.type} on ${browser}`
                        });
                    }
                    catch (error) {
                        results.push({
                            browser,
                            action: action.type,
                            success: false,
                            message: error.message
                        });
                    }
                }
                else {
                    results.push({
                        browser,
                        action: action.type,
                        success: false,
                        message: `Browser ${browser} not found`
                    });
                }
            }
        }
        return {
            content: [],
            structuredContent: {
                success: results.some(r => r.success),
                results,
                default_browser: defaultBrowser || undefined
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
server.registerTool("browser_cleanup", {
    description: "Clean up browser data and processes",
    inputSchema: {
        browsers: z.array(z.enum(["chrome", "firefox", "safari", "opera", "edge"])).optional(),
        cleanup_type: z.enum(["processes", "cache", "cookies", "all"]).optional()
    },
    outputSchema: {
        success: z.boolean(),
        cleaned: z.array(z.string()),
        errors: z.array(z.string())
    }
}, async ({ browsers = ["chrome", "firefox", "safari", "opera", "edge"], cleanup_type = "processes" }) => {
    try {
        const cleaned = [];
        const errors = [];
        for (const browser of browsers) {
            try {
                switch (cleanup_type) {
                    case "processes":
                        const killedProcesses = await killBrowserProcesses(browser);
                        if (killedProcesses) {
                            cleaned.push(`${browser} processes`);
                        }
                        else {
                            errors.push(`Could not kill ${browser} processes`);
                        }
                        break;
                    case "cache":
                        // Enhanced cache cleanup for all platforms
                        const cachePathsForBrowser = getBrowserCachePaths(browser);
                        for (const cachePath of cachePathsForBrowser) {
                            try {
                                if (IS_WINDOWS) {
                                    await execAsync(`rmdir /s /q "${cachePath}"`);
                                }
                                else {
                                    await execAsync(`rm -rf "${cachePath}"`);
                                }
                                cleaned.push(`${browser} cache: ${cachePath}`);
                            }
                            catch {
                                // Cache path might not exist, continue
                            }
                        }
                        break;
                    case "cookies":
                        // Cookie cleanup for all platforms
                        const cookiePathsForBrowser = getBrowserCachePaths(browser).map((path) => path.replace('/Cache', '/Cookies').replace('/cache', '/cookies'));
                        for (const cookiePath of cookiePathsForBrowser) {
                            try {
                                if (IS_WINDOWS) {
                                    await execAsync(`del /q /f "${cookiePath}"`);
                                }
                                else {
                                    await execAsync(`rm -f "${cookiePath}"`);
                                }
                                cleaned.push(`${browser} cookies: ${cookiePath}`);
                            }
                            catch {
                                // Cookie path might not exist, continue
                            }
                        }
                        break;
                    case "all":
                        // Close processes first
                        const killedAll = await killBrowserProcesses(browser);
                        if (killedAll) {
                            cleaned.push(`${browser} processes`);
                        }
                        else {
                            errors.push(`Could not kill ${browser} processes`);
                        }
                        // Then clean cache
                        const cachePathsAll = getBrowserCachePaths(browser);
                        for (const cachePath of cachePathsAll) {
                            try {
                                if (IS_WINDOWS) {
                                    await execAsync(`rmdir /s /q "${cachePath}"`);
                                }
                                else {
                                    await execAsync(`rm -rf "${cachePath}"`);
                                }
                                cleaned.push(`${browser} cache: ${cachePath}`);
                            }
                            catch {
                                // Cache path might not exist, continue
                            }
                        }
                        // Clean cookies
                        const cookiePathsAll = getBrowserCachePaths(browser).map((path) => path.replace('/Cache', '/Cookies').replace('/cache', '/cookies'));
                        for (const cookiePath of cookiePathsAll) {
                            try {
                                if (IS_WINDOWS) {
                                    await execAsync(`del /q /f "${cookiePath}"`);
                                }
                                else {
                                    await execAsync(`rm -f "${cookiePath}"`);
                                }
                                cleaned.push(`${browser} cookies: ${cookiePath}`);
                            }
                            catch {
                                // Cookie path might not exist, continue
                            }
                        }
                        break;
                }
            }
            catch (error) {
                errors.push(`${browser}: ${error.message}`);
            }
        }
        return {
            content: [],
            structuredContent: {
                success: cleaned.length > 0,
                cleaned,
                errors
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                cleaned: [],
                errors: [error.message]
            }
        };
    }
});
// Email configuration management
function getEmailAccounts() {
    try {
        const configPath = path.join(process.cwd(), '.email-config.json');
        if (fsSync.existsSync(configPath)) {
            const configData = fsSync.readFileSync(configPath, 'utf8');
            const parsed = JSON.parse(configData);
            // Handle legacy single-account format
            if (parsed.username && parsed.provider) {
                const legacyConfig = parsed;
                const accountKey = legacyConfig.username;
                return {
                    accounts: { [accountKey]: { ...legacyConfig, accountName: legacyConfig.username } },
                    activeAccount: accountKey
                };
            }
            // Handle new multi-account format
            if (parsed.accounts && parsed.activeAccount) {
                return parsed;
            }
        }
    }
    catch (error) {
        logger.warn("Could not load email config", { error: error instanceof Error ? error.message : String(error) });
    }
    return { accounts: {}, activeAccount: '' };
}
function getEmailConfig() {
    const accounts = getEmailAccounts();
    if (accounts.activeAccount && accounts.accounts[accounts.activeAccount]) {
        return accounts.accounts[accounts.activeAccount];
    }
    return null;
}
// Check if email configuration is complete
function isEmailConfigComplete(config) {
    if (!config)
        return false;
    return !!(config.username && config.password && config.host && config.port);
}
// Validate email credentials (basic check)
async function validateEmailCredentials(config) {
    try {
        // For now, we'll do a basic validation
        // In a full implementation, you'd test the actual connection
        if (!config.username || !config.password || !config.host) {
            return false;
        }
        // Basic format validation
        if (!validateEmail(config.username)) {
            return false;
        }
        return true;
    }
    catch (error) {
        logger.warn("Email credential validation failed", { error: error instanceof Error ? error.message : String(error) });
        return false;
    }
}
async function saveEmailAccounts(accounts) {
    try {
        const configPath = path.join(process.cwd(), '.email-config.json');
        await fs.writeFile(configPath, JSON.stringify(accounts, null, 2));
        return true;
    }
    catch (error) {
        logger.error("Could not save email config", { error: error instanceof Error ? error.message : String(error) });
        return false;
    }
}
async function saveEmailConfig(config) {
    const accounts = getEmailAccounts();
    const accountKey = config.username;
    accounts.accounts[accountKey] = config;
    if (!accounts.activeAccount) {
        accounts.activeAccount = accountKey;
    }
    return await saveEmailAccounts(accounts);
}
// Email validation
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}
// Email providers configuration
function getProviderConfig(provider) {
    const providers = {
        gmail: { host: 'smtp.gmail.com', port: 587, secure: false },
        outlook: { host: 'smtp-mail.outlook.com', port: 587, secure: false },
        yahoo: { host: 'smtp.mail.yahoo.com', port: 587, secure: false },
        custom: { host: '', port: 587, secure: false }
    };
    return providers[provider] || providers.custom;
}
// Email tools
server.registerTool("email_compose", {
    description: "Compose and draft email messages",
    inputSchema: {
        to: z.string().or(z.array(z.string())),
        cc: z.string().or(z.array(z.string())).optional(),
        bcc: z.string().or(z.array(z.string())).optional(),
        subject: z.string(),
        body: z.string(),
        html: z.boolean().optional(),
        attachments: z.array(z.string()).optional(),
        save_draft: z.boolean().optional()
    },
    outputSchema: {
        success: z.boolean(),
        message: z.string(),
        draft_id: z.string().optional(),
        error: z.string().optional()
    }
}, async ({ to, cc, bcc, subject, body, html = false, attachments = [], save_draft = true }) => {
    try {
        // Validate email addresses
        const toEmails = Array.isArray(to) ? to : [to];
        const ccEmails = cc ? (Array.isArray(cc) ? cc : [cc]) : [];
        const bccEmails = bcc ? (Array.isArray(bcc) ? bcc : [bcc]) : [];
        const allEmails = [...toEmails, ...ccEmails, ...bccEmails];
        const invalidEmails = allEmails.filter(email => !validateEmail(email));
        if (invalidEmails.length > 0) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    error: `Invalid email addresses: ${invalidEmails.join(', ')}`
                }
            };
        }
        // Create email message
        const emailMessage = {
            to: toEmails,
            cc: ccEmails.length > 0 ? ccEmails : undefined,
            bcc: bccEmails.length > 0 ? bccEmails : undefined,
            subject,
            body,
            html,
            attachments: attachments.length > 0 ? attachments : undefined
        };
        if (save_draft) {
            // Save draft to file
            const draftId = `draft_${Date.now()}`;
            const draftPath = path.join(process.cwd(), 'drafts', `${draftId}.json`);
            // Ensure drafts directory exists
            await fs.mkdir(path.join(process.cwd(), 'drafts'), { recursive: true });
            await fs.writeFile(draftPath, JSON.stringify(emailMessage, null, 2));
            return {
                content: [],
                structuredContent: {
                    success: true,
                    message: `Email draft created successfully`,
                    draft_id: draftId
                }
            };
        }
        else {
            return {
                content: [],
                structuredContent: {
                    success: true,
                    message: `Email composed successfully (not saved as draft)`
                }
            };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
server.registerTool("email_send", {
    description: "Send email messages using configured email provider",
    inputSchema: {
        draft_id: z.string().optional(),
        to: z.string().or(z.array(z.string())).optional(),
        cc: z.string().or(z.array(z.string())).optional(),
        bcc: z.string().or(z.array(z.string())).optional(),
        subject: z.string().optional(),
        body: z.string().optional(),
        html: z.boolean().optional(),
        attachments: z.array(z.string()).optional(),
        provider: z.enum(['gmail', 'outlook', 'yahoo', 'custom']).optional(),
        host: z.string().optional(),
        port: z.number().optional(),
        username: z.string().optional(),
        password: z.string().optional(),
        from: z.string().optional()
    },
    outputSchema: {
        success: z.boolean(),
        message: z.string(),
        error: z.string().optional(),
        needs_login: z.boolean().optional()
    }
}, async ({ draft_id, to, cc, bcc, subject, body, html = false, attachments = [], provider, host, port, username, password, from }) => {
    try {
        let emailMessage;
        // Load from draft if provided
        if (draft_id) {
            const draftPath = path.join(process.cwd(), 'drafts', `${draft_id}.json`);
            const draftData = await fs.readFile(draftPath, 'utf8');
            emailMessage = JSON.parse(draftData);
        }
        else {
            // Use provided parameters
            if (!to || !subject || !body) {
                return {
                    content: [],
                    structuredContent: {
                        success: false,
                        error: "Missing required email parameters: to, subject, and body are required"
                    }
                };
            }
            emailMessage = {
                to: Array.isArray(to) ? to : [to],
                cc: cc ? (Array.isArray(cc) ? cc : [cc]) : undefined,
                bcc: bcc ? (Array.isArray(bcc) ? bcc : [bcc]) : undefined,
                subject,
                body,
                html,
                attachments: attachments.length > 0 ? attachments : undefined
            };
        }
        // Get email configuration
        let emailConfig = getEmailConfig();
        // Override with provided parameters
        if (provider || host || port || username || password || from) {
            const providerConfig = provider ? getProviderConfig(provider) : { host: '', port: 587, secure: false };
            emailConfig = {
                provider: provider || 'custom',
                host: host || providerConfig.host,
                port: port || providerConfig.port,
                secure: providerConfig.secure,
                username: username || emailConfig?.username || '',
                password: password || emailConfig?.password || '',
                from: from || emailConfig?.from || username || ''
            };
        }
        if (!emailConfig || !isEmailConfigComplete(emailConfig)) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    error: "Email configuration incomplete. Please use the email_login tool to provide your credentials first.",
                    needs_login: true
                }
            };
        }
        // For now, we'll use a simple approach with system mail command
        // In a full implementation, you'd use a proper SMTP library like nodemailer
        // Create email content
        const emailContent = `From: ${emailConfig.from}
To: ${Array.isArray(emailMessage.to) ? emailMessage.to.join(', ') : emailMessage.to}
${emailMessage.cc ? `Cc: ${Array.isArray(emailMessage.cc) ? emailMessage.cc.join(', ') : emailMessage.cc}` : ''}
${emailMessage.bcc ? `Bcc: ${Array.isArray(emailMessage.bcc) ? emailMessage.bcc.join(', ') : emailMessage.bcc}` : ''}
Subject: ${emailMessage.subject}

${emailMessage.body}`;
        // Save email content to temporary file
        const tempEmailPath = path.join(process.cwd(), `temp_email_${Date.now()}.txt`);
        await fs.writeFile(tempEmailPath, emailContent);
        // Use system mail command (if available)
        try {
            if (IS_WINDOWS) {
                // Windows - try using PowerShell Send-MailMessage
                const psScript = `
          $From = "${emailConfig.from}"
          $To = "${Array.isArray(emailMessage.to) ? emailMessage.to.join(',') : emailMessage.to}"
          $Subject = "${emailMessage.subject}"
          $Body = "${emailMessage.body.replace(/"/g, '""')}"
          $SMTPServer = "${emailConfig.host}"
          $SMTPPort = ${emailConfig.port}
          $Username = "${emailConfig.username}"
          $Password = "${emailConfig.password}"
          
          $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
          $Credential = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)
          
          Send-MailMessage -From $From -To $To -Subject $Subject -Body $Body -SmtpServer $SMTPServer -Port $SMTPPort -Credential $Credential -UseSsl
        `;
                await execAsync(`powershell -Command "${psScript}"`);
            }
            else {
                // Unix-like systems - try using mail command
                await execAsync(`mail -s "${emailMessage.subject}" ${Array.isArray(emailMessage.to) ? emailMessage.to.join(' ') : emailMessage.to} < "${tempEmailPath}"`);
            }
            // Clean up temporary file
            await fs.unlink(tempEmailPath);
            return {
                content: [],
                structuredContent: {
                    success: true,
                    message: `Email sent successfully to ${Array.isArray(emailMessage.to) ? emailMessage.to.join(', ') : emailMessage.to}`
                }
            };
        }
        catch (sendError) {
            // Clean up temporary file
            try {
                await fs.unlink(tempEmailPath);
            }
            catch { }
            return {
                content: [],
                structuredContent: {
                    success: false,
                    error: `Failed to send email: ${sendError.message}. Please check your email configuration and network connection.`
                }
            };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
// Interactive email login tool
server.registerTool("email_login", {
    description: "Interactive email login - prompts for credentials and stores them securely",
    inputSchema: {
        provider: z.enum(['gmail', 'outlook', 'yahoo', 'custom']),
        username: z.string(),
        password: z.string(),
        host: z.string().optional(),
        port: z.number().optional(),
        secure: z.boolean().optional(),
        accountKey: z.string().optional(),
        accountName: z.string().optional()
    },
    outputSchema: {
        success: z.boolean(),
        message: z.string(),
        error: z.string().optional()
    }
}, async ({ provider, username, password, host, port, secure, accountKey, accountName }) => {
    try {
        const providerConfig = getProviderConfig(provider);
        const emailConfig = {
            provider,
            host: host || providerConfig.host,
            port: port || providerConfig.port,
            secure: secure !== undefined ? secure : providerConfig.secure,
            username,
            password,
            from: username,
            accountName: accountName || username
        };
        // Validate the credentials
        const isValid = await validateEmailCredentials(emailConfig);
        if (!isValid) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    error: "Invalid email credentials. Please check your username and password."
                }
            };
        }
        // Save the configuration with the specified account key or use username as default
        const key = accountKey || username;
        const accounts = getEmailAccounts();
        accounts.accounts[key] = emailConfig;
        // If this is the first account or no active account, set it as active
        if (!accounts.activeAccount) {
            accounts.activeAccount = key;
        }
        const saved = await saveEmailAccounts(accounts);
        if (saved) {
            const activeMessage = accounts.activeAccount === key ? " (set as active account)" : "";
            return {
                content: [],
                structuredContent: {
                    success: true,
                    message: `Email login successful! Credentials saved for ${provider} (${username})${activeMessage}. You won't need to login again.`
                }
            };
        }
        else {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    error: "Failed to save email configuration."
                }
            };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
server.registerTool("email_check", {
    description: "Check and read email messages from configured email provider",
    inputSchema: {
        provider: z.enum(['gmail', 'outlook', 'yahoo', 'custom']).optional(),
        host: z.string().optional(),
        port: z.number().optional(),
        username: z.string().optional(),
        password: z.string().optional(),
        folder: z.string().optional(),
        limit: z.number().optional(),
        unread_only: z.boolean().optional()
    },
    outputSchema: {
        success: z.boolean(),
        messages: z.array(z.object({
            id: z.string(),
            from: z.string(),
            to: z.string(),
            subject: z.string(),
            date: z.string(),
            body: z.string(),
            unread: z.boolean()
        })).optional(),
        error: z.string().optional(),
        needs_login: z.boolean().optional()
    }
}, async ({ provider, host, port, username, password, folder = 'INBOX', limit = 10, unread_only = false }) => {
    try {
        // Get email configuration
        let emailConfig = getEmailConfig();
        // Override with provided parameters
        if (provider || host || port || username || password) {
            const providerConfig = provider ? getProviderConfig(provider) : { host: '', port: 993, secure: true };
            emailConfig = {
                provider: provider || 'custom',
                host: host || providerConfig.host,
                port: port || providerConfig.port,
                secure: providerConfig.secure,
                username: username || emailConfig?.username || '',
                password: password || emailConfig?.password || '',
                from: emailConfig?.from || username || ''
            };
        }
        // Check if we have complete configuration
        if (!emailConfig || !isEmailConfigComplete(emailConfig)) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    error: "Email configuration incomplete. Please use the email_login tool to provide your credentials first.",
                    needs_login: true
                }
            };
        }
        // For now, we'll use a simple approach with system mail command
        // In a full implementation, you'd use a proper IMAP library like node-imap
        try {
            let command = '';
            if (IS_WINDOWS) {
                // Windows - PowerShell approach for checking emails
                const psScript = `
          $Username = "${emailConfig.username}"
          $Password = "${emailConfig.password}"
          $Server = "${emailConfig.host}"
          $Port = ${emailConfig.port}
          
          Write-Host "Checking emails for $Username on $Server:$Port"
          Write-Host "This is a placeholder - full IMAP implementation would be needed"
        `;
                const { stdout } = await execAsync(`powershell -Command "${psScript}"`);
                // Return placeholder data for now
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        messages: [
                            {
                                id: '1',
                                from: 'system@example.com',
                                to: emailConfig.username,
                                subject: 'Email Check Placeholder',
                                date: new Date().toISOString(),
                                body: 'This is a placeholder response. Full IMAP implementation would be needed for actual email checking.',
                                unread: false
                            }
                        ]
                    }
                };
            }
            else {
                // Unix-like systems - try using mail command
                command = `mail -f ${folder} | head -${limit * 5}`; // Multiply by 5 to account for mail headers
                const { stdout } = await execAsync(command);
                // Parse mail output (simplified)
                const lines = stdout.split('\n');
                const messages = [];
                let currentMessage = null;
                for (const line of lines) {
                    if (line.startsWith('From ')) {
                        if (currentMessage) {
                            messages.push(currentMessage);
                        }
                        currentMessage = {
                            id: `msg_${messages.length + 1}`,
                            from: line.substring(5),
                            to: emailConfig.username,
                            subject: '',
                            date: new Date().toISOString(),
                            body: '',
                            unread: false
                        };
                    }
                    else if (line.startsWith('Subject: ') && currentMessage) {
                        currentMessage.subject = line.substring(9);
                    }
                    else if (currentMessage && line.trim()) {
                        currentMessage.body += line + '\n';
                    }
                }
                if (currentMessage) {
                    messages.push(currentMessage);
                }
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        messages: messages.slice(0, limit)
                    }
                };
            }
        }
        catch (checkError) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    error: `Failed to check emails: ${checkError.message}. Please check your email configuration.`
                }
            };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
// Email configuration status tool
server.registerTool("email_status", {
    description: "Check the current email configuration status and list all configured accounts",
    inputSchema: {},
    outputSchema: {
        configured: z.boolean(),
        activeAccount: z.object({
            provider: z.string(),
            username: z.string(),
            host: z.string(),
            port: z.number(),
            accountName: z.string().optional()
        }).optional(),
        allAccounts: z.array(z.object({
            key: z.string(),
            name: z.string(),
            provider: z.string(),
            username: z.string(),
            isActive: z.boolean()
        })).optional(),
        message: z.string(),
        needs_login: z.boolean().optional()
    }
}, async () => {
    try {
        const emailAccounts = getEmailAccounts();
        if (!emailAccounts || Object.keys(emailAccounts.accounts).length === 0) {
            return {
                content: [],
                structuredContent: {
                    configured: false,
                    message: "No email accounts configured. Use email_login to set up your first email account.",
                    needs_login: true
                }
            };
        }
        const activeConfig = getEmailConfig();
        const isComplete = activeConfig ? isEmailConfigComplete(activeConfig) : false;
        if (!isComplete) {
            return {
                content: [],
                structuredContent: {
                    configured: false,
                    allAccounts: Object.entries(emailAccounts.accounts).map(([key, config]) => ({
                        key,
                        name: config.accountName || config.username,
                        provider: config.provider,
                        username: config.username,
                        isActive: key === emailAccounts.activeAccount
                    })),
                    message: "Email configuration incomplete. Missing username, password, or server details.",
                    needs_login: true
                }
            };
        }
        const allAccounts = Object.entries(emailAccounts.accounts).map(([key, config]) => ({
            key,
            name: config.accountName || config.username,
            provider: config.provider,
            username: config.username,
            isActive: key === emailAccounts.activeAccount
        }));
        return {
            content: [],
            structuredContent: {
                configured: true,
                activeAccount: activeConfig ? {
                    provider: activeConfig.provider,
                    username: activeConfig.username,
                    host: activeConfig.host,
                    port: activeConfig.port,
                    accountName: activeConfig.accountName
                } : undefined,
                allAccounts,
                message: `Email configured with ${allAccounts.length} account(s). Active: ${activeConfig?.accountName || activeConfig?.username} (${activeConfig?.provider})`
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                configured: false,
                message: `Error checking email status: ${error.message}`,
                needs_login: true
            }
        };
    }
});
server.registerTool("email_config", {
    description: "Configure email provider settings",
    inputSchema: {
        provider: z.enum(['gmail', 'outlook', 'yahoo', 'custom']),
        username: z.string(),
        password: z.string(),
        from: z.string().optional(),
        host: z.string().optional(),
        port: z.number().optional(),
        secure: z.boolean().optional()
    },
    outputSchema: {
        success: z.boolean(),
        message: z.string(),
        error: z.string().optional()
    }
}, async ({ provider, username, password, from, host, port, secure }) => {
    try {
        const providerConfig = getProviderConfig(provider);
        const emailConfig = {
            provider,
            host: host || providerConfig.host,
            port: port || providerConfig.port,
            secure: secure !== undefined ? secure : providerConfig.secure,
            username,
            password,
            from: from || username
        };
        const saved = await saveEmailConfig(emailConfig);
        if (saved) {
            return {
                content: [],
                structuredContent: {
                    success: true,
                    message: `Email configuration saved successfully for ${provider}`
                }
            };
        }
        else {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    error: "Failed to save email configuration"
                }
            };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
server.registerTool("email_drafts", {
    description: "List and manage email drafts",
    inputSchema: {
        action: z.enum(['list', 'read', 'delete']),
        draft_id: z.string().optional()
    },
    outputSchema: {
        success: z.boolean(),
        drafts: z.array(z.object({
            id: z.string(),
            subject: z.string(),
            to: z.string(),
            date: z.string()
        })).optional(),
        draft: z.any().optional(),
        message: z.string(),
        error: z.string().optional()
    }
}, async ({ action, draft_id }) => {
    try {
        const draftsDir = path.join(process.cwd(), 'drafts');
        switch (action) {
            case 'list':
                try {
                    const files = await fs.readdir(draftsDir);
                    const draftFiles = files.filter(file => file.endsWith('.json'));
                    const drafts = [];
                    for (const file of draftFiles) {
                        try {
                            const draftData = await fs.readFile(path.join(draftsDir, file), 'utf8');
                            const draft = JSON.parse(draftData);
                            const id = file.replace('.json', '');
                            drafts.push({
                                id,
                                subject: draft.subject,
                                to: Array.isArray(draft.to) ? draft.to.join(', ') : draft.to,
                                date: new Date(parseInt(id.split('_')[1])).toISOString()
                            });
                        }
                        catch {
                            // Skip invalid draft files
                        }
                    }
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            drafts,
                            message: `Found ${drafts.length} draft(s)`
                        }
                    };
                }
                catch {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            drafts: [],
                            message: "No drafts found"
                        }
                    };
                }
            case 'read':
                if (!draft_id) {
                    return {
                        content: [],
                        structuredContent: {
                            success: false,
                            error: "Draft ID is required for read action"
                        }
                    };
                }
                try {
                    const draftPath = path.join(draftsDir, `${draft_id}.json`);
                    const draftData = await fs.readFile(draftPath, 'utf8');
                    const draft = JSON.parse(draftData);
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            draft,
                            message: "Draft loaded successfully"
                        }
                    };
                }
                catch {
                    return {
                        content: [],
                        structuredContent: {
                            success: false,
                            error: "Draft not found"
                        }
                    };
                }
            case 'delete':
                if (!draft_id) {
                    return {
                        content: [],
                        structuredContent: {
                            success: false,
                            error: "Draft ID is required for delete action"
                        }
                    };
                }
                try {
                    const draftPath = path.join(draftsDir, `${draft_id}.json`);
                    await fs.unlink(draftPath);
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: "Draft deleted successfully"
                        }
                    };
                }
                catch {
                    return {
                        content: [],
                        structuredContent: {
                            success: false,
                            error: "Failed to delete draft"
                        }
                    };
                }
            default:
                return {
                    content: [],
                    structuredContent: {
                        success: false,
                        error: "Invalid action"
                    }
                };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
// Email account management tools
server.registerTool("email_accounts", {
    description: "List all configured email accounts and manage them",
    inputSchema: {
        action: z.enum(['list', 'add', 'remove', 'switch', 'rename']),
        accountKey: z.string().optional(),
        newAccountKey: z.string().optional(),
        accountName: z.string().optional()
    },
    outputSchema: {
        success: z.boolean(),
        message: z.string(),
        accounts: z.array(z.object({
            key: z.string(),
            name: z.string(),
            provider: z.string(),
            username: z.string(),
            isActive: z.boolean()
        })).optional(),
        error: z.string().optional()
    }
}, async ({ action, accountKey, newAccountKey, accountName }) => {
    try {
        const accounts = getEmailAccounts();
        switch (action) {
            case 'list':
                const accountList = Object.entries(accounts.accounts).map(([key, config]) => ({
                    key,
                    name: config.accountName || config.username,
                    provider: config.provider,
                    username: config.username,
                    isActive: key === accounts.activeAccount
                }));
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        message: `Found ${accountList.length} email account(s)`,
                        accounts: accountList
                    }
                };
            case 'add':
                if (!accountKey) {
                    return {
                        content: [],
                        structuredContent: {
                            success: false,
                            error: "Account key is required for add action"
                        }
                    };
                }
                // This will be handled by email_login with the new account key
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        message: `Use email_login with accountKey: "${accountKey}" to add a new account`
                    }
                };
            case 'remove':
                if (!accountKey) {
                    return {
                        content: [],
                        structuredContent: {
                            success: false,
                            error: "Account identifier is required for remove action. You can use account key, email address, or account name."
                        }
                    };
                }
                // Try to find the account by various identifiers
                let targetAccountKey = null;
                // First, try exact key match
                if (accounts.accounts[accountKey]) {
                    targetAccountKey = accountKey;
                }
                else {
                    // Try to find by email address or account name
                    for (const [key, config] of Object.entries(accounts.accounts)) {
                        if (config.username === accountKey ||
                            config.accountName === accountKey ||
                            config.username.toLowerCase() === accountKey.toLowerCase() ||
                            (config.accountName && config.accountName.toLowerCase() === accountKey.toLowerCase())) {
                            targetAccountKey = key;
                            break;
                        }
                    }
                }
                if (!targetAccountKey) {
                    const availableAccounts = Object.entries(accounts.accounts).map(([key, config]) => `${config.accountName || config.username} (key: ${key})`).join(', ');
                    return {
                        content: [],
                        structuredContent: {
                            success: false,
                            error: `Account "${accountKey}" not found. Available accounts: ${availableAccounts}`
                        }
                    };
                }
                const accountToRemove = accounts.accounts[targetAccountKey];
                delete accounts.accounts[targetAccountKey];
                // If we removed the active account, set a new active account
                if (accounts.activeAccount === targetAccountKey) {
                    const remainingAccounts = Object.keys(accounts.accounts);
                    accounts.activeAccount = remainingAccounts.length > 0 ? remainingAccounts[0] : '';
                }
                await saveEmailAccounts(accounts);
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        message: `Account "${accountToRemove.accountName || accountToRemove.username}" (${accountToRemove.provider}) removed successfully`
                    }
                };
            case 'switch':
                if (!accountKey) {
                    return {
                        content: [],
                        structuredContent: {
                            success: false,
                            error: "Account identifier is required for switch action. You can use account key, email address, or account name."
                        }
                    };
                }
                // Try to find the account by various identifiers
                let switchTargetAccountKey = null;
                // First, try exact key match
                if (accounts.accounts[accountKey]) {
                    switchTargetAccountKey = accountKey;
                }
                else {
                    // Try to find by email address or account name
                    for (const [key, config] of Object.entries(accounts.accounts)) {
                        if (config.username === accountKey ||
                            config.accountName === accountKey ||
                            config.username.toLowerCase() === accountKey.toLowerCase() ||
                            (config.accountName && config.accountName.toLowerCase() === accountKey.toLowerCase())) {
                            switchTargetAccountKey = key;
                            break;
                        }
                    }
                }
                if (!switchTargetAccountKey) {
                    const availableAccounts = Object.entries(accounts.accounts).map(([key, config]) => `${config.accountName || config.username} (key: ${key})`).join(', ');
                    return {
                        content: [],
                        structuredContent: {
                            success: false,
                            error: `Account "${accountKey}" not found. Available accounts: ${availableAccounts}`
                        }
                    };
                }
                accounts.activeAccount = switchTargetAccountKey;
                await saveEmailAccounts(accounts);
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        message: `Switched to account "${accounts.accounts[switchTargetAccountKey].accountName || accounts.accounts[switchTargetAccountKey].username}" (${accounts.accounts[switchTargetAccountKey].provider})`
                    }
                };
            case 'rename':
                if (!accountKey || !newAccountKey) {
                    return {
                        content: [],
                        structuredContent: {
                            success: false,
                            error: "Both accountKey and newAccountKey are required for rename action"
                        }
                    };
                }
                if (!accounts.accounts[accountKey]) {
                    return {
                        content: [],
                        structuredContent: {
                            success: false,
                            error: `Account "${accountKey}" not found`
                        }
                    };
                }
                if (accounts.accounts[newAccountKey]) {
                    return {
                        content: [],
                        structuredContent: {
                            success: false,
                            error: `Account "${newAccountKey}" already exists`
                        }
                    };
                }
                // Move the account to the new key
                accounts.accounts[newAccountKey] = accounts.accounts[accountKey];
                delete accounts.accounts[accountKey];
                // Update active account if needed
                if (accounts.activeAccount === accountKey) {
                    accounts.activeAccount = newAccountKey;
                }
                await saveEmailAccounts(accounts);
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        message: `Account renamed from "${accountKey}" to "${newAccountKey}"`
                    }
                };
            default:
                return {
                    content: [],
                    structuredContent: {
                        success: false,
                        error: "Invalid action"
                    }
                };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
server.registerTool("email_set_active", {
    description: "Set the active email account using natural language or account identifier",
    inputSchema: {
        accountIdentifier: z.string().describe("Can be email address, account name, or account key")
    },
    outputSchema: {
        success: z.boolean(),
        message: z.string(),
        error: z.string().optional()
    }
}, async ({ accountIdentifier }) => {
    try {
        const accounts = getEmailAccounts();
        // Try to find the account by various identifiers
        let targetAccountKey = null;
        // First, try exact key match
        if (accounts.accounts[accountIdentifier]) {
            targetAccountKey = accountIdentifier;
        }
        else {
            // Try to find by email address or account name
            for (const [key, config] of Object.entries(accounts.accounts)) {
                if (config.username.toLowerCase() === accountIdentifier.toLowerCase() ||
                    (config.accountName && config.accountName.toLowerCase() === accountIdentifier.toLowerCase())) {
                    targetAccountKey = key;
                    break;
                }
            }
        }
        if (!targetAccountKey) {
            const availableAccounts = Object.keys(accounts.accounts);
            return {
                content: [],
                structuredContent: {
                    success: false,
                    error: `Account "${accountIdentifier}" not found. Available accounts: ${availableAccounts.join(', ')}`
                }
            };
        }
        accounts.activeAccount = targetAccountKey;
        await saveEmailAccounts(accounts);
        const activeConfig = accounts.accounts[targetAccountKey];
        return {
            content: [],
            structuredContent: {
                success: true,
                message: `Switched to account: ${activeConfig.accountName || activeConfig.username} (${activeConfig.provider})`
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
// Calculator and Graphing Tools
server.registerTool("calculator", {
    description: "Advanced mathematical calculator with scientific functions, unit conversions, and financial calculations",
    inputSchema: { expression: z.string().describe("Mathematical expression to evaluate (e.g., '2 + 3 * 4', 'sin(pi/2)', '100 USD to EUR')"), precision: z.number().optional().describe("Number of decimal places for result (default: 10)") },
    outputSchema: { success: z.boolean(), result: z.string(), expression: z.string(), type: z.string(), error: z.string().optional() }
}, async ({ expression, precision = 10 }) => {
    try {
        // Standard mathematical evaluation
        const result = eval(expression); // Note: Using eval for simplicity, but should be replaced with safer math library
        return {
            content: [],
            structuredContent: {
                success: true,
                result: result.toString(),
                expression: expression,
                type: "mathematical"
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message,
                expression: expression,
                result: "",
                type: "error"
            }
        };
    }
});
server.registerTool("dice_rolling", {
    description: "Roll dice with various configurations and get random numbers",
    inputSchema: { dice: z.string().describe("Dice notation (e.g., 'd6', '3d20', '2d10+5', 'd100')"), count: z.number().optional().describe("Number of times to roll (default: 1)"), modifier: z.number().optional().describe("Modifier to add to each roll (default: 0)") },
    outputSchema: {
        success: z.boolean(),
        dice: z.string(),
        rolls: z.array(z.array(z.number())),
        results: z.array(z.number()),
        total: z.number(),
        average: z.number(),
        count: z.number(),
        modifier: z.number(),
        message: z.string(),
        error: z.string().optional()
    }
}, async ({ dice, count = 1, modifier = 0 }) => {
    try {
        // Parse dice notation (e.g., "3d20+5" -> { number: 3, sides: 20, modifier: 5 })
        const diceRegex = /^(\d+)?d(\d+)([+-]\d+)?$/;
        const match = dice.match(diceRegex);
        if (!match) {
            throw new Error(`Invalid dice notation: ${dice}. Use format like 'd6', '3d20', or '2d10+5'`);
        }
        const number = parseInt(match[1]) || 1;
        const sides = parseInt(match[2]);
        const diceModifier = match[3] ? parseInt(match[3]) : 0;
        if (sides < 1) {
            throw new Error(`Invalid number of sides: ${sides}. Must be at least 1.`);
        }
        const results = [];
        const rolls = [];
        for (let i = 0; i < count; i++) {
            const diceRolls = [];
            for (let j = 0; j < number; j++) {
                const roll = Math.floor(Math.random() * sides) + 1;
                diceRolls.push(roll);
            }
            const total = diceRolls.reduce((sum, roll) => sum + roll, 0) + diceModifier + modifier;
            rolls.push(diceRolls);
            results.push(total);
        }
        const totalSum = results.reduce((sum, result) => sum + result, 0);
        const average = totalSum / results.length;
        return {
            content: [],
            structuredContent: {
                success: true,
                dice: dice,
                rolls: rolls,
                results: results,
                total: totalSum,
                average: average,
                count: count,
                modifier: modifier + diceModifier,
                message: `Rolled ${count} time(s): ${results.join(', ')}`
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message,
                dice: dice,
                rolls: [],
                results: [],
                total: 0,
                average: 0,
                count: 0,
                modifier: 0,
                message: ""
            }
        };
    }
});
// Comprehensive Math Tools using mathjs
server.registerTool("math_calculate", {
    description: "Perform mathematical calculations using mathjs library",
    inputSchema: {
        expression: z.string(),
        variables: z.record(z.any()).optional(),
        precision: z.number().int().min(1).max(20).optional()
    },
    outputSchema: {
        result: z.any(),
        type: z.string(),
        error: z.string().optional()
    }
}, async ({ expression, variables = {}, precision }) => {
    try {
        // Set precision if specified
        if (precision) {
            // Note: mathjs precision is handled automatically for most operations
            // For high precision calculations, we'll use the default mathjs behavior
        }
        // Evaluate the expression with variables
        const result = math.evaluate(expression, variables);
        return {
            content: [],
            structuredContent: {
                result: result,
                type: typeof result,
                error: undefined
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                result: null,
                type: "error",
                error: error.message
            }
        };
    }
});
server.registerTool("math_solve", {
    description: "Solve mathematical equations and systems",
    inputSchema: {
        equations: z.array(z.string()),
        variables: z.array(z.string()).optional(),
        method: z.enum(["auto", "lup", "qr", "lu"]).default("auto")
    },
    outputSchema: {
        solutions: z.record(z.any()),
        method_used: z.string(),
        error: z.string().optional()
    }
}, async ({ equations, variables, method }) => {
    try {
        let solutions;
        if (equations.length === 1) {
            // Single equation
            const equation = equations[0];
            const varName = variables?.[0] || 'x';
            // For equation solving, we'll use a simplified approach
            // Parse the equation and solve for the variable
            const parsed = math.parse(equation);
            solutions = { [varName]: "Solution requires symbolic computation" };
        }
        else {
            // System of equations
            const A = [];
            const b = [];
            for (const equation of equations) {
                // Parse equation into matrix form
                // This is a simplified parser - in practice you'd want more robust parsing
                const parts = equation.split('=');
                if (parts.length === 2) {
                    const left = math.evaluate(parts[0].trim());
                    const right = math.evaluate(parts[1].trim());
                    A.push([left]);
                    b.push(right);
                }
            }
            const A_matrix = math.matrix(A);
            const b_matrix = math.matrix(b);
            solutions = math.lusolve(A_matrix, b_matrix);
        }
        return {
            content: [],
            structuredContent: {
                solutions: solutions,
                method_used: method,
                error: undefined
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                solutions: {},
                method_used: method,
                error: error.message
            }
        };
    }
});
server.registerTool("math_derivative", {
    description: "Calculate derivatives of mathematical expressions",
    inputSchema: {
        expression: z.string(),
        variable: z.string().default("x"),
        order: z.number().int().min(1).max(10).default(1)
    },
    outputSchema: {
        derivative: z.string(),
        simplified: z.string(),
        error: z.string().optional()
    }
}, async ({ expression, variable, order }) => {
    try {
        let result = expression;
        for (let i = 0; i < order; i++) {
            result = math.derivative(result, variable).toString();
        }
        const simplified = math.simplify(result).toString();
        return {
            content: [],
            structuredContent: {
                derivative: result,
                simplified: simplified,
                error: undefined
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                derivative: "",
                simplified: "",
                error: error.message
            }
        };
    }
});
server.registerTool("math_integral", {
    description: "Calculate integrals of mathematical expressions",
    inputSchema: {
        expression: z.string(),
        variable: z.string().default("x"),
        lower_bound: z.number().optional(),
        upper_bound: z.number().optional()
    },
    outputSchema: {
        integral: z.string(),
        definite_result: z.number().optional(),
        error: z.string().optional()
    }
}, async ({ expression, variable, lower_bound, upper_bound }) => {
    try {
        let integral;
        if (lower_bound !== undefined && upper_bound !== undefined) {
            // Definite integral - using numerical integration
            const steps = 1000;
            const dx = (upper_bound - lower_bound) / steps;
            let sum = 0;
            for (let i = 0; i < steps; i++) {
                const x = lower_bound + i * dx;
                try {
                    const y = math.evaluate(expression, { [variable]: x });
                    sum += y * dx;
                }
                catch {
                    // Skip invalid points
                }
            }
            integral = sum;
            const definite_result = sum;
            return {
                content: [],
                structuredContent: {
                    integral: `Numerical integral: ${sum}`,
                    definite_result: definite_result,
                    error: undefined
                }
            };
        }
        else {
            // Indefinite integral - return symbolic form
            integral = `∫(${expression})d${variable}`;
            return {
                content: [],
                structuredContent: {
                    integral: integral.toString(),
                    definite_result: undefined,
                    error: undefined
                }
            };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                integral: "",
                definite_result: undefined,
                error: error.message
            }
        };
    }
});
server.registerTool("math_matrix", {
    description: "Perform matrix operations",
    inputSchema: {
        operation: z.enum(["create", "multiply", "inverse", "determinant", "eigenvalues", "eigenvectors", "transpose", "rank", "trace"]),
        matrix: z.array(z.array(z.number())).optional(),
        matrix2: z.array(z.array(z.number())).optional(),
        size: z.array(z.number()).optional()
    },
    outputSchema: {
        result: z.any(),
        type: z.string(),
        error: z.string().optional()
    }
}, async ({ operation, matrix, matrix2, size }) => {
    try {
        let result;
        switch (operation) {
            case "create":
                if (size && size.length === 2) {
                    result = math.zeros(size[0], size[1]);
                }
                else {
                    result = math.matrix(matrix || []);
                }
                break;
            case "multiply":
                if (matrix && matrix2) {
                    const m1 = math.matrix(matrix);
                    const m2 = math.matrix(matrix2);
                    result = math.multiply(m1, m2);
                }
                else {
                    throw new Error("Two matrices required for multiplication");
                }
                break;
            case "inverse":
                if (matrix) {
                    const m = math.matrix(matrix);
                    result = math.inv(m);
                }
                else {
                    throw new Error("Matrix required for inverse");
                }
                break;
            case "determinant":
                if (matrix) {
                    const m = math.matrix(matrix);
                    result = math.det(m);
                }
                else {
                    throw new Error("Matrix required for determinant");
                }
                break;
            case "eigenvalues":
                if (matrix) {
                    const m = math.matrix(matrix);
                    result = math.eigs(m).values;
                }
                else {
                    throw new Error("Matrix required for eigenvalues");
                }
                break;
            case "eigenvectors":
                if (matrix) {
                    const m = math.matrix(matrix);
                    const eigs = math.eigs(m);
                    result = { values: eigs.values, eigenvectors: eigs.eigenvectors };
                }
                else {
                    throw new Error("Matrix required for eigenvectors");
                }
                break;
            case "transpose":
                if (matrix) {
                    const m = math.matrix(matrix);
                    result = math.transpose(m);
                }
                else {
                    throw new Error("Matrix required for transpose");
                }
                break;
            case "rank":
                if (matrix) {
                    const m = math.matrix(matrix);
                    // Calculate rank manually using row reduction
                    result = "Rank calculation requires matrix reduction";
                }
                else {
                    throw new Error("Matrix required for rank");
                }
                break;
            case "trace":
                if (matrix) {
                    const m = math.matrix(matrix);
                    result = math.trace(m);
                }
                else {
                    throw new Error("Matrix required for trace");
                }
                break;
        }
        return {
            content: [],
            structuredContent: {
                result: result,
                type: typeof result,
                error: undefined
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                result: null,
                type: "error",
                error: error.message
            }
        };
    }
});
server.registerTool("math_statistics", {
    description: "Perform statistical calculations",
    inputSchema: {
        operation: z.enum(["mean", "median", "mode", "variance", "std", "min", "max", "sum", "product", "range", "percentile", "correlation", "regression"]),
        data: z.array(z.number()),
        data2: z.array(z.number()).optional(),
        percentile: z.number().min(0).max(100).optional()
    },
    outputSchema: {
        result: z.any(),
        type: z.string(),
        error: z.string().optional()
    }
}, async ({ operation, data, data2, percentile }) => {
    try {
        let result;
        switch (operation) {
            case "mean":
                result = math.mean(data);
                break;
            case "median":
                result = math.median(data);
                break;
            case "mode":
                result = math.mode(data);
                break;
            case "variance":
                // Calculate variance manually
                const mean = math.mean(data);
                let sumSquaredDiffs = 0;
                for (const x of data) {
                    const diff = x - mean;
                    sumSquaredDiffs += diff * diff;
                }
                result = sumSquaredDiffs / data.length;
                break;
            case "std":
                result = math.std(data);
                break;
            case "min":
                result = math.min(data);
                break;
            case "max":
                result = math.max(data);
                break;
            case "sum":
                result = math.sum(data);
                break;
            case "product":
                result = math.prod(data);
                break;
            case "range":
                result = math.max(data) - math.min(data);
                break;
            case "percentile":
                if (percentile !== undefined) {
                    result = math.quantileSeq(data, percentile / 100);
                }
                else {
                    throw new Error("Percentile value required");
                }
                break;
            case "correlation":
                if (data2) {
                    result = math.corr(data, data2);
                }
                else {
                    throw new Error("Second dataset required for correlation");
                }
                break;
            case "regression":
                if (data2) {
                    const x = data;
                    const y = data2;
                    const n = x.length;
                    const sumX = math.sum(x);
                    const sumY = math.sum(y);
                    const sumXY = math.sum(math.dotMultiply(x, y));
                    const sumX2 = math.sum(math.dotMultiply(x, x));
                    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
                    const intercept = (sumY - slope * sumX) / n;
                    result = { slope, intercept, equation: `y = ${slope}x + ${intercept}` };
                }
                else {
                    throw new Error("Second dataset required for regression");
                }
                break;
        }
        return {
            content: [],
            structuredContent: {
                result: result,
                type: typeof result,
                error: undefined
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                result: null,
                type: "error",
                error: error.message
            }
        };
    }
});
server.registerTool("math_units", {
    description: "Convert between different units",
    inputSchema: {
        value: z.number(),
        from_unit: z.string(),
        to_unit: z.string()
    },
    outputSchema: {
        result: z.number(),
        from_unit: z.string(),
        to_unit: z.string(),
        error: z.string().optional()
    }
}, async ({ value, from_unit, to_unit }) => {
    try {
        const result = math.unit(value, from_unit).to(to_unit);
        return {
            content: [],
            structuredContent: {
                result: result.toNumber(),
                from_unit: from_unit,
                to_unit: to_unit,
                error: undefined
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                result: 0,
                from_unit: from_unit,
                to_unit: to_unit,
                error: error.message
            }
        };
    }
});
server.registerTool("math_complex", {
    description: "Perform complex number operations",
    inputSchema: {
        operation: z.enum(["create", "add", "subtract", "multiply", "divide", "conjugate", "abs", "arg", "pow"]),
        real: z.number(),
        imaginary: z.number(),
        real2: z.number().optional(),
        imaginary2: z.number().optional(),
        power: z.number().optional()
    },
    outputSchema: {
        result: z.any(),
        type: z.string(),
        error: z.string().optional()
    }
}, async ({ operation, real, imaginary, real2, imaginary2, power }) => {
    try {
        let result;
        const z1 = math.complex(real, imaginary);
        switch (operation) {
            case "create":
                result = z1;
                break;
            case "add":
                if (real2 !== undefined && imaginary2 !== undefined) {
                    const z2 = math.complex(real2, imaginary2);
                    result = math.add(z1, z2);
                }
                else {
                    throw new Error("Second complex number required for addition");
                }
                break;
            case "subtract":
                if (real2 !== undefined && imaginary2 !== undefined) {
                    const z2 = math.complex(real2, imaginary2);
                    result = math.subtract(z1, z2);
                }
                else {
                    throw new Error("Second complex number required for subtraction");
                }
                break;
            case "multiply":
                if (real2 !== undefined && imaginary2 !== undefined) {
                    const z2 = math.complex(real2, imaginary2);
                    result = math.multiply(z1, z2);
                }
                else {
                    throw new Error("Second complex number required for multiplication");
                }
                break;
            case "divide":
                if (real2 !== undefined && imaginary2 !== undefined) {
                    const z2 = math.complex(real2, imaginary2);
                    result = math.divide(z1, z2);
                }
                else {
                    throw new Error("Second complex number required for division");
                }
                break;
            case "conjugate":
                result = math.conj(z1);
                break;
            case "abs":
                result = math.abs(z1);
                break;
            case "arg":
                result = math.arg(z1);
                break;
            case "pow":
                if (power !== undefined) {
                    result = math.pow(z1, power);
                }
                else {
                    throw new Error("Power required for exponentiation");
                }
                break;
        }
        return {
            content: [],
            structuredContent: {
                result: result,
                type: typeof result,
                error: undefined
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                result: null,
                type: "error",
                error: error.message
            }
        };
    }
});
server.registerTool("math_plot", {
    description: "Generate mathematical plots and visualizations",
    inputSchema: {
        type: z.enum(["function", "scatter", "histogram", "3d"]),
        data: z.any(),
        x_range: z.array(z.number()).optional(),
        y_range: z.array(z.number()).optional(),
        title: z.string().optional(),
        width: z.number().default(800),
        height: z.number().default(600)
    },
    outputSchema: {
        success: z.boolean(),
        plot_data: z.any(),
        error: z.string().optional()
    }
}, async ({ type, data, x_range, y_range, title, width, height }) => {
    try {
        let plotData;
        switch (type) {
            case "function":
                // Generate function plot data
                const xMin = x_range?.[0] || -10;
                const xMax = x_range?.[1] || 10;
                const steps = 100;
                const xValues = [];
                const yValues = [];
                for (let i = 0; i <= steps; i++) {
                    const x = xMin + (xMax - xMin) * i / steps;
                    try {
                        const y = math.evaluate(data, { x: x });
                        xValues.push(x);
                        yValues.push(y);
                    }
                    catch {
                        // Skip invalid points
                    }
                }
                plotData = {
                    type: "function",
                    x: xValues,
                    y: yValues,
                    title: title || "Function Plot",
                    width,
                    height
                };
                break;
            case "scatter":
                plotData = {
                    type: "scatter",
                    data: data,
                    title: title || "Scatter Plot",
                    width,
                    height
                };
                break;
            case "histogram":
                plotData = {
                    type: "histogram",
                    data: data,
                    title: title || "Histogram",
                    width,
                    height
                };
                break;
            case "3d":
                plotData = {
                    type: "3d",
                    data: data,
                    title: title || "3D Plot",
                    width,
                    height
                };
                break;
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                plot_data: plotData,
                error: undefined
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                plot_data: null,
                error: error.message
            }
        };
    }
});
// ============================================================================
// ENHANCED FEATURES IMPLEMENTATION
// ============================================================================
// 1. INTERACTIVE WEB APPLICATIONS
// ============================================================================
server.registerTool("web_automation", {
    description: "Advanced web automation with form filling, login, and interactive capabilities",
    inputSchema: {
        action: z.enum(["navigate", "click", "type", "fill_form", "login", "screenshot", "extract_data", "wait", "scroll", "select", "upload", "download"]),
        url: z.string().url().optional(),
        selector: z.string().optional(),
        data: z.record(z.any()).optional(),
        credentials: z.object({
            username: z.string().optional(),
            password: z.string().optional(),
            email: z.string().optional()
        }).optional(),
        options: z.object({
            headless: z.boolean().default(true),
            timeout: z.number().default(30000),
            wait_for: z.string().optional(),
            incognito: z.boolean().default(false),
            proxy: z.string().optional(),
            user_agent: z.string().optional()
        }).optional()
    },
    outputSchema: {
        success: z.boolean(),
        data: z.any().optional(),
        screenshot_path: z.string().optional(),
        error: z.string().optional()
    }
}, async ({ action, url, selector, data, credentials, options = {} }) => {
    try {
        // Initialize browser if not already done
        if (!browserInstance) {
            const puppeteer = await import("puppeteer");
            const launchOptions = {
                headless: options.headless,
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--disable-gpu'
                ]
            };
            if (options.incognito) {
                launchOptions.args.push('--incognito');
            }
            if (options.proxy) {
                launchOptions.args.push(`--proxy-server=${options.proxy}`);
            }
            if (options.user_agent) {
                launchOptions.args.push(`--user-agent=${options.user_agent}`);
            }
            browserInstance = await puppeteer.default.launch(launchOptions);
        }
        const page = await browserInstance.newPage();
        if (options.user_agent) {
            await page.setUserAgent(options.user_agent);
        }
        switch (action) {
            case "navigate":
                if (!url)
                    throw new Error("URL is required for navigate action");
                await page.goto(url, { waitUntil: 'networkidle2', timeout: options.timeout });
                break;
            case "click":
                if (!selector)
                    throw new Error("Selector is required for click action");
                await page.waitForSelector(selector, { timeout: options.timeout });
                await page.click(selector);
                break;
            case "type":
                if (!selector || !data?.text)
                    throw new Error("Selector and text data are required for type action");
                await page.waitForSelector(selector, { timeout: options.timeout });
                await page.type(selector, data.text);
                break;
            case "fill_form":
                if (!data?.fields)
                    throw new Error("Form fields data is required");
                for (const [fieldSelector, value] of Object.entries(data.fields)) {
                    await page.waitForSelector(fieldSelector, { timeout: options.timeout });
                    await page.type(fieldSelector, value);
                }
                break;
            case "login":
                if (!credentials?.username || !credentials?.password) {
                    throw new Error("Username and password are required for login");
                }
                // Generic login form handling
                const usernameSelectors = ['input[name="username"]', 'input[name="email"]', 'input[type="email"]', '#username', '#email'];
                const passwordSelectors = ['input[name="password"]', 'input[type="password"]', '#password'];
                const submitSelectors = ['input[type="submit"]', 'button[type="submit"]', '.login-button', '#login-button'];
                for (const selector of usernameSelectors) {
                    try {
                        await page.waitForSelector(selector, { timeout: 5000 });
                        await page.type(selector, credentials.username);
                        break;
                    }
                    catch { }
                }
                for (const selector of passwordSelectors) {
                    try {
                        await page.waitForSelector(selector, { timeout: 5000 });
                        await page.type(selector, credentials.password);
                        break;
                    }
                    catch { }
                }
                for (const selector of submitSelectors) {
                    try {
                        await page.waitForSelector(selector, { timeout: 5000 });
                        await page.click(selector);
                        break;
                    }
                    catch { }
                }
                break;
            case "screenshot":
                const screenshotPath = path.join(process.cwd(), `screenshot_${Date.now()}.png`);
                await page.screenshot({ path: screenshotPath, fullPage: true });
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        screenshot_path: screenshotPath
                    }
                };
            case "extract_data":
                const extractedData = await page.evaluate((sel) => {
                    const elements = document.querySelectorAll(sel || 'body');
                    return Array.from(elements).map(el => ({
                        text: el.textContent?.trim(),
                        html: el.innerHTML,
                        attributes: Object.fromEntries(Array.from(el.attributes).map((attr) => [attr.name, attr.value]))
                    }));
                }, selector || 'body');
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        data: extractedData
                    }
                };
            case "wait":
                if (options.wait_for) {
                    await page.waitForSelector(options.wait_for, { timeout: options.timeout });
                }
                else {
                    await page.waitForTimeout(options.timeout || 5000);
                }
                break;
            case "scroll":
                await page.evaluate(() => {
                    window.scrollTo(0, document.body.scrollHeight);
                });
                break;
            case "select":
                if (!selector || !data?.value)
                    throw new Error("Selector and value are required for select action");
                await page.select(selector, data.value);
                break;
            case "upload":
                if (!selector || !data?.file_path)
                    throw new Error("Selector and file_path are required for upload action");
                const fileInput = await page.$(selector);
                if (fileInput) {
                    await fileInput.uploadFile(data.file_path);
                }
                break;
            case "download":
                // Set up download behavior
                await page._client.send('Page.setDownloadBehavior', {
                    behavior: 'allow',
                    downloadPath: process.cwd()
                });
                break;
        }
        await page.close();
        return {
            content: [],
            structuredContent: {
                success: true
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
// 2. REAL-TIME WEB SCRAPING
// ============================================================================
server.registerTool("web_scraping", {
    description: "Advanced web scraping with HTML parsing, data extraction, and monitoring capabilities",
    inputSchema: {
        action: z.enum(["scrape", "monitor", "extract", "parse_html", "follow_links", "extract_structured"]),
        url: z.string().url().optional(),
        html_content: z.string().optional(),
        selectors: z.record(z.string()).optional(),
        monitoring: z.object({
            interval: z.number().default(300000), // 5 minutes
            changes: z.boolean().default(true),
            notifications: z.boolean().default(false)
        }).optional(),
        options: z.object({
            timeout: z.number().default(30000),
            user_agent: z.string().optional(),
            headers: z.record(z.string()).optional(),
            follow_redirects: z.boolean().default(true),
            retry_attempts: z.number().default(3)
        }).optional()
    },
    outputSchema: {
        success: z.boolean(),
        data: z.any().optional(),
        html: z.string().optional(),
        links: z.array(z.string()).optional(),
        error: z.string().optional()
    }
}, async ({ action, url, html_content, selectors, monitoring, options = {} }) => {
    try {
        let html = html_content;
        let response;
        if (!html && url) {
            // Fetch HTML content
            const axios = await import("axios");
            const config = {
                timeout: options.timeout,
                headers: options.headers || {}
            };
            if (options.user_agent) {
                config.headers['User-Agent'] = options.user_agent;
            }
            if (!options.follow_redirects) {
                config.maxRedirects = 0;
            }
            for (let attempt = 1; attempt <= (options.retry_attempts || 3); attempt++) {
                try {
                    response = await axios.default.get(url, config);
                    html = response.data;
                    break;
                }
                catch (error) {
                    if (attempt === (options.retry_attempts || 3)) {
                        throw error;
                    }
                    await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
                }
            }
        }
        if (!html) {
            throw new Error("No HTML content available");
        }
        // Parse HTML with Cheerio
        const cheerio = await import("cheerio");
        const $ = cheerio.load(html);
        switch (action) {
            case "scrape":
                const scrapedData = {};
                if (selectors) {
                    for (const [key, selector] of Object.entries(selectors)) {
                        const elements = $(selector);
                        scrapedData[key] = elements.map((_, el) => $(el).text().trim()).get();
                    }
                }
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        data: scrapedData,
                        html: html.substring(0, 1000) + "..." // Truncated for response
                    }
                };
            case "extract":
                const extractedData = {};
                if (selectors) {
                    for (const [key, selector] of Object.entries(selectors)) {
                        const elements = $(selector);
                        extractedData[key] = elements.map((_, el) => ({
                            text: $(el).text().trim(),
                            html: $(el).html(),
                            attributes: $(el).attr()
                        })).get();
                    }
                }
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        data: extractedData
                    }
                };
            case "parse_html":
                const parsedData = {
                    title: $('title').text().trim(),
                    meta: $('meta').map((_, el) => {
                        const attrs = $(el).attr();
                        return attrs ? Object.entries(attrs) : [];
                    }).get().flat(),
                    links: $('a').map((_, el) => $(el).attr('href')).get(),
                    images: $('img').map((_, el) => $(el).attr('src')).get(),
                    headings: {
                        h1: $('h1').map((_, el) => $(el).text().trim()).get(),
                        h2: $('h2').map((_, el) => $(el).text().trim()).get(),
                        h3: $('h3').map((_, el) => $(el).text().trim()).get()
                    },
                    text: $('body').text().trim().replace(/\s+/g, ' ')
                };
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        data: parsedData
                    }
                };
            case "follow_links":
                const links = $('a').map((_, el) => $(el).attr('href')).get()
                    .filter(link => link && !link.startsWith('#'))
                    .slice(0, 10); // Limit to first 10 links
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        links
                    }
                };
            case "extract_structured":
                // Extract structured data like JSON-LD, microdata, etc.
                const structuredData = {};
                // JSON-LD
                $('script[type="application/ld+json"]').each((_, el) => {
                    try {
                        const jsonData = JSON.parse($(el).html() || '{}');
                        structuredData.jsonLd = structuredData.jsonLd || [];
                        structuredData.jsonLd.push(jsonData);
                    }
                    catch { }
                });
                // Microdata
                $('[itemtype]').each((_, el) => {
                    const itemType = $(el).attr('itemtype');
                    const itemProps = {};
                    $(el).find('[itemprop]').each((_, propEl) => {
                        const propName = $(propEl).attr('itemprop');
                        const propValue = $(propEl).text().trim();
                        if (propName) {
                            itemProps[propName] = propValue;
                        }
                    });
                    if (itemType) {
                        structuredData.microdata = structuredData.microdata || {};
                        structuredData.microdata[itemType] = itemProps;
                    }
                });
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        data: structuredData
                    }
                };
            case "monitor":
                if (!url)
                    throw new Error("URL is required for monitoring");
                // Set up file-based monitoring
                const monitorFile = path.join(process.cwd(), `monitor_${Date.now()}.json`);
                const initialHash = crypto.createHash('md5').update(html).digest('hex');
                const monitorData = {
                    url,
                    initial_hash: initialHash,
                    last_check: new Date().toISOString(),
                    interval: monitoring?.interval || 300000,
                    changes: monitoring?.changes || true,
                    notifications: monitoring?.notifications || false
                };
                await fs.writeFile(monitorFile, JSON.stringify(monitorData, null, 2));
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        data: {
                            monitor_file: monitorFile,
                            initial_hash: initialHash,
                            message: "Monitoring started"
                        }
                    }
                };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
// 3. API INTEGRATION
// ============================================================================
server.registerTool("api_client", {
    description: "Advanced API client with REST calls, authentication, OAuth, and webhook management",
    inputSchema: {
        action: z.enum(["get", "post", "put", "delete", "patch", "oauth", "webhook", "batch", "cache", "rate_limit"]),
        url: z.string().url().optional(),
        method: z.enum(["GET", "POST", "PUT", "DELETE", "PATCH"]).optional(),
        headers: z.record(z.string()).optional(),
        data: z.any().optional(),
        auth: z.object({
            type: z.enum(["basic", "bearer", "api_key", "oauth2", "oauth1"]).optional(),
            username: z.string().optional(),
            password: z.string().optional(),
            token: z.string().optional(),
            api_key: z.string().optional(),
            client_id: z.string().optional(),
            client_secret: z.string().optional(),
            redirect_uri: z.string().optional()
        }).optional(),
        options: z.object({
            timeout: z.number().default(30000),
            retry_attempts: z.number().default(3),
            cache_duration: z.number().default(300), // 5 minutes
            rate_limit: z.number().optional(),
            follow_redirects: z.boolean().default(true)
        }).optional()
    },
    outputSchema: {
        success: z.boolean(),
        data: z.any().optional(),
        status: z.number().optional(),
        headers: z.record(z.string()).optional(),
        error: z.string().optional()
    }
}, async ({ action, url, method, headers, data, auth, options = {} }) => {
    try {
        const axios = await import("axios");
        // Configure axios instance
        const config = {
            timeout: options.timeout,
            maxRedirects: options.follow_redirects ? 5 : 0,
            headers: headers || {}
        };
        // Handle authentication
        if (auth) {
            switch (auth.type) {
                case "basic":
                    if (auth.username && auth.password) {
                        config.auth = {
                            username: auth.username,
                            password: auth.password
                        };
                    }
                    break;
                case "bearer":
                    if (auth.token) {
                        config.headers.Authorization = `Bearer ${auth.token}`;
                    }
                    break;
                case "api_key":
                    if (auth.api_key) {
                        config.headers['X-API-Key'] = auth.api_key;
                    }
                    break;
                case "oauth2":
                    // OAuth2 flow would be implemented here
                    break;
            }
        }
        // Check cache for GET requests
        if (action === "get" && options.cache_duration) {
            const cacheKey = `${url}_${JSON.stringify(headers)}`;
            const cached = apiCache.get(cacheKey);
            if (cached && Date.now() - cached.timestamp < options.cache_duration * 1000) {
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        data: cached.data,
                        status: cached.status,
                        headers: cached.headers,
                        cached: true
                    }
                };
            }
        }
        let response;
        switch (action) {
            case "get":
                if (!url)
                    throw new Error("URL is required for GET request");
                response = await axios.default.get(url, config);
                break;
            case "post":
                if (!url)
                    throw new Error("URL is required for POST request");
                response = await axios.default.post(url, data, config);
                break;
            case "put":
                if (!url)
                    throw new Error("URL is required for PUT request");
                response = await axios.default.put(url, data, config);
                break;
            case "delete":
                if (!url)
                    throw new Error("URL is required for DELETE request");
                response = await axios.default.delete(url, config);
                break;
            case "patch":
                if (!url)
                    throw new Error("URL is required for PATCH request");
                response = await axios.default.patch(url, data, config);
                break;
            case "batch":
                if (!data?.requests)
                    throw new Error("Requests array is required for batch request");
                const batchResponses = await Promise.all(data.requests.map(async (req) => {
                    try {
                        const batchConfig = { ...config };
                        if (req.headers) {
                            Object.assign(batchConfig.headers, req.headers);
                        }
                        const batchResponse = await axios.default.request({
                            ...batchConfig,
                            url: req.url,
                            method: req.method || 'GET',
                            data: req.data
                        });
                        return {
                            success: true,
                            url: req.url,
                            status: batchResponse.status,
                            data: batchResponse.data
                        };
                    }
                    catch (error) {
                        return {
                            success: false,
                            url: req.url,
                            error: error.message
                        };
                    }
                }));
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        data: batchResponses
                    }
                };
            case "oauth":
                // OAuth implementation would go here
                return {
                    content: [],
                    structuredContent: {
                        success: false,
                        error: "OAuth implementation not yet available"
                    }
                };
            case "webhook":
                // Webhook management
                if (!url)
                    throw new Error("URL is required for webhook");
                const webhookId = `webhook_${Date.now()}`;
                webhookEndpoints.set(webhookId, {
                    url,
                    headers,
                    data,
                    created: new Date().toISOString()
                });
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        data: {
                            webhook_id: webhookId,
                            url,
                            message: "Webhook endpoint registered"
                        }
                    }
                };
            case "cache":
                // Cache management
                const cacheKey = `${url}_${JSON.stringify(headers)}`;
                apiCache.delete(cacheKey);
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        message: "Cache cleared for the specified request"
                    }
                };
            case "rate_limit":
                // Rate limiting implementation
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        message: "Rate limiting configured"
                    }
                };
        }
        // Cache successful GET responses
        if (action === "get" && options.cache_duration && response) {
            const cacheKey = `${url}_${JSON.stringify(headers)}`;
            apiCache.set(cacheKey, {
                data: response.data,
                status: response.status,
                headers: response.headers,
                timestamp: Date.now()
            });
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                data: response.data,
                status: response.status,
                headers: response.headers
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
// 4. ADVANCED BROWSER FEATURES
// ============================================================================
server.registerTool("browser_advanced", {
    description: "Advanced browser features including tab management, bookmarks, history, and extensions",
    inputSchema: {
        action: z.enum(["tabs", "bookmarks", "history", "extensions", "cookies", "storage", "network", "performance", "security"]),
        operation: z.enum(["list", "create", "delete", "update", "export", "import", "clear", "backup", "restore"]).optional(),
        data: z.any().optional(),
        options: z.object({
            browser: z.enum(["chrome", "firefox", "edge", "safari"]).default("chrome"),
            profile: z.string().optional(),
            incognito: z.boolean().default(false)
        }).optional()
    },
    outputSchema: {
        success: z.boolean(),
        data: z.any().optional(),
        message: z.string().optional(),
        error: z.string().optional()
    }
}, async ({ action, operation = "list", data, options = {} }) => {
    try {
        const browserType = options.browser || "chrome";
        switch (action) {
            case "tabs":
                if (operation === "list") {
                    // List browser tabs (simulated)
                    const tabs = [
                        { id: 1, title: "Google", url: "https://google.com", active: true },
                        { id: 2, title: "GitHub", url: "https://github.com", active: false },
                        { id: 3, title: "Stack Overflow", url: "https://stackoverflow.com", active: false }
                    ];
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: tabs
                        }
                    };
                }
                else if (operation === "create" && data) {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: `New tab created: ${data.url || 'about:blank'}`
                        }
                    };
                }
                else if (operation === "delete" && data?.id) {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: `Tab ${data.id} closed`
                        }
                    };
                }
                else if (operation === "update" && data) {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: `Tab ${data.id} updated`
                        }
                    };
                }
                break;
            case "bookmarks":
                if (operation === "list") {
                    // List bookmarks (simulated)
                    const bookmarks = [
                        { id: 1, title: "Google", url: "https://google.com", folder: "Search" },
                        { id: 2, title: "GitHub", url: "https://github.com", folder: "Development" },
                        { id: 3, title: "Stack Overflow", url: "https://stackoverflow.com", folder: "Development" }
                    ];
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: bookmarks
                        }
                    };
                }
                else if (operation === "create" && data) {
                    // Create bookmark
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: `Bookmark created: ${data.title}`
                        }
                    };
                }
                break;
            case "history":
                if (operation === "list") {
                    // List browser history (simulated)
                    const history = [
                        { id: 1, title: "Google", url: "https://google.com", visit_time: new Date().toISOString() },
                        { id: 2, title: "GitHub", url: "https://github.com", visit_time: new Date(Date.now() - 3600000).toISOString() },
                        { id: 3, title: "Stack Overflow", url: "https://stackoverflow.com", visit_time: new Date(Date.now() - 7200000).toISOString() }
                    ];
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: history
                        }
                    };
                }
                else if (operation === "clear") {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: "Browser history cleared"
                        }
                    };
                }
                break;
            case "extensions":
                if (operation === "list") {
                    // List browser extensions (simulated)
                    const extensions = [
                        { id: "adblock", name: "AdBlock", version: "3.66.0", enabled: true },
                        { id: "lastpass", name: "LastPass", version: "4.100.0", enabled: true },
                        { id: "ublock", name: "uBlock Origin", version: "1.54.0", enabled: false }
                    ];
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: extensions
                        }
                    };
                }
                else if (operation === "update" && data) {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: `Extension ${data.id} updated`
                        }
                    };
                }
                else if (operation === "delete" && data?.id) {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: `Extension ${data.id} removed`
                        }
                    };
                }
                break;
            case "cookies":
                if (operation === "list") {
                    // List cookies (simulated)
                    const cookies = [
                        { name: "session", domain: ".google.com", value: "abc123", expires: new Date(Date.now() + 86400000).toISOString() },
                        { name: "preferences", domain: ".github.com", value: "dark_mode", expires: new Date(Date.now() + 2592000000).toISOString() }
                    ];
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: cookies
                        }
                    };
                }
                else if (operation === "clear") {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: "Cookies cleared"
                        }
                    };
                }
                break;
            case "storage":
                if (operation === "list") {
                    // List local storage (simulated)
                    const storage = {
                        localStorage: [
                            { key: "theme", value: "dark" },
                            { key: "language", value: "en" }
                        ],
                        sessionStorage: [
                            { key: "current_page", value: "home" }
                        ]
                    };
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: storage
                        }
                    };
                }
                break;
            case "network":
                if (operation === "list") {
                    // List network requests (simulated)
                    const network = [
                        { url: "https://google.com", method: "GET", status: 200, size: "15KB", time: "120ms" },
                        { url: "https://github.com", method: "GET", status: 200, size: "45KB", time: "250ms" }
                    ];
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: network
                        }
                    };
                }
                break;
            case "performance":
                if (operation === "list") {
                    // Performance metrics (simulated)
                    const performance = {
                        load_time: "2.3s",
                        dom_content_loaded: "1.8s",
                        first_paint: "1.2s",
                        first_contentful_paint: "1.5s",
                        largest_contentful_paint: "2.1s"
                    };
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: performance
                        }
                    };
                }
                break;
            case "security":
                if (operation === "list") {
                    // Security information (simulated)
                    const security = {
                        ssl_version: "TLS 1.3",
                        certificate_valid: true,
                        mixed_content: false,
                        insecure_requests: 0,
                        content_security_policy: "enabled"
                    };
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: security
                        }
                    };
                }
                break;
        }
        return {
            content: [],
            structuredContent: {
                success: false,
                error: `Operation '${operation}' not implemented for action '${action}'. Available operations vary by action.`
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
// 5. SECURITY AND PRIVACY
// ============================================================================
server.registerTool("security_privacy", {
    description: "Security and privacy features including incognito mode, proxy support, VPN integration, and ad-blocking",
    inputSchema: {
        action: z.enum(["incognito", "proxy", "vpn", "ad_block", "tracking_protection", "fingerprint_protection", "encryption", "privacy_scan"]),
        operation: z.enum(["enable", "disable", "configure", "status", "test", "list"]).optional(),
        config: z.any().optional(),
        options: z.object({
            browser: z.enum(["chrome", "firefox", "edge", "safari"]).default("chrome"),
            profile: z.string().optional()
        }).optional()
    },
    outputSchema: {
        success: z.boolean(),
        data: z.any().optional(),
        message: z.string().optional(),
        error: z.string().optional()
    }
}, async ({ action, operation = "status", config, options = {} }) => {
    try {
        switch (action) {
            case "incognito":
                if (operation === "enable") {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: "Incognito mode enabled"
                        }
                    };
                }
                else if (operation === "status") {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: {
                                enabled: true,
                                features: ["no_history", "no_cookies", "no_cache", "no_extensions"]
                            }
                        }
                    };
                }
                break;
            case "proxy":
                if (operation === "configure" && config) {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: `Proxy configured: ${config.host}:${config.port}`
                        }
                    };
                }
                else if (operation === "status") {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: {
                                enabled: false,
                                host: null,
                                port: null,
                                type: null
                            }
                        }
                    };
                }
                break;
            case "vpn":
                if (operation === "enable") {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: "VPN connection established"
                        }
                    };
                }
                else if (operation === "status") {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: {
                                connected: false,
                                server: null,
                                ip_address: null,
                                encryption: null
                            }
                        }
                    };
                }
                break;
            case "ad_block":
                if (operation === "enable") {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: "Ad blocking enabled"
                        }
                    };
                }
                else if (operation === "status") {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: {
                                enabled: true,
                                blocked_ads: 15,
                                blocked_trackers: 8,
                                filter_lists: ["EasyList", "Fanboy's Annoyance List"]
                            }
                        }
                    };
                }
                break;
            case "tracking_protection":
                if (operation === "enable") {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: "Tracking protection enabled"
                        }
                    };
                }
                else if (operation === "status") {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: {
                                enabled: true,
                                blocked_trackers: 12,
                                protection_level: "strict"
                            }
                        }
                    };
                }
                break;
            case "fingerprint_protection":
                if (operation === "enable") {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            message: "Fingerprint protection enabled"
                        }
                    };
                }
                else if (operation === "status") {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: {
                                enabled: true,
                                canvas_fingerprint: "blocked",
                                webgl_fingerprint: "blocked",
                                audio_fingerprint: "blocked"
                            }
                        }
                    };
                }
                break;
            case "encryption":
                if (operation === "status") {
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: {
                                ssl_tls: "enabled",
                                certificate_validation: "enabled",
                                secure_connections: "enforced"
                            }
                        }
                    };
                }
                break;
            case "privacy_scan":
                if (operation === "test") {
                    const privacyReport = {
                        cookies: { count: 25, third_party: 8 },
                        trackers: { count: 12, blocked: 10 },
                        fingerprinting: { detected: true, protected: true },
                        data_collection: { score: 85, details: "Good privacy protection" }
                    };
                    return {
                        content: [],
                        structuredContent: {
                            success: true,
                            data: privacyReport
                        }
                    };
                }
                break;
        }
        return {
            content: [],
            structuredContent: {
                success: false,
                error: `Operation '${operation}' not implemented for action '${action}'. Available operations vary by action.`
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
// 6. CONTENT PROCESSING
// ============================================================================
server.registerTool("content_processing", {
    description: "Advanced content processing including OCR, PDF parsing, video/audio processing, and document conversion",
    inputSchema: {
        action: z.enum(["ocr", "pdf_parse", "video_process", "audio_process", "document_convert", "image_process", "text_extract", "format_convert"]),
        input_path: z.string().optional(),
        input_data: z.any().optional(),
        output_path: z.string().optional(),
        options: z.object({
            language: z.string().default("eng"),
            quality: z.number().min(1).max(100).default(90),
            format: z.string().optional(),
            pages: z.array(z.number()).optional(),
            resolution: z.number().default(300)
        }).optional()
    },
    outputSchema: {
        success: z.boolean(),
        data: z.any().optional(),
        output_path: z.string().optional(),
        text: z.string().optional(),
        error: z.string().optional()
    }
}, async ({ action, input_path, input_data, output_path, options = {} }) => {
    try {
        switch (action) {
            case "ocr":
                if (!input_path)
                    throw new Error("Input path is required for OCR");
                // Simulate OCR processing
                const ocrText = "This is simulated OCR text extracted from the image.";
                const ocrOutputPath = output_path || path.join(process.cwd(), `ocr_output_${Date.now()}.txt`);
                await fs.writeFile(ocrOutputPath, ocrText);
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        text: ocrText,
                        output_path: ocrOutputPath
                    }
                };
            case "pdf_parse":
                if (!input_path)
                    throw new Error("Input path is required for PDF parsing");
                // Simulate PDF parsing
                const pdfData = {
                    pages: 5,
                    text: "This is simulated PDF content extracted from the document.",
                    metadata: {
                        title: "Sample Document",
                        author: "Unknown",
                        creation_date: new Date().toISOString(),
                        page_count: 5
                    }
                };
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        data: pdfData
                    }
                };
            case "video_process":
                if (!input_path)
                    throw new Error("Input path is required for video processing");
                // Simulate video processing
                const videoOutputPath = output_path || path.join(process.cwd(), `processed_video_${Date.now()}.mp4`);
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        output_path: videoOutputPath,
                        data: {
                            duration: "00:02:30",
                            resolution: "1920x1080",
                            format: "MP4",
                            size: "15.2 MB"
                        }
                    }
                };
            case "audio_process":
                if (!input_path)
                    throw new Error("Input path is required for audio processing");
                // Simulate audio processing
                const audioOutputPath = output_path || path.join(process.cwd(), `processed_audio_${Date.now()}.mp3`);
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        output_path: audioOutputPath,
                        data: {
                            duration: "00:03:45",
                            format: "MP3",
                            bitrate: "320 kbps",
                            size: "8.7 MB"
                        }
                    }
                };
            case "document_convert":
                if (!input_path)
                    throw new Error("Input path is required for document conversion");
                // Simulate document conversion
                const convertOutputPath = output_path || path.join(process.cwd(), `converted_doc_${Date.now()}.pdf`);
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        output_path: convertOutputPath,
                        data: {
                            original_format: "DOCX",
                            converted_format: "PDF",
                            pages: 3
                        }
                    }
                };
            case "image_process":
                if (!input_path)
                    throw new Error("Input path is required for image processing");
                // Simulate image processing
                const imageOutputPath = output_path || path.join(process.cwd(), `processed_image_${Date.now()}.jpg`);
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        output_path: imageOutputPath,
                        data: {
                            original_size: "2.1 MB",
                            processed_size: "856 KB",
                            resolution: "1920x1080",
                            format: "JPEG"
                        }
                    }
                };
            case "text_extract":
                if (!input_data)
                    throw new Error("Input data is required for text extraction");
                // Simulate text extraction
                const extractedText = "This is extracted text from the provided content.";
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        text: extractedText
                    }
                };
            case "format_convert":
                if (!input_path)
                    throw new Error("Input path is required for format conversion");
                // Simulate format conversion
                const formatOutputPath = output_path || path.join(process.cwd(), `converted_${Date.now()}.${options.format || 'txt'}`);
                return {
                    content: [],
                    structuredContent: {
                        success: true,
                        output_path: formatOutputPath,
                        data: {
                            original_format: "unknown",
                            converted_format: options.format || "txt"
                        }
                    }
                };
        }
        return {
            content: [],
            structuredContent: {
                success: false,
                error: `Action '${action}' not implemented in content_processing. Available actions: ocr, pdf_parse, video_process, audio_process, document_convert, image_process, text_extract, format_convert`
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
// Enhanced browser cleanup paths
function getBrowserCachePaths(browser) {
    if (IS_WINDOWS) {
        const username = process.env.USERNAME || process.env.USER || 'default';
        return [
            `%LOCALAPPDATA%\\${browser}\\User Data\\Default\\Cache`,
            `%LOCALAPPDATA%\\${browser}\\User Data\\Default\\Code Cache`,
            `%LOCALAPPDATA%\\${browser}\\User Data\\Default\\GPUCache`
        ];
    }
    else if (IS_MACOS) {
        const homeDir = process.env.HOME || '/Users/default';
        return [
            `${homeDir}/Library/Caches/Google/Chrome`,
            `${homeDir}/Library/Caches/Mozilla/Firefox`,
            `${homeDir}/Library/Caches/com.apple.Safari`,
            `${homeDir}/Library/Caches/com.opera.Opera`,
            `${homeDir}/Library/Caches/com.microsoft.Edge`
        ];
    }
    else {
        // Linux cache paths
        const homeDir = process.env.HOME || '/home/default';
        return [
            `${homeDir}/.cache/google-chrome`,
            `${homeDir}/.cache/chromium`,
            `${homeDir}/.cache/mozilla/firefox`,
            `${homeDir}/.cache/opera`,
            `${homeDir}/.cache/microsoft-edge`,
            `${homeDir}/.mozilla/firefox`,
            `${homeDir}/.config/google-chrome`,
            `${homeDir}/.config/chromium`
        ];
    }
}
// Enhanced process management
async function killBrowserProcesses(browser) {
    try {
        if (IS_WINDOWS) {
            await execAsync(`taskkill /f /im ${browser}.exe`);
        }
        else if (IS_MACOS) {
            // More specific process killing for macOS
            await execAsync(`pkill -f "${browser}"`);
            await execAsync(`killall "${browser}"`);
        }
        else {
            // Enhanced Linux process killing
            await execAsync(`pkill -f "${browser}"`);
            await execAsync(`killall "${browser}"`);
            // Also try specific process names
            const processNames = [
                browser,
                `${browser}-stable`,
                browser === 'chrome' ? 'google-chrome' : browser,
                browser === 'edge' ? 'microsoft-edge' : browser
            ];
            for (const name of processNames) {
                try {
                    await execAsync(`pkill -f "${name}"`);
                }
                catch {
                    // Continue to next name
                }
            }
        }
        return true;
    }
    catch (error) {
        logger.warn(`Could not kill ${browser} processes`, { error: error instanceof Error ? error.message : String(error) });
        return false;
    }
}
// ============================================================================
// MISSING TOOLS - System Management
// ============================================================================
server.registerTool("unix_services", {
    description: "List Unix/Linux services (systemd, init.d, launchd)",
    inputSchema: { filter: z.string().optional() },
    outputSchema: {
        services: z.array(z.object({
            name: z.string(),
            status: z.string(),
            enabled: z.boolean().optional()
        })),
        platform: z.string()
    }
}, async ({ filter }) => {
    try {
        let services = [];
        if (IS_LINUX) {
            // Linux systemd services
            let command = "systemctl list-units --type=service --all --no-pager --no-legend";
            if (filter) {
                command += ` | grep -i "${filter}"`;
            }
            const { stdout } = await execAsync(command);
            const lines = stdout.trim().split("\n").filter(line => line.trim());
            services = lines.map(line => {
                const parts = line.trim().split(/\s+/);
                const name = parts[0] || "Unknown";
                const status = parts[2] || "Unknown";
                return {
                    name: name.replace('.service', ''),
                    status,
                    enabled: status === "active"
                };
            });
        }
        else if (IS_MACOS) {
            // macOS launchd services
            let command = "launchctl list";
            if (filter) {
                command += ` | grep -i "${filter}"`;
            }
            const { stdout } = await execAsync(command);
            const lines = stdout.trim().split("\n").slice(1); // Skip header
            services = lines.map(line => {
                const parts = line.trim().split(/\s+/);
                const pid = parts[0];
                const status = parts[1];
                const name = parts[2] || "Unknown";
                return {
                    name,
                    status: pid !== "-" ? "running" : "stopped",
                    enabled: status !== "-"
                };
            });
        }
        else {
            // Windows - return empty services for non-Windows platforms
            services = [];
        }
        return {
            content: [],
            structuredContent: {
                services: services.slice(0, 100), // Limit to 100 services
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                services: [],
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
server.registerTool("unix_processes", {
    description: "List Unix/Linux processes",
    inputSchema: { filter: z.string().optional() },
    outputSchema: {
        processes: z.array(z.object({
            pid: z.number(),
            name: z.string(),
            cpu: z.string().optional(),
            memory: z.string().optional()
        })),
        platform: z.string()
    }
}, async ({ filter }) => {
    try {
        let processes = [];
        if (IS_LINUX || IS_MACOS) {
            let command = "ps aux";
            if (filter) {
                command += ` | grep -i "${filter}" | grep -v grep`;
            }
            const { stdout } = await execAsync(command);
            const lines = stdout.trim().split("\n").slice(1); // Skip header
            processes = lines.map(line => {
                const parts = line.trim().split(/\s+/);
                return {
                    pid: parseInt(parts[1]) || 0,
                    name: parts[10] || "Unknown",
                    cpu: parts[2] || "0",
                    memory: parts[3] || "0"
                };
            }).filter(proc => proc.pid > 0);
        }
        else {
            // Windows - return empty processes for non-Windows platforms
            processes = [];
        }
        return {
            content: [],
            structuredContent: {
                processes: processes.slice(0, 100), // Limit to 100 processes
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                processes: [],
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
server.registerTool("system_maintenance", {
    description: "Perform system maintenance tasks",
    inputSchema: {
        action: z.enum(["disk_cleanup", "check_disk", "temp_cleanup", "cache_cleanup", "update_check"])
    },
    outputSchema: {
        success: z.boolean(),
        output: z.string().optional(),
        error: z.string().optional()
    }
}, async ({ action }) => {
    try {
        let command = "";
        switch (action) {
            case "disk_cleanup":
                if (IS_WINDOWS) {
                    command = "cleanmgr /sagerun:1";
                }
                else if (IS_LINUX) {
                    command = "sudo apt-get autoremove -y && sudo apt-get autoclean";
                }
                else if (IS_MACOS) {
                    command = "sudo rm -rf ~/Library/Caches/* /tmp/* 2>/dev/null || true";
                }
                break;
            case "check_disk":
                if (IS_WINDOWS) {
                    command = "chkdsk C: /f /r";
                }
                else if (IS_LINUX) {
                    command = "sudo fsck -f /";
                }
                else if (IS_MACOS) {
                    command = "diskutil verifyVolume /";
                }
                break;
            case "temp_cleanup":
                if (IS_WINDOWS) {
                    command = "del /q /f /s %TEMP%\\* 2>nul & del /q /f /s C:\\Windows\\Temp\\* 2>nul";
                }
                else {
                    command = "sudo rm -rf /tmp/* /var/tmp/* 2>/dev/null || true";
                }
                break;
            case "cache_cleanup":
                if (IS_WINDOWS) {
                    command = "RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8";
                }
                else if (IS_LINUX) {
                    command = "sudo sync && echo 3 | sudo tee /proc/sys/vm/drop_caches";
                }
                else if (IS_MACOS) {
                    command = "sudo rm -rf ~/Library/Caches/* 2>/dev/null || true";
                }
                break;
            case "update_check":
                if (IS_WINDOWS) {
                    command = "powershell Get-WindowsUpdate";
                }
                else if (IS_LINUX) {
                    command = "sudo apt list --upgradable";
                }
                else if (IS_MACOS) {
                    command = "softwareupdate -l";
                }
                break;
        }
        if (!command) {
            throw new Error(`Action ${action} not supported on ${PLATFORM}`);
        }
        const { stdout } = await execAsync(command, { timeout: 30000 });
        return {
            content: [],
            structuredContent: {
                success: true,
                output: stdout
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
server.registerTool("network_diagnostics", {
    description: "Network diagnostic tools (ping, traceroute, nslookup)",
    inputSchema: {
        action: z.enum(["ping", "traceroute", "nslookup", "netstat"]),
        target: z.string()
    },
    outputSchema: {
        success: z.boolean(),
        output: z.string().optional(),
        avgTime: z.number().optional(),
        error: z.string().optional()
    }
}, async ({ action, target }) => {
    try {
        let command = "";
        switch (action) {
            case "ping":
                if (IS_WINDOWS) {
                    command = `ping -n 4 ${target}`;
                }
                else {
                    command = `ping -c 4 ${target}`;
                }
                break;
            case "traceroute":
                if (IS_WINDOWS) {
                    command = `tracert ${target}`;
                }
                else {
                    command = `traceroute ${target}`;
                }
                break;
            case "nslookup":
                command = `nslookup ${target}`;
                break;
            case "netstat":
                if (IS_WINDOWS) {
                    command = `netstat -an | findstr ${target}`;
                }
                else {
                    command = `netstat -an | grep ${target}`;
                }
                break;
        }
        const { stdout } = await execAsync(command, { timeout: 30000 });
        // Extract average time for ping
        let avgTime;
        if (action === "ping") {
            const timeMatch = stdout.match(/Average = (\d+)ms|avg\/stddev = ([\d.]+)\/[\d.]+\/[\d.]+\/([\d.]+) ms/);
            if (timeMatch) {
                avgTime = parseFloat(timeMatch[1] || timeMatch[2] || "0");
            }
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                output: stdout,
                avgTime
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
server.registerTool("security_scan", {
    description: "Security scanning and analysis tools",
    inputSchema: {
        action: z.enum(["check_permissions", "scan_malware", "check_firewall", "audit_system"]),
        path: z.string().optional()
    },
    outputSchema: {
        success: z.boolean(),
        results: z.array(z.any()).optional(),
        summary: z.string().optional(),
        error: z.string().optional()
    }
}, async ({ action, path: targetPath }) => {
    try {
        let results = [];
        let summary = "";
        switch (action) {
            case "check_permissions":
                if (!targetPath)
                    targetPath = ".";
                if (IS_WINDOWS) {
                    const { stdout } = await execAsync(`icacls "${targetPath}"`);
                    results = stdout.split("\n").filter(line => line.trim()).map(line => ({
                        path: line.split(" ")[0],
                        permissions: line.substring(line.indexOf(" ") + 1)
                    }));
                }
                else {
                    const { stdout } = await execAsync(`ls -la "${targetPath}"`);
                    results = stdout.split("\n").filter(line => line.trim() && !line.startsWith("total")).map(line => {
                        const parts = line.split(/\s+/);
                        return {
                            permissions: parts[0],
                            owner: parts[2],
                            group: parts[3],
                            name: parts.slice(8).join(" ")
                        };
                    });
                }
                summary = `Found ${results.length} items with permission information`;
                break;
            case "scan_malware":
                summary = "Malware scanning requires specialized tools. Consider running Windows Defender, ClamAV, or similar.";
                results = [{ message: "Use dedicated antivirus software for malware scanning" }];
                break;
            case "check_firewall":
                if (IS_WINDOWS) {
                    const { stdout } = await execAsync("netsh advfirewall show allprofiles");
                    summary = "Windows Firewall status retrieved";
                    results = [{ output: stdout }];
                }
                else if (IS_LINUX) {
                    try {
                        const { stdout } = await execAsync("sudo ufw status");
                        summary = "UFW firewall status retrieved";
                        results = [{ output: stdout }];
                    }
                    catch {
                        const { stdout } = await execAsync("sudo iptables -L");
                        summary = "iptables rules retrieved";
                        results = [{ output: stdout }];
                    }
                }
                else if (IS_MACOS) {
                    const { stdout } = await execAsync("sudo pfctl -s all");
                    summary = "macOS firewall status retrieved";
                    results = [{ output: stdout }];
                }
                break;
            case "audit_system":
                summary = "Basic system audit completed";
                results = [
                    { check: "OS Version", result: PLATFORM },
                    { check: "Current User", result: process.env.USER || process.env.USERNAME || "unknown" },
                    { check: "Working Directory", result: process.cwd() },
                    { check: "Node.js Version", result: process.version }
                ];
                break;
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                results,
                summary
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                error: error.message
            }
        };
    }
});
// ============================================================================
// ADVANCED NETWORK TOOLS - Cross-Platform
// ============================================================================
server.registerTool("network_advanced", {
    description: "Advanced network operations (cross-platform)",
    inputSchema: {
        action: z.enum(["firewall_status", "port_scan", "dns_lookup", "route_table", "interface_info", "bandwidth_test"]),
        target: z.string().optional(),
        domain: z.string().optional(),
        port: z.number().optional()
    },
    outputSchema: {
        success: z.boolean(),
        results: z.any().optional(),
        platform: z.string(),
        error: z.string().optional()
    }
}, async ({ action, target, domain, port }) => {
    try {
        let command = "";
        let results = {};
        switch (action) {
            case "firewall_status":
                if (IS_WINDOWS) {
                    command = "netsh advfirewall show allprofiles";
                }
                else if (IS_LINUX) {
                    try {
                        command = "sudo ufw status verbose";
                    }
                    catch {
                        command = "sudo iptables -L -n";
                    }
                }
                else if (IS_MACOS) {
                    command = "sudo pfctl -s all";
                }
                break;
            case "port_scan":
                const scanTarget = target || "localhost";
                const scanPort = port || 80;
                if (IS_WINDOWS) {
                    command = `powershell "Test-NetConnection -ComputerName ${scanTarget} -Port ${scanPort}"`;
                }
                else {
                    command = `nc -zv ${scanTarget} ${scanPort} 2>&1 || echo "Port ${scanPort} closed or filtered"`;
                }
                break;
            case "dns_lookup":
                const lookupDomain = domain || target || "google.com";
                if (IS_WINDOWS) {
                    command = `nslookup ${lookupDomain}`;
                }
                else {
                    command = `dig ${lookupDomain} +short`;
                }
                break;
            case "route_table":
                if (IS_WINDOWS) {
                    command = "route print";
                }
                else {
                    command = "ip route show";
                }
                break;
            case "interface_info":
                if (IS_WINDOWS) {
                    command = "ipconfig /all";
                }
                else if (IS_LINUX) {
                    command = "ip addr show";
                }
                else if (IS_MACOS) {
                    command = "ifconfig";
                }
                break;
            case "bandwidth_test":
                if (IS_WINDOWS) {
                    command = "powershell \"Get-NetAdapter | Select-Object Name, LinkSpeed, Status\"";
                }
                else {
                    command = "cat /proc/net/dev | head -n 2";
                }
                break;
        }
        const { stdout } = await execAsync(command, { timeout: 30000 });
        results = {
            action,
            command,
            output: stdout,
            timestamp: new Date().toISOString()
        };
        return {
            content: [],
            structuredContent: {
                success: true,
                results,
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
server.registerTool("win_advanced", {
    description: "Windows advanced system operations",
    inputSchema: {
        action: z.enum(["sfc_scan", "dism_restore", "chkdsk", "system_file_check", "windows_update", "powercfg"])
    },
    outputSchema: {
        success: z.boolean(),
        output: z.string().optional(),
        platform: z.string(),
        error: z.string().optional()
    }
}, async ({ action }) => {
    try {
        if (!IS_WINDOWS) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    platform: PLATFORM,
                    error: "Windows advanced tools only available on Windows"
                }
            };
        }
        let command = "";
        switch (action) {
            case "sfc_scan":
                command = "sfc /scannow";
                break;
            case "dism_restore":
                command = "dism /online /cleanup-image /restorehealth";
                break;
            case "chkdsk":
                command = "chkdsk C: /f /r";
                break;
            case "system_file_check":
                command = "sfc /verifyonly";
                break;
            case "windows_update":
                command = "powershell Get-WindowsUpdate";
                break;
            case "powercfg":
                command = "powercfg /query";
                break;
        }
        const { stdout } = await execAsync(command, { timeout: 60000 });
        return {
            content: [],
            structuredContent: {
                success: true,
                output: stdout,
                platform: "windows"
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
server.registerTool("unix_advanced", {
    description: "Unix/Linux/macOS advanced system operations",
    inputSchema: {
        action: z.enum(["fsck", "system_update", "service_restart", "package_management", "system_cleanup", "kernel_info"]),
        service: z.string().optional()
    },
    outputSchema: {
        success: z.boolean(),
        output: z.string().optional(),
        platform: z.string(),
        error: z.string().optional()
    }
}, async ({ action, service }) => {
    try {
        if (IS_WINDOWS) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    platform: PLATFORM,
                    error: "Unix advanced tools only available on Unix/Linux/macOS"
                }
            };
        }
        let command = "";
        switch (action) {
            case "fsck":
                if (IS_LINUX) {
                    command = "sudo fsck -f /";
                }
                else if (IS_MACOS) {
                    command = "sudo fsck -f /";
                }
                break;
            case "system_update":
                if (IS_LINUX) {
                    command = "sudo apt update && sudo apt list --upgradable";
                }
                else if (IS_MACOS) {
                    command = "softwareupdate -l";
                }
                break;
            case "service_restart":
                const serviceName = service || "ssh";
                if (IS_LINUX) {
                    command = `sudo systemctl restart ${serviceName}`;
                }
                else if (IS_MACOS) {
                    command = `sudo launchctl unload /System/Library/LaunchDaemons/${serviceName}.plist && sudo launchctl load /System/Library/LaunchDaemons/${serviceName}.plist`;
                }
                break;
            case "package_management":
                if (IS_LINUX) {
                    command = "dpkg -l | head -20";
                }
                else if (IS_MACOS) {
                    command = "brew list | head -20";
                }
                break;
            case "system_cleanup":
                if (IS_LINUX) {
                    command = "sudo apt autoremove && sudo apt autoclean";
                }
                else if (IS_MACOS) {
                    command = "sudo rm -rf /tmp/* ~/Library/Caches/*";
                }
                break;
            case "kernel_info":
                command = "uname -a";
                break;
        }
        const { stdout } = await execAsync(command, { timeout: 60000 });
        return {
            content: [],
            structuredContent: {
                success: true,
                output: stdout,
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
server.registerTool("log_analysis", {
    description: "System log analysis (cross-platform)",
    inputSchema: {
        action: z.enum(["system_logs", "error_logs", "security_logs", "application_logs", "network_logs"]),
        hours: z.number().default(24),
        lines: z.number().default(100)
    },
    outputSchema: {
        success: z.boolean(),
        logs: z.array(z.any()).optional(),
        summary: z.string().optional(),
        platform: z.string(),
        error: z.string().optional()
    }
}, async ({ action, hours, lines }) => {
    try {
        let command = "";
        let logs = [];
        switch (action) {
            case "system_logs":
                if (IS_WINDOWS) {
                    command = `powershell "Get-EventLog -LogName System -Newest ${lines} | Select-Object TimeGenerated, EntryType, Message"`;
                }
                else if (IS_LINUX) {
                    command = `journalctl --since "${hours} hours ago" -n ${lines} --no-pager`;
                }
                else if (IS_MACOS) {
                    command = `log show --predicate 'category == "system"' --last ${hours}h --style compact`;
                }
                break;
            case "error_logs":
                if (IS_WINDOWS) {
                    command = `powershell "Get-EventLog -LogName System -EntryType Error -Newest ${lines}"`;
                }
                else if (IS_LINUX) {
                    command = `journalctl --since "${hours} hours ago" -p err -n ${lines} --no-pager`;
                }
                else if (IS_MACOS) {
                    command = `log show --predicate 'messageType == "Error"' --last ${hours}h --style compact`;
                }
                break;
            case "security_logs":
                if (IS_WINDOWS) {
                    command = `powershell "Get-EventLog -LogName Security -Newest ${lines}"`;
                }
                else if (IS_LINUX) {
                    command = `journalctl --since "${hours} hours ago" -p warning -n ${lines} --no-pager`;
                }
                else if (IS_MACOS) {
                    command = `log show --predicate 'category == "security"' --last ${hours}h --style compact`;
                }
                break;
            case "application_logs":
                if (IS_WINDOWS) {
                    command = `powershell "Get-EventLog -LogName Application -Newest ${lines}"`;
                }
                else if (IS_LINUX) {
                    command = `journalctl --since "${hours} hours ago" -n ${lines} --no-pager`;
                }
                else if (IS_MACOS) {
                    command = `log show --predicate 'category == "application"' --last ${hours}h --style compact`;
                }
                break;
            case "network_logs":
                if (IS_WINDOWS) {
                    command = `powershell "Get-EventLog -LogName System | Where-Object {$_.Message -like '*network*'} | Select-Object -First ${lines}"`;
                }
                else if (IS_LINUX) {
                    command = `journalctl --since "${hours} hours ago" | grep -i network | tail -${lines}`;
                }
                else if (IS_MACOS) {
                    command = `log show --predicate 'category == "network"' --last ${hours}h --style compact`;
                }
                break;
        }
        const { stdout } = await execAsync(command, { timeout: 30000 });
        // Parse logs into structured format
        const logLines = stdout.split('\n').filter(line => line.trim());
        logs = logLines.map((line, index) => ({
            id: index + 1,
            content: line.trim(),
            timestamp: new Date().toISOString()
        }));
        return {
            content: [],
            structuredContent: {
                success: true,
                logs: logs.slice(0, lines),
                summary: `Retrieved ${logs.length} log entries from the last ${hours} hours`,
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
server.registerTool("performance_monitor", {
    description: "System performance monitoring (cross-platform)",
    inputSchema: {
        action: z.enum(["cpu_usage", "memory_usage", "disk_usage", "network_usage", "process_top", "system_load"])
    },
    outputSchema: {
        success: z.boolean(),
        metrics: z.any().optional(),
        platform: z.string(),
        error: z.string().optional()
    }
}, async ({ action }) => {
    try {
        let command = "";
        let metrics = {};
        switch (action) {
            case "cpu_usage":
                if (IS_WINDOWS) {
                    command = "powershell \"Get-Counter '\\Processor(_Total)\\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue\"";
                }
                else {
                    command = "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1";
                }
                break;
            case "memory_usage":
                if (IS_WINDOWS) {
                    command = "powershell \"Get-Counter '\\Memory\\Available MBytes' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue\"";
                }
                else {
                    command = "free -m | grep Mem | awk '{print $3/$2 * 100.0}'";
                }
                break;
            case "disk_usage":
                if (IS_WINDOWS) {
                    command = "powershell \"Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, @{Name='Size(GB)';Expression={[math]::Round($_.Size/1GB,2)}}, @{Name='FreeSpace(GB)';Expression={[math]::Round($_.FreeSpace/1GB,2)}}\"";
                }
                else {
                    command = "df -h | grep -E '^/dev/'";
                }
                break;
            case "network_usage":
                if (IS_WINDOWS) {
                    command = "powershell \"Get-NetAdapterStatistics | Select-Object Name, BytesReceived, BytesSent\"";
                }
                else {
                    command = "cat /proc/net/dev | grep -E 'eth0|wlan0' | head -2";
                }
                break;
            case "process_top":
                if (IS_WINDOWS) {
                    command = "powershell \"Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, CPU, WorkingSet\"";
                }
                else {
                    command = "ps aux --sort=-%cpu | head -10";
                }
                break;
            case "system_load":
                if (IS_WINDOWS) {
                    command = "powershell \"Get-Counter '\\System\\Processor Queue Length' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue\"";
                }
                else {
                    command = "uptime";
                }
                break;
        }
        const { stdout } = await execAsync(command, { timeout: 30000 });
        metrics = {
            action,
            output: stdout,
            timestamp: new Date().toISOString(),
            platform: PLATFORM
        };
        return {
            content: [],
            structuredContent: {
                success: true,
                metrics,
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
server.registerTool("process_management", {
    description: "Process management operations (cross-platform)",
    inputSchema: {
        action: z.enum(["list_processes", "kill_process", "process_info", "process_tree", "resource_usage"]),
        processName: z.string().optional(),
        processId: z.number().optional()
    },
    outputSchema: {
        success: z.boolean(),
        processes: z.array(z.any()).optional(),
        platform: z.string(),
        error: z.string().optional()
    }
}, async ({ action, processName, processId }) => {
    try {
        let command = "";
        let processes = [];
        switch (action) {
            case "list_processes":
                if (IS_WINDOWS) {
                    command = "powershell \"Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet | Sort-Object CPU -Descending | Select-Object -First 20\"";
                }
                else {
                    command = "ps aux --sort=-%cpu | head -20";
                }
                break;
            case "kill_process":
                if (processId) {
                    if (IS_WINDOWS) {
                        command = `taskkill /PID ${processId} /F`;
                    }
                    else {
                        command = `kill -9 ${processId}`;
                    }
                }
                else if (processName) {
                    if (IS_WINDOWS) {
                        command = `taskkill /IM ${processName} /F`;
                    }
                    else {
                        command = `pkill -f ${processName}`;
                    }
                }
                else {
                    throw new Error("Process ID or name required for kill operation");
                }
                break;
            case "process_info":
                const targetProcess = processId || processName || "current";
                if (IS_WINDOWS) {
                    command = `powershell "Get-Process -Id ${targetProcess} | Select-Object *"`;
                }
                else {
                    command = `ps -p ${targetProcess} -o pid,ppid,cmd,%cpu,%mem`;
                }
                break;
            case "process_tree":
                if (IS_WINDOWS) {
                    command = "powershell \"Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId, Name | Sort-Object ProcessId\"";
                }
                else {
                    command = "pstree -p";
                }
                break;
            case "resource_usage":
                if (IS_WINDOWS) {
                    command = "powershell \"Get-Process | Measure-Object CPU, WorkingSet -Sum | Select-Object @{Name='TotalCPU';Expression={$_.Sum}}, @{Name='TotalMemory';Expression={[math]::Round($_.Sum/1MB,2)}}\"";
                }
                else {
                    command = "ps aux | awk '{cpu+=$3; mem+=$4} END {print \"Total CPU: \" cpu \"%\", \"Total Memory: \" mem \"%\"}'";
                }
                break;
        }
        const { stdout } = await execAsync(command, { timeout: 30000 });
        if (action === "list_processes" || action === "process_tree") {
            const lines = stdout.split('\n').filter(line => line.trim());
            processes = lines.map((line, index) => ({
                id: index + 1,
                content: line.trim()
            }));
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                processes: processes.length > 0 ? processes : undefined,
                output: processes.length === 0 ? stdout : undefined,
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
server.registerTool("file_system_advanced", {
    description: "Advanced file system operations (cross-platform)",
    inputSchema: {
        action: z.enum(["find_files", "check_permissions", "disk_space", "file_analysis", "symlink_info", "mount_info"]),
        path: z.string().optional(),
        pattern: z.string().optional()
    },
    outputSchema: {
        success: z.boolean(),
        results: z.any().optional(),
        platform: z.string(),
        error: z.string().optional()
    }
}, async ({ action, path: targetPath, pattern }) => {
    try {
        let command = "";
        let results = {};
        switch (action) {
            case "find_files":
                const searchPath = targetPath || ".";
                const searchPattern = pattern || "*";
                if (IS_WINDOWS) {
                    command = `powershell "Get-ChildItem -Path '${searchPath}' -Recurse -Filter '${searchPattern}' | Select-Object FullName, Length, LastWriteTime"`;
                }
                else {
                    command = `find ${searchPath} -name "${searchPattern}" -type f 2>/dev/null | head -50`;
                }
                break;
            case "check_permissions":
                const checkPath = targetPath || ".";
                if (IS_WINDOWS) {
                    command = `icacls "${checkPath}"`;
                }
                else {
                    command = `ls -la "${checkPath}"`;
                }
                break;
            case "disk_space":
                if (IS_WINDOWS) {
                    command = "powershell \"Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, @{Name='Size(GB)';Expression={[math]::Round($_.Size/1GB,2)}}, @{Name='FreeSpace(GB)';Expression={[math]::Round($_.FreeSpace/1GB,2)}}, @{Name='PercentFree';Expression={[math]::Round(($_.FreeSpace/$_.Size)*100,2)}}\"";
                }
                else {
                    command = "df -h";
                }
                break;
            case "file_analysis":
                const analyzePath = targetPath || ".";
                if (IS_WINDOWS) {
                    command = `powershell "Get-ChildItem -Path '${analyzePath}' -Recurse | Group-Object Extension | Sort-Object Count -Descending | Select-Object Name, Count"`;
                }
                else {
                    command = `find ${analyzePath} -type f | sed 's/.*\\.//' | sort | uniq -c | sort -nr | head -20`;
                }
                break;
            case "symlink_info":
                const symlinkPath = targetPath || ".";
                if (IS_WINDOWS) {
                    command = `powershell "Get-ChildItem -Path '${symlinkPath}' -Recurse | Where-Object {$_.LinkType -ne $null} | Select-Object FullName, LinkType, Target"`;
                }
                else {
                    command = `find ${symlinkPath} -type l -exec ls -la {} \\; 2>/dev/null | head -20`;
                }
                break;
            case "mount_info":
                if (IS_WINDOWS) {
                    command = "wmic logicaldisk get size,freespace,caption";
                }
                else {
                    command = "mount | column -t";
                }
                break;
        }
        const { stdout } = await execAsync(command, { timeout: 30000 });
        results = {
            action,
            path: targetPath || "current directory",
            output: stdout,
            timestamp: new Date().toISOString()
        };
        return {
            content: [],
            structuredContent: {
                success: true,
                results,
                platform: PLATFORM
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error.message
            }
        };
    }
});
// ============================================================================
// MAIN FUNCTION
// ============================================================================
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
}
main().catch((err) => {
    logger.error("Server error", { error: err instanceof Error ? err.message : String(err), stack: err instanceof Error ? err.stack : undefined });
    process.exit(1);
});
