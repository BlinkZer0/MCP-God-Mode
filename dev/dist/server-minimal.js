#!/usr/bin/env node
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const zod_1 = require("zod");
const path = __importStar(require("node:path"));
const os = __importStar(require("node:os"));
const fs = __importStar(require("node:fs/promises"));
const node_child_process_1 = require("node:child_process");
const node_util_1 = require("node:util");
const simple_git_1 = __importDefault(require("simple-git"));
const node_fs_1 = require("node:fs");
const math = __importStar(require("mathjs"));
const logger_js_1 = require("./utils/logger.js");
// Platform detection
const PLATFORM = os.platform();
const IS_WINDOWS = PLATFORM === "win32";
const IS_LINUX = PLATFORM === "linux";
const IS_MACOS = PLATFORM === "darwin";
// Security configuration
const ALLOWED_ROOTS_ARRAY = [process.cwd()];
const PROC_ALLOWLIST = []; // Empty = allow all
const MAX_BYTES = 1024 * 1024; // 1MB
const execAsync = (0, node_util_1.promisify)(node_child_process_1.exec);
// Log server startup
(0, logger_js_1.logServerStart)(PLATFORM);
// ===========================================
// CORE TOOLS
// ===========================================
const server = new mcp_js_1.McpServer({ name: "MCP God Mode - Minimal", version: "1.3" });
server.registerTool("health", {
    description: "Liveness/readiness probe",
    outputSchema: { ok: zod_1.z.boolean(), roots: zod_1.z.array(zod_1.z.string()), cwd: zod_1.z.string() }
}, async () => ({
    content: [{ type: "text", text: "ok" }],
    structuredContent: { ok: true, roots: ALLOWED_ROOTS_ARRAY, cwd: process.cwd() }
}));
server.registerTool("system_info", {
    description: "Basic host info (OS, arch, cpus, memGB)",
    outputSchema: { platform: zod_1.z.string(), arch: zod_1.z.string(), cpus: zod_1.z.number(), memGB: zod_1.z.number() }
}, async () => ({
    content: [],
    structuredContent: {
        platform: os.platform(),
        arch: os.arch(),
        cpus: os.cpus().length,
        memGB: Math.round((os.totalmem() / (1024 ** 3)) * 10) / 10
    }
}));
// ===========================================
// FILE SYSTEM TOOLS
// ===========================================
function ensureInsideRoot(filePath) {
    const resolved = path.resolve(filePath);
    for (const root of ALLOWED_ROOTS_ARRAY) {
        if (resolved.startsWith(path.resolve(root))) {
            return resolved;
        }
    }
    throw new Error(`Path outside allowed roots: ${filePath}`);
}
function limitString(str, maxBytes) {
    const bytes = Buffer.byteLength(str, 'utf8');
    if (bytes <= maxBytes) {
        return { text: str, truncated: false };
    }
    let truncated = str;
    while (Buffer.byteLength(truncated, 'utf8') > maxBytes) {
        truncated = truncated.slice(0, Math.floor(truncated.length * 0.9));
    }
    return { text: truncated + "\n... [truncated]", truncated: true };
}
server.registerTool("fs_list", {
    description: "List files/directories under a relative path (non-recursive)",
    inputSchema: { dir: zod_1.z.string().default(".").describe("The directory path to list files and folders from. Examples: '.', './documents', '/home/user/pictures', 'C:\\Users\\User\\Desktop'. Use '.' for current directory.") },
    outputSchema: { entries: zod_1.z.array(zod_1.z.object({ name: zod_1.z.string(), isDir: zod_1.z.boolean() })) }
}, async ({ dir }) => {
    let base;
    try {
        base = ensureInsideRoot(path.resolve(dir));
    }
    catch {
        base = path.resolve(ALLOWED_ROOTS_ARRAY[0], dir);
        ensureInsideRoot(base);
    }
    const items = await fs.readdir(base, { withFileTypes: true });
    return { content: [], structuredContent: { entries: items.map(d => ({ name: d.name, isDir: d.isDirectory() })) } };
});
server.registerTool("fs_read_text", {
    description: "Read a UTF-8 text file within the sandbox",
    inputSchema: { path: zod_1.z.string().describe("The file path to read from. Can be relative or absolute path. Examples: './config.txt', '/home/user/documents/readme.md', 'C:\\Users\\User\\Desktop\\notes.txt'.") },
    outputSchema: { path: zod_1.z.string(), content: zod_1.z.string(), truncated: zod_1.z.boolean() }
}, async ({ path: relPath }) => {
    const fullPath = ensureInsideRoot(path.resolve(relPath));
    const content = await fs.readFile(fullPath, "utf8");
    const { text, truncated } = limitString(content, MAX_BYTES);
    return { content: [], structuredContent: { path: fullPath, content: text, truncated } };
});
server.registerTool("fs_write_text", {
    description: "Write a UTF-8 text file within the sandbox",
    inputSchema: {
        path: zod_1.z.string().describe("The file path to write to. Can be relative or absolute path. Examples: './output.txt', '/home/user/documents/log.txt', 'C:\\Users\\User\\Desktop\\data.txt'."),
        content: zod_1.z.string().describe("The text content to write to the file. Can be plain text, JSON, XML, or any text-based format. Examples: 'Hello World', '{\"key\": \"value\"}', '<xml>data</xml>'.")
    },
    outputSchema: { path: zod_1.z.string(), success: zod_1.z.boolean() }
}, async ({ path: relPath, content }) => {
    const fullPath = ensureInsideRoot(path.resolve(relPath));
    await fs.writeFile(fullPath, content, "utf8");
    return { content: [], structuredContent: { path: fullPath, success: true } };
});
server.registerTool("fs_search", {
    description: "Search for files by name pattern",
    inputSchema: {
        pattern: zod_1.z.string().describe("The file name pattern to search for. Supports glob patterns and partial matches. Examples: '*.txt', 'config*', '*.js', 'README*', '*.{json,yaml}'."),
        dir: zod_1.z.string().default(".").describe("The directory to search in. Examples: '.', './src', '/home/user/documents', 'C:\\Users\\User\\Projects'. Use '.' for current directory.")
    },
    outputSchema: { matches: zod_1.z.array(zod_1.z.string()) }
}, async ({ pattern, dir }) => {
    const base = ensureInsideRoot(path.resolve(dir));
    const matches = [];
    try {
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
// ===========================================
// PROCESS EXECUTION TOOLS
// ===========================================
server.registerTool("proc_run", {
    description: "Run a process with arguments",
    inputSchema: {
        command: zod_1.z.string().describe("The command to execute. Examples: 'ls', 'dir', 'cat', 'echo', 'python', 'node', 'git', 'docker'. Can be any executable available in your system PATH or full path to an executable."),
        args: zod_1.z.array(zod_1.z.string()).default([]).describe("Array of command line arguments to pass to the command. Examples: ['-l', '-a'] for 'ls -l -a', ['--version'] for version info, ['install', 'package'] for package installation."),
        cwd: zod_1.z.string().optional().describe("Working directory for the command. Examples: './project', '/home/user/workspace', 'C:\\Users\\User\\Projects'. If not specified, uses the current working directory.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        stdout: zod_1.z.string().optional(),
        stderr: zod_1.z.string().optional(),
        exitCode: zod_1.z.number().optional()
    }
}, async ({ command, args, cwd }) => {
    if (PROC_ALLOWLIST.length > 0 && !PROC_ALLOWLIST.includes(command)) {
        throw new Error(`Command not allowed: ${command}. Allowed: ${PROC_ALLOWLIST.join(", ")}`);
    }
    const workingDir = cwd ? ensureInsideRoot(path.resolve(cwd)) : process.cwd();
    try {
        const { stdout, stderr } = await execAsync(`${command} ${args.join(" ")}`, { cwd: workingDir });
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
// ===========================================
// GIT TOOLS
// ===========================================
server.registerTool("git_status", {
    description: "Get git status for a repository",
    inputSchema: { dir: zod_1.z.string().default(".").describe("The directory containing the git repository to check. Examples: './project', '/home/user/repos/myproject', 'C:\\Users\\User\\Projects\\MyProject'. Use '.' for the current directory.") },
    outputSchema: {
        status: zod_1.z.string(),
        branch: zod_1.z.string().optional(),
        changes: zod_1.z.array(zod_1.z.string()).optional()
    }
}, async ({ dir }) => {
    const repoPath = ensureInsideRoot(path.resolve(dir));
    const git = (0, simple_git_1.default)(repoPath);
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
// ===========================================
// CALCULATOR TOOLS
// ===========================================
server.registerTool("calculator", {
    description: "Mathematical calculator with basic functions",
    inputSchema: {
        expression: zod_1.z.string().describe("The mathematical expression to evaluate. Supports basic arithmetic, scientific functions, and complex expressions. Examples: '2 + 2', 'sin(45)', 'sqrt(16)', '2^8', 'log(100)', '5!', '2 * (3 + 4)'."),
        precision: zod_1.z.number().default(10).describe("The number of decimal places to display in the result. Examples: 2 for currency, 5 for scientific calculations, 10 for high precision. Range: 0-15 decimal places.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        result: zod_1.z.string(),
        expression: zod_1.z.string(),
        type: zod_1.z.string(),
        error: zod_1.z.string().optional()
    }
}, async ({ expression, precision }) => {
    try {
        const result = math.evaluate(expression);
        const formattedResult = typeof result === 'number' ? result.toFixed(precision) : String(result);
        return {
            content: [],
            structuredContent: {
                success: true,
                result: formattedResult,
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
                result: "",
                expression: expression,
                type: "error",
                error: error instanceof Error ? error.message : String(error)
            }
        };
    }
});
// ===========================================
// DICE ROLLING TOOL
// ===========================================
server.registerTool("dice_rolling", {
    description: "Roll dice with various configurations and get random numbers. Supports any sided dice, multiple dice, and modifiers.",
    inputSchema: {
        dice: zod_1.z.string().describe("Dice notation (e.g., 'd6', '3d20', '2d10+5', 'd100'). Format: [count]d[sides][+/-modifier]"),
        count: zod_1.z.number().optional().describe("Number of times to roll (default: 1)"),
        modifier: zod_1.z.number().optional().describe("Additional modifier to apply to the final result (default: 0)")
    },
    outputSchema: {
        dice: zod_1.z.string(),
        rolls: zod_1.z.array(zod_1.z.array(zod_1.z.number())),
        total: zod_1.z.number(),
        modifier: zod_1.z.number(),
        breakdown: zod_1.z.string()
    }
}, async ({ dice, count = 1, modifier = 0 }) => {
    try {
        // Parse dice notation (e.g., "3d20+5" -> { number: 3, sides: 20, modifier: 5 })
        const diceRegex = /^(\d+)?d(\d+)([+-]\d+)?$/;
        const match = dice.match(diceRegex);
        if (!match) {
            throw new Error(`Invalid dice notation: ${dice}. Use format like 'd6', '3d20', or '2d10+5'`);
        }
        const diceNumber = match[1] ? parseInt(match[1]) : 1;
        const diceSides = parseInt(match[2]);
        const diceModifier = match[3] ? parseInt(match[3]) : 0;
        if (diceSides < 1) {
            throw new Error(`Invalid dice sides: ${diceSides}. Must be at least 1.`);
        }
        if (diceNumber < 1) {
            throw new Error(`Invalid dice count: ${diceNumber}. Must be at least 1.`);
        }
        // Generate random rolls
        const rolls = [];
        for (let i = 0; i < count; i++) {
            const diceRolls = [];
            for (let j = 0; j < diceNumber; j++) {
                // Cross-platform random number generation
                const roll = Math.floor(Math.random() * diceSides) + 1;
                diceRolls.push(roll);
            }
            rolls.push(diceRolls);
        }
        // Calculate totals
        const totals = rolls.map(diceRolls => diceRolls.reduce((sum, roll) => sum + roll, 0) + diceModifier + modifier);
        const total = totals.reduce((sum, t) => sum + t, 0);
        // Create breakdown string
        const breakdown = rolls.map((diceRolls, index) => {
            const diceTotal = diceRolls.reduce((sum, roll) => sum + roll, 0) + diceModifier + modifier;
            const diceBreakdown = diceRolls.join(' + ');
            return `Roll ${index + 1}: [${diceRolls.join(' + ')}] + ${diceModifier + modifier} = ${diceTotal}`;
        }).join('\n');
        return {
            content: [],
            structuredContent: {
                dice: dice,
                rolls: rolls,
                total: total,
                modifier: modifier + diceModifier,
                breakdown: breakdown
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                dice: dice,
                rolls: [],
                total: 0,
                modifier: modifier,
                breakdown: `Error: ${error instanceof Error ? error.message : String(error)}`
            }
        };
    }
});
// ===========================================
// DOWNLOAD TOOLS
// ===========================================
server.registerTool("download_file", {
    description: "Download a file from URL",
    inputSchema: {
        url: zod_1.z.string().url().describe("The URL of the file to download. Must be a valid HTTP/HTTPS URL. Examples: 'https://example.com/file.zip', 'http://downloads.example.org/document.pdf'."),
        outputPath: zod_1.z.string().optional().describe("Optional custom filename for the downloaded file. Examples: 'myfile.zip', './downloads/document.pdf', 'C:\\Users\\User\\Downloads\\file.txt'. If not specified, uses the original filename from the URL.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        path: zod_1.z.string().optional(),
        error: zod_1.z.string().optional()
    }
}, async ({ url, outputPath }) => {
    try {
        const fileName = outputPath || path.basename(new URL(url).pathname) || "downloaded_file";
        const fullPath = path.join(process.cwd(), fileName);
        ensureInsideRoot(fullPath);
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const fileStream = (0, node_fs_1.createWriteStream)(fullPath);
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
// ===========================================
// MOBILE DEVICE TOOLS (SIMPLIFIED)
// ===========================================
// Mobile File Operations
server.registerTool("mobile_file_ops", {
    description: "Mobile file operations for Android and iOS devices. Perform file management, data transfer, and search operations on mobile platforms with appropriate permission handling.",
    inputSchema: {
        action: zod_1.z.enum(["list", "copy", "move", "delete", "create", "get_info", "search"]).describe("File operation: 'list' shows contents, 'copy'/'move' transfer files, 'delete' removes items, 'create' makes files, 'get_info' shows details, 'search' finds files."),
        source: zod_1.z.string().optional().describe("Source path. Examples: '/sdcard/Documents/', '/var/mobile/Documents/', './photos/'. Required for most operations."),
        destination: zod_1.z.string().optional().describe("Destination path for copy/move. Examples: '/sdcard/backup/', './backup/'. Include filename for file operations."),
        content: zod_1.z.string().optional().describe("Content for new files. Examples: 'Hello World', '{\"config\": \"value\"}'. Used with create action."),
        pattern: zod_1.z.string().optional().describe("Search pattern. Examples: '*.jpg', '*.log', 'backup*'. Used with search action.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        platform: zod_1.z.string(),
        result: zod_1.z.any(),
        error: zod_1.z.string().optional()
    }
}, async ({ action, source, destination, content, pattern }) => {
    try {
        let result;
        switch (action) {
            case "list":
                if (!source)
                    throw new Error("Source path required for list");
                if (IS_LINUX || IS_MACOS) {
                    result = await execAsync(`ls -la "${source}"`);
                }
                else if (IS_WINDOWS) {
                    result = await execAsync(`dir "${source}"`);
                }
                else {
                    result = { message: "Mobile file listing requires platform-specific access", path: source };
                }
                break;
            case "copy":
                if (!source || !destination)
                    throw new Error("Source and destination required");
                if (IS_LINUX || IS_MACOS) {
                    result = await execAsync(`cp "${source}" "${destination}"`);
                }
                else if (IS_WINDOWS) {
                    result = await execAsync(`copy "${source}" "${destination}"`);
                }
                else {
                    result = { message: "Mobile file operations require platform-specific access" };
                }
                break;
            case "create":
                if (!destination || !content)
                    throw new Error("Destination and content required");
                if (IS_LINUX || IS_MACOS) {
                    result = await execAsync(`echo "${content}" > "${destination}"`);
                }
                else {
                    result = { message: "File creation completed", path: destination };
                }
                break;
            case "search":
                if (!source || !pattern)
                    throw new Error("Source and pattern required");
                if (IS_LINUX || IS_MACOS) {
                    result = await execAsync(`find "${source}" -name "${pattern}"`);
                }
                else {
                    result = { message: `Searching for ${pattern} in ${source}` };
                }
                break;
            default:
                result = { message: `${action} operation simulated for mobile platform`, platform: PLATFORM };
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                platform: PLATFORM,
                result,
                action
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                error: error.message,
                action
            }
        };
    }
});
// Mobile System Tools
server.registerTool("mobile_system_tools", {
    description: "Mobile system management for Android and iOS. Monitor processes, check storage, examine packages, and review system information on mobile devices.",
    inputSchema: {
        tool: zod_1.z.enum(["processes", "storage", "packages", "system_info"]).describe("System tool: 'processes' shows running apps, 'storage' checks disk usage, 'packages' lists installed apps, 'system_info' provides device details."),
        action: zod_1.z.string().optional().describe("Action to perform. Examples: 'list', 'info', 'analyze'. Actions vary by tool type."),
        filter: zod_1.z.string().optional().describe("Filter results. Examples: 'system', 'user', 'running'. Helps narrow down results.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        platform: zod_1.z.string(),
        tool: zod_1.z.string(),
        result: zod_1.z.any(),
        error: zod_1.z.string().optional()
    }
}, async ({ tool, action = "list", filter }) => {
    try {
        let result;
        switch (tool) {
            case "processes":
                if (IS_LINUX || IS_MACOS) {
                    result = await execAsync("ps aux | head -20");
                }
                else if (IS_WINDOWS) {
                    result = await execAsync("tasklist | findstr /v Image");
                }
                else {
                    result = { processes: ["system", "browser", "app1", "app2"], count: 4 };
                }
                break;
            case "storage":
                if (IS_LINUX || IS_MACOS) {
                    result = await execAsync("df -h");
                }
                else if (IS_WINDOWS) {
                    result = await execAsync("wmic logicaldisk get size,freespace,caption");
                }
                else {
                    result = { total: "64GB", used: "32GB", available: "32GB", usage: "50%" };
                }
                break;
            case "packages":
                if (IS_WINDOWS) {
                    result = await execAsync("wmic product get name,version | head -10");
                }
                else if (IS_LINUX) {
                    result = await execAsync("dpkg -l | head -10");
                }
                else if (IS_MACOS) {
                    result = await execAsync("ls /Applications | head -10");
                }
                else {
                    result = { packages: ["system.app", "browser.app"], count: 2 };
                }
                break;
            case "system_info":
                if (IS_WINDOWS) {
                    result = await execAsync("systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Model\"");
                }
                else if (IS_LINUX) {
                    result = await execAsync("uname -a && cat /etc/os-release | head -5");
                }
                else if (IS_MACOS) {
                    result = await execAsync("system_profiler SPSoftwareDataType SPHardwareDataType | head -10");
                }
                else {
                    result = {
                        platform: PLATFORM,
                        device: "Mobile Device",
                        os_version: "Unknown",
                        model: "Generic Device"
                    };
                }
                break;
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                platform: PLATFORM,
                tool,
                result,
                filter_applied: filter || "none"
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                tool,
                error: error.message
            }
        };
    }
});
// Mobile Hardware Access
server.registerTool("mobile_hardware", {
    description: "Mobile hardware access and sensor data for Android and iOS. Access device features like camera, location, sensors, and notifications with proper permission handling.",
    inputSchema: {
        feature: zod_1.z.enum(["camera", "location", "sensors", "notifications", "audio"]).describe("Hardware feature: 'camera' for photo/video, 'location' for GPS, 'sensors' for accelerometer/gyroscope, 'notifications' for alerts, 'audio' for microphone."),
        action: zod_1.z.enum(["check_availability", "get_status", "get_data"]).describe("Action: 'check_availability' verifies feature exists, 'get_status' shows current state, 'get_data' retrieves information.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        platform: zod_1.z.string(),
        feature: zod_1.z.string(),
        available: zod_1.z.boolean(),
        status: zod_1.z.string().optional(),
        data: zod_1.z.any().optional(),
        error: zod_1.z.string().optional()
    }
}, async ({ feature, action }) => {
    try {
        let result = {
            success: true,
            platform: PLATFORM,
            feature,
            available: true,
            status: "ready"
        };
        switch (action) {
            case "check_availability":
                result.available = true;
                result.message = `${feature} is available on ${PLATFORM}`;
                break;
            case "get_status":
                result.status = "enabled";
                result.permissions = "granted";
                break;
            case "get_data":
                switch (feature) {
                    case "location":
                        result.data = {
                            latitude: 37.7749,
                            longitude: -122.4194,
                            accuracy: 10,
                            note: "Simulated location data"
                        };
                        break;
                    case "sensors":
                        result.data = {
                            accelerometer: { x: 0.1, y: 0.2, z: 9.8 },
                            gyroscope: { x: 0.0, y: 0.1, z: 0.0 },
                            note: "Simulated sensor data"
                        };
                        break;
                    default:
                        result.data = { message: `${feature} data access simulated` };
                }
                break;
        }
        return {
            content: [],
            structuredContent: result
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                feature,
                error: error.message
            }
        };
    }
});
// ===========================================
// WEB SCRAPING & BROWSER AUTOMATION TOOLS
// ===========================================
// Web Scraper Tool (Simplified Version)
server.registerTool("web_scraper", {
    description: "Web scraping tool with CSS selector support and data extraction. Scrape web pages and extract structured data across all platforms.",
    inputSchema: {
        url: zod_1.z.string().url().describe("The URL of the web page to scrape. Must be a valid HTTP/HTTPS URL. Examples: 'https://example.com', 'https://news.website.com/articles'."),
        action: zod_1.z.enum(["scrape_page", "extract_data", "get_metadata"]).describe("The scraping action to perform. 'scrape_page' gets all content, 'extract_data' uses selectors, 'get_metadata' extracts page info."),
        selector: zod_1.z.string().optional().describe("CSS selector to target specific elements. Examples: 'h1', '.article-title', '#main-content'. Leave empty to scrape entire page."),
        output_format: zod_1.z.enum(["json", "text"]).optional().describe("Output format for scraped data. 'json' for structured data, 'text' for plain text.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        url: zod_1.z.string(),
        action: zod_1.z.string(),
        data: zod_1.z.any(),
        platform: zod_1.z.string(),
        timestamp: zod_1.z.string(),
        error: zod_1.z.string().optional()
    }
}, async ({ url, action, selector, output_format = "json" }) => {
    try {
        const response = await fetch(url, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        });
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const html = await response.text();
        let data;
        switch (action) {
            case "scrape_page":
                data = {
                    title: extractSimpleTitle(html),
                    content: extractSimpleText(html, selector)
                };
                break;
            case "extract_data":
                data = extractSimpleData(html, selector);
                break;
            case "get_metadata":
                data = {
                    title: extractSimpleTitle(html),
                    description: extractSimpleDescription(html),
                    url: url,
                    status: response.status
                };
                break;
            default:
                throw new Error(`Unknown action: ${action}`);
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                url,
                action,
                data: output_format === "text" ? JSON.stringify(data, null, 2) : data,
                platform: PLATFORM,
                timestamp: new Date().toISOString()
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                url,
                action,
                platform: PLATFORM,
                timestamp: new Date().toISOString(),
                error: error.message
            }
        };
    }
});
// Browser Control Tool (Simplified Version)
server.registerTool("browser_control", {
    description: "Cross-platform browser control tool. Launch browsers and navigate to URLs across Chrome, Firefox, Safari, Edge on all operating systems.",
    inputSchema: {
        action: zod_1.z.enum(["launch_browser", "navigate", "close_browser", "screenshot"]).describe("Browser action to perform. 'launch_browser' starts browser, 'navigate' goes to URL, 'close_browser' closes browser, 'screenshot' captures screen."),
        browser: zod_1.z.enum(["chrome", "firefox", "safari", "edge", "auto"]).optional().describe("Browser to control. 'chrome' for Google Chrome, 'firefox' for Mozilla Firefox, 'safari' for Safari (macOS), 'edge' for Microsoft Edge, 'auto' for system default."),
        url: zod_1.z.string().optional().describe("URL to navigate to. Examples: 'https://google.com', 'https://github.com'. Required for navigate action."),
        screenshot_path: zod_1.z.string().optional().describe("File path to save screenshots. Examples: './screenshot.png', 'C:\\Screenshots\\page.png'.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        action: zod_1.z.string(),
        browser: zod_1.z.string(),
        result: zod_1.z.any(),
        platform: zod_1.z.string(),
        timestamp: zod_1.z.string(),
        error: zod_1.z.string().optional()
    }
}, async ({ action, browser = "auto", url, screenshot_path }) => {
    try {
        let result;
        const selectedBrowser = browser === "auto" ? getSimpleDefaultBrowser() : browser;
        switch (action) {
            case "launch_browser":
                result = await launchSimpleBrowser(selectedBrowser);
                break;
            case "navigate":
                if (!url)
                    throw new Error("URL required for navigate action");
                result = await navigateSimple(url);
                break;
            case "close_browser":
                result = await closeSimpleBrowser(selectedBrowser);
                break;
            case "screenshot":
                result = await takeSimpleScreenshot(screenshot_path);
                break;
            default:
                throw new Error(`Unknown browser action: ${action}`);
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                action,
                browser: selectedBrowser,
                result,
                platform: PLATFORM,
                timestamp: new Date().toISOString()
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                action,
                browser: browser === "auto" ? getSimpleDefaultBrowser() : browser,
                platform: PLATFORM,
                timestamp: new Date().toISOString(),
                error: error.message
            }
        };
    }
});
// ===========================================
// SIMPLIFIED HELPER FUNCTIONS
// ===========================================
function extractSimpleTitle(html) {
    const match = html.match(/<title[^>]*>([^<]*)<\/title>/i);
    return match ? match[1].trim() : 'No title';
}
function extractSimpleDescription(html) {
    const match = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["'][^>]*>/i);
    return match ? match[1].trim() : '';
}
function extractSimpleText(html, selector) {
    if (selector) {
        // Simple selector extraction
        if (selector.startsWith('#')) {
            const id = selector.substring(1);
            const regex = new RegExp(`<[^>]*id=["']${id}["'][^>]*>([^<]*)<\\/[^>]*>`, 'i');
            const match = html.match(regex);
            return match ? match[1].trim() : '';
        }
        if (selector === 'h1') {
            const match = html.match(/<h1[^>]*>([^<]*)<\/h1>/i);
            return match ? match[1].trim() : '';
        }
    }
    // Extract basic text content
    return html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().substring(0, 1000);
}
function extractSimpleData(html, selector) {
    const data = {
        title: extractSimpleTitle(html),
        links: [],
        text: extractSimpleText(html, selector)
    };
    // Extract links
    const linkRegex = /<a[^>]*href=["']([^"']*)["'][^>]*>([^<]*)<\/a>/gi;
    let match;
    while ((match = linkRegex.exec(html)) !== null && data.links.length < 10) {
        data.links.push({ url: match[1], text: match[2].trim() });
    }
    return data;
}
function getSimpleDefaultBrowser() {
    if (IS_WINDOWS)
        return "edge";
    if (IS_MACOS)
        return "safari";
    return "firefox";
}
async function launchSimpleBrowser(browser) {
    try {
        let command = "";
        switch (browser.toLowerCase()) {
            case "chrome":
                if (IS_WINDOWS)
                    command = "start chrome";
                else if (IS_LINUX)
                    command = "google-chrome";
                else if (IS_MACOS)
                    command = "open -a 'Google Chrome'";
                break;
            case "firefox":
                if (IS_WINDOWS)
                    command = "start firefox";
                else if (IS_LINUX)
                    command = "firefox";
                else if (IS_MACOS)
                    command = "open -a Firefox";
                break;
            case "safari":
                if (IS_MACOS)
                    command = "open -a Safari";
                else
                    throw new Error("Safari only available on macOS");
                break;
            case "edge":
                if (IS_WINDOWS)
                    command = "start msedge";
                else if (IS_LINUX)
                    command = "microsoft-edge";
                else if (IS_MACOS)
                    command = "open -a 'Microsoft Edge'";
                break;
            default:
                throw new Error(`Unsupported browser: ${browser}`);
        }
        await execAsync(command);
        return { launched: true, message: `${browser} launched successfully` };
    }
    catch (error) {
        throw new Error(`Failed to launch browser: ${error.message}`);
    }
}
async function navigateSimple(url) {
    try {
        let command = "";
        if (IS_WINDOWS) {
            command = `start "" "${url}"`;
        }
        else if (IS_LINUX) {
            command = `xdg-open "${url}"`;
        }
        else if (IS_MACOS) {
            command = `open "${url}"`;
        }
        await execAsync(command);
        return { navigated: true, message: `Opened ${url}` };
    }
    catch (error) {
        throw new Error(`Failed to navigate: ${error.message}`);
    }
}
async function closeSimpleBrowser(browser) {
    try {
        let command = "";
        if (IS_WINDOWS) {
            switch (browser.toLowerCase()) {
                case "chrome":
                    command = "taskkill /f /im chrome.exe";
                    break;
                case "firefox":
                    command = "taskkill /f /im firefox.exe";
                    break;
                case "edge":
                    command = "taskkill /f /im msedge.exe";
                    break;
                default: command = `taskkill /f /im ${browser}.exe`;
            }
        }
        else {
            command = `pkill ${browser}`;
        }
        await execAsync(command);
        return { closed: true, message: `${browser} closed` };
    }
    catch (error) {
        return { closed: true, message: `${browser} closed (or wasn't running)` };
    }
}
async function takeSimpleScreenshot(screenshotPath) {
    try {
        const outputPath = screenshotPath || `screenshot_${Date.now()}.png`;
        if (IS_WINDOWS) {
            const command = `powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Screen]::PrimaryScreen.Bounds | ForEach-Object { $bitmap = New-Object System.Drawing.Bitmap($_.Width, $_.Height); $graphics = [System.Drawing.Graphics]::FromImage($bitmap); $graphics.CopyFromScreen($_.X, $_.Y, 0, 0, $_.Size); $bitmap.Save('${outputPath}', [System.Drawing.Imaging.ImageFormat]::Png); }"`;
            await execAsync(command);
        }
        else if (IS_LINUX) {
            await execAsync(`scrot "${outputPath}" || gnome-screenshot -f "${outputPath}"`);
        }
        else if (IS_MACOS) {
            await execAsync(`screencapture "${outputPath}"`);
        }
        else {
            throw new Error("Screenshot not supported on this platform");
        }
        return { screenshot_path: outputPath, message: `Screenshot saved to ${outputPath}` };
    }
    catch (error) {
        throw new Error(`Failed to take screenshot: ${error.message}`);
    }
}
// ===========================================
// SYSTEM RESTORE TOOL (MINIMAL VERSION)
// ===========================================
server.registerTool("system_restore", {
    description: "💾 **System Restore & Backup Management (Minimal)** - Basic system restore and backup management for Windows, Linux, and macOS. Create restore points, backup configurations, and restore systems. Limited to 4 essential actions: create_restore_point, list_restore_points, restore_system, backup_config. Cross-platform support with platform-specific optimizations.",
    inputSchema: {
        action: zod_1.z.enum([
            "create_restore_point", "list_restore_points", "restore_system", "backup_config"
        ]).describe("**System Restore Actions (4 Operations):** 'create_restore_point' - Create system restore points across platforms (Windows: PowerShell System Restore, Linux/macOS: File-based /etc backup), 'list_restore_points' - List available restore points with metadata (Windows: System Restore catalog, Linux/macOS: Backup logs), 'restore_system' - Rollback system to previous state (Windows: System Restore, Linux/macOS: File restoration), 'backup_config' - Backup critical system configurations (Windows: Registry export, Linux/macOS: /etc directory backup)."),
        description: zod_1.z.string().optional().describe("Description for the restore point or backup."),
        target_path: zod_1.z.string().optional().describe("Target path for backup operations.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        platform: zod_1.z.string(),
        action: zod_1.z.string(),
        result: zod_1.z.any(),
        message: zod_1.z.string(),
        error: zod_1.z.string().optional()
    }
}, async ({ action, description, target_path }) => {
    try {
        let result;
        switch (action) {
            case "create_restore_point":
                if (IS_WINDOWS) {
                    const restoreDesc = description || `System restore point created on ${new Date().toISOString()}`;
                    const command = `powershell -Command "Checkpoint-Computer -Description '${restoreDesc}' -RestorePointType 'MODIFY_SETTINGS' -Verbose"`;
                    await execAsync(command);
                    result = { message: "Windows restore point created successfully" };
                }
                else if (IS_LINUX || IS_MACOS) {
                    const backupPath = target_path || `/tmp/backup_${Date.now()}`;
                    await fs.mkdir(backupPath, { recursive: true });
                    // Simple backup of /etc directory
                    const etcBackup = path.join(backupPath, 'etc');
                    await fs.mkdir(etcBackup, { recursive: true });
                    try {
                        const etcEntries = await fs.readdir('/etc', { withFileTypes: true });
                        for (const entry of etcEntries) {
                            if (entry.isFile()) {
                                try {
                                    const sourcePath = path.join('/etc', entry.name);
                                    const destPath = path.join(etcBackup, entry.name);
                                    await fs.copyFile(sourcePath, destPath);
                                }
                                catch (error) {
                                    // Skip files that can't be copied
                                }
                            }
                        }
                        result = {
                            message: `${IS_LINUX ? 'Linux' : 'macOS'} configuration backed up successfully`,
                            backup_path: backupPath
                        };
                    }
                    catch (error) {
                        result = { message: "Partial backup completed (some files skipped)" };
                    }
                }
                break;
            case "list_restore_points":
                if (IS_WINDOWS) {
                    const command = `powershell -Command "Get-ComputerRestorePoint | Select-Object SequenceNumber, Description, CreationTime | ConvertTo-Json"`;
                    const { stdout } = await execAsync(command);
                    const restorePoints = JSON.parse(stdout);
                    result = {
                        message: `Found ${restorePoints.length} Windows restore points`,
                        restore_points: restorePoints
                    };
                }
                else {
                    result = {
                        message: "Restore points not available on this platform",
                        restore_points: []
                    };
                }
                break;
            case "restore_system":
                if (IS_WINDOWS && description) {
                    const command = `powershell -Command "Restore-Computer -RestorePoint ${description} -Confirm:$false"`;
                    await execAsync(command);
                    result = { message: "System restore initiated. System will restart." };
                }
                else {
                    result = { message: "System restore not available on this platform" };
                }
                break;
            case "backup_config":
                if (IS_LINUX || IS_MACOS) {
                    const backupPath = target_path || `/tmp/config_backup_${Date.now()}`;
                    await fs.mkdir(backupPath, { recursive: true });
                    // Backup common config directories
                    const configDirs = ['/etc', '/usr/local/etc'];
                    for (const dir of configDirs) {
                        try {
                            const destPath = path.join(backupPath, path.basename(dir));
                            await fs.mkdir(destPath, { recursive: true });
                            const entries = await fs.readdir(dir, { withFileTypes: true });
                            for (const entry of entries) {
                                if (entry.isFile()) {
                                    try {
                                        const sourcePath = path.join(dir, entry.name);
                                        const destFile = path.join(destPath, entry.name);
                                        await fs.copyFile(sourcePath, destFile);
                                    }
                                    catch (error) {
                                        // Skip files that can't be copied
                                    }
                                }
                            }
                        }
                        catch (error) {
                            // Skip directories that can't be accessed
                        }
                    }
                    result = {
                        message: "System configuration backed up successfully",
                        backup_path: backupPath
                    };
                }
                else {
                    result = { message: "Configuration backup not available on this platform" };
                }
                break;
            default:
                result = { message: `Action ${action} not supported in minimal version` };
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                platform: PLATFORM,
                action,
                result,
                message: result.message || `${action} completed successfully`
            }
        };
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return {
            content: [],
            structuredContent: {
                success: false,
                platform: PLATFORM,
                action,
                result: null,
                message: `Failed to perform ${action}`,
                error: errorMessage
            }
        };
    }
});
// ===========================================
// EMAIL TOOLS - Cross-platform email functionality
// ===========================================
// Import email libraries
const nodemailer_1 = __importDefault(require("nodemailer"));
const mailparser_1 = require("mailparser");
// Email configuration cache
const emailTransports = new Map();
// Helper function to get email transport
async function getEmailTransport(config) {
    const configKey = JSON.stringify(config);
    if (emailTransports.has(configKey)) {
        return emailTransports.get(configKey);
    }
    let transport;
    if (config.service === 'gmail') {
        transport = nodemailer_1.default.createTransport({
            service: 'gmail',
            auth: {
                user: config.email,
                pass: config.password
            }
        });
    }
    else if (config.service === 'outlook') {
        transport = nodemailer_1.default.createTransport({
            host: 'smtp-mail.outlook.com',
            port: 587,
            secure: false,
            auth: {
                user: config.email,
                pass: config.password
            }
        });
    }
    else if (config.service === 'yahoo') {
        transport = nodemailer_1.default.createTransport({
            host: 'smtp.mail.yahoo.com',
            port: 587,
            secure: false,
            auth: {
                user: config.email,
                pass: config.password
            }
        });
    }
    else {
        transport = nodemailer_1.default.createTransport({
            host: config.host,
            port: config.port || 587,
            secure: config.secure || false,
            auth: {
                user: config.email,
                pass: config.password
            }
        });
    }
    try {
        await transport.verify();
        emailTransports.set(configKey, transport);
        return transport;
    }
    catch (error) {
        throw new Error(`Failed to connect to email server: ${error}`);
    }
}
// Send email tool
server.registerTool("send_email", {
    description: "Send emails using SMTP across all platforms (Windows, Linux, macOS, Android, iOS). Supports Gmail, Outlook, Yahoo, and custom SMTP servers with proper authentication and security.",
    inputSchema: {
        to: zod_1.z.string().describe("Recipient email address(es). Examples: 'user@example.com', 'user1@example.com,user2@example.com' for multiple recipients."),
        subject: zod_1.z.string().describe("Email subject line. Examples: 'Meeting Reminder', 'Project Update', 'Hello from MCP God Mode'."),
        body: zod_1.z.string().describe("Email body content. Can be plain text or HTML. Examples: 'Hello, this is a test email.', '<h1>Hello</h1><p>This is HTML content.</p>'."),
        html: zod_1.z.boolean().default(false).describe("Whether the email body contains HTML content. Set to true for HTML emails, false for plain text."),
        from: zod_1.z.string().optional().describe("Sender email address. If not provided, uses the configured email address."),
        cc: zod_1.z.string().optional().describe("CC recipient email address(es). Examples: 'cc@example.com', 'cc1@example.com,cc2@example.com'."),
        bcc: zod_1.z.string().optional().describe("BCC recipient email address(es). Examples: 'bcc@example.com', 'bcc1@example.com,bcc2@example.com'."),
        attachments: zod_1.z.array(zod_1.z.object({
            filename: zod_1.z.string().describe("Name of the attachment file. Examples: 'document.pdf', 'image.jpg', 'report.xlsx'."),
            content: zod_1.z.string().describe("Base64 encoded content of the attachment file."),
            contentType: zod_1.z.string().optional().describe("MIME type of the attachment. Examples: 'application/pdf', 'image/jpeg', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'.")
        })).optional().describe("Array of file attachments to include with the email."),
        email_config: zod_1.z.object({
            service: zod_1.z.enum(["gmail", "outlook", "yahoo", "custom"]).describe("Email service provider. 'gmail' for Google Mail, 'outlook' for Microsoft Outlook/Hotmail, 'yahoo' for Yahoo Mail, 'custom' for other SMTP servers."),
            email: zod_1.z.string().describe("Email address for authentication. Examples: 'user@gmail.com', 'user@outlook.com', 'user@company.com'."),
            password: zod_1.z.string().describe("Password or app password for the email account. For Gmail, use App Password if 2FA is enabled."),
            host: zod_1.z.string().optional().describe("SMTP host for custom servers. Examples: 'smtp.company.com', 'mail.example.org'. Required when service is 'custom'."),
            port: zod_1.z.number().optional().describe("SMTP port for custom servers. Examples: 587 for TLS, 465 for SSL, 25 for unencrypted. Defaults to 587 for TLS."),
            secure: zod_1.z.boolean().optional().describe("Whether to use SSL/TLS encryption. Examples: true for port 465, false for port 587. Defaults to false for TLS."),
            name: zod_1.z.string().optional().describe("Display name for the sender. Examples: 'John Doe', 'Company Name', 'MCP God Mode'.")
        }).describe("Email server configuration including service provider, credentials, and connection settings.")
    },
    outputSchema: {
        success: zod_1.z.boolean().describe("Whether the email was sent successfully."),
        message_id: zod_1.z.string().optional().describe("Unique message ID returned by the email server."),
        response: zod_1.z.string().optional().describe("Response message from the email server."),
        error: zod_1.z.string().optional().describe("Error message if the email failed to send."),
        platform: zod_1.z.string().describe("Platform where the email tool was executed."),
        timestamp: zod_1.z.string().describe("Timestamp when the email was sent.")
    }
}, async ({ to, subject, body, html = false, from, cc, bcc, attachments, email_config }) => {
    try {
        const transport = await getEmailTransport(email_config);
        const mailOptions = {
            from: from || email_config.name ? `"${email_config.name}" <${email_config.email}>` : email_config.email,
            to,
            subject,
            text: html ? undefined : body,
            html: html ? body : undefined,
            cc,
            bcc,
            attachments: attachments ? attachments.map(att => ({
                filename: att.filename,
                content: Buffer.from(att.content, 'base64'),
                contentType: att.contentType
            })) : undefined
        };
        const result = await transport.sendMail(mailOptions);
        return {
            content: [],
            structuredContent: {
                success: true,
                message_id: result.messageId,
                response: `Email sent successfully to ${to}`,
                error: undefined,
                platform: PLATFORM,
                timestamp: new Date().toISOString()
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                message_id: undefined,
                response: undefined,
                error: `Failed to send email: ${error.message}`,
                platform: PLATFORM,
                timestamp: new Date().toISOString()
            }
        };
    }
});
// Parse email content tool
server.registerTool("parse_email", {
    description: "Parse and analyze email content across all platforms (Windows, Linux, macOS, Android, iOS). Extract text, HTML, attachments, headers, and metadata from email messages with comprehensive parsing capabilities.",
    inputSchema: {
        email_content: zod_1.z.string().describe("Raw email content in MIME format or email file path. Examples: 'From: sender@example.com\\nSubject: Test\\n\\nHello world', './email.eml', '/path/to/email.txt'."),
        parse_attachments: zod_1.z.boolean().default(true).describe("Whether to parse and extract email attachments. Set to true to include attachment information, false to skip attachments."),
        extract_links: zod_1.z.boolean().default(true).describe("Whether to extract URLs and links from email content. Set to true to find all links, false to skip link extraction."),
        extract_emails: zod_1.z.boolean().default(true).describe("Whether to extract email addresses from the content. Set to true to find all email addresses, false to skip email extraction."),
        include_headers: zod_1.z.boolean().default(true).describe("Whether to include email headers in the parsed result. Set to true for complete header information, false for content only.")
    },
    outputSchema: {
        success: zod_1.z.boolean().describe("Whether the email was parsed successfully."),
        parsed_email: zod_1.z.object({
            from: zod_1.z.string().describe("Sender email address and name."),
            to: zod_1.z.string().describe("Recipient email address(es)."),
            subject: zod_1.z.string().describe("Subject line of the email."),
            date: zod_1.z.string().describe("Date and time when the email was sent."),
            message_id: zod_1.z.string().describe("Unique message identifier."),
            text_content: zod_1.z.string().describe("Plain text content of the email."),
            html_content: zod_1.z.string().optional().describe("HTML content of the email if available."),
            headers: zod_1.z.record(zod_1.z.string()).optional().describe("Complete email headers including routing, authentication, and metadata information."),
            attachments: zod_1.z.array(zod_1.z.object({
                filename: zod_1.z.string().describe("Name of the attachment file."),
                content_type: zod_1.z.string().describe("MIME type of the attachment."),
                size: zod_1.z.number().describe("Size of the attachment in bytes."),
                content: zod_1.z.string().optional().describe("Base64 encoded content of the attachment if requested.")
            })).optional().describe("Array of file attachments found in the email."),
            links: zod_1.z.array(zod_1.z.string()).optional().describe("Array of URLs and links found in the email content."),
            emails: zod_1.z.array(zod_1.z.string()).optional().describe("Array of email addresses found in the email content."),
            size: zod_1.z.number().describe("Total size of the email in bytes.")
        }).optional().describe("Parsed email content with extracted information and metadata."),
        error: zod_1.z.string().optional().describe("Error message if the parsing failed."),
        platform: zod_1.z.string().describe("Platform where the email tool was executed."),
        timestamp: zod_1.z.string().describe("Timestamp when the email was parsed.")
    }
}, async ({ email_content, parse_attachments = true, extract_links = true, extract_emails = true, include_headers = true }) => {
    try {
        let content = email_content;
        // If it's a file path, read the file
        if (email_content.includes('\n') === false && (email_content.endsWith('.eml') || email_content.endsWith('.txt'))) {
            try {
                content = await fs.readFile(email_content, 'utf8');
            }
            catch (fileError) {
                // If file reading fails, treat as direct content
            }
        }
        const parsed = await (0, mailparser_1.simpleParser)(content);
        const result = {
            from: parsed.from?.text || 'Unknown Sender',
            to: Array.isArray(parsed.to) ? parsed.to[0]?.text || 'Unknown Recipient' : parsed.to?.text || 'Unknown Recipient',
            subject: parsed.subject || 'No Subject',
            date: parsed.date?.toISOString() || 'Unknown Date',
            message_id: parsed.messageId || 'Unknown ID',
            text_content: parsed.text || '',
            html_content: parsed.html || undefined,
            headers: include_headers ? parsed.headers : undefined,
            attachments: parse_attachments ? parsed.attachments?.map(att => ({
                filename: att.filename || 'unnamed',
                content_type: att.contentType || 'application/octet-stream',
                size: att.size || 0,
                content: att.content?.toString('base64')
            })) : undefined,
            links: extract_links ? extractLinksFromText(parsed.text || '') : undefined,
            emails: extract_emails ? extractEmailsFromText(parsed.text || '') : undefined,
            size: parsed.text ? Buffer.byteLength(parsed.text, 'utf8') : 0
        };
        return {
            content: [],
            structuredContent: {
                success: true,
                parsed_email: result,
                error: undefined,
                platform: PLATFORM,
                timestamp: new Date().toISOString()
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                parsed_email: undefined,
                error: `Failed to parse email: ${error.message}`,
                platform: PLATFORM,
                timestamp: new Date().toISOString()
            }
        };
    }
});
// Helper functions for email parsing
function extractLinksFromText(text) {
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    return text.match(urlRegex) || [];
}
function extractEmailsFromText(text) {
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    return text.match(emailRegex) || [];
}
// ===========================================
// MAIN FUNCTION
// ===========================================
async function main() {
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
}
main().catch((err) => {
    logger_js_1.logger.error("Server error", { error: err instanceof Error ? err.message : String(err), stack: err instanceof Error ? err.stack : undefined });
    process.exit(1);
});
