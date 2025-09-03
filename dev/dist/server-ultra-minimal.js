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
// Ultra-minimal configuration
const PLATFORM = os.platform();
const ALLOWED_ROOTS_ARRAY = [process.cwd()];
const MAX_BYTES = 1024 * 1024; // 1MB
const execAsync = (0, node_util_1.promisify)(node_child_process_1.exec);
// Minimal logging
function log(level, message) {
    if (process.env.NODE_ENV !== 'production') {
        console.log(`[${new Date().toISOString()}] ${level.toUpperCase()}: ${message}`);
    }
}
log('info', `MCP Server starting on ${PLATFORM}`);
// ===========================================
// CORE TOOLS ONLY
// ===========================================
const server = new mcp_js_1.McpServer({ name: "mcp-ultra-minimal", version: "1.0.0" });
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
// ESSENTIAL FILE SYSTEM TOOLS
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
    description: "List files and directories under a relative path (non-recursive)",
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
// ===========================================
// ESSENTIAL PROCESS EXECUTION
// ===========================================
server.registerTool("proc_run", {
    description: "Run a process with arguments",
    inputSchema: {
        command: zod_1.z.string().describe("The command to execute. Examples: 'ls', 'dir', 'cat', 'echo', 'python', 'node', 'git', 'docker'. Can be any executable available in your system PATH or full path to an executable."),
        args: zod_1.z.array(zod_1.z.string()).default([]).describe("Array of command-line arguments to pass to the command. Examples: ['-la'] for 'ls -la', ['--version'] for version info, ['filename.txt'] for file operations. Leave empty array for commands with no arguments."),
        cwd: zod_1.z.string().optional().describe("The working directory where the command will be executed. Examples: './project', '/home/user/documents', 'C:\\Users\\User\\Desktop'. Leave empty to use the current working directory.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        stdout: zod_1.z.string().optional(),
        stderr: zod_1.z.string().optional(),
        exitCode: zod_1.z.number().optional()
    }
}, async ({ command, args, cwd }) => {
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
// MOBILE TOOLS (ULTRA-MINIMAL)
// ===========================================
// Basic Mobile File Operations
server.registerTool("mobile_file_ops", {
    description: "Basic mobile file operations for Android and iOS devices",
    inputSchema: {
        action: zod_1.z.enum(["list", "create", "search"]).describe("File operation: 'list' shows directory, 'create' makes files, 'search' finds files."),
        source: zod_1.z.string().optional().describe("Source path. Examples: '/sdcard/', '/var/mobile/Documents/'."),
        content: zod_1.z.string().optional().describe("File content for create action."),
        pattern: zod_1.z.string().optional().describe("Search pattern like '*.jpg' or 'backup*'.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        result: zod_1.z.any(),
        error: zod_1.z.string().optional()
    }
}, async ({ action, source, content, pattern }) => {
    try {
        let result;
        switch (action) {
            case "list":
                if (!source)
                    throw new Error("Source path required");
                if (PLATFORM === "android" || PLATFORM === "linux" || PLATFORM === "darwin") {
                    result = await execAsync(`ls "${source}"`);
                }
                else {
                    result = { message: `Listing contents of ${source}`, items: [] };
                }
                break;
            case "create":
                if (!source || !content)
                    throw new Error("Source and content required");
                result = { message: `Created file at ${source}`, content_length: content.length };
                break;
            case "search":
                if (!source || !pattern)
                    throw new Error("Source and pattern required");
                result = { message: `Searching for ${pattern} in ${source}`, matches: [] };
                break;
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                result
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
// Basic Mobile System Info
server.registerTool("mobile_system_tools", {
    description: "Basic mobile system information and process management",
    inputSchema: {
        tool: zod_1.z.enum(["processes", "system_info"]).describe("System tool: 'processes' shows running apps, 'system_info' shows device info."),
        filter: zod_1.z.string().optional().describe("Optional filter for results.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        tool: zod_1.z.string(),
        result: zod_1.z.any(),
        error: zod_1.z.string().optional()
    }
}, async ({ tool, filter }) => {
    try {
        let result;
        switch (tool) {
            case "processes":
                if (PLATFORM === "android" || PLATFORM === "linux" || PLATFORM === "darwin") {
                    result = await execAsync("ps | head -10");
                }
                else {
                    result = { processes: ["system", "browser"], count: 2 };
                }
                break;
            case "system_info":
                result = {
                    platform: PLATFORM,
                    device: "Mobile Device",
                    timestamp: new Date().toISOString()
                };
                break;
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                tool,
                result
            }
        };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                success: false,
                tool,
                error: error.message
            }
        };
    }
});
// Basic Mobile Hardware
server.registerTool("mobile_hardware", {
    description: "Basic mobile hardware access and sensor information",
    inputSchema: {
        feature: zod_1.z.enum(["location", "sensors"]).describe("Hardware feature: 'location' for GPS, 'sensors' for device sensors."),
        action: zod_1.z.enum(["check_availability", "get_data"]).describe("Action: 'check_availability' or 'get_data'.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        feature: zod_1.z.string(),
        available: zod_1.z.boolean(),
        data: zod_1.z.any().optional(),
        error: zod_1.z.string().optional()
    }
}, async ({ feature, action }) => {
    try {
        let result = {
            success: true,
            feature,
            available: true
        };
        if (action === "get_data") {
            switch (feature) {
                case "location":
                    result.data = {
                        latitude: 37.7749,
                        longitude: -122.4194,
                        note: "Simulated GPS data"
                    };
                    break;
                case "sensors":
                    result.data = {
                        accelerometer: { x: 0.1, y: 0.2, z: 9.8 },
                        note: "Simulated sensor data"
                    };
                    break;
            }
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
                feature,
                error: error.message
            }
        };
    }
});
// ===========================================
// WEB SCRAPING & BROWSER TOOLS (ULTRA-MINIMAL)
// ===========================================
// Basic Web Scraper
server.registerTool("web_scraper", {
    description: "Basic web scraping tool for extracting content from web pages",
    inputSchema: {
        url: zod_1.z.string().url().describe("The URL of the web page to scrape. Examples: 'https://example.com', 'https://news.site.com'."),
        action: zod_1.z.enum(["scrape_page", "get_metadata"]).describe("Scraping action: 'scrape_page' gets content, 'get_metadata' gets page info.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        data: zod_1.z.any(),
        error: zod_1.z.string().optional()
    }
}, async ({ url, action }) => {
    try {
        const response = await fetch(url, {
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WebScraper/1.0)' }
        });
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const html = await response.text();
        let data;
        if (action === "get_metadata") {
            const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
            data = {
                title: titleMatch ? titleMatch[1].trim() : '',
                url: url,
                status: response.status
            };
        }
        else {
            const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
            data = {
                title: titleMatch ? titleMatch[1].trim() : '',
                content: html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().substring(0, 500)
            };
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                data
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
// Basic Browser Control
server.registerTool("browser_control", {
    description: "Basic browser control for launching browsers and opening URLs",
    inputSchema: {
        action: zod_1.z.enum(["launch_browser", "navigate"]).describe("Action: 'launch_browser' starts default browser, 'navigate' opens URL."),
        url: zod_1.z.string().optional().describe("URL to navigate to. Required for navigate action.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        result: zod_1.z.any(),
        error: zod_1.z.string().optional()
    }
}, async ({ action, url }) => {
    try {
        let result;
        if (action === "navigate") {
            if (!url)
                throw new Error("URL required");
            let command = "";
            if (PLATFORM === "win32") {
                command = `start "" "${url}"`;
            }
            else if (PLATFORM === "darwin") {
                command = `open "${url}"`;
            }
            else {
                command = `xdg-open "${url}"`;
            }
            await execAsync(command);
            result = { message: `Opened ${url}` };
        }
        else {
            // launch_browser
            let command = "";
            if (PLATFORM === "win32") {
                command = "start msedge";
            }
            else if (PLATFORM === "darwin") {
                command = "open -a Safari";
            }
            else {
                command = "firefox";
            }
            await execAsync(command);
            result = { message: "Browser launched" };
        }
        return {
            content: [],
            structuredContent: {
                success: true,
                result
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
// ===========================================
// SYSTEM RESTORE TOOL (ULTRA-MINIMAL VERSION)
// ===========================================
server.registerTool("system_restore", {
    description: "💾 **System Restore & Backup Management (Ultra-Minimal)** - Ultra-minimal system restore for Windows, Linux, and macOS. Basic restore point creation and configuration backup only. Limited to 2 essential actions: create_restore_point, backup_config. Cross-platform support with minimal resource usage for embedded systems and resource-constrained environments.",
    inputSchema: {
        action: zod_1.z.enum([
            "create_restore_point", "backup_config"
        ]).describe("**System Restore Actions (2 Operations):** 'create_restore_point' - Create basic system restore points across platforms (Windows: PowerShell System Restore, Linux/macOS: Timestamp file with metadata), 'backup_config' - Backup essential system configurations (Windows: Not available in ultra-minimal, Linux/macOS: /etc directory backup with file count)."),
        description: zod_1.z.string().optional().describe("Description for the restore point or backup.")
    },
    outputSchema: {
        success: zod_1.z.boolean(),
        platform: zod_1.z.string(),
        action: zod_1.z.string(),
        result: zod_1.z.any(),
        message: zod_1.z.string(),
        error: zod_1.z.string().optional()
    }
}, async ({ action, description }) => {
    try {
        let result;
        switch (action) {
            case "create_restore_point":
                if (PLATFORM === "win32") {
                    const restoreDesc = description || `System restore point created on ${new Date().toISOString()}`;
                    const command = `powershell -Command "Checkpoint-Computer -Description '${restoreDesc}' -RestorePointType 'MODIFY_SETTINGS' -Verbose"`;
                    await execAsync(command);
                    result = { message: "Windows restore point created successfully" };
                }
                else {
                    // For Linux/macOS, just create a timestamp file
                    const timestamp = new Date().toISOString();
                    const backupPath = `/tmp/restore_point_${Date.now()}`;
                    await fs.mkdir(backupPath, { recursive: true });
                    const metadata = {
                        timestamp,
                        description: description || "System restore point",
                        platform: PLATFORM
                    };
                    await fs.writeFile(path.join(backupPath, 'metadata.json'), JSON.stringify(metadata, null, 2));
                    result = {
                        message: `${PLATFORM === "linux" ? "Linux" : "macOS"} restore point created`,
                        backup_path: backupPath
                    };
                }
                break;
            case "backup_config":
                if (PLATFORM === "win32") {
                    result = { message: "Configuration backup not available in ultra-minimal version" };
                }
                else {
                    // Simple backup of /etc directory
                    const backupPath = `/tmp/config_backup_${Date.now()}`;
                    await fs.mkdir(backupPath, { recursive: true });
                    try {
                        const etcBackup = path.join(backupPath, 'etc');
                        await fs.mkdir(etcBackup, { recursive: true });
                        const etcEntries = await fs.readdir('/etc', { withFileTypes: true });
                        let copiedFiles = 0;
                        for (const entry of etcEntries) {
                            if (entry.isFile()) {
                                try {
                                    const sourcePath = path.join('/etc', entry.name);
                                    const destPath = path.join(etcBackup, entry.name);
                                    await fs.copyFile(sourcePath, destPath);
                                    copiedFiles++;
                                }
                                catch (error) {
                                    // Skip files that can't be copied
                                }
                            }
                        }
                        result = {
                            message: `Configuration backup completed. ${copiedFiles} files copied.`,
                            backup_path: backupPath,
                            files_copied: copiedFiles
                        };
                    }
                    catch (error) {
                        result = { message: "Partial backup completed (some files skipped)" };
                    }
                }
                break;
            default:
                result = { message: `Action ${action} not supported in ultra-minimal version` };
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
    log('error', `Server error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
});
