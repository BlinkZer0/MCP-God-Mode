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
