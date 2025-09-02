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
const server = new mcp_js_1.McpServer({ name: "windows-dev-mcp-minimal", version: "1.0.0" });
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
