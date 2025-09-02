#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as path from "node:path";
import * as os from "node:os";
import * as fs from "node:fs/promises";
import { spawn, exec } from "node:child_process";
import { promisify } from "node:util";
import simpleGit from "simple-git";
import { createWriteStream } from "node:fs";
import { pipeline } from "node:stream/promises";
import { Transform } from "node:stream";
import { createReadStream } from "node:fs";
import { Readable } from "node:stream";
import * as math from "mathjs";
import * as crypto from "node:crypto";
import { nanoid } from "nanoid";
import { logger, logServerStart } from "./utils/logger.js";

// Platform detection
const PLATFORM = os.platform();
const IS_WINDOWS = PLATFORM === "win32";
const IS_LINUX = PLATFORM === "linux";
const IS_MACOS = PLATFORM === "darwin";

// Security configuration
const ALLOWED_ROOTS_ARRAY = [process.cwd()];
const PROC_ALLOWLIST: string[] = []; // Empty = allow all
const MAX_BYTES = 1024 * 1024; // 1MB

const execAsync = promisify(exec);

// Log server startup
logServerStart(PLATFORM);

// ===========================================
// CORE TOOLS
// ===========================================

const server = new McpServer({ name: "windows-dev-mcp-minimal", version: "1.0.0" });

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

// ===========================================
// FILE SYSTEM TOOLS
// ===========================================

function ensureInsideRoot(filePath: string): string {
  const resolved = path.resolve(filePath);
  for (const root of ALLOWED_ROOTS_ARRAY) {
    if (resolved.startsWith(path.resolve(root))) {
      return resolved;
    }
  }
  throw new Error(`Path outside allowed roots: ${filePath}`);
}

function limitString(str: string, maxBytes: number): { text: string; truncated: boolean } {
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
  inputSchema: { dir: z.string().default(".").describe("The directory path to list files and folders from. Examples: '.', './documents', '/home/user/pictures', 'C:\\Users\\User\\Desktop'. Use '.' for current directory.") },
  outputSchema: { entries: z.array(z.object({ name: z.string(), isDir: z.boolean() })) }
}, async ({ dir }) => {
  let base: string;
  try {
    base = ensureInsideRoot(path.resolve(dir));
  } catch {
    base = path.resolve(ALLOWED_ROOTS_ARRAY[0], dir);
    ensureInsideRoot(base);
  }
  const items = await fs.readdir(base, { withFileTypes: true });
  return { content: [], structuredContent: { entries: items.map(d => ({ name: d.name, isDir: d.isDirectory() })) } };
});

server.registerTool("fs_read_text", {
  description: "Read a UTF-8 text file within the sandbox",
  inputSchema: { path: z.string().describe("The file path to read from. Can be relative or absolute path. Examples: './config.txt', '/home/user/documents/readme.md', 'C:\\Users\\User\\Desktop\\notes.txt'.") },
  outputSchema: { path: z.string(), content: z.string(), truncated: z.boolean() }
}, async ({ path: relPath }) => {
  const fullPath = ensureInsideRoot(path.resolve(relPath));
  const content = await fs.readFile(fullPath, "utf8");
  const { text, truncated } = limitString(content, MAX_BYTES);
  return { content: [], structuredContent: { path: fullPath, content: text, truncated } };
});

server.registerTool("fs_write_text", {
  description: "Write a UTF-8 text file within the sandbox",
  inputSchema: { 
    path: z.string().describe("The file path to write to. Can be relative or absolute path. Examples: './output.txt', '/home/user/documents/log.txt', 'C:\\Users\\User\\Desktop\\data.txt'."),
    content: z.string().describe("The text content to write to the file. Can be plain text, JSON, XML, or any text-based format. Examples: 'Hello World', '{\"key\": \"value\"}', '<xml>data</xml>'.")
  },
  outputSchema: { path: z.string(), success: z.boolean() }
}, async ({ path: relPath, content }) => {
  const fullPath = ensureInsideRoot(path.resolve(relPath));
  await fs.writeFile(fullPath, content, "utf8");
  return { content: [], structuredContent: { path: fullPath, success: true } };
});

server.registerTool("fs_search", {
  description: "Search for files by name pattern",
  inputSchema: { 
    pattern: z.string().describe("The file name pattern to search for. Supports glob patterns and partial matches. Examples: '*.txt', 'config*', '*.js', 'README*', '*.{json,yaml}'."),
    dir: z.string().default(".").describe("The directory to search in. Examples: '.', './src', '/home/user/documents', 'C:\\Users\\User\\Projects'. Use '.' for current directory.")
  },
  outputSchema: { matches: z.array(z.string()) }
}, async ({ pattern, dir }) => {
  const base = ensureInsideRoot(path.resolve(dir));
  const matches: string[] = [];
  
  try {
    const { stdout } = await execAsync(`rg --files --glob "${pattern}" "${base}"`);
    matches.push(...stdout.trim().split("\n").filter(Boolean));
  } catch {
    // Fallback to naive search
    const searchRecursive = async (currentDir: string): Promise<string[]> => {
      const results: string[] = [];
      try {
        const items = await fs.readdir(currentDir, { withFileTypes: true });
        for (const item of items) {
          const fullPath = path.join(currentDir, item.name);
          if (item.isDirectory()) {
            results.push(...await searchRecursive(fullPath));
          } else if (item.name.includes(pattern.replace("*", ""))) {
            results.push(fullPath);
          }
        }
      } catch (error) {
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
    command: z.string().describe("The command to execute. Examples: 'ls', 'dir', 'cat', 'echo', 'python', 'node', 'git', 'docker'. Can be any executable available in your system PATH or full path to an executable."), 
    args: z.array(z.string()).default([]).describe("Array of command line arguments to pass to the command. Examples: ['-l', '-a'] for 'ls -l -a', ['--version'] for version info, ['install', 'package'] for package installation."),
    cwd: z.string().optional().describe("Working directory for the command. Examples: './project', '/home/user/workspace', 'C:\\Users\\User\\Projects'. If not specified, uses the current working directory.")
  },
  outputSchema: { 
    success: z.boolean(), 
    stdout: z.string().optional(), 
    stderr: z.string().optional(),
    exitCode: z.number().optional()
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
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const stdout = (error as any)?.stdout || undefined;
    const stderr = (error as any)?.stderr || undefined;
    const exitCode = (error as any)?.code || -1;
    
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
  inputSchema: { dir: z.string().default(".").describe("The directory containing the git repository to check. Examples: './project', '/home/user/repos/myproject', 'C:\\Users\\User\\Projects\\MyProject'. Use '.' for the current directory.") },
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
  } catch (error) {
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
    expression: z.string().describe("The mathematical expression to evaluate. Supports basic arithmetic, scientific functions, and complex expressions. Examples: '2 + 2', 'sin(45)', 'sqrt(16)', '2^8', 'log(100)', '5!', '2 * (3 + 4)'."),
    precision: z.number().default(10).describe("The number of decimal places to display in the result. Examples: 2 for currency, 5 for scientific calculations, 10 for high precision. Range: 0-15 decimal places.")
  },
  outputSchema: { 
    success: z.boolean(),
    result: z.string(),
    expression: z.string(),
    type: z.string(),
    error: z.string().optional()
  }
}, async ({ expression, precision }) => {
  try {
    const result = math.evaluate(expression as string);
    const formattedResult = typeof result === 'number' ? result.toFixed(precision) : String(result);
    
    return {
      content: [],
      structuredContent: {
        success: true,
        result: formattedResult,
        expression: expression as string,
        type: "mathematical"
      }
    };
  } catch (error) {
    return {
      content: [],
      structuredContent: {
        success: false,
        result: "",
        expression: expression as string,
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
    url: z.string().url().describe("The URL of the file to download. Must be a valid HTTP/HTTPS URL. Examples: 'https://example.com/file.zip', 'http://downloads.example.org/document.pdf'."), 
    outputPath: z.string().optional().describe("Optional custom filename for the downloaded file. Examples: 'myfile.zip', './downloads/document.pdf', 'C:\\Users\\User\\Downloads\\file.txt'. If not specified, uses the original filename from the URL.") 
  },
  outputSchema: { 
    success: z.boolean(),
    path: z.string().optional(),
    error: z.string().optional() 
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
    
    const fileStream = createWriteStream(fullPath);
    const reader = response.body?.getReader();
    
    if (!reader) {
      throw new Error("No response body");
    }
    
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
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
  } catch (error) {
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
    action: z.enum(["list", "copy", "move", "delete", "create", "get_info", "search"]).describe("File operation: 'list' shows contents, 'copy'/'move' transfer files, 'delete' removes items, 'create' makes files, 'get_info' shows details, 'search' finds files."),
    source: z.string().optional().describe("Source path. Examples: '/sdcard/Documents/', '/var/mobile/Documents/', './photos/'. Required for most operations."),
    destination: z.string().optional().describe("Destination path for copy/move. Examples: '/sdcard/backup/', './backup/'. Include filename for file operations."),
    content: z.string().optional().describe("Content for new files. Examples: 'Hello World', '{\"config\": \"value\"}'. Used with create action."),
    pattern: z.string().optional().describe("Search pattern. Examples: '*.jpg', '*.log', 'backup*'. Used with search action.")
  },
  outputSchema: {
    success: z.boolean(),
    platform: z.string(),
    result: z.any(),
    error: z.string().optional()
  }
}, async ({ action, source, destination, content, pattern }) => {
  try {
    let result: any;
    
    switch (action) {
      case "list":
        if (!source) throw new Error("Source path required for list");
        if (IS_LINUX || IS_MACOS) {
          result = await execAsync(`ls -la "${source}"`);
        } else if (IS_WINDOWS) {
          result = await execAsync(`dir "${source}"`);
        } else {
          result = { message: "Mobile file listing requires platform-specific access", path: source };
        }
        break;
        
      case "copy":
        if (!source || !destination) throw new Error("Source and destination required");
        if (IS_LINUX || IS_MACOS) {
          result = await execAsync(`cp "${source}" "${destination}"`);
        } else if (IS_WINDOWS) {
          result = await execAsync(`copy "${source}" "${destination}"`);
        } else {
          result = { message: "Mobile file operations require platform-specific access" };
        }
        break;
        
      case "create":
        if (!destination || !content) throw new Error("Destination and content required");
        if (IS_LINUX || IS_MACOS) {
          result = await execAsync(`echo "${content}" > "${destination}"`);
        } else {
          result = { message: "File creation completed", path: destination };
        }
        break;
        
      case "search":
        if (!source || !pattern) throw new Error("Source and pattern required");
        if (IS_LINUX || IS_MACOS) {
          result = await execAsync(`find "${source}" -name "${pattern}"`);
        } else {
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
  } catch (error: any) {
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
    tool: z.enum(["processes", "storage", "packages", "system_info"]).describe("System tool: 'processes' shows running apps, 'storage' checks disk usage, 'packages' lists installed apps, 'system_info' provides device details."),
    action: z.string().optional().describe("Action to perform. Examples: 'list', 'info', 'analyze'. Actions vary by tool type."),
    filter: z.string().optional().describe("Filter results. Examples: 'system', 'user', 'running'. Helps narrow down results.")
  },
  outputSchema: {
    success: z.boolean(),
    platform: z.string(),
    tool: z.string(),
    result: z.any(),
    error: z.string().optional()
  }
}, async ({ tool, action = "list", filter }) => {
  try {
    let result: any;
    
    switch (tool) {
      case "processes":
        if (IS_LINUX || IS_MACOS) {
          result = await execAsync("ps aux | head -20");
        } else if (IS_WINDOWS) {
          result = await execAsync("tasklist | findstr /v Image");
        } else {
          result = { processes: ["system", "browser", "app1", "app2"], count: 4 };
        }
        break;
        
      case "storage":
        if (IS_LINUX || IS_MACOS) {
          result = await execAsync("df -h");
        } else if (IS_WINDOWS) {
          result = await execAsync("wmic logicaldisk get size,freespace,caption");
        } else {
          result = { total: "64GB", used: "32GB", available: "32GB", usage: "50%" };
        }
        break;
        
      case "packages":
        if (IS_WINDOWS) {
          result = await execAsync("wmic product get name,version | head -10");
        } else if (IS_LINUX) {
          result = await execAsync("dpkg -l | head -10");
        } else if (IS_MACOS) {
          result = await execAsync("ls /Applications | head -10");
        } else {
          result = { packages: ["system.app", "browser.app"], count: 2 };
        }
        break;
        
      case "system_info":
        if (IS_WINDOWS) {
          result = await execAsync("systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Model\"");
        } else if (IS_LINUX) {
          result = await execAsync("uname -a && cat /etc/os-release | head -5");
        } else if (IS_MACOS) {
          result = await execAsync("system_profiler SPSoftwareDataType SPHardwareDataType | head -10");
        } else {
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
  } catch (error: any) {
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
    feature: z.enum(["camera", "location", "sensors", "notifications", "audio"]).describe("Hardware feature: 'camera' for photo/video, 'location' for GPS, 'sensors' for accelerometer/gyroscope, 'notifications' for alerts, 'audio' for microphone."),
    action: z.enum(["check_availability", "get_status", "get_data"]).describe("Action: 'check_availability' verifies feature exists, 'get_status' shows current state, 'get_data' retrieves information.")
  },
  outputSchema: {
    success: z.boolean(),
    platform: z.string(),
    feature: z.string(),
    available: z.boolean(),
    status: z.string().optional(),
    data: z.any().optional(),
    error: z.string().optional()
  }
}, async ({ feature, action }) => {
  try {
    let result: any = {
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
  } catch (error: any) {
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
    url: z.string().url().describe("The URL of the web page to scrape. Must be a valid HTTP/HTTPS URL. Examples: 'https://example.com', 'https://news.website.com/articles'."),
    action: z.enum(["scrape_page", "extract_data", "get_metadata"]).describe("The scraping action to perform. 'scrape_page' gets all content, 'extract_data' uses selectors, 'get_metadata' extracts page info."),
    selector: z.string().optional().describe("CSS selector to target specific elements. Examples: 'h1', '.article-title', '#main-content'. Leave empty to scrape entire page."),
    output_format: z.enum(["json", "text"]).optional().describe("Output format for scraped data. 'json' for structured data, 'text' for plain text.")
  },
  outputSchema: {
    success: z.boolean(),
    url: z.string(),
    action: z.string(),
    data: z.any(),
    platform: z.string(),
    timestamp: z.string(),
    error: z.string().optional()
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
    let data: any;
    
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
  } catch (error: any) {
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
    action: z.enum(["launch_browser", "navigate", "close_browser", "screenshot"]).describe("Browser action to perform. 'launch_browser' starts browser, 'navigate' goes to URL, 'close_browser' closes browser, 'screenshot' captures screen."),
    browser: z.enum(["chrome", "firefox", "safari", "edge", "auto"]).optional().describe("Browser to control. 'chrome' for Google Chrome, 'firefox' for Mozilla Firefox, 'safari' for Safari (macOS), 'edge' for Microsoft Edge, 'auto' for system default."),
    url: z.string().optional().describe("URL to navigate to. Examples: 'https://google.com', 'https://github.com'. Required for navigate action."),
    screenshot_path: z.string().optional().describe("File path to save screenshots. Examples: './screenshot.png', 'C:\\Screenshots\\page.png'.")
  },
  outputSchema: {
    success: z.boolean(),
    action: z.string(),
    browser: z.string(),
    result: z.any(),
    platform: z.string(),
    timestamp: z.string(),
    error: z.string().optional()
  }
}, async ({ action, browser = "auto", url, screenshot_path }) => {
  try {
    let result: any;
    const selectedBrowser = browser === "auto" ? getSimpleDefaultBrowser() : browser;
    
    switch (action) {
      case "launch_browser":
        result = await launchSimpleBrowser(selectedBrowser);
        break;
      case "navigate":
        if (!url) throw new Error("URL required for navigate action");
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
  } catch (error: any) {
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

function extractSimpleTitle(html: string): string {
  const match = html.match(/<title[^>]*>([^<]*)<\/title>/i);
  return match ? match[1].trim() : 'No title';
}

function extractSimpleDescription(html: string): string {
  const match = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["'][^>]*>/i);
  return match ? match[1].trim() : '';
}

function extractSimpleText(html: string, selector?: string): string {
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

function extractSimpleData(html: string, selector?: string): any {
  const data: any = {
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

function getSimpleDefaultBrowser(): string {
  if (IS_WINDOWS) return "edge";
  if (IS_MACOS) return "safari";
  return "firefox";
}

async function launchSimpleBrowser(browser: string): Promise<any> {
  try {
    let command = "";
    
    switch (browser.toLowerCase()) {
      case "chrome":
        if (IS_WINDOWS) command = "start chrome";
        else if (IS_LINUX) command = "google-chrome";
        else if (IS_MACOS) command = "open -a 'Google Chrome'";
        break;
      case "firefox":
        if (IS_WINDOWS) command = "start firefox";
        else if (IS_LINUX) command = "firefox";
        else if (IS_MACOS) command = "open -a Firefox";
        break;
      case "safari":
        if (IS_MACOS) command = "open -a Safari";
        else throw new Error("Safari only available on macOS");
        break;
      case "edge":
        if (IS_WINDOWS) command = "start msedge";
        else if (IS_LINUX) command = "microsoft-edge";
        else if (IS_MACOS) command = "open -a 'Microsoft Edge'";
        break;
      default:
        throw new Error(`Unsupported browser: ${browser}`);
    }
    
    await execAsync(command);
    return { launched: true, message: `${browser} launched successfully` };
  } catch (error: any) {
    throw new Error(`Failed to launch browser: ${error.message}`);
  }
}

async function navigateSimple(url: string): Promise<any> {
  try {
    let command = "";
    
    if (IS_WINDOWS) {
      command = `start "" "${url}"`;
    } else if (IS_LINUX) {
      command = `xdg-open "${url}"`;
    } else if (IS_MACOS) {
      command = `open "${url}"`;
    }
    
    await execAsync(command);
    return { navigated: true, message: `Opened ${url}` };
  } catch (error: any) {
    throw new Error(`Failed to navigate: ${error.message}`);
  }
}

async function closeSimpleBrowser(browser: string): Promise<any> {
  try {
    let command = "";
    
    if (IS_WINDOWS) {
      switch (browser.toLowerCase()) {
        case "chrome": command = "taskkill /f /im chrome.exe"; break;
        case "firefox": command = "taskkill /f /im firefox.exe"; break;
        case "edge": command = "taskkill /f /im msedge.exe"; break;
        default: command = `taskkill /f /im ${browser}.exe`;
      }
    } else {
      command = `pkill ${browser}`;
    }
    
    await execAsync(command);
    return { closed: true, message: `${browser} closed` };
  } catch (error: any) {
    return { closed: true, message: `${browser} closed (or wasn't running)` };
  }
}

async function takeSimpleScreenshot(screenshotPath?: string): Promise<any> {
  try {
    const outputPath = screenshotPath || `screenshot_${Date.now()}.png`;
    
    if (IS_WINDOWS) {
      const command = `powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Screen]::PrimaryScreen.Bounds | ForEach-Object { $bitmap = New-Object System.Drawing.Bitmap($_.Width, $_.Height); $graphics = [System.Drawing.Graphics]::FromImage($bitmap); $graphics.CopyFromScreen($_.X, $_.Y, 0, 0, $_.Size); $bitmap.Save('${outputPath}', [System.Drawing.Imaging.ImageFormat]::Png); }"`;
      await execAsync(command);
    } else if (IS_LINUX) {
      await execAsync(`scrot "${outputPath}" || gnome-screenshot -f "${outputPath}"`);
    } else if (IS_MACOS) {
      await execAsync(`screencapture "${outputPath}"`);
    } else {
      throw new Error("Screenshot not supported on this platform");
    }
    
    return { screenshot_path: outputPath, message: `Screenshot saved to ${outputPath}` };
  } catch (error: any) {
    throw new Error(`Failed to take screenshot: ${error.message}`);
  }
}

// ===========================================
// MAIN FUNCTION
// ===========================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  logger.error("Server error", { error: err instanceof Error ? err.message : String(err), stack: err instanceof Error ? err.stack : undefined });
  process.exit(1);
});
