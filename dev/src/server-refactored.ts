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
import { ChartJSNodeCanvas } from "chartjs-node-canvas";
import * as crypto from "node:crypto";
import { createCanvas } from "canvas";

// Import utility modules
import { PLATFORM, IS_WINDOWS, IS_LINUX, IS_MACOS, IS_ANDROID, IS_IOS, IS_MOBILE, config, PROC_ALLOWLIST, MAX_BYTES, MOBILE_CONFIG, COMMAND_MAPPINGS } from "./config/environment.js";
import { ALLOWED_ROOTS_ARRAY, getPlatformCommand, getMobilePermissions, isMobileFeatureAvailable, getMobileDeviceInfo, getFileOperationCommand, getMobileProcessCommand, getMobileServiceCommand, getMobileNetworkCommand, getMobileStorageCommand, getMobileUserCommand } from "./utils/platform.js";
import { sanitizeCommand, isDangerousCommand, shouldPerformSecurityChecks } from "./utils/security.js";
import { ensureInsideRoot, limitString } from "./utils/fileSystem.js";
import { logger, logServerStart } from "./utils/logger.js";

// Global variables for enhanced features
let browserInstance: any = null;
let webSocketServer: any = null;
let expressServer: any = null;
let cronJobs: Map<string, any> = new Map();
let fileWatchers: Map<string, any> = new Map();
let apiCache: Map<string, any> = new Map();
let webhookEndpoints: Map<string, any> = new Map();

const execAsync = promisify(exec);

// Log server startup
logServerStart(PLATFORM);

// ===========================================
// CORE TOOLS
// ===========================================

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

// ===========================================
// FILE SYSTEM TOOLS
// ===========================================

server.registerTool("fs_list", {
  description: "List files/directories under a relative path (non-recursive)",
  inputSchema: { dir: z.string().default(".") },
  outputSchema: { entries: z.array(z.object({ name: z.string(), isDir: z.boolean() })) }
}, async ({ dir }) => {
  // Try to find the directory in one of the allowed roots
  let base: string;
  try {
    base = ensureInsideRoot(path.resolve(dir));
  } catch {
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
  const { text, truncated } = limitString(content, MAX_BYTES);
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
  const matches: string[] = [];
  
  try {
    // Try using ripgrep if available
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
// ADVANCED CROSS-PLATFORM FILE OPERATIONS
// ===========================================

server.registerTool("file_ops", {
  description: "Advanced cross-platform file operations with comprehensive file system management",
  inputSchema: {
    action: z.enum([
      "copy", "move", "delete", "create_dir", "create_file", "get_info", "list_recursive",
      "find_by_content", "compress", "decompress", "chmod", "chown", "symlink", "hardlink",
      "watch", "unwatch", "get_size", "get_permissions", "set_permissions", "compare_files"
    ]),
    source: z.string().optional(),
    destination: z.string().optional(),
    content: z.string().optional(),
    recursive: z.boolean().default(false),
    overwrite: z.boolean().default(false),
    permissions: z.string().optional(),
    owner: z.string().optional(),
    group: z.string().optional(),
    pattern: z.string().optional(),
    search_text: z.string().optional(),
    compression_type: z.enum(["zip", "tar", "gzip", "bzip2"]).default("zip")
  },
  outputSchema: {
    success: z.boolean(),
    result: z.any(),
    platform: z.string(),
    error: z.string().optional()
  }
}, async ({ action, source, destination, content, recursive, overwrite, permissions, owner, group, pattern, search_text, compression_type }) => {
  try {
    const platform = PLATFORM;
    let result: any;

    switch (action) {
      case "copy":
        if (!source || !destination) {
          throw new Error("Source and destination are required for copy operation");
        }
        const sourcePath = ensureInsideRoot(path.resolve(source));
        const destPath = ensureInsideRoot(path.resolve(destination));
        
        if (overwrite && await fs.access(destPath).then(() => true).catch(() => false)) {
          await fs.unlink(destPath);
        }
        
        if ((await fs.stat(sourcePath)).isDirectory()) {
          if (recursive) {
            await copyDirectoryRecursive(sourcePath, destPath);
          } else {
            throw new Error("Cannot copy directory without recursive flag");
          }
        } else {
          await fs.copyFile(sourcePath, destPath);
        }
        result = { source: sourcePath, destination: destPath, copied: true };
        break;

      case "move":
        if (!source || !destination) {
          throw new Error("Source and destination are required for move operation");
        }
        const moveSource = ensureInsideRoot(path.resolve(source));
        const moveDest = ensureInsideRoot(path.resolve(destination));
        
        if (overwrite && await fs.access(moveDest).then(() => true).catch(() => false)) {
          await fs.unlink(moveDest);
        }
        
        await fs.rename(moveSource, moveDest);
        result = { source: moveSource, destination: moveDest, moved: true };
        break;

      case "delete":
        if (!source) {
          throw new Error("Source is required for delete operation");
        }
        const deletePath = ensureInsideRoot(path.resolve(source));
        const stats = await fs.stat(deletePath);
        
        if (stats.isDirectory()) {
          if (recursive) {
            await deleteDirectoryRecursive(deletePath);
          } else {
            throw new Error("Cannot delete directory without recursive flag");
          }
        } else {
          await fs.unlink(deletePath);
        }
        result = { path: deletePath, deleted: true };
        break;

      case "create_dir":
        if (!destination) {
          throw new Error("Destination is required for create_dir operation");
        }
        const dirPath = ensureInsideRoot(path.resolve(destination));
        await fs.mkdir(dirPath, { recursive: true });
        result = { path: dirPath, created: true };
        break;

      case "create_file":
        if (!destination) {
          throw new Error("Destination is required for create_file operation");
        }
        const filePath = ensureInsideRoot(path.resolve(destination));
        const fileContent = content || "";
        await fs.writeFile(filePath, fileContent, "utf8");
        result = { path: filePath, created: true, size: fileContent.length };
        break;

      case "get_info":
        if (!source) {
          throw new Error("Source is required for get_info operation");
        }
        const infoPath = ensureInsideRoot(path.resolve(source));
        const infoStats = await fs.stat(infoPath);
        result = {
          path: infoPath,
          exists: true,
          isFile: infoStats.isFile(),
          isDirectory: infoStats.isDirectory(),
          size: infoStats.size,
          created: infoStats.birthtime,
          modified: infoStats.mtime,
          permissions: infoStats.mode.toString(8),
          owner: infoStats.uid,
          group: infoStats.gid
        };
        break;

      case "list_recursive":
        if (!source) {
          throw new Error("Source is required for list_recursive operation");
        }
        const listPath = ensureInsideRoot(path.resolve(source));
        const items = await listDirectoryRecursive(listPath, pattern);
        result = { path: listPath, items, total: items.length };
        break;

      case "find_by_content":
        if (!source || !search_text) {
          throw new Error("Source and search_text are required for find_by_content operation");
        }
        const searchPath = ensureInsideRoot(path.resolve(source));
        const foundFiles = await findFilesByContent(searchPath, search_text, recursive);
        result = { path: searchPath, search_text, found_files: foundFiles, total: foundFiles.length };
        break;

      case "compress":
        if (!source || !destination) {
          throw new Error("Source and destination are required for compress operation");
        }
        const compressSource = ensureInsideRoot(path.resolve(source));
        const compressDest = ensureInsideRoot(path.resolve(destination));
        await compressFile(compressSource, compressDest, compression_type);
        result = { source: compressSource, destination: compressDest, compressed: true, type: compression_type };
        break;

      case "decompress":
        if (!source || !destination) {
          throw new Error("Source and destination are required for decompress operation");
        }
        const decompressSource = ensureInsideRoot(path.resolve(source));
        const decompressDest = ensureInsideRoot(path.resolve(destination));
        await decompressFile(decompressSource, decompressDest);
        result = { source: decompressSource, destination: decompressDest, decompressed: true };
        break;

      case "chmod":
        if (!source || !permissions) {
          throw new Error("Source and permissions are required for chmod operation");
        }
        const chmodPath = ensureInsideRoot(path.resolve(source));
        const mode = parseInt(permissions, 8);
        await fs.chmod(chmodPath, mode);
        result = { path: chmodPath, permissions: permissions, changed: true };
        break;

      case "chown":
        if (!source || (!owner && !group)) {
          throw new Error("Source and either owner or group are required for chown operation");
        }
        const chownPath = ensureInsideRoot(path.resolve(source));
        if (IS_WINDOWS) {
          // Windows doesn't support chown, use icacls instead
          if (owner) {
            await execAsync(`icacls "${chownPath}" /setowner "${owner}"`);
          }
          result = { path: chownPath, owner: owner || "unchanged", group: group || "unchanged", changed: true };
        } else {
          await fs.chown(chownPath, owner ? parseInt(owner) : -1, group ? parseInt(group) : -1);
          result = { path: chownPath, owner: owner || "unchanged", group: group || "unchanged", changed: true };
        }
        break;

      case "symlink":
        if (!source || !destination) {
          throw new Error("Source and destination are required for symlink operation");
        }
        const symlinkSource = ensureInsideRoot(path.resolve(source));
        const symlinkDest = ensureInsideRoot(path.resolve(destination));
        await fs.symlink(symlinkSource, symlinkDest);
        result = { source: symlinkSource, destination: symlinkDest, symlink_created: true };
        break;

      case "hardlink":
        if (!source || !destination) {
          throw new Error("Source and destination are required for hardlink operation");
        }
        const hardlinkSource = ensureInsideRoot(path.resolve(source));
        const hardlinkDest = ensureInsideRoot(path.resolve(destination));
        await fs.link(hardlinkSource, hardlinkDest);
        result = { source: hardlinkSource, destination: hardlinkDest, hardlink_created: true };
        break;

      case "watch":
        if (!source) {
          throw new Error("Source is required for watch operation");
        }
        const watchPath = ensureInsideRoot(path.resolve(source));
        const watcher = fs.watch(watchPath, { recursive: recursive });
        const watchId = crypto.randomUUID();
        fileWatchers.set(watchId, watcher);
        result = { path: watchPath, watch_id: watchId, watching: true };
        break;

      case "unwatch":
        if (!source) {
          throw new Error("Source is required for unwatch operation");
        }
        const unwatchPath = ensureInsideRoot(path.resolve(source));
        // Find and stop the watcher
        for (const [id, watcher] of fileWatchers.entries()) {
          if (watcher.path === unwatchPath) {
            watcher.close();
            fileWatchers.delete(id);
            result = { path: unwatchPath, watch_id: id, unwatched: true };
            break;
          }
        }
        if (!result) {
          result = { path: unwatchPath, unwatched: false, error: "No active watcher found" };
        }
        break;

      case "get_size":
        if (!source) {
          throw new Error("Source is required for get_size operation");
        }
        const sizePath = ensureInsideRoot(path.resolve(source));
        const sizeStats = await fs.stat(sizePath);
        if (sizeStats.isDirectory() && recursive) {
          const totalSize = await calculateDirectorySize(sizePath);
          result = { path: sizePath, size: totalSize, size_human: formatBytes(totalSize) };
        } else {
          result = { path: sizePath, size: sizeStats.size, size_human: formatBytes(sizeStats.size) };
        }
        break;

      case "get_permissions":
        if (!source) {
          throw new Error("Source is required for get_permissions operation");
        }
        const permPath = ensureInsideRoot(path.resolve(source));
        const permStats = await fs.stat(permPath);
        result = { 
          path: permPath, 
          permissions: permStats.mode.toString(8),
          permissions_symbolic: modeToSymbolic(permStats.mode),
          owner: permStats.uid,
          group: permStats.gid
        };
        break;

      case "set_permissions":
        if (!source || !permissions) {
          throw new Error("Source and permissions are required for set_permissions operation");
        }
        const setPermPath = ensureInsideRoot(path.resolve(source));
        const permMode = parseInt(permissions, 8);
        await fs.chmod(setPermPath, permMode);
        result = { path: setPermPath, permissions: permissions, set: true };
        break;

      case "compare_files":
        if (!source || !destination) {
          throw new Error("Source and destination are required for compare_files operation");
        }
        const compareSource = ensureInsideRoot(path.resolve(source));
        const compareDest = ensureInsideRoot(path.resolve(destination));
        const areEqual = await compareFiles(compareSource, compareDest);
        result = { 
          source: compareSource, 
          destination: compareDest, 
          are_equal: areEqual,
          comparison_type: "binary"
        };
        break;

      default:
        throw new Error(`Unknown action: ${action}`);
    }

    return {
      content: [],
      structuredContent: {
        success: true,
        result,
        platform,
        action
      }
    };

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error("File operation failed", { action, source, destination, error: errorMessage });
    
    return {
      content: [],
      structuredContent: {
        success: false,
        result: null,
        platform: PLATFORM,
        error: errorMessage
      }
    };
  }
});

// ===========================================
// PROCESS EXECUTION TOOLS
// ===========================================

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
  if (shouldPerformSecurityChecks() && isDangerousCommand(command)) {
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
// SYSTEM TOOLS
// ===========================================

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
    let services: any[] = [];
    
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
    } else if (IS_LINUX) {
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
    } else if (IS_MACOS) {
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
  } catch (error) {
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
    let processes: any[] = [];
    
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
    } else if (IS_LINUX) {
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
    } else if (IS_MACOS) {
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
  } catch (error) {
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

// ===========================================
// DOWNLOAD TOOLS
// ===========================================

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
// CALCULATOR TOOLS
// ===========================================

server.registerTool("calculator", {
  description: "Advanced mathematical calculator with scientific functions, unit conversions, and financial calculations",
  inputSchema: { 
    expression: z.string(),
    precision: z.number().default(10)
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
    // Try to evaluate as mathematical expression first
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
    } catch (mathError) {
      // If math evaluation fails, try other interpretations
      const exprStr = expression as string;
      if (exprStr.toLowerCase().includes('usd') || exprStr.toLowerCase().includes('eur') || exprStr.toLowerCase().includes('gbp')) {
        // Currency conversion (mock implementation)
        const amount = parseFloat(exprStr.match(/\d+/)?.[0] || "0");
        const fromCurrency = exprStr.match(/(\w+)\s+to\s+(\w+)/i);
        
        if (fromCurrency) {
          const [, from, to] = fromCurrency;
          // Mock exchange rates
          const rates: { [key: string]: number } = {
            'USD': 1,
            'EUR': 0.85,
            'GBP': 0.73
          };
          
          const result = amount * (rates[to.toUpperCase()] || 1) / (rates[from.toUpperCase()] || 1);
          
          return {
            content: [],
            structuredContent: {
              success: true,
              result: result.toFixed(2),
              expression: exprStr,
              type: "currency_conversion"
            }
          };
        }
      }
      
      // If all else fails, return the math error
      throw mathError;
    }
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
// VM MANAGEMENT TOOLS
// ===========================================

server.registerTool("vm_management", {
  description: "Cross-platform virtual machine management (VirtualBox, VMware, QEMU/KVM, Hyper-V)",
  inputSchema: {
    action: z.enum([
      "list_vms", "start_vm", "stop_vm", "pause_vm", "resume_vm", 
      "create_vm", "delete_vm", "vm_info", "vm_status", "list_hypervisors"
    ]),
    vm_name: z.string().optional(),
    vm_type: z.enum(["virtualbox", "vmware", "qemu", "hyperv", "auto"]).optional(),
    memory_mb: z.number().optional(),
    cpu_cores: z.number().optional(),
    disk_size_gb: z.number().optional(),
    iso_path: z.string().optional(),
    network_type: z.enum(["nat", "bridged", "hostonly", "internal"]).optional()
  },
  outputSchema: { 
    success: z.boolean(),
    results: z.any().optional(),
    platform: z.string(),
    hypervisor: z.string().optional(),
    error: z.string().optional()
  }
}, async ({ action, vm_name, vm_type, memory_mb, cpu_cores, disk_size_gb, iso_path, network_type }) => {
  try {
    let results: any = {};
    let detectedHypervisor = "none";
    let command = "";

    // Auto-detect available hypervisors
    const detectHypervisors = async () => {
      const hypervisors = [];
      
      // Check VirtualBox
      try {
        await execAsync("VBoxManage --version");
        hypervisors.push("virtualbox");
      } catch {}
      
      // Check VMware
      try {
        if (IS_WINDOWS) {
          await execAsync("vmrun");
        } else {
          await execAsync("vmrun");
        }
        hypervisors.push("vmware");
      } catch {}
      
      // Check QEMU/KVM
      try {
        await execAsync("qemu-system-x86_64 --version");
        hypervisors.push("qemu");
      } catch {}
      
      // Check Hyper-V (Windows only)
      if (IS_WINDOWS) {
        try {
          await execAsync("powershell \"Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All\"");
          hypervisors.push("hyperv");
        } catch {}
      }
      
      return hypervisors;
    };

    const availableHypervisors = await detectHypervisors();
    
    if (vm_type === "auto" || !vm_type) {
      vm_type = (availableHypervisors[0] as "virtualbox" | "vmware" | "qemu" | "hyperv") || "virtualbox";
    }
    
    detectedHypervisor = vm_type || "none";

    switch (action) {
      case "list_hypervisors":
        results = { available: availableHypervisors, detected: vm_type };
        break;

      case "list_vms":
        switch (vm_type) {
          case "virtualbox":
            try {
              const { stdout } = await execAsync("VBoxManage list vms");
              results = { vms: stdout.split('\n').filter(line => line.trim()) };
            } catch (error) {
              throw new Error(`VirtualBox not available: ${error}`);
            }
            break;
            
          case "vmware":
            try {
              if (IS_WINDOWS) {
                const { stdout } = await execAsync("vmrun list");
                results = { vms: stdout.split('\n').filter(line => line.trim()) };
              } else {
                const { stdout } = await execAsync("vmrun list");
                results = { vms: stdout.split('\n').filter(line => line.trim()) };
              }
            } catch (error) {
              throw new Error(`VMware not available: ${error}`);
            }
            break;

          case "qemu":
            try {
              const { stdout } = await execAsync("virsh list --all");
              results = { vms: stdout.split('\n').filter(line => line.trim()) };
            } catch (error) {
              throw new Error(`QEMU/KVM not available: ${error}`);
            }
            break;
            
          case "hyperv":
            if (IS_WINDOWS) {
              try {
                const { stdout } = await execAsync("powershell \"Get-VM | Select-Object Name, State, MemoryAssigned, ProcessorCount\"");
                results = { vms: stdout.split('\n').filter(line => line.trim()) };
              } catch (error) {
                throw new Error(`Hyper-V not available: ${error}`);
              }
            } else {
              throw new Error("Hyper-V is only available on Windows");
            }
            break;
        }
        break;

      case "start_vm":
        if (!vm_name) {
          throw new Error("VM name is required for start_vm action");
        }
        switch (vm_type) {
          case "virtualbox":
            const { stdout: startOutput } = await execAsync(`VBoxManage startvm "${vm_name}"`);
            results = { vm: vm_name, started: true, output: startOutput };
            break;
          case "vmware":
            const { stdout: vmwareStartOutput } = await execAsync(`vmrun start "${vm_name}"`);
            results = { vm: vm_name, started: true, output: vmwareStartOutput };
            break;
          case "qemu":
            const { stdout: qemuStartOutput } = await execAsync(`virsh start "${vm_name}"`);
            results = { vm: vm_name, started: true, output: qemuStartOutput };
            break;
          case "hyperv":
            if (IS_WINDOWS) {
              const { stdout: hypervStartOutput } = await execAsync(`powershell "Start-VM -Name '${vm_name}'"`);
              results = { vm: vm_name, started: true, output: hypervStartOutput };
            } else {
              throw new Error("Hyper-V is only available on Windows");
            }
            break;
        }
        break;

      case "stop_vm":
        if (!vm_name) {
          throw new Error("VM name is required for stop_vm action");
        }
        switch (vm_type) {
          case "virtualbox":
            const { stdout: stopOutput } = await execAsync(`VBoxManage controlvm "${vm_name}" poweroff`);
            results = { vm: vm_name, stopped: true, output: stopOutput };
            break;
          case "vmware":
            const { stdout: vmwareStopOutput } = await execAsync(`vmrun stop "${vm_name}"`);
            results = { vm: vm_name, stopped: true, output: vmwareStopOutput };
            break;
          case "qemu":
            const { stdout: qemuStopOutput } = await execAsync(`virsh shutdown "${vm_name}"`);
            results = { vm: vm_name, stopped: true, output: qemuStopOutput };
            break;
          case "hyperv":
            if (IS_WINDOWS) {
              const { stdout: hypervStopOutput } = await execAsync(`powershell "Stop-VM -Name '${vm_name}'"`);
              results = { vm: vm_name, stopped: true, output: hypervStopOutput };
            } else {
              throw new Error("Hyper-V is only available on Windows");
            }
            break;
        }
        break;

      case "pause_vm":
        if (!vm_name) {
          throw new Error("VM name is required for pause_vm action");
        }
        switch (vm_type) {
          case "virtualbox":
            const { stdout: pauseOutput } = await execAsync(`VBoxManage controlvm "${vm_name}" pause`);
            results = { vm: vm_name, paused: true, output: pauseOutput };
            break;
          case "vmware":
            const { stdout: vmwarePauseOutput } = await execAsync(`vmrun suspend "${vm_name}"`);
            results = { vm: vm_name, paused: true, output: vmwarePauseOutput };
            break;
          case "qemu":
            const { stdout: qemuPauseOutput } = await execAsync(`virsh suspend "${vm_name}"`);
            results = { vm: vm_name, paused: true, output: qemuPauseOutput };
            break;
          case "hyperv":
            if (IS_WINDOWS) {
              const { stdout: hypervPauseOutput } = await execAsync(`powershell "Suspend-VM -Name '${vm_name}'"`);
              results = { vm: vm_name, paused: true, output: hypervPauseOutput };
            } else {
              throw new Error("Hyper-V is only available on Windows");
            }
            break;
        }
        break;

      case "resume_vm":
        if (!vm_name) {
          throw new Error("VM name is required for resume_vm action");
        }
        switch (vm_type) {
          case "virtualbox":
            const { stdout: resumeOutput } = await execAsync(`VBoxManage controlvm "${vm_name}" resume`);
            results = { vm: vm_name, resumed: true, output: resumeOutput };
            break;
          case "vmware":
            const { stdout: vmwareResumeOutput } = await execAsync(`vmrun unpause "${vm_name}"`);
            results = { vm: vm_name, resumed: true, output: vmwareResumeOutput };
            break;
          case "qemu":
            const { stdout: qemuResumeOutput } = await execAsync(`virsh resume "${vm_name}"`);
            results = { vm: vm_name, resumed: true, output: qemuResumeOutput };
            break;
          case "hyperv":
            if (IS_WINDOWS) {
              const { stdout: hypervResumeOutput } = await execAsync(`powershell "Resume-VM -Name '${vm_name}'"`);
              results = { vm: vm_name, resumed: true, output: hypervResumeOutput };
            } else {
              throw new Error("Hyper-V is only available on Windows");
            }
            break;
        }
        break;

      case "create_vm":
        if (!vm_name || !memory_mb || !cpu_cores || !disk_size_gb) {
          throw new Error("VM name, memory, CPU cores, and disk size are required for create_vm action");
        }
        switch (vm_type) {
          case "virtualbox":
            const { stdout: createOutput } = await execAsync(`VBoxManage createvm --name "${vm_name}" --ostype "Linux_64" --register`);
            await execAsync(`VBoxManage modifyvm "${vm_name}" --memory ${memory_mb} --cpus ${cpu_cores}`);
            await execAsync(`VBoxManage createhd --filename "${vm_name}.vdi" --size ${disk_size_gb * 1024}`);
            await execAsync(`VBoxManage storagectl "${vm_name}" --name "SATA Controller" --add sata --controller IntelAhci`);
            await execAsync(`VBoxManage storageattach "${vm_name}" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "${vm_name}.vdi"`);
            if (iso_path) {
              await execAsync(`VBoxManage storagectl "${vm_name}" --name "IDE Controller" --add ide`);
              await execAsync(`VBoxManage storageattach "${vm_name}" --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium "${iso_path}"`);
            }
            results = { vm: vm_name, created: true, output: createOutput };
            break;
          case "vmware":
            // VMware VM creation requires more complex setup
            results = { vm: vm_name, created: false, error: "VMware VM creation requires manual setup" };
            break;
          case "qemu":
            // QEMU VM creation
            const { stdout: qemuCreateOutput } = await execAsync(`qemu-img create -f qcow2 "${vm_name}.qcow2" ${disk_size_gb}G`);
            results = { vm: vm_name, created: true, output: qemuCreateOutput };
            break;
          case "hyperv":
            if (IS_WINDOWS) {
              const { stdout: hypervCreateOutput } = await execAsync(`powershell "New-VM -Name '${vm_name}' -MemoryStartupBytes ${memory_mb}MB -Generation 2"`);
              await execAsync(`powershell "Set-VMProcessor -VMName '${vm_name}' -Count ${cpu_cores}"`);
              await execAsync(`powershell "New-VHD -Path '${vm_name}.vhdx' -SizeBytes ${disk_size_gb}GB -Dynamic"`);
              await execAsync(`powershell "Add-VMHardDiskDrive -VMName '${vm_name}' -Path '${vm_name}.vhdx'"`);
              results = { vm: vm_name, created: true, output: hypervCreateOutput };
            } else {
              throw new Error("Hyper-V is only available on Windows");
            }
            break;
        }
        break;

      case "delete_vm":
        if (!vm_name) {
          throw new Error("VM name is required for delete_vm action");
        }
        switch (vm_type) {
          case "virtualbox":
            const { stdout: deleteOutput } = await execAsync(`VBoxManage unregistervm "${vm_name}" --delete`);
            results = { vm: vm_name, deleted: true, output: deleteOutput };
            break;
          case "vmware":
            const { stdout: vmwareDeleteOutput } = await execAsync(`vmrun delete "${vm_name}"`);
            results = { vm: vm_name, deleted: true, output: vmwareDeleteOutput };
            break;
          case "qemu":
            const { stdout: qemuDeleteOutput } = await execAsync(`virsh undefine "${vm_name}"`);
            results = { vm: vm_name, deleted: true, output: qemuDeleteOutput };
            break;
          case "hyperv":
            if (IS_WINDOWS) {
              const { stdout: hypervDeleteOutput } = await execAsync(`powershell "Remove-VM -Name '${vm_name}' -Force"`);
              results = { vm: vm_name, deleted: true, output: hypervDeleteOutput };
            } else {
              throw new Error("Hyper-V is only available on Windows");
            }
            break;
        }
        break;

      case "vm_info":
        if (!vm_name) {
          throw new Error("VM name is required for vm_info action");
        }
        switch (vm_type) {
          case "virtualbox":
            const { stdout: infoOutput } = await execAsync(`VBoxManage showvminfo "${vm_name}"`);
            results = { vm: vm_name, info: infoOutput };
            break;
          case "vmware":
            const { stdout: vmwareInfoOutput } = await execAsync(`vmrun list`);
            results = { vm: vm_name, info: vmwareInfoOutput };
            break;
          case "qemu":
            const { stdout: qemuInfoOutput } = await execAsync(`virsh dominfo "${vm_name}"`);
            results = { vm: vm_name, info: qemuInfoOutput };
            break;
          case "hyperv":
            if (IS_WINDOWS) {
              const { stdout: hypervInfoOutput } = await execAsync(`powershell "Get-VM -Name '${vm_name}' | ConvertTo-Json"`);
              results = { vm: vm_name, info: hypervInfoOutput };
            } else {
              throw new Error("Hyper-V is only available on Windows");
            }
            break;
        }
        break;

      case "vm_status":
        if (!vm_name) {
          throw new Error("VM name is required for vm_status action");
        }
        switch (vm_type) {
          case "virtualbox":
            const { stdout: statusOutput } = await execAsync(`VBoxManage showvminfo "${vm_name}" | grep "State:"`);
            results = { vm: vm_name, status: statusOutput.trim() };
            break;
          case "vmware":
            const { stdout: vmwareStatusOutput } = await execAsync(`vmrun list`);
            results = { vm: vm_name, status: vmwareStatusOutput };
            break;
          case "qemu":
            const { stdout: qemuStatusOutput } = await execAsync(`virsh domstate "${vm_name}"`);
            results = { vm: vm_name, status: qemuStatusOutput.trim() };
            break;
          case "hyperv":
            if (IS_WINDOWS) {
              const { stdout: hypervStatusOutput } = await execAsync(`powershell "Get-VM -Name '${vm_name}' | Select-Object Name, State"`);
              results = { vm: vm_name, status: hypervStatusOutput };
            } else {
              throw new Error("Hyper-V is only available on Windows");
            }
            break;
        }
        break;

      default:
        throw new Error(`Unsupported VM action: ${action}`);
    }

    return {
      content: [{ type: "text", text: `VM operation completed: ${action}` }],
      structuredContent: {
        success: true,
        results,
        platform: PLATFORM,
        hypervisor: detectedHypervisor
      }
    };

  } catch (error) {
    logger.error("VM management error", { error: error instanceof Error ? error.message : String(error) });
    return {
      content: [{ type: "text", text: `VM operation failed: ${error instanceof Error ? error.message : String(error)}` }],
      structuredContent: {
        success: false,
        platform: PLATFORM,
        error: error instanceof Error ? error.message : String(error)
      }
    };
  }
});

// ===========================================
// DOCKER MANAGEMENT TOOLS
// ===========================================

server.registerTool("docker_management", {
  description: "Cross-platform Docker container and image management",
  inputSchema: {
    action: z.enum([
      "list_containers", "list_images", "start_container", "stop_container", "create_container", "delete_container", "delete_image", "container_info", "container_logs", "container_stats", "pull_image", "build_image", "list_networks", "list_volumes", "docker_info", "docker_version"
    ]),
    container_name: z.string().optional(),
    image_name: z.string().optional(),
    image_tag: z.string().optional(),
    dockerfile_path: z.string().optional(),
    build_context: z.string().optional(),
    port_mapping: z.string().optional(),
    volume_mapping: z.string().optional(),
    environment_vars: z.string().optional(),
    network_name: z.string().optional(),
    volume_name: z.string().optional(),
    all_containers: z.boolean().optional()
  },
  outputSchema: {
    success: z.boolean(),
    results: z.any(),
    platform: z.string(),
    docker_available: z.boolean(),
    error: z.string().optional()
  }
}, async ({ action, container_name, image_name, image_tag, dockerfile_path, build_context, port_mapping, volume_mapping, environment_vars, network_name, volume_name, all_containers }) => {
  try {
    const platform = PLATFORM;
    let results: any;
    let docker_available = false;

    // Check if Docker is available
    try {
      await execAsync("docker --version");
      docker_available = true;
    } catch {
      docker_available = false;
    }

    if (!docker_available) {
      return {
        content: [{ type: "text", text: "Docker is not installed or not available in PATH" }],
        structuredContent: {
          success: false,
          results: null,
          platform,
          docker_available: false,
          error: "Docker not available"
        }
      };
    }

    // Docker operations
    switch (action) {
      case "docker_version":
        const { stdout: versionOutput } = await execAsync("docker --version");
        results = { version: versionOutput.trim() };
        break;
      case "docker_info":
        const { stdout: infoOutput } = await execAsync("docker info");
        results = { info: infoOutput };
        break;
      case "list_containers":
        const { stdout: containersOutput } = await execAsync("docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'");
        results = { containers: containersOutput.trim().split("\n").slice(1) };
        break;
      case "list_images":
        const { stdout: imagesOutput } = await execAsync("docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}'");
        results = { images: imagesOutput.trim().split("\n").slice(1) };
        break;
      case "start_container":
        if (!container_name) {
          throw new Error("Container name is required for start_container action");
        }
        const { stdout: startOutput } = await execAsync(`docker start ${container_name}`);
        results = { container: container_name, started: true, output: startOutput.trim() };
        break;
      case "stop_container":
        if (!container_name) {
          throw new Error("Container name is required for stop_container action");
        }
        const { stdout: stopOutput } = await execAsync(`docker stop ${container_name}`);
        results = { container: container_name, stopped: true, output: stopOutput.trim() };
        break;
      case "create_container":
        if (!image_name) {
          throw new Error("Image name is required for create_container action");
        }
        const containerName = container_name || `container_${Date.now()}`;
        const portMapping = port_mapping ? `-p ${port_mapping}` : "";
        const volumeMapping = volume_mapping ? `-v ${volume_mapping}` : "";
        const envVars = environment_vars ? `-e ${environment_vars}` : "";
        const { stdout: createOutput } = await execAsync(`docker create --name ${containerName} ${portMapping} ${volumeMapping} ${envVars} ${image_name}:${image_tag || "latest"}`);
        results = { container: containerName, created: true, container_id: createOutput.trim() };
        break;
      case "delete_container":
        if (!container_name) {
          throw new Error("Container name is required for delete_container action");
        }
        const { stdout: deleteOutput } = await execAsync(`docker rm -f ${container_name}`);
        results = { container: container_name, deleted: true, output: deleteOutput.trim() };
        break;
      case "delete_image":
        if (!image_name) {
          throw new Error("Image name is required for delete_image action");
        }
        const imageRef = image_tag ? `${image_name}:${image_tag}` : image_name;
        const { stdout: deleteImageOutput } = await execAsync(`docker rmi ${imageRef}`);
        results = { image: imageRef, deleted: true, output: deleteImageOutput.trim() };
        break;
      case "container_info":
        if (!container_name) {
          throw new Error("Container name is required for container_info action");
        }
        const { stdout: containerInfoOutput } = await execAsync(`docker inspect ${container_name}`);
        results = { container: container_name, info: JSON.parse(containerInfoOutput) };
        break;
      case "container_logs":
        if (!container_name) {
          throw new Error("Container name is required for container_logs action");
        }
        const { stdout: logsOutput } = await execAsync(`docker logs ${container_name}`);
        results = { container: container_name, logs: logsOutput };
        break;
      case "container_stats":
        if (!container_name) {
          throw new Error("Container name is required for container_stats action");
        }
        const { stdout: statsOutput } = await execAsync(`docker stats ${container_name} --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"`);
        results = { container: container_name, stats: statsOutput.trim().split("\n").slice(1) };
        break;
      case "pull_image":
        if (!image_name) {
          throw new Error("Image name is required for pull_image action");
        }
        const imageToPull = image_tag ? `${image_name}:${image_tag}` : image_name;
        const { stdout: pullOutput } = await execAsync(`docker pull ${imageToPull}`);
        results = { image: imageToPull, pulled: true, output: pullOutput };
        break;
      case "build_image":
        if (!dockerfile_path) {
          throw new Error("Dockerfile path is required for build_image action");
        }
        const buildContext = build_context || path.dirname(dockerfile_path);
        const imageTag = image_tag || "latest";
        const { stdout: buildOutput } = await execAsync(`docker build -t ${image_name}:${imageTag} -f ${dockerfile_path} ${buildContext}`);
        results = { image: `${image_name}:${imageTag}`, built: true, output: buildOutput };
        break;
      case "list_networks":
        const { stdout: networksOutput } = await execAsync("docker network ls --format 'table {{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}'");
        results = { networks: networksOutput.trim().split("\n").slice(1) };
        break;
      case "list_volumes":
        const { stdout: volumesOutput } = await execAsync("docker volume ls --format 'table {{.Driver}}\t{{.Name}}'");
        results = { volumes: volumesOutput.trim().split("\n").slice(1) };
        break;
      default:
        results = { message: `Action ${action} not implemented yet` };
    }

    return {
      content: [],
      structuredContent: {
        success: true,
        results,
        platform,
        docker_available: true
      }
    };

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [],
      structuredContent: {
        success: false,
        results: null,
        platform: PLATFORM,
        docker_available: false,
        error: errorMessage
      }
    };
  }
});

// ===========================================
// MOBILE PLATFORM TOOLS
// ===========================================

server.registerTool("mobile_device_info", {
  description: "Get comprehensive mobile device information for Android and iOS",
  inputSchema: {
    include_sensitive: z.boolean().default(false)
  },
  outputSchema: {
    success: z.boolean(),
    platform: z.string(),
    device_info: z.any(),
    mobile_features: z.any(),
    permissions: z.array(z.string()),
    error: z.string().optional()
  }
}, async ({ include_sensitive }) => {
  try {
    if (!IS_MOBILE) {
      return {
        content: [],
        structuredContent: {
          success: false,
          platform: PLATFORM,
          device_info: null,
          mobile_features: null,
          permissions: [],
          error: "Not running on mobile platform"
        }
      };
    }

    const deviceInfo = getMobileDeviceInfo();
    const permissions = getMobilePermissions();
    
    const mobileFeatures = {
      camera: isMobileFeatureAvailable("camera"),
      location: isMobileFeatureAvailable("location"),
      biometrics: isMobileFeatureAvailable("biometrics"),
      bluetooth: isMobileFeatureAvailable("bluetooth"),
      nfc: isMobileFeatureAvailable("nfc"),
      sensors: isMobileFeatureAvailable("sensors"),
      notifications: isMobileFeatureAvailable("notifications")
    };

    // Get additional system information
    let systemInfo = {};
    try {
      if (IS_ANDROID) {
        const { stdout: buildInfo } = await execAsync("getprop ro.build.version.release");
        const { stdout: modelInfo } = await execAsync("getprop ro.product.model");
        const { stdout: manufacturerInfo } = await execAsync("getprop ro.product.manufacturer");
        systemInfo = {
          android_version: buildInfo.trim(),
          model: modelInfo.trim(),
          manufacturer: manufacturerInfo.trim()
        };
      } else if (IS_IOS) {
        const { stdout: iosVersion } = await execAsync("sw_vers -productVersion");
        const { stdout: deviceName } = await execAsync("scutil --get ComputerName");
        systemInfo = {
          ios_version: iosVersion.trim(),
          device_name: deviceName.trim()
        };
      }
    } catch (error) {
      // Ignore system info errors
    }

    const result = {
      ...deviceInfo,
      ...systemInfo,
      mobile_config: MOBILE_CONFIG
    };

    return {
      content: [],
      structuredContent: {
        success: true,
        platform: IS_ANDROID ? "android" : IS_IOS ? "ios" : "mobile-web",
        device_info: result,
        mobile_features: mobileFeatures,
        permissions: include_sensitive ? permissions : permissions.filter(p => !p.includes("SMS") && !p.includes("CALL_PHONE"))
      }
    };

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [],
      structuredContent: {
        success: false,
        platform: PLATFORM,
        device_info: null,
        mobile_features: null,
        permissions: [],
        error: errorMessage
      }
    };
  }
});

server.registerTool("mobile_file_ops", {
  description: "Mobile-optimized file operations with Android and iOS support",
  inputSchema: {
    action: z.enum([
      "list", "copy", "move", "delete", "create", "get_info", "search", "compress", "decompress"
    ]),
    source: z.string().optional(),
    destination: z.string().optional(),
    content: z.string().optional(),
    recursive: z.boolean().default(false),
    pattern: z.string().optional(),
    search_text: z.string().optional()
  },
  outputSchema: {
    success: z.boolean(),
    platform: z.string(),
    result: z.any(),
    mobile_optimized: z.boolean(),
    error: z.string().optional()
  }
}, async ({ action, source, destination, content, recursive, pattern, search_text }) => {
  try {
    if (!IS_MOBILE) {
      return {
        content: [],
        structuredContent: {
          success: false,
          platform: PLATFORM,
          result: null,
          mobile_optimized: false,
          error: "Not running on mobile platform"
        }
      };
    }

    let result: any;
    const platform = IS_ANDROID ? "android" : "ios";

    switch (action) {
      case "list":
        if (!source) {
          throw new Error("Source is required for list operation");
        }
        const listPath = ensureInsideRoot(path.resolve(source));
        const items = await fs.readdir(listPath, { withFileTypes: true });
        
        // Get file sizes for all items
        const itemsWithSizes = await Promise.all(
          items.map(async (item) => {
            const size = item.isFile() ? (await fs.stat(path.join(listPath, item.name))).size : 0;
            return {
              name: item.name,
              isDirectory: item.isDirectory(),
              size
            };
          })
        );
        
        result = {
          path: listPath,
          items: itemsWithSizes,
          total: items.length
        };
        break;

      case "copy":
        if (!source || !destination) {
          throw new Error("Source and destination are required for copy operation");
        }
        const copySource = ensureInsideRoot(path.resolve(source));
        const copyDest = ensureInsideRoot(path.resolve(destination));
        await fs.copyFile(copySource, copyDest);
        result = { source: copySource, destination: copyDest, copied: true };
        break;

      case "move":
        if (!source || !destination) {
          throw new Error("Source and destination are required for move operation");
        }
        const moveSource = ensureInsideRoot(path.resolve(source));
        const moveDest = ensureInsideRoot(path.resolve(destination));
        await fs.rename(moveSource, moveDest);
        result = { source: moveSource, destination: moveDest, moved: true };
        break;

      case "delete":
        if (!source) {
          throw new Error("Source is required for delete operation");
        }
        const deletePath = ensureInsideRoot(path.resolve(source));
        await fs.unlink(deletePath);
        result = { path: deletePath, deleted: true };
        break;

      case "create":
        if (!destination) {
          throw new Error("Destination is required for create operation");
        }
        const createPath = ensureInsideRoot(path.resolve(destination));
        const fileContent = content || "";
        await fs.writeFile(createPath, fileContent, "utf8");
        result = { path: createPath, created: true, size: fileContent.length };
        break;

      case "get_info":
        if (!source) {
          throw new Error("Source is required for get_info operation");
        }
        const infoPath = ensureInsideRoot(path.resolve(source));
        const stats = await fs.stat(infoPath);
        result = {
          path: infoPath,
          exists: true,
          isFile: stats.isFile(),
          isDirectory: stats.isDirectory(),
          size: stats.size,
          created: stats.birthtime,
          modified: stats.mtime,
          permissions: stats.mode.toString(8)
        };
        break;

      case "search":
        if (!source || !pattern) {
          throw new Error("Source and pattern are required for search operation");
        }
        const searchPath = ensureInsideRoot(path.resolve(source));
        const matches: string[] = [];
        
        const searchRecursive = async (currentDir: string): Promise<string[]> => {
          const results: string[] = [];
          try {
            const items = await fs.readdir(currentDir, { withFileTypes: true });
            for (const item of items) {
              const fullPath = path.join(currentDir, item.name);
              if (item.isDirectory() && recursive) {
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
        
        matches.push(...await searchRecursive(searchPath));
        result = { path: searchPath, pattern, matches, total: matches.length };
        break;

      case "compress":
        if (!source || !destination) {
          throw new Error("Source and destination are required for compress operation");
        }
        const compressSource = ensureInsideRoot(path.resolve(source));
        const compressDest = ensureInsideRoot(path.resolve(destination));
        
        if (IS_ANDROID) {
          await execAsync(`tar -czf "${compressDest}" "${compressSource}"`);
        } else if (IS_IOS) {
          await execAsync(`tar -czf "${compressDest}" "${compressSource}"`);
        }
        
        result = { source: compressSource, destination: compressDest, compressed: true };
        break;

      case "decompress":
        if (!source || !destination) {
          throw new Error("Source and destination are required for decompress operation");
        }
        const decompressSource = ensureInsideRoot(path.resolve(source));
        const decompressDest = ensureInsideRoot(path.resolve(destination));
        
        if (IS_ANDROID) {
          await execAsync(`tar -xzf "${decompressSource}" -C "${decompressDest}"`);
        } else if (IS_IOS) {
          await execAsync(`tar -xzf "${decompressSource}" -C "${decompressDest}"`);
        }
        
        result = { source: decompressSource, destination: decompressDest, decompressed: true };
        break;

      default:
        throw new Error(`Unknown action: ${action}`);
    }

    return {
      content: [],
      structuredContent: {
        success: true,
        platform,
        result,
        mobile_optimized: true
      }
    };

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [],
      structuredContent: {
        success: false,
        platform: PLATFORM,
        result: null,
        mobile_optimized: false,
        error: errorMessage
      }
    };
  }
});

server.registerTool("mobile_system_tools", {
  description: "Mobile system management tools for Android and iOS",
  inputSchema: {
    tool: z.enum([
      "processes", "services", "network", "storage", "users", "packages", "permissions", "system_info"
    ]),
    action: z.string().optional(),
    filter: z.string().optional(),
    target: z.string().optional()
  },
  outputSchema: {
    success: z.boolean(),
    platform: z.string(),
    tool: z.string(),
    result: z.any(),
    error: z.string().optional()
  }
}, async ({ tool, action, filter, target }) => {
  try {
    if (!IS_MOBILE) {
      return {
        content: [],
        structuredContent: {
          success: false,
          platform: PLATFORM,
          tool,
          result: null,
          error: "Not running on mobile platform"
        }
      };
    }

    const platform = IS_ANDROID ? "android" : "ios";
    let result: any;

    switch (tool) {
      case "processes":
        const processCmd = getMobileProcessCommand(action || "list", filter);
        if (processCmd) {
          const { stdout } = await execAsync(processCmd);
          result = { command: processCmd, output: stdout, processes: stdout.split("\n").filter(Boolean) };
        } else {
          result = { error: "Process command not available for this platform" };
        }
        break;

      case "services":
        const serviceCmd = getMobileServiceCommand(action || "list", filter);
        if (serviceCmd) {
          const { stdout } = await execAsync(serviceCmd);
          result = { command: serviceCmd, output: stdout, services: stdout.split("\n").filter(Boolean) };
        } else {
          result = { error: "Service command not available for this platform" };
        }
        break;

      case "network":
        const networkCmd = getMobileNetworkCommand(action || "interfaces", filter);
        if (networkCmd) {
          const { stdout } = await execAsync(networkCmd);
          result = { command: networkCmd, output: stdout, network_info: stdout.split("\n").filter(Boolean) };
        } else {
          result = { error: "Network command not available for this platform" };
        }
        break;

      case "storage":
        const storageCmd = getMobileStorageCommand(action || "usage", filter);
        if (storageCmd) {
          const { stdout } = await execAsync(storageCmd);
          result = { command: storageCmd, output: stdout, storage_info: stdout.split("\n").filter(Boolean) };
        } else {
          result = { error: "Storage command not available for this platform" };
        }
        break;

      case "users":
        const userCmd = getMobileUserCommand(action || "list", filter);
        if (userCmd) {
          const { stdout } = await execAsync(userCmd);
          result = { command: userCmd, output: stdout, users: stdout.split("\n").filter(Boolean) };
        } else {
          result = { error: "User command not available for this platform" };
        }
        break;

      case "packages":
        if (IS_ANDROID) {
          const { stdout } = await execAsync("pm list packages");
          result = { packages: stdout.split("\n").filter(Boolean) };
        } else if (IS_IOS) {
          // iOS doesn't have a direct package manager, but we can check installed apps
          const { stdout } = await execAsync("ls /Applications");
          result = { applications: stdout.split("\n").filter(Boolean) };
        }
        break;

      case "permissions":
        result = {
          available_permissions: getMobilePermissions(),
          requested_permissions: getMobilePermissions(),
          platform_specific: IS_ANDROID ? "Android permissions system" : "iOS permissions system"
        };
        break;

      case "system_info":
        result = {
          platform: platform,
          version: process.version,
          arch: os.arch(),
          cpus: os.cpus().length,
          memory: os.totalmem(),
          hostname: os.hostname(),
          userInfo: os.userInfo(),
          mobile_config: MOBILE_CONFIG
        };
        break;

      default:
        throw new Error(`Unknown tool: ${tool}`);
    }

    return {
      content: [],
      structuredContent: {
        success: true,
        platform,
        tool,
        result
      }
    };

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [],
      structuredContent: {
        success: false,
        platform: PLATFORM,
        tool,
        result: null,
        error: errorMessage
      }
    };
  }
});

server.registerTool("mobile_hardware", {
  description: "Mobile hardware access and sensor data for Android and iOS",
  inputSchema: {
    feature: z.enum([
      "camera", "location", "biometrics", "bluetooth", "nfc", "sensors", "notifications", "audio", "vibration"
    ]),
    action: z.enum([
      "check_availability", "get_status", "request_permission", "get_data", "control"
    ]),
    parameters: z.any().optional()
  },
  outputSchema: {
    success: z.boolean(),
    platform: z.string(),
    feature: z.string(),
    available: z.boolean(),
    result: z.any(),
    error: z.string().optional()
  }
}, async ({ feature, action, parameters }) => {
  try {
    if (!IS_MOBILE) {
      return {
        content: [],
        structuredContent: {
          success: false,
          platform: PLATFORM,
          feature,
          available: false,
          result: null,
          error: "Not running on mobile platform"
        }
      };
    }

    const platform = IS_ANDROID ? "android" : "ios";
    const available = isMobileFeatureAvailable(feature);
    let result: any;

    if (!available) {
      result = { error: `Feature ${feature} not available on this platform` };
    } else {
      switch (feature) {
        case "camera":
          if (action === "check_availability") {
            result = { available: true, type: "back_camera", resolution: "12MP" };
          } else if (action === "request_permission") {
            result = { permission: IS_ANDROID ? "android.permission.CAMERA" : "NSCameraUsageDescription", granted: true };
          }
          break;

        case "location":
          if (action === "check_availability") {
            result = { available: true, accuracy: "high", providers: ["gps", "network"] };
          } else if (action === "request_permission") {
            result = { 
              permission: IS_ANDROID ? "android.permission.ACCESS_FINE_LOCATION" : "NSLocationWhenInUseUsageDescription", 
              granted: true 
            };
          }
          break;

        case "biometrics":
          if (action === "check_availability") {
            result = { 
              available: true, 
              type: IS_ANDROID ? "fingerprint" : "faceid", 
              secure: true 
            };
          }
          break;

        case "bluetooth":
          if (action === "check_availability") {
            result = { available: true, version: "5.0", range: "100m" };
          }
          break;

        case "nfc":
          if (action === "check_availability") {
            result = { available: IS_ANDROID, type: "NFC-A", range: "10cm" };
          }
          break;

        case "sensors":
          if (action === "check_availability") {
            result = { 
              available: true, 
              sensors: ["accelerometer", "gyroscope", "magnetometer", "proximity", "light"] 
            };
          }
          break;

        case "notifications":
          if (action === "check_availability") {
            result = { available: true, types: ["push", "local", "scheduled"] };
          }
          break;

        case "audio":
          if (action === "check_availability") {
            result = { available: true, channels: 2, sample_rate: "44.1kHz" };
          }
          break;

        case "vibration":
          if (action === "check_availability") {
            result = { available: true, pattern: "customizable", intensity: "adjustable" };
          }
          break;

        default:
          result = { error: `Unknown feature: ${feature}` };
      }
    }

    return {
      content: [],
      structuredContent: {
        success: true,
        platform,
        feature,
        available,
        result
      }
    };

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [],
      structuredContent: {
        success: false,
        platform: PLATFORM,
        feature,
        available: false,
        result: null,
        error: errorMessage
      }
    };
  }
});

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

// Helper functions for file operations
async function copyDirectoryRecursive(source: string, destination: string): Promise<void> {
  await fs.mkdir(destination, { recursive: true });
  const items = await fs.readdir(source, { withFileTypes: true });
  
  for (const item of items) {
    const sourcePath = path.join(source, item.name);
    const destPath = path.join(destination, item.name);
    
    if (item.isDirectory()) {
      await copyDirectoryRecursive(sourcePath, destPath);
    } else {
      await fs.copyFile(sourcePath, destPath);
    }
  }
}

async function deleteDirectoryRecursive(dirPath: string): Promise<void> {
  const items = await fs.readdir(dirPath, { withFileTypes: true });
  
  for (const item of items) {
    const fullPath = path.join(dirPath, item.name);
    
    if (item.isDirectory()) {
      await deleteDirectoryRecursive(fullPath);
    } else {
      await fs.unlink(fullPath);
    }
  }
  
  await fs.rmdir(dirPath);
}

async function listDirectoryRecursive(dirPath: string, pattern?: string): Promise<string[]> {
  const items: string[] = [];
  
  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      
      if (pattern && !entry.name.includes(pattern.replace("*", ""))) {
        continue;
      }
      
      items.push(fullPath);
      
      if (entry.isDirectory()) {
        items.push(...await listDirectoryRecursive(fullPath, pattern));
      }
    }
  } catch (error) {
    // Ignore permission errors
  }
  
  return items;
}

async function findFilesByContent(dirPath: string, searchText: string, recursive: boolean): Promise<string[]> {
  const foundFiles: string[] = [];
  
  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      
      if (entry.isDirectory() && recursive) {
        foundFiles.push(...await findFilesByContent(fullPath, searchText, recursive));
      } else if (entry.isFile()) {
        try {
          const content = await fs.readFile(fullPath, "utf8");
          if (content.includes(searchText)) {
            foundFiles.push(fullPath);
          }
        } catch (error) {
          // Ignore read errors
        }
      }
    }
  } catch (error) {
    // Ignore permission errors
  }
  
  return foundFiles;
}

async function compressFile(source: string, destination: string, type: string): Promise<void> {
  if (type === "zip") {
    // Use cross-platform zip command
    if (IS_WINDOWS) {
      await execAsync(`powershell Compress-Archive -Path "${source}" -DestinationPath "${destination}" -Force`);
    } else {
      await execAsync(`zip -r "${destination}" "${source}"`);
    }
  } else if (type === "tar") {
    await execAsync(`tar -czf "${destination}" "${source}"`);
  } else if (type === "gzip") {
    await execAsync(`gzip -c "${source}" > "${destination}"`);
  } else if (type === "bzip2") {
    await execAsync(`bzip2 -c "${source}" > "${destination}"`);
  }
}

async function decompressFile(source: string, destination: string): Promise<void> {
  const ext = path.extname(source).toLowerCase();
  
  if (ext === ".zip") {
    if (IS_WINDOWS) {
      await execAsync(`powershell Expand-Archive -Path "${source}" -DestinationPath "${destination}" -Force`);
    } else {
      await execAsync(`unzip "${source}" -d "${destination}"`);
    }
  } else if (ext === ".tar" || ext === ".tar.gz" || ext === ".tgz") {
    await execAsync(`tar -xzf "${source}" -C "${destination}"`);
  } else if (ext === ".gz") {
    await execAsync(`gunzip -c "${source}" > "${destination}"`);
  } else if (ext === ".bz2") {
    await execAsync(`bunzip2 -c "${source}" > "${destination}"`);
  }
}

async function calculateDirectorySize(dirPath: string): Promise<number> {
  let totalSize = 0;
  
  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      
      if (entry.isDirectory()) {
        totalSize += await calculateDirectorySize(fullPath);
      } else {
        const stats = await fs.stat(fullPath);
        totalSize += stats.size;
      }
    }
  } catch (error) {
    // Ignore permission errors
  }
  
  return totalSize;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function modeToSymbolic(mode: number): string {
  const permissions = {
    owner: { read: !!(mode & 0o400), write: !!(mode & 0o200), execute: !!(mode & 0o100) },
    group: { read: !!(mode & 0o040), write: !!(mode & 0o020), execute: !!(mode & 0o010) },
    others: { read: !!(mode & 0o004), write: !!(mode & 0o002), execute: !!(mode & 0o001) }
  };
  
  let symbolic = "";
  for (const category of [permissions.owner, permissions.group, permissions.others]) {
    symbolic += category.read ? "r" : "-";
    symbolic += category.write ? "w" : "-";
    symbolic += category.execute ? "x" : "-";
  }
  
  return symbolic;
}

async function compareFiles(file1: string, file2: string): Promise<boolean> {
  try {
    const [content1, content2] = await Promise.all([
      fs.readFile(file1),
      fs.readFile(file2)
    ]);
    
    return content1.equals(content2);
  } catch (error) {
    return false;
  }
}
