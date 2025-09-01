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
  inputSchema: { dir: z.string().default(".") },
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
// CALCULATOR TOOLS
// ===========================================

server.registerTool("calculator", {
  description: "Mathematical calculator with basic functions",
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
