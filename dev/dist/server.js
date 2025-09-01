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
const execAsync = promisify(exec);
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
    config: {
        ...config,
        allowedRoot: config.allowedRoot ? "configured" : "unrestricted",
        webAllowlist: config.webAllowlist ? "configured" : "unrestricted",
        procAllowlist: config.procAllowlist ? "configured" : "unrestricted"
    }
});
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
        'diskpart', 'reg', 'sc', 'wmic', 'powershell', 'cmd'
    ];
    return dangerousCommands.some(cmd => command.toLowerCase().includes(cmd.toLowerCase()));
}
// Universal access - allow all drives and paths
const ALLOWED_ROOTS = config.allowedRoot
    ? config.allowedRoot.split(",").map(s => path.resolve(s.trim())).filter(Boolean)
    : [];
// Get all available drives on Windows
function getAllDrives() {
    const drives = [];
    try {
        // Get all drive letters from A to Z
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
// Combine environment roots with all available drives
const ALL_DRIVES = getAllDrives();
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
    // Allow any path that starts with a drive letter (Windows)
    if (/^[A-Za-z]:\\/.test(resolved)) {
        return resolved;
    }
    // Allow any absolute path
    if (path.isAbsolute(resolved)) {
        return resolved;
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
    description: "List Windows services",
    inputSchema: { filter: z.string().optional() },
    outputSchema: {
        services: z.array(z.object({
            name: z.string(),
            displayName: z.string(),
            status: z.string(),
            startupType: z.string()
        }))
    }
}, async ({ filter }) => {
    try {
        let cmd = "wmic service get name,displayname,state,startmode /format:csv";
        if (filter) {
            cmd += ` | findstr /i "${filter}"`;
        }
        const { stdout } = await execAsync(cmd);
        const lines = stdout.trim().split("\n").slice(1); // Skip header
        const services = lines.map(line => {
            const parts = line.split(",");
            return {
                name: parts[1] || "Unknown",
                displayName: parts[2] || "Unknown",
                status: parts[3] || "Unknown",
                startupType: parts[4] || "Unknown"
            };
        }).filter(service => service.name !== "Unknown");
        return { content: [], structuredContent: { services } };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                services: [],
                error: error instanceof Error ? error.message : String(error)
            }
        };
    }
});
server.registerTool("win_processes", {
    description: "List Windows processes",
    inputSchema: { filter: z.string().optional() },
    outputSchema: {
        processes: z.array(z.object({
            pid: z.number(),
            name: z.string(),
            memory: z.string(),
            cpu: z.string()
        }))
    }
}, async ({ filter }) => {
    try {
        let cmd = "tasklist /fo csv /nh";
        if (filter) {
            cmd += ` | findstr /i "${filter}"`;
        }
        const { stdout } = await execAsync(cmd);
        const lines = stdout.trim().split("\n");
        const processes = lines.map(line => {
            const parts = line.split(",");
            return {
                pid: parseInt(parts[1]) || 0,
                name: parts[0]?.replace(/"/g, "") || "Unknown",
                memory: parts[4]?.replace(/"/g, "") || "Unknown",
                cpu: parts[8]?.replace(/"/g, "") || "Unknown"
            };
        }).filter(process => process.pid > 0);
        return { content: [], structuredContent: { processes } };
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                processes: [],
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
    description: "Change Windows desktop wallpaper",
    inputSchema: { imagePath: z.string() },
    outputSchema: { success: z.boolean(), error: z.string().optional() }
}, async ({ imagePath }) => {
    try {
        const fullPath = ensureInsideRoot(path.resolve(imagePath));
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
                success: true
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
    description: "Read Windows registry values",
    inputSchema: {
        key: z.string(),
        value: z.string().optional()
    },
    outputSchema: {
        success: z.boolean(),
        data: z.any().optional(),
        error: z.string().optional()
    }
}, async ({ key, value }) => {
    try {
        const command = value
            ? `reg query "${key}" /v "${value}"`
            : `reg query "${key}"`;
        const { stdout } = await execAsync(command);
        return {
            content: [],
            structuredContent: {
                success: true,
                data: stdout
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
server.registerTool("registry_write", {
    description: "Write Windows registry values",
    inputSchema: {
        key: z.string(),
        value: z.string(),
        data: z.string(),
        type: z.enum(["REG_SZ", "REG_DWORD", "REG_QWORD", "REG_BINARY", "REG_MULTI_SZ", "REG_EXPAND_SZ"]).default("REG_SZ")
    },
    outputSchema: {
        success: z.boolean(),
        error: z.string().optional()
    }
}, async ({ key, value, data, type }) => {
    try {
        const command = `reg add "${key}" /v "${value}" /t ${type} /d "${data}" /f`;
        await execAsync(command);
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
server.registerTool("service_control", {
    description: "Control Windows services (start, stop, restart, etc.)",
    inputSchema: {
        serviceName: z.string(),
        action: z.enum(["start", "stop", "restart", "pause", "resume", "status"])
    },
    outputSchema: {
        success: z.boolean(),
        output: z.string().optional(),
        error: z.string().optional()
    }
}, async ({ serviceName, action }) => {
    try {
        const command = `sc ${action} "${serviceName}"`;
        const { stdout } = await execAsync(command);
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
server.registerTool("disk_management", {
    description: "Manage disk partitions and volumes",
    inputSchema: {
        action: z.enum(["list", "create", "delete", "format", "extend", "shrink"]),
        disk: z.number().optional(),
        partition: z.number().optional(),
        size: z.string().optional(),
        format: z.string().optional()
    },
    outputSchema: {
        success: z.boolean(),
        output: z.string().optional(),
        error: z.string().optional()
    }
}, async ({ action, disk, partition, size, format }) => {
    try {
        let command = "";
        switch (action) {
            case "list":
                command = "diskpart /s -";
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
                command = `diskpart /s -`;
        }
        const { stdout } = await execAsync(command);
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
server.registerTool("network_scan", {
    description: "Scan network for devices and open ports",
    inputSchema: {
        target: z.string().optional(),
        ports: z.string().optional(),
        scanType: z.enum(["ping", "port", "arp", "full"]).default("ping")
    },
    outputSchema: {
        success: z.boolean(),
        results: z.array(z.any()).optional(),
        error: z.string().optional()
    }
}, async ({ target, ports, scanType }) => {
    try {
        let command = "";
        let results = [];
        switch (scanType) {
            case "ping":
                command = `ping -n 1 ${target || "127.0.0.1"}`;
                break;
            case "port":
                command = `netstat -an | findstr :${ports || "80"}`;
                break;
            case "arp":
                command = "arp -a";
                break;
            case "full":
                command = `nmap -sn ${target || "192.168.1.0/24"}`;
                break;
        }
        const { stdout } = await execAsync(command);
        results.push({ command, output: stdout });
        return {
            content: [],
            structuredContent: {
                success: true,
                results
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
// Utility: Run a command elevated by generating a PowerShell script and invoking RunAs
async function runElevatedCommand(command, args, workingDirectory, timeoutMs = config.timeout) {
    const tempDir = os.tmpdir();
    const uid = Date.now().toString(36) + Math.random().toString(36).slice(2);
    const stdoutPath = path.join(tempDir, `mcp_elev_${uid}.out.txt`);
    const stderrPath = path.join(tempDir, `mcp_elev_${uid}.err.txt`);
    const exitPath = path.join(tempDir, `mcp_elev_${uid}.code.txt`);
    const scriptPath = path.join(tempDir, `mcp_elev_${uid}.ps1`);
    const cdLine = workingDirectory ? `Set-Location -Path '${workingDirectory.replace(/'/g, "''")}'` : '';
    const psArgs = args.map(a => a.replace(/'/g, "''")).join("' ,' ");
    const argList = args.length > 0 ? `, ${args.map(a => `'${a.replace(/'/g, "''")}'`).join(", ")}` : '';
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
    // Cleanup
    await Promise.all([
        fs.unlink(scriptPath).catch(() => { }),
        fs.unlink(stdoutPath).catch(() => { }),
        fs.unlink(stderrPath).catch(() => { }),
        fs.unlink(exitPath).catch(() => { }),
    ]);
    return { stdout, stderr, exitCode: Number.isFinite(exitCode) ? exitCode : -1 };
}
// Elevated process execution
server.registerTool("proc_run_elevated", {
    description: "Run a command with UAC elevation (will prompt). Captures stdout/stderr via temp files.",
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
        note: z.string().optional()
    }
}, async ({ command, args, cwd, timeout }) => {
    const elevated = await isProcessElevated();
    const workingDir = cwd ? path.resolve(cwd) : process.cwd();
    if (elevated) {
        try {
            const { stdout, stderr } = await execAsync(`${command} ${args.join(' ')}`, { cwd: workingDir, timeout });
            return { content: [], structuredContent: { success: true, stdout: stdout || undefined, stderr: stderr || undefined, exitCode: 0, elevated: true } };
        }
        catch (error) {
            return { content: [], structuredContent: { success: false, stdout: error.stdout || undefined, stderr: error.stderr || undefined, exitCode: error.code || -1, elevated: true } };
        }
    }
    const { stdout, stderr, exitCode } = await runElevatedCommand(command, args, workingDir, timeout);
    const success = exitCode === 0;
    const note = success ? undefined : 'If you did not accept the UAC prompt, the command did not run.';
    return { content: [], structuredContent: { success, stdout: stdout || undefined, stderr: stderr || undefined, exitCode, elevated: false, note } };
});
// Create a Windows Restore Point (requires System Protection enabled)
server.registerTool("create_restore_point", {
    description: "Create a Windows Restore Point (will request elevation).",
    inputSchema: {
        description: z.string().default("MCP Restore Point"),
        restorePointType: z.enum(["APPLICATION_INSTALL", "APPLICATION_UNINSTALL", "DEVICE_DRIVER_INSTALL", "MODIFY_SETTINGS", "CANCELLED_OPERATION"]).default("MODIFY_SETTINGS")
    },
    outputSchema: {
        success: z.boolean(),
        stdout: z.string().optional(),
        stderr: z.string().optional(),
        elevated: z.boolean(),
        error: z.string().optional()
    }
}, async ({ description, restorePointType }) => {
    const elevated = await isProcessElevated();
    const psCommand = `Checkpoint-Computer -Description '${description.replace(/'/g, "''")}' -RestorePointType '${restorePointType}'`;
    if (elevated) {
        try {
            const { stdout, stderr } = await execAsync(`powershell -NoProfile -ExecutionPolicy Bypass -Command "${psCommand}"`, { timeout: 3 * 60 * 1000 });
            return { content: [], structuredContent: { success: true, stdout: stdout || undefined, stderr: stderr || undefined, elevated: true } };
        }
        catch (error) {
            return { content: [], structuredContent: { success: false, stdout: error.stdout || undefined, stderr: error.stderr || undefined, elevated: true, error: error.message } };
        }
    }
    const { stdout, stderr, exitCode } = await runElevatedCommand('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', psCommand], process.cwd(), 3 * 60 * 1000);
    const success = exitCode === 0;
    return { content: [], structuredContent: { success, stdout: stdout || undefined, stderr: stderr || undefined, elevated: false, error: success ? undefined : 'Failed to create restore point (UAC denied, System Protection disabled, or policy restrictions).' } };
});
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
}
main().catch((err) => {
    logger.error("Server error", { error: err instanceof Error ? err.message : String(err), stack: err instanceof Error ? err.stack : undefined });
    process.exit(1);
});
