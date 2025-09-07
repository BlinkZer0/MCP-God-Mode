#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import * as os from "node:os";
import * as fs from "node:fs/promises";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import * as crypto from "node:crypto";
// Import utility modules
import { PLATFORM, IS_WINDOWS, PROC_ALLOWLIST, MAX_BYTES } from "./config/environment.js";
import { ALLOWED_ROOTS_ARRAY } from "./utils/platform.js";
import { sanitizeCommand, isDangerousCommand, shouldPerformSecurityChecks } from "./utils/security.js";
import { ensureInsideRoot, limitString } from "./utils/fileSystem.js";
import { logger, logServerStart } from "./utils/logger.js";
import { registerElevatedPermissionsManager } from "./tools/system/elevated_permissions_manager.js";
// Global variables for enhanced features
let browserInstance = null;
let webSocketServer = null;
let expressServer = null;
let cronJobs = new Map();
let fileWatchers = new Map();
let apiCache = new Map();
let webhookEndpoints = new Map();
const execAsync = promisify(exec);
// Log server startup
logServerStart(PLATFORM);
// ===========================================
// CORE TOOLS
// ===========================================
const server = new McpServer({ name: "MCP God Mode", version: "1.6.0" });
// Register elevated permissions manager (parity with modular server)
registerElevatedPermissionsManager(server);
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
    inputSchema: { dir: z.string().default(".").describe("The directory path to list files and folders from. Examples: '.', './documents', '/home/user/pictures', 'C:\\Users\\User\\Desktop'. Use '.' for current directory.") },
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
        ]).describe("The file operation to perform."),
        source: z.string().optional().describe("The source file or directory path for operations like copy, move, delete, or get_info. Can be relative or absolute path. Examples: './file.txt', '/home/user/documents', 'C:\\Users\\User\\Desktop'."),
        destination: z.string().optional().describe("The destination path for operations like copy, move, create_dir, or create_file. Can be relative or absolute path. Examples: './backup/file.txt', '/home/user/backups', 'C:\\Users\\User\\Backups'."),
        content: z.string().optional().describe("The content to write when creating a new file. Can be plain text, JSON, XML, or any text-based format. Examples: 'Hello World', '{\"key\": \"value\"}', '<xml>data</xml>'."),
        recursive: z.boolean().default(false).describe("Whether to perform the operation recursively on directories and their contents. Required for copying, moving, or deleting directories. Set to true for directory operations, false for single file operations."),
        overwrite: z.boolean().default(false).describe("Whether to overwrite existing files at the destination. Set to true to replace existing files, false to fail if destination already exists. Useful for backup operations or when you want to update files."),
        permissions: z.string().optional().describe("Unix-style file permissions in octal format (e.g., '755', '644') or symbolic format (e.g., 'rwxr-xr-x', 'u+rw'). Examples: '755' for executable directories, '644' for readable files, '600' for private files."),
        owner: z.string().optional().describe("The username to set as the owner of the file or directory. Examples: 'john', 'root', 'www-data'. Only works on Unix-like systems with appropriate permissions."),
        group: z.string().optional().describe("The group name to set for the file or directory. Examples: 'users', 'admin', 'www-data'. Only works on Unix-like systems with appropriate permissions."),
        pattern: z.string().optional().describe("File pattern for search operations. Supports glob patterns like '*.txt', '**/*.log', 'file*'. Examples: '*.py' for Python files, '**/*.json' for JSON files in subdirectories, 'backup*' for files starting with 'backup'."),
        search_text: z.string().optional().describe("Text content to search for within files. Used with 'find_by_content' action to locate files containing specific text. Examples: 'password', 'API_KEY', 'TODO', 'FIXME'."),
        compression_type: z.enum(["zip", "tar", "gzip", "bzip2"]).default("zip").describe("The compression format to use. ZIP is most universal, TAR preserves Unix permissions, GZIP is fast compression, BZIP2 is high compression. Choose based on your needs: ZIP for Windows compatibility, TAR for Unix systems, GZIP for speed, BZIP2 for space savings.")
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
        let result;
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
                    }
                    else {
                        throw new Error("Cannot copy directory without recursive flag");
                    }
                }
                else {
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
                    }
                    else {
                        throw new Error("Cannot delete directory without recursive flag");
                    }
                }
                else {
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
                }
                else {
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
                for (const [id, watcher] of Array.from(fileWatchers.entries())) {
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
                }
                else {
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
    }
    catch (error) {
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
        command: z.string().describe("The command to execute. Examples: 'ls', 'dir', 'cat', 'echo', 'python', 'node', 'git', 'docker'. Can be any executable available in your system PATH or full path to an executable."),
        args: z.array(z.string()).default([]).describe("Array of command-line arguments to pass to the command. Examples: ['-la'] for 'ls -la', ['--version'] for version info, ['filename.txt'] for file operations. Leave empty array for commands with no arguments."),
        cwd: z.string().optional().describe("The working directory where the command will be executed. Examples: './project', '/home/user/documents', 'C:\\Users\\User\\Desktop'. Leave empty to use the current working directory.")
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
// ELEVATED PROCESS EXECUTION TOOLS
// ===========================================
server.registerTool("proc_run_elevated", {
    description: "Run a process with elevated privileges (admin/root/sudo) across all platforms",
    inputSchema: {
        command: z.string().describe("The command to execute with elevated privileges. Examples: 'netstat', 'systemctl', 'sc', 'launchctl'. Commands that require admin/root access."),
        args: z.array(z.string()).default([]).describe("Array of command-line arguments to pass to the command. Examples: ['-tuln'] for 'netstat -tuln', ['status', 'ssh'] for 'systemctl status ssh'."),
        cwd: z.string().optional().describe("The working directory where the command will be executed. Examples: './project', '/home/user/documents', 'C:\\Users\\User\\Desktop'. Leave empty to use the current working directory."),
        interactive: z.boolean().default(false).describe("Whether to use interactive elevation prompt. Set to true for commands that require user input during elevation.")
    },
    outputSchema: {
        success: z.boolean(),
        stdout: z.string().optional(),
        stderr: z.string().optional(),
        exitCode: z.number().optional(),
        elevated: z.boolean().optional(),
        elevationMethod: z.string().optional()
    }
}, async ({ command, args, cwd, interactive }) => {
    // Import elevated permissions utility
    const { executeElevated, executeInteractiveElevated, requiresElevation, canElevateCommand, getElevationMethod } = await import("./utils/elevated-permissions.js");
    // Check if command can be elevated safely
    if (!canElevateCommand(command)) {
        throw new Error(`Command cannot be elevated for security reasons: ${command}`);
    }
    // Check if this command actually needs elevation
    const needsElevation = requiresElevation("proc_run_elevated") ||
        command.includes("systemctl") ||
        command.includes("sc ") ||
        command.includes("wmic ") ||
        command.includes("net ") ||
        command.includes("launchctl");
    if (!needsElevation) {
        // Command doesn't need elevation, run normally
        const { command: sanitizedCommand, args: sanitizedArgs } = sanitizeCommand(command, args);
        const { stdout, stderr } = await execAsync(`${sanitizedCommand} ${sanitizedArgs.join(" ")}`, { cwd: cwd || process.cwd() });
        return {
            content: [],
            structuredContent: {
                success: true,
                stdout: stdout || undefined,
                stderr: stderr || undefined,
                exitCode: 0,
                elevated: false,
                elevationMethod: "Not required"
            }
        };
    }
    // Execute with elevation
    try {
        const workingDir = cwd ? ensureInsideRoot(path.resolve(cwd)) : process.cwd();
        const { command: sanitizedCommand, args: sanitizedArgs } = sanitizeCommand(command, args);
        let result;
        if (interactive) {
            result = await executeInteractiveElevated(sanitizedCommand, sanitizedArgs, workingDir);
        }
        else {
            result = await executeElevated(sanitizedCommand, sanitizedArgs, workingDir);
        }
        return {
            content: [],
            structuredContent: {
                success: result.success,
                stdout: result.stdout,
                stderr: result.stderr,
                exitCode: result.exitCode,
                elevated: true,
                elevationMethod: getElevationMethod()
            }
        };
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return {
            content: [],
            structuredContent: {
                success: false,
                stdout: undefined,
                stderr: undefined,
                exitCode: -1,
                elevated: false,
                elevationMethod: getElevationMethod(),
                error: errorMessage
            }
        };
    }
});
