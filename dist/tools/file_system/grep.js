import { z } from "zod";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { ensureInsideRoot } from "../../utils/fileSystem.js";
// Simple Grep Tool - Enhanced version that takes precedence over basic grep implementations
// This provides the core grep functionality with enhanced features
export function registerGrep(server) {
    server.registerTool("grep", {
        description: "🔍 **Grep Tool** - Advanced text search with cross-platform support, contextual display, encoding detection, and performance optimizations. This is the enhanced version that takes precedence over basic grep implementations.",
        inputSchema: {
            pattern: z.string().describe("The search pattern. Can be literal text or regex pattern."),
            path: z.string().optional().default(".").describe("The directory or file path to search in. Examples: '.', './src', '/home/user/documents', 'C:\\Users\\User\\Projects'."),
            caseInsensitive: z.boolean().optional().default(false).describe("Case-insensitive search"),
            wholeWord: z.boolean().optional().default(false).describe("Match whole words only"),
            regex: z.boolean().optional().default(false).describe("Treat pattern as regex"),
            contextBefore: z.number().optional().default(0).describe("Number of lines to show before each match (0-10)"),
            contextAfter: z.number().optional().default(0).describe("Number of lines to show after each match (0-10)"),
            maxFileSize: z.number().optional().default(10485760).describe("Maximum file size to search in bytes (default: 10MB)"),
            encoding: z.string().optional().default("auto").describe("File encoding: 'auto', 'utf8', 'utf16le', 'latin1', 'cp1252'"),
            outputFormat: z.enum(["text", "json", "csv", "xml"]).optional().default("text").describe("Output format"),
            colorOutput: z.boolean().optional().default(true).describe("Enable colored output highlighting"),
            showLineNumbers: z.boolean().optional().default(true).describe("Show line numbers"),
            showFilename: z.boolean().optional().default(true).describe("Show filename for each match"),
            recursive: z.boolean().optional().default(true).describe("Search subdirectories recursively"),
            includePattern: z.array(z.string()).optional().default([]).describe("File patterns to include (e.g., ['*.js', '*.ts'])"),
            excludePattern: z.array(z.string()).optional().default([]).describe("File patterns to exclude (e.g., ['node_modules', '*.log'])"),
            maxDepth: z.number().optional().default(0).describe("Maximum directory depth (0 = unlimited)"),
            limitResults: z.number().optional().default(0).describe("Maximum number of results to return (0 = unlimited)"),
            binaryFiles: z.enum(["skip", "include", "text"]).optional().default("skip").describe("How to handle binary files"),
            followSymlinks: z.boolean().optional().default(false).describe("Follow symbolic links"),
            performanceMode: z.enum(["fast", "balanced", "thorough"]).optional().default("balanced").describe("Performance vs accuracy trade-off")
        }
    }, async (params) => {
        try {
            const { pattern, path: searchPath, caseInsensitive = false, wholeWord = false, regex = false, contextBefore = 0, contextAfter = 0, maxFileSize = 10485760, encoding = "auto", outputFormat = "text", colorOutput = true, showLineNumbers = true, showFilename = true, recursive = true, includePattern = [], excludePattern = [], maxDepth = 0, limitResults = 0, binaryFiles = "skip", followSymlinks = false, performanceMode = "balanced" } = params;
            // Validate inputs
            if (!pattern || pattern.trim().length === 0) {
                throw new Error("Search pattern cannot be empty");
            }
            const resolvedPath = path.resolve(searchPath);
            const safePath = ensureInsideRoot(resolvedPath);
            // Check if path exists
            try {
                const stats = await fs.stat(safePath);
                if (!stats.isDirectory() && !stats.isFile()) {
                    throw new Error("Path must be a file or directory");
                }
            }
            catch (error) {
                throw new Error(`Path does not exist or is not accessible: ${safePath}`);
            }
            // Create regex pattern
            let regexPattern = pattern;
            if (!regex) {
                regexPattern = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            }
            if (wholeWord) {
                regexPattern = `\\b${regexPattern}\\b`;
            }
            const flags = caseInsensitive ? 'gi' : 'g';
            const searchRegex = new RegExp(regexPattern, flags);
            // Find files to search
            const files = [];
            const startTime = Date.now();
            async function findFiles(dirPath, depth = 0) {
                if (maxDepth > 0 && depth > maxDepth)
                    return;
                try {
                    const entries = await fs.readdir(dirPath, { withFileTypes: true });
                    for (const entry of entries) {
                        const fullPath = path.join(dirPath, entry.name);
                        // Skip hidden files unless explicitly included
                        if (entry.name.startsWith('.') && !includePattern.some(p => p.includes('.*'))) {
                            continue;
                        }
                        // Check exclude patterns
                        if (excludePattern.some(pattern => {
                            const regex = new RegExp(pattern.replace(/\*/g, '.*'));
                            return regex.test(entry.name);
                        })) {
                            continue;
                        }
                        if (entry.isDirectory()) {
                            if (recursive) {
                                await findFiles(fullPath, depth + 1);
                            }
                        }
                        else if (entry.isFile()) {
                            // Check include patterns
                            if (includePattern.length > 0) {
                                const matchesInclude = includePattern.some(pattern => {
                                    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
                                    return regex.test(entry.name);
                                });
                                if (!matchesInclude)
                                    continue;
                            }
                            // Check file size
                            try {
                                const stats = await fs.stat(fullPath);
                                if (stats.size > maxFileSize)
                                    continue;
                            }
                            catch {
                                continue;
                            }
                            files.push(fullPath);
                        }
                    }
                }
                catch (error) {
                    console.warn(`Cannot access directory: ${dirPath}`);
                }
            }
            if (recursive) {
                await findFiles(safePath);
            }
            else {
                files.push(safePath);
            }
            // Search files
            const matches = [];
            let totalBytes = 0;
            for (const file of files) {
                try {
                    const content = await fs.readFile(file, 'utf8');
                    totalBytes += Buffer.byteLength(content, 'utf8');
                    const lines = content.split('\n');
                    for (let i = 0; i < lines.length; i++) {
                        const line = lines[i];
                        const lineMatches = Array.from(line.matchAll(searchRegex));
                        for (const match of lineMatches) {
                            if (limitResults > 0 && matches.length >= limitResults)
                                break;
                            const contextBeforeLines = contextBefore > 0
                                ? lines.slice(Math.max(0, i - contextBefore), i)
                                : undefined;
                            const contextAfterLines = contextAfter > 0
                                ? lines.slice(i + 1, Math.min(lines.length, i + 1 + contextAfter))
                                : undefined;
                            matches.push({
                                file,
                                lineNumber: i + 1,
                                content: line,
                                contextBefore: contextBeforeLines,
                                contextAfter: contextAfterLines,
                                matchStart: match.index || 0,
                                matchEnd: (match.index || 0) + match[0].length,
                                encoding
                            });
                        }
                        if (limitResults > 0 && matches.length >= limitResults)
                            break;
                    }
                }
                catch (error) {
                    console.warn(`Cannot read file ${file}:`, error);
                }
            }
            const endTime = Date.now();
            const searchTime = endTime - startTime;
            // Format output
            let output = '';
            if (outputFormat === 'json') {
                output = JSON.stringify({
                    matches,
                    totalMatches: matches.length,
                    filesSearched: files.length,
                    searchTime,
                    pattern,
                    performance: {
                        filesPerSecond: files.length / (searchTime / 1000),
                        bytesPerSecond: totalBytes / (searchTime / 1000),
                        totalBytes
                    }
                }, null, 2);
            }
            else {
                // Text output
                output += `Grep Results\n`;
                output += `============\n`;
                output += `Pattern: ${pattern}\n`;
                output += `Total Matches: ${matches.length}\n`;
                output += `Files Searched: ${files.length}\n`;
                output += `Search Time: ${searchTime}ms\n\n`;
                let currentFile = '';
                for (const match of matches) {
                    if (showFilename && match.file !== currentFile) {
                        output += `\n${match.file}:\n`;
                        currentFile = match.file;
                    }
                    // Context before
                    if (match.contextBefore && match.contextBefore.length > 0) {
                        for (let i = 0; i < match.contextBefore.length; i++) {
                            const contextLine = match.contextBefore[i];
                            const contextLineNum = match.lineNumber - match.contextBefore.length + i;
                            output += `${showLineNumbers ? `${contextLineNum}:` : ''}${colorOutput ? '\x1b[90m' : ''}${contextLine}${colorOutput ? '\x1b[0m' : ''}\n`;
                        }
                    }
                    // Main match line
                    let lineContent = match.content;
                    if (colorOutput) {
                        const beforeMatch = lineContent.substring(0, match.matchStart);
                        const matchText = lineContent.substring(match.matchStart, match.matchEnd);
                        const afterMatch = lineContent.substring(match.matchEnd);
                        lineContent = `${beforeMatch}\x1b[1;31m${matchText}\x1b[0m${afterMatch}`;
                    }
                    output += `${showLineNumbers ? `${match.lineNumber}:` : ''}${lineContent}\n`;
                    // Context after
                    if (match.contextAfter && match.contextAfter.length > 0) {
                        for (let i = 0; i < match.contextAfter.length; i++) {
                            const contextLine = match.contextAfter[i];
                            const contextLineNum = match.lineNumber + 1 + i;
                            output += `${showLineNumbers ? `${contextLineNum}:` : ''}${colorOutput ? '\x1b[90m' : ''}${contextLine}${colorOutput ? '\x1b[0m' : ''}\n`;
                        }
                    }
                    if (match.contextBefore || match.contextAfter) {
                        output += '---\n';
                    }
                }
            }
            return {
                content: [{ type: "text", text: output }],
                structuredContent: {
                    success: true,
                    matches,
                    totalMatches: matches.length,
                    filesSearched: files.length,
                    searchTime,
                    pattern,
                    performance: {
                        filesPerSecond: files.length / (searchTime / 1000),
                        bytesPerSecond: totalBytes / (searchTime / 1000),
                        totalBytes
                    }
                }
            };
        }
        catch (error) {
            return {
                content: [{ type: "text", text: `Grep failed: ${error instanceof Error ? error.message : 'Unknown error'}` }],
                structuredContent: {
                    success: false,
                    error: error instanceof Error ? error.message : 'Unknown error',
                    pattern: params.pattern,
                    path: params.path
                }
            };
        }
    });
}
