import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { spawn, exec } from "node:child_process";
import { promisify } from "node:util";
import { ensureInsideRoot } from "../../utils/fileSystem.js";
import { PLATFORM, IS_WINDOWS, IS_LINUX, IS_MACOS, IS_ANDROID, IS_IOS, IS_MOBILE } from "../../config/environment.js";

const execAsync = promisify(exec);

// Enhanced Grep Tool - Advanced Text Search with Cross-Platform Support
// Based on user requests for improved grep functionality
// Features: Contextual display, encoding support, enhanced formatting, performance optimizations

interface GrepMatch {
  file: string;
  lineNumber: number;
  content: string;
  contextBefore?: string[];
  contextAfter?: string[];
  matchStart: number;
  matchEnd: number;
  encoding?: string;
}

interface GrepResult {
  matches: GrepMatch[];
  totalMatches: number;
  filesSearched: number;
  filesWithMatches: number;
  searchTime: number;
  pattern: string;
  options: GrepOptions;
  encoding: string;
  performance: {
    filesPerSecond: number;
    bytesPerSecond: number;
    totalBytes: number;
  };
}

interface GrepOptions {
  caseInsensitive: boolean;
  wholeWord: boolean;
  regex: boolean;
  contextBefore: number;
  contextAfter: number;
  maxFileSize: number;
  encoding: string;
  outputFormat: 'text' | 'json' | 'csv' | 'xml';
  colorOutput: boolean;
  showLineNumbers: boolean;
  showFilename: boolean;
  recursive: boolean;
  includePattern: string[];
  excludePattern: string[];
  maxDepth: number;
  limitResults: number;
  binaryFiles: 'skip' | 'include' | 'text';
  followSymlinks: boolean;
  performanceMode: 'fast' | 'balanced' | 'thorough';
}

// Cross-platform encoding detection
async function detectEncoding(filePath: string): Promise<string> {
  try {
    if (IS_WINDOWS) {
      // Windows: Use PowerShell to detect encoding
      const { stdout } = await execAsync(`powershell -Command "Get-Content '${filePath}' -Encoding Byte -TotalCount 4 | ForEach-Object { [char]$_ }"`);
      const bytes = stdout.trim().split('\n').map(b => parseInt(b));
      return detectEncodingFromBytes(bytes);
    } else if (IS_LINUX || IS_MACOS) {
      // Unix: Use file command
      try {
        const { stdout } = await execAsync(`file -bi "${filePath}"`);
        if (stdout.includes('utf-8')) return 'utf8';
        if (stdout.includes('utf-16')) return 'utf16le';
        if (stdout.includes('iso-8859')) return 'latin1';
        if (stdout.includes('windows-1252')) return 'cp1252';
      } catch {
        // Fallback to BOM detection
        const buffer = await fs.readFile(filePath, { encoding: null });
        return detectEncodingFromBytes(Array.from(buffer.slice(0, 4)));
      }
    } else if (IS_ANDROID || IS_IOS) {
      // Mobile: Use Node.js built-in detection
      const buffer = await fs.readFile(filePath, { encoding: null });
      return detectEncodingFromBytes(Array.from(buffer.slice(0, 4)));
    }
  } catch (error) {
    console.warn(`Could not detect encoding for ${filePath}:`, error);
  }
  return 'utf8'; // Default fallback
}

function detectEncodingFromBytes(bytes: number[]): string {
  // BOM detection
  if (bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) {
    return 'utf8';
  }
  if (bytes.length >= 2 && bytes[0] === 0xFF && bytes[1] === 0xFE) {
    return 'utf16le';
  }
  if (bytes.length >= 2 && bytes[0] === 0xFE && bytes[1] === 0xFF) {
    return 'utf16be';
  }
  
  // Heuristic detection
  let utf8Score = 0;
  let latin1Score = 0;
  
  for (let i = 0; i < Math.min(bytes.length, 1000); i++) {
    const byte = bytes[i];
    if (byte === 0) {
      // Null bytes suggest binary or UTF-16
      return 'binary';
    }
    if (byte < 0x80) {
      utf8Score++;
      latin1Score++;
    } else if (byte < 0xC0) {
      latin1Score++;
    } else if (byte < 0xE0) {
      utf8Score += 2;
    } else if (byte < 0xF0) {
      utf8Score += 3;
    } else {
      utf8Score += 4;
    }
  }
  
  return utf8Score > latin1Score ? 'utf8' : 'latin1';
}

// Cross-platform file reading with encoding support
async function readFileWithEncoding(filePath: string, encoding: string): Promise<string> {
  try {
    if (encoding === 'auto') {
      encoding = await detectEncoding(filePath);
    }
    
    // Handle different encodings
    switch (encoding.toLowerCase()) {
      case 'utf8':
      case 'utf-8':
        return await fs.readFile(filePath, 'utf8');
      case 'utf16le':
      case 'utf-16le':
        const buffer16 = await fs.readFile(filePath, { encoding: null });
        return buffer16.toString('utf16le');
      case 'latin1':
      case 'iso-8859-1':
        return await fs.readFile(filePath, 'latin1');
      case 'cp1252':
      case 'windows-1252':
        // Node.js doesn't support cp1252 natively, use latin1 as fallback
        return await fs.readFile(filePath, 'latin1');
      case 'binary':
        // Skip binary files
        throw new Error('Binary file detected');
      default:
        return await fs.readFile(filePath, 'utf8');
    }
  } catch (error) {
    throw new Error(`Failed to read file ${filePath} with encoding ${encoding}: ${error}`);
  }
}

// Advanced pattern matching with regex support
function createRegexPattern(pattern: string, options: GrepOptions): RegExp {
  let regexPattern = pattern;
  
  if (!options.regex) {
    // Escape special regex characters for literal search
    regexPattern = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  
  if (options.wholeWord) {
    regexPattern = `\\b${regexPattern}\\b`;
  }
  
  const flags = options.caseInsensitive ? 'gi' : 'g';
  return new RegExp(regexPattern, flags);
}

// Cross-platform file traversal with performance optimizations
async function findFiles(
  searchPath: string, 
  options: GrepOptions, 
  startTime: number
): Promise<string[]> {
  const files: string[] = [];
  const maxSearchTime = 30000; // 30 seconds max search time
  
  async function traverseDirectory(dirPath: string, depth: number = 0): Promise<void> {
    // Performance check
    if (Date.now() - startTime > maxSearchTime) {
      throw new Error('Search timeout - too many files to search');
    }
    
    if (options.maxDepth > 0 && depth > options.maxDepth) {
      return;
    }
    
    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        
        // Skip hidden files and directories (except when explicitly included)
        if (entry.name.startsWith('.') && !options.includePattern.some(p => p.includes('.*'))) {
          continue;
        }
        
        // Check exclude patterns
        if (options.excludePattern.some(pattern => {
          const regex = new RegExp(pattern.replace(/\*/g, '.*'));
          return regex.test(entry.name);
        })) {
          continue;
        }
        
        if (entry.isDirectory()) {
          if (options.recursive) {
            await traverseDirectory(fullPath, depth + 1);
          }
        } else if (entry.isFile()) {
          // Check include patterns
          if (options.includePattern.length > 0) {
            const matchesInclude = options.includePattern.some(pattern => {
              const regex = new RegExp(pattern.replace(/\*/g, '.*'));
              return regex.test(entry.name);
            });
            if (!matchesInclude) continue;
          }
          
          // Check file size
          try {
            const stats = await fs.stat(fullPath);
            if (stats.size > options.maxFileSize) {
              continue;
            }
          } catch {
            continue; // Skip files we can't stat
          }
          
          files.push(fullPath);
        }
      }
    } catch (error) {
      // Skip directories we can't access
      console.warn(`Cannot access directory: ${dirPath}`);
    }
  }
  
  await traverseDirectory(searchPath);
  return files;
}

// Main grep search function
async function performGrepSearch(
  pattern: string,
  searchPath: string,
  options: GrepOptions
): Promise<GrepResult> {
  const startTime = Date.now();
  const regex = createRegexPattern(pattern, options);
  const matches: GrepMatch[] = [];
  let totalBytes = 0;
  
  try {
    // Find files to search
    const files = await findFiles(searchPath, options, startTime);
    const filesWithMatches = new Set<string>();
    
    // Search each file
    for (const file of files) {
      try {
        const content = await readFileWithEncoding(file, options.encoding);
        totalBytes += Buffer.byteLength(content, 'utf8');
        
        const lines = content.split('\n');
        let fileMatches = 0;
        
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const lineMatches = Array.from(line.matchAll(regex));
          
          for (const match of lineMatches) {
            if (options.limitResults > 0 && matches.length >= options.limitResults) {
              break;
            }
            
            const contextBefore = options.contextBefore > 0 
              ? lines.slice(Math.max(0, i - options.contextBefore), i)
              : undefined;
            
            const contextAfter = options.contextAfter > 0
              ? lines.slice(i + 1, Math.min(lines.length, i + 1 + options.contextAfter))
              : undefined;
            
            matches.push({
              file,
              lineNumber: i + 1,
              content: line,
              contextBefore,
              contextAfter,
              matchStart: match.index || 0,
              matchEnd: (match.index || 0) + match[0].length,
              encoding: options.encoding
            });
            
            fileMatches++;
            filesWithMatches.add(file);
          }
          
          if (options.limitResults > 0 && matches.length >= options.limitResults) {
            break;
          }
        }
      } catch (error) {
        // Skip files that can't be read
        console.warn(`Cannot read file ${file}:`, error);
      }
    }
    
    const endTime = Date.now();
    const searchTime = endTime - startTime;
    
    return {
      matches,
      totalMatches: matches.length,
      filesSearched: files.length,
      filesWithMatches: filesWithMatches.size,
      searchTime,
      pattern,
      options,
      encoding: options.encoding,
      performance: {
        filesPerSecond: files.length / (searchTime / 1000),
        bytesPerSecond: totalBytes / (searchTime / 1000),
        totalBytes
      }
    };
  } catch (error) {
    throw new Error(`Grep search failed: ${error}`);
  }
}

// Format output based on requested format
function formatOutput(result: GrepResult, options: GrepOptions): string {
  switch (options.outputFormat) {
    case 'json':
      return JSON.stringify(result, null, 2);
    
    case 'csv':
      const csvLines = ['File,Line,Content,Match Start,Match End'];
      for (const match of result.matches) {
        const escapedContent = `"${match.content.replace(/"/g, '""')}"`;
        csvLines.push(`${match.file},${match.lineNumber},${escapedContent},${match.matchStart},${match.matchEnd}`);
      }
      return csvLines.join('\n');
    
    case 'xml':
      let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<grep-results>\n';
      xml += `  <search-info>\n`;
      xml += `    <pattern>${result.pattern}</pattern>\n`;
      xml += `    <total-matches>${result.totalMatches}</total-matches>\n`;
      xml += `    <files-searched>${result.filesSearched}</files-searched>\n`;
      xml += `    <search-time>${result.searchTime}ms</search-time>\n`;
      xml += `  </search-info>\n`;
      
      for (const match of result.matches) {
        xml += `  <match>\n`;
        xml += `    <file>${match.file}</file>\n`;
        xml += `    <line>${match.lineNumber}</line>\n`;
        xml += `    <content><![CDATA[${match.content}]]></content>\n`;
        xml += `    <match-start>${match.matchStart}</match-start>\n`;
        xml += `    <match-end>${match.matchEnd}</match-end>\n`;
        xml += `  </match>\n`;
      }
      xml += '</grep-results>';
      return xml;
    
    case 'text':
    default:
      let output = '';
      
      // Header
      output += `Advanced Grep Results\n`;
      output += `===================\n`;
      output += `Pattern: ${result.pattern}\n`;
      output += `Total Matches: ${result.totalMatches}\n`;
      output += `Files Searched: ${result.filesSearched}\n`;
      output += `Files with Matches: ${result.filesWithMatches}\n`;
      output += `Search Time: ${result.searchTime}ms\n`;
      output += `Performance: ${result.performance.filesPerSecond.toFixed(2)} files/sec, ${(result.performance.bytesPerSecond / 1024 / 1024).toFixed(2)} MB/sec\n`;
      output += `Encoding: ${result.encoding}\n\n`;
      
      // Matches
      let currentFile = '';
      for (const match of result.matches) {
        if (options.showFilename && match.file !== currentFile) {
          output += `\n${match.file}:\n`;
          currentFile = match.file;
        }
        
        // Context before
        if (match.contextBefore && match.contextBefore.length > 0) {
          for (let i = 0; i < match.contextBefore.length; i++) {
            const contextLine = match.contextBefore[i];
            const contextLineNum = match.lineNumber - match.contextBefore.length + i;
            output += `${options.showLineNumbers ? `${contextLineNum}:` : ''}${options.colorOutput ? '\x1b[90m' : ''}${contextLine}${options.colorOutput ? '\x1b[0m' : ''}\n`;
          }
        }
        
        // Main match line
        let lineContent = match.content;
        if (options.colorOutput) {
          // Highlight the match
          const beforeMatch = lineContent.substring(0, match.matchStart);
          const matchText = lineContent.substring(match.matchStart, match.matchEnd);
          const afterMatch = lineContent.substring(match.matchEnd);
          lineContent = `${beforeMatch}\x1b[1;31m${matchText}\x1b[0m${afterMatch}`;
        }
        
        output += `${options.showLineNumbers ? `${match.lineNumber}:` : ''}${lineContent}\n`;
        
        // Context after
        if (match.contextAfter && match.contextAfter.length > 0) {
          for (let i = 0; i < match.contextAfter.length; i++) {
            const contextLine = match.contextAfter[i];
            const contextLineNum = match.lineNumber + 1 + i;
            output += `${options.showLineNumbers ? `${contextLineNum}:` : ''}${options.colorOutput ? '\x1b[90m' : ''}${contextLine}${options.colorOutput ? '\x1b[0m' : ''}\n`;
          }
        }
        
        if (match.contextBefore || match.contextAfter) {
          output += '---\n';
        }
      }
      
      return output;
  }
}

export function registerAdvancedGrep(server: McpServer) {
  server.registerTool("advanced_grep", {
    description: "🔍 **Advanced Grep Tool** - Enhanced text search with cross-platform support, contextual display, encoding detection, and performance optimizations. Based on user requests for improved grep functionality.",
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
      const {
        pattern,
        path: searchPath,
        caseInsensitive = false,
        wholeWord = false,
        regex = false,
        contextBefore = 0,
        contextAfter = 0,
        maxFileSize = 10485760, // 10MB
        encoding = "auto",
        outputFormat = "text",
        colorOutput = true,
        showLineNumbers = true,
        showFilename = true,
        recursive = true,
        includePattern = [],
        excludePattern = [],
        maxDepth = 0,
        limitResults = 0,
        binaryFiles = "skip",
        followSymlinks = false,
        performanceMode = "balanced"
      } = params;

      // Validate and sanitize inputs
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
      } catch (error) {
        throw new Error(`Path does not exist or is not accessible: ${safePath}`);
      }

      // Build options object
      const options: GrepOptions = {
        caseInsensitive,
        wholeWord,
        regex,
        contextBefore: Math.min(Math.max(contextBefore, 0), 10),
        contextAfter: Math.min(Math.max(contextAfter, 0), 10),
        maxFileSize,
        encoding,
        outputFormat,
        colorOutput,
        showLineNumbers,
        showFilename,
        recursive,
        includePattern,
        excludePattern,
        maxDepth,
        limitResults,
        binaryFiles,
        followSymlinks,
        performanceMode
      };

      // Perform the search
      const result = await performGrepSearch(pattern, safePath, options);
      
      // Format output
      const formattedOutput = formatOutput(result, options);

      return {
        content: [{ type: "text", text: formattedOutput }],
        structuredContent: {
          success: true,
          result,
          summary: {
            pattern: result.pattern,
            totalMatches: result.totalMatches,
            filesSearched: result.filesSearched,
            filesWithMatches: result.filesWithMatches,
            searchTime: result.searchTime,
            performance: result.performance
          }
        }
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Advanced grep failed: ${error instanceof Error ? error.message : 'Unknown error'}` }],
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
