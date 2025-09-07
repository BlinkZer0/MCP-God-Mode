import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { ensureInsideRoot } from "../../utils/fileSystem.js";

export function registerFsSearch(server: McpServer) {
  server.registerTool("fs_search", {
    description: "Search for files by name pattern",
    inputSchema: {
      pattern: z.string().describe("The file name pattern to search for. Supports glob patterns and partial matches. Examples: '*.txt', 'config*', '*.js', 'README*', '*.{json,yaml}'."),
      dir: z.string().optional().default(".").describe("The directory to search in. Examples: '.', './src', '/home/user/documents', 'C:\\Users\\User\\Projects'. Use '.' for current directory."),
    },
    outputSchema: {
      files: z.array(z.string()).describe("Array of found file paths matching the pattern"),
      count: z.number().describe("Number of files found"),
      pattern: z.string().describe("The search pattern used"),
      directory: z.string().describe("The directory that was searched"),
    }
  }, async ({ pattern, dir: searchDir }) => {
    try {
      const resolvedDir = path.resolve(searchDir);
      const safeDir = ensureInsideRoot(resolvedDir);

      // Simple pattern matching implementation
      const files: string[] = [];
      
      // Use arrow function expression instead of function declaration
      const searchDirectory = async (currentDir: string): Promise<void> => {
        try {
          const entries = await fs.readdir(currentDir, { withFileTypes: true });
          
          for (const entry of entries) {
            const fullPath = path.join(currentDir, entry.name);
            
            if (entry.isDirectory()) {
              // Recursively search subdirectories
              await searchDirectory(fullPath);
            } else if (entry.isFile()) {
              // Check if file matches pattern
              if (matchesPattern(entry.name, pattern)) {
                files.push(fullPath);
              }
            }
          }
        } catch (error) {
          // Skip directories we can't access
          console.warn(`Cannot access directory: ${currentDir}`);
        }
      };

      await searchDirectory(safeDir);

      return {
        content: [{ type: "text", text: `Found ${files.length} files matching pattern '${pattern}'` }],
        structuredContent: {
          files,
          count: files.length,
          pattern,
          directory: safeDir
        }
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Failed to search files: ${error instanceof Error ? (error as Error).message : 'Unknown error'}` }],
        structuredContent: {
          files: [],
          count: 0,
          pattern,
          directory: searchDir,
          error: error instanceof Error ? (error as Error).message : 'Unknown error'
        }
      };
    }
  });
}

// Simple pattern matching function
function matchesPattern(filename: string, pattern: string): boolean {
  // Convert glob pattern to regex
  const regexPattern = pattern
    .replace(/\./g, '\\.')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.')
    .replace(/\{([^}]+)\}/g, '($1)')
    .replace(/,/g, '|');
  
  const regex = new RegExp(`^${regexPattern}$`, 'i');
  return regex.test(filename);
}
