import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { ensureInsideRoot } from "../../utils/fileSystem.js";

export function registerFsReadText(server: McpServer) {
  server.registerTool("fs_read_text", {
    description: "Advanced text file reader with UTF-8 encoding support, path validation, and comprehensive error handling for secure file access",
    inputSchema: {
      path: z.string().describe("The file path to read from. Can be relative or absolute path. Examples: './config.txt', '/home/user/documents/readme.md', 'C:\\Users\\User\\Desktop\\notes.txt'."),
    },
    outputSchema: {
      content: z.string().describe("The text content of the file"),
      path: z.string().describe("The resolved path that was read"),
      size: z.number().describe("Size of the file in bytes"),
      encoding: z.string().describe("The encoding used to read the file"),
    },
  }, async ({ path: filePath }) => {
    try {
      // Resolve and validate the path
      const resolvedPath = path.resolve(filePath);
      const safePath = ensureInsideRoot(resolvedPath);

      // Read the file
      const content = await fs.readFile(safePath, 'utf-8');
      const stats = await fs.stat(safePath);

      return {
        content: [{ type: "text", text: content }],
        structuredContent: {
          content,
          path: safePath,
          size: stats.size,
          encoding: 'utf-8'
        }
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Failed to read file: ${error instanceof Error ? error.message : 'Unknown error'}` }],
        structuredContent: {
          content: "",
          path: filePath,
          size: 0,
          encoding: 'utf-8',
          error: error instanceof Error ? error.message : 'Unknown error'
        }
      };
    }
  });
}
