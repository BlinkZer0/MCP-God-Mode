import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { ensureInsideRoot } from "../../utils/fileSystem.js";

export function registerFsWriteText(server: McpServer) {
  server.registerTool("fs_write_text", {
    description: "Write a UTF-8 text file within the sandbox",
    inputSchema: {
      path: z.string().describe("The file path to write to. Can be relative or absolute path. Examples: './output.txt', '/home/user/documents/log.txt', 'C:\\Users\\User\\Desktop\\data.txt'."),
      content: z.string().describe("The text content to write to the file. Can be plain text, JSON, XML, or any text-based format. Examples: 'Hello World', '{\"key\": \"value\"}', '<xml>data</xml>'."),
    },
    outputSchema: {
      path: z.string().describe("The resolved path where the file was written"),
      size: z.number().describe("Size of the written file in bytes"),
      success: z.boolean().describe("Whether the write operation was successful"),
    }
  }, async ({ path: filePath, content }) => {
    try {
      // Resolve and validate the path
      const resolvedPath = path.resolve(filePath);
      const safePath = ensureInsideRoot(resolvedPath);

      // Ensure directory exists
      const dir = path.dirname(safePath);
      await fs.mkdir(dir, { recursive: true });

      // Write the file
      await fs.writeFile(safePath, content, 'utf-8');
      const stats = await fs.stat(safePath);

      return {
        content: [{ type: "text", text: `Successfully wrote file: ${safePath}` }],
        structuredContent: {
          path: safePath,
          size: stats.size,
          success: true
        }
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Failed to write file: ${error instanceof Error ? error.message : 'Unknown error'}` }],
        structuredContent: {
          path: filePath,
          size: 0,
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        }
      };
    }
  });
}
