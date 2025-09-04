import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { createWriteStream } from "node:fs";
import { pipeline } from "node:stream/promises";
import { Transform } from "node:stream";
import * as path from "node:path";
import { ensureInsideRoot } from "../../utils/fileSystem.js";

export function registerDownloadFile(server: McpServer) {
  server.registerTool("download_file", {
    description: "Download a file from URL",
    inputSchema: {
      url: z.string().describe("The URL of the file to download. Must be a valid HTTP/HTTPS URL. Examples: 'https://example.com/file.zip', 'http://downloads.example.org/document.pdf'."),
      outputPath: z.string().optional().describe("Optional custom filename for the downloaded file. Examples: 'myfile.zip', './downloads/document.pdf', 'C:\\Users\\User\\Downloads\\file.txt'. If not specified, uses the original filename from the URL."),
    },
    outputSchema: {
      success: z.boolean().describe("Whether the download was successful"),
      url: z.string().describe("The URL that was downloaded from"),
      outputPath: z.string().describe("The path where the file was saved"),
      size: z.number().describe("Size of the downloaded file in bytes"),
      filename: z.string().describe("Name of the downloaded file"),
      contentType: z.string().optional().describe("Content type of the downloaded file"),
    },
  }, async ({ url, outputPath }) => {
    try {
      // Validate URL
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        return {
          content: [{ type: "text", text: `Error: ${'URL must start with http:// or https://'}` }],
          structuredContent: {
            success: false,
            error: `${'URL must start with http:// or https://'}`
          }
        };
      }

      // Determine output path
      let finalOutputPath: string;
      if (outputPath) {
        const resolvedPath = path.resolve(outputPath);
        finalOutputPath = ensureInsideRoot(resolvedPath);
      } else {
        // Extract filename from URL
        const urlObj = new URL(url);
        const filename = path.basename(urlObj.pathname) || 'downloaded_file';
        finalOutputPath = ensureInsideRoot(path.join(process.cwd(), filename));
      }

      // Ensure directory exists
      const dir = path.dirname(finalOutputPath);
      await import('node:fs/promises').then(fs => fs.mkdir(dir, { recursive: true }));

      // Download the file
      const response = await fetch(url);
      
      if (!response.ok) {
        return {
          content: [{ type: "text", text: `Error: ${`HTTP error! status: ${response.status}`}` }],
          structuredContent: {
            success: false,
            error: `${`HTTP error! status: ${response.status}`}`
          }
        };
      }

      const contentType = response.headers.get('content-type') || 'application/octet-stream';
      const contentLength = response.headers.get('content-length');
      const size = contentLength ? parseInt(contentLength, 10) : 0;

      // Create write stream
      const writeStream = createWriteStream(finalOutputPath);
      
      // Create transform stream to track progress
      let downloadedBytes = 0;
      const progressStream = new Transform({
        transform(chunk, encoding, callback) {
          downloadedBytes += chunk.length;
          callback(null, chunk);
        }
      });

      // Pipe the response to file
      await pipeline(
        response.body as any,
        progressStream,
        writeStream
      );

      // Get final file size
      const finalSize = downloadedBytes || size;

      return {
        content: [{ type: "text", text: `File downloaded successfully: ${path.basename(finalOutputPath)}` }],
        structuredContent: {
          success: true,
          url,
          outputPath: finalOutputPath,
          size: finalSize,
          filename: path.basename(finalOutputPath),
          contentType
        }
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Download failed: ${error instanceof Error ? error.message : 'Unknown error'}` }],
        structuredContent: {
          success: false,
          url,
          outputPath: "",
          size: 0,
          filename: "",
          contentType: "",
          error: error instanceof Error ? error.message : 'Unknown error'
        }
      };
    }
  });
}
