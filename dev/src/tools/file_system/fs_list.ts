import { z } from "zod";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { ALLOWED_ROOTS } from "../../config/environment.js";
import { ensureInsideRoot } from "../../utils/fileSystem.js";

export function registerFsList(server: any) {
  server.registerTool("fs_list", {
    description: "List files/directories under a relative path (non-recursive)",
    inputSchema: { dir: z.string().default(".").describe("The directory path to list files and folders from. Examples: '.', './documents', '/home/user/pictures', 'C:\\Users\\User\\Desktop'. Use '.' for current directory.") },
    outputSchema: { entries: z.array(z.object({ name: z.string(), isDir: z.boolean() })) }
  }, async ({ dir }) => {
    // Try to find the directory in one of the allowed roots
    let base: string;
    try {
      base = ensureInsideRoot(path.resolve(dir));
    } catch {
      // If not an absolute path, try the first allowed root
      base = path.resolve(ALLOWED_ROOTS[0], dir);
      ensureInsideRoot(base); // Verify it's still within allowed roots
    }
    const items = await fs.readdir(base, { withFileTypes: true });
    return { content: [], structuredContent: { entries: items.map(d => ({ name: d.name, isDir: d.isDirectory() })) } };
  });
}
