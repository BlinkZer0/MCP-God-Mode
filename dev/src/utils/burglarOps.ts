import fs from "fs/promises";
import path from "path";
import crypto from "crypto";
// Using custom file search instead of fast-glob
import { patchRegistrations } from "./registry.js";

type Discovered = { sourceRoot: string; file: string; toolName: string; licenseFile?: string; desc?: string; };

export async function planConflicts(discovered: Discovered[], opts: { prefix?: string } = {}) {
  const items = [];
  const targetBase = "dev/src/tools/external";
  await fs.mkdir(targetBase, { recursive: true });

  for (const d of discovered) {
    const sourceName = path.basename(d.sourceRoot);
    const baseName = (opts.prefix ? `${opts.prefix}${d.toolName}` : d.toolName);
    const targetPath = path.join(targetBase, sourceName, `${baseName}.ts`);
    items.push({
      toolName: d.toolName,
      targetName: baseName,
      sourceRoot: d.sourceRoot,
      sourceFile: d.file,
      targetPath,
      licenseFile: d.licenseFile,
      desc: d.desc
    });
  }

  const summary = {
    count: items.length,
    targets: items.map(i => ({ from: i.toolName, to: i.targetName, path: i.targetPath }))
  };
  return { items, summary };
}

export async function applyWritePlan(plan: any, opts: { dryRun: boolean; force: boolean; autoDeps: boolean }) {
  const writeOps: string[] = [];
  if (!plan?.items) return { summary: { count: 0, targets: [] } };

  for (const it of plan.items) {
    await fs.mkdir(path.dirname(it.targetPath), { recursive: true });
    const code = await fs.readFile(it.sourceFile, "utf8");
    const patched = rewriteExportNameIfNeeded(code, it);
    if (!opts.dryRun) {
      await fs.writeFile(it.targetPath, patched, "utf8");
      if (it.licenseFile && !opts.force) {
        const licTxt = await fs.readFile(it.licenseFile, "utf8");
        await fs.writeFile(it.targetPath + ".LICENSE.txt", licTxt, "utf8");
      }
    }
    writeOps.push(it.targetPath);
  }

  // patch registrations in both servers
  if (!opts.dryRun) {
    const added = plan.items.map((i: any) => i.targetName);
    await patchRegistrations(added);
  }

  return { summary: { count: writeOps.length, targets: writeOps } };
}

export async function writeDocs(plan: any, licenseReport: any) {
  const docDir = "docs/external";
  await fs.mkdir(docDir, { recursive: true });
  const name = "import-" + crypto.randomBytes(6).toString("hex") + ".md";
  const lines: string[] = [];
  lines.push(`# Imported Tools\n`);
  for (const it of plan.items || []) {
    lines.push(`- **${it.targetName}** ← ${it.sourceFile}`);
  }
  lines.push(`\n## Licenses\n`);
  lines.push("```json\n" + JSON.stringify(licenseReport, null, 2) + "\n```");
  await fs.writeFile(path.join(docDir, name), lines.join("\n"), "utf8");
}

export async function buildRollbackPlan(plan: any) {
  const file = ".mcp_rollback/tool_burglar-" + Date.now() + ".json";
  await fs.mkdir(".mcp_rollback", { recursive: true });
  await fs.writeFile(file, JSON.stringify(plan, null, 2), "utf8");
  return { file };
}

export async function moveLocalTool(toolName: string, destDir: string) {
  const matches = await findFilesByPattern(`dev/src/tools/**/${toolName}.ts`);
  if (matches.length === 0) return { moved: 0, error: "Tool not found" };
  const src = matches[0];
  const target = path.join("dev/src/tools", destDir, `${toolName}.ts`);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.rename(src, target);
  return { moved: 1, from: src, to: target };
}

export async function exportLocalTool(toolName: string, exportPath: string) {
  const matches = await findFilesByPattern(`dev/src/tools/**/${toolName}.ts`);
  if (matches.length === 0) return { exported: 0, error: "Tool not found" };
  const src = matches[0];
  const dst = path.isAbsolute(exportPath) ? exportPath :
              path.join(process.cwd(), exportPath.endsWith(".ts") ? exportPath : path.join(exportPath, `${toolName}.ts`));
  await fs.mkdir(path.dirname(dst), { recursive: true });
  await fs.copyFile(src, dst);
  return { exported: 1, from: src, to: dst };
}

function rewriteExportNameIfNeeded(code: string, it: any) {
  // If exported const name differs, rename it (simple regex-based).
  if (new RegExp(`export\\s+const\\s+${it.toolName}\\s*:\\s*MCPTool`).test(code) && it.toolName !== it.targetName) {
    return code
      .replace(new RegExp(`export\\s+const\\s+${it.toolName}\\s*:\\s*MCPTool`), `export const ${it.targetName}: MCPTool`)
      .replace(new RegExp(`register\\((?:\\s*)${it.toolName}(?:\\s*)\\)`), `register(${it.targetName})`)
      .replace(new RegExp(`name:\\s*["'\`]${it.toolName}["'\`]`), `name: "${it.targetName}"`);
  }
  return code;
}

async function findFilesByPattern(pattern: string): Promise<string[]> {
  const files: string[] = [];
  const baseDir = process.cwd();
  
  const searchDirectory = async (currentDir: string, relativePath: string = ""): Promise<void> => {
    try {
      const entries = await fs.readdir(currentDir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        const relativeFilePath = path.join(relativePath, entry.name);
        
        // Skip node_modules
        if (entry.name === "node_modules") continue;
        
        if (entry.isDirectory()) {
          await searchDirectory(fullPath, relativeFilePath);
        } else if (entry.isFile()) {
          // Check if file matches the pattern
          if (matchesPattern(relativeFilePath, pattern)) {
            files.push(fullPath);
          }
        }
      }
    } catch (error) {
      // Skip directories we can't access
      console.warn(`Cannot access directory: ${currentDir}`);
    }
  };
  
  await searchDirectory(baseDir);
  return files;
}

function matchesPattern(filepath: string, pattern: string): boolean {
  // Convert glob pattern to regex
  const regexPattern = pattern
    .replace(/\./g, '\\.')
    .replace(/\*\*/g, '.*')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '.')
    .replace(/\{([^}]+)\}/g, '($1)')
    .replace(/,/g, '|');
  
  const regex = new RegExp(`^${regexPattern}$`, 'i');
  return regex.test(filepath.replace(/\\/g, '/'));
}
