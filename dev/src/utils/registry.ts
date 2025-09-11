import fs from "fs/promises";
import path from "path";
// Using custom file search instead of fast-glob

const REG_FILES = [
  "server-refactored.ts", "server-refactored.js",
  "dev/src/tools/index.ts", "dev/src/tools/index.js"
];

export async function listVendoredSources() {
  const dirs = await findDirectoriesByPattern("dev/src/tools/external/*");
  return dirs.map(d => path.basename(d));
}

export async function listLocalTools() {
  const files = await findFilesByPattern("dev/src/tools/**/*.ts");
  // Filter out external and node_modules
  const filteredFiles = files.filter(f => 
    !f.includes("/external/") && 
    !f.includes("\\external\\") && 
    !f.includes("/node_modules/") && 
    !f.includes("\\node_modules\\")
  );
  return filteredFiles.map(f => path.basename(f, ".ts")).sort();
}

export async function enableTool(toolName: string) {
  // ensure registered in both registries
  await patchRegistrations([toolName]);
  return { enabled: toolName };
}

export async function disableTool(toolName: string, deprecate = false) {
  const files = await findFilesByPatterns(["server-refactored.*", "dev/src/tools/index.*"]);
  let changed = 0;
  for (const f of files) {
    let text = await safeRead(f);
    const before = text;
    text = text.replace(new RegExp(`\\bregister\\((?:\\s*)${toolName}(?:\\s*)\\)`, "g"), m =>
      deprecate ? `/* DEPRECATED: ${m} */` : `/* DISABLED: ${m} */`
    );
    if (text !== before) { await fs.writeFile(f, text, "utf8"); changed++; }
  }
  return { disabled: toolName, filesChanged: changed };
}

export async function renameTool(oldName: string, newName: string) {
  // adjust file name if exists
  const matches = await findFilesByPattern(`dev/src/tools/**/${oldName}.ts`);
  if (matches.length > 0) {
    const oldFile = matches[0];
    const newFile = path.join(path.dirname(oldFile), `${newName}.ts`);
    await fs.rename(oldFile, newFile);
    // also rewrite export const name inside file
    let code = await fs.readFile(newFile, "utf8");
    code = code
      .replace(new RegExp(`export\\s+const\\s+${oldName}\\s*:\\s*MCPTool`), `export const ${newName}: MCPTool`)
      .replace(new RegExp(`name:\\s*["'\`]${oldName}["'\`]`), `name: "${newName}"`);
    await fs.writeFile(newFile, code, "utf8");
  }
  // update registrations
  const regFiles = await findFilesByPatterns(["server-refactored.*", "dev/src/tools/index.*"]);
  for (const f of regFiles) {
    let t = await fs.readFile(f, "utf8");
    t = t.replace(new RegExp(`\\b${oldName}\\b`, "g"), newName);
    await fs.writeFile(f, t, "utf8");
  }
  return { renamed: { from: oldName, to: newName } };
}

export async function ensureRegisteredParity() {
  // naive parity check: if a tool file exists but not registered, add it.
  const tools = await findFilesByPattern("dev/src/tools/**/*.ts");
  // Filter out external tools
  const filteredTools = tools.filter(f => 
    !f.includes("/external/") && 
    !f.includes("\\external\\")
  );
  const names = filteredTools.map(f => path.basename(f, ".ts"));
  await patchRegistrations(names);
}

export async function patchRegistrations(addToolNames: string[]) {
  const files = await findFilesByPatterns(REG_FILES);
  for (const f of files) {
    let text = await safeRead(f);
    const before = text;

    // 1) ensure imports or references present
    for (const name of addToolNames) {
      if (!new RegExp(`\\b${name}\\b`).test(text)) {
        // try to append to a REGISTER BLOCK
        text = ensureRegisterBlock(text);
        text = text.replace(/(\/\/\s*<TOOLS AUTO-REGISTER START>[\s\S]*?)(\/\/\s*<TOOLS AUTO-REGISTER END>)/,
          (m, a, b) => `${a}register(${name});\n${b}`);
        // also try an import if TS file with obvious path
        const candidate = await guessToolPath(name);
        if (candidate) {
          if (!/from\s+["']\.\/dev\/src\/tools/.test(text) && !new RegExp(`from\\s+["'][^"']*${escapeReg(candidate)}["']`).test(text)) {
            text = `// auto-import ${name}\n${importLine(name, candidate)}\n` + text;
          }
        }
      }
    }

    if (text !== before) await fs.writeFile(f, text, "utf8");
  }
}

function ensureRegisterBlock(text: string) {
  if (!/\/\/\s*<TOOLS AUTO-REGISTER START>/.test(text)) {
    text += `

/** Tool auto-registration block (managed by tool_burglar) */
 // <TOOLS AUTO-REGISTER START>
 // <TOOLS AUTO-REGISTER END>
`;
  }
  return text;
}

async function guessToolPath(name: string) {
  const matches = await findFilesByPattern(`dev/src/tools/**/${name}.ts`);
  if (matches.length === 0) return null;
  let p = matches[0].replace(/^dev\/src\//, "../");
  if (p.startsWith("..") === false) p = "./" + p;
  return p;
}

function importLine(name: string, p: string) {
  return `import { ${name} } from "${p.replace(/\\/g, "/").replace(/\.ts$/, "")}";`;
}

async function safeRead(p: string) {
  try { return await fs.readFile(p, "utf8"); } catch { return ""; }
}

function escapeReg(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
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

async function findFilesByPatterns(patterns: string[]): Promise<string[]> {
  const allFiles: string[] = [];
  for (const pattern of patterns) {
    const files = await findFilesByPattern(pattern);
    allFiles.push(...files);
  }
  return [...new Set(allFiles)]; // Remove duplicates
}

async function findDirectoriesByPattern(pattern: string): Promise<string[]> {
  const dirs: string[] = [];
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
          // Check if directory matches the pattern
          if (matchesPattern(relativeFilePath, pattern)) {
            dirs.push(fullPath);
          }
          await searchDirectory(fullPath, relativeFilePath);
        }
      }
    } catch (error) {
      // Skip directories we can't access
      console.warn(`Cannot access directory: ${currentDir}`);
    }
  };
  
  await searchDirectory(baseDir);
  return dirs;
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
