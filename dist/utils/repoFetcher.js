import fs from "fs/promises";
import path from "path";
import os from "os";
import { exec as _exec } from "child_process";
import { promisify } from "util";
// Using custom pattern matching instead of fast-glob
const exec = promisify(_exec);
export async function fetchSourceRepos(sources) {
    if (!sources || sources.length === 0)
        return [];
    const roots = [];
    const base = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-burglar-"));
    for (const src of sources) {
        if (await exists(src)) {
            roots.push(path.resolve(src));
            continue;
        }
        // assume git URL
        const dest = path.join(base, safeName(src));
        await exec(`git clone --depth 1 ${shellEscape(src)} ${shellEscape(dest)}`);
        roots.push(dest);
    }
    return roots;
}
export async function scanForMcpTools(roots, opts = {}) {
    const results = [];
    for (const root of roots) {
        const toolPatterns = [
            "dev/src/tools/**/*.ts",
            "src/tools/**/*.ts",
            "tools/**/*.ts",
            "**/mcp.json"
        ];
        // Use custom file search instead of glob
        const files = await findFilesByPatterns(root, toolPatterns);
        for (const file of files) {
            // quick heuristic: a TS file exporting a MCP tool
            if (file.endsWith(".ts")) {
                const content = await fs.readFile(file, "utf8");
                const m = content.match(/export\s+const\s+([a-zA-Z0-9_]+)\s*:\s*MCPTool/);
                if (m) {
                    const toolName = m[1];
                    if (filterName(toolName, opts))
                        continue;
                    results.push({
                        sourceRoot: root,
                        file,
                        toolName,
                        exportName: toolName,
                        licenseFile: await findLicense(root),
                        desc: findDescription(content)
                    });
                }
            }
            else if (file.endsWith("mcp.json")) {
                results.push({
                    sourceRoot: root,
                    file,
                    toolName: path.basename(file),
                    licenseFile: await findLicense(root),
                    desc: "mcp.json tool definition"
                });
            }
        }
    }
    return results;
}
function filterName(name, opts) {
    const { include, exclude } = opts;
    const match = (pat) => new RegExp("^" + pat.replace(/\*/g, ".*") + "$", "i").test(name);
    if (include && include.length > 0 && !include.some(match))
        return true;
    if (exclude && exclude.length > 0 && exclude.some(match))
        return true;
    return false;
}
function safeName(s) {
    return s.replace(/[^a-z0-9._-]+/gi, "_");
}
async function exists(p) {
    try {
        await fs.access(p);
        return true;
    }
    catch {
        return false;
    }
}
async function findLicense(root) {
    const candidates = ["LICENSE", "LICENSE.md", "license", "license.md", "COPYING", "COPYRIGHT"];
    for (const c of candidates) {
        const p = path.join(root, c);
        if (await exists(p))
            return p;
    }
    return undefined;
}
function findDescription(content) {
    const d = content.match(/description:\s*["'`](.+?)["'`]/);
    return d ? d[1] : undefined;
}
function shellEscape(s) {
    return `"${s.replace(/"/g, '\\"')}"`;
}
async function findFilesByPatterns(root, patterns) {
    const files = [];
    const searchDirectory = async (currentDir, relativePath = "") => {
        try {
            const entries = await fs.readdir(currentDir, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(currentDir, entry.name);
                const relativeFilePath = path.join(relativePath, entry.name);
                // Skip node_modules
                if (entry.name === "node_modules")
                    continue;
                if (entry.isDirectory()) {
                    await searchDirectory(fullPath, relativeFilePath);
                }
                else if (entry.isFile()) {
                    // Check if file matches any of the patterns
                    for (const pattern of patterns) {
                        if (matchesPattern(relativeFilePath, pattern)) {
                            files.push(fullPath);
                            break;
                        }
                    }
                }
            }
        }
        catch (error) {
            // Skip directories we can't access
            console.warn(`Cannot access directory: ${currentDir}`);
        }
    };
    await searchDirectory(root);
    return files;
}
function matchesPattern(filepath, pattern) {
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
