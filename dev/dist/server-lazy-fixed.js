#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as path from "node:path";
import * as fs from "node:fs/promises";
// ===========================================
// FIXED LAZY LOADING MCP SERVER
// ===========================================
const server = new McpServer({
    name: "MCP God Mode - Fixed Lazy Loading Server",
    version: "1.9.0"
});
// Track loaded tools and metadata
const loadedTools = new Set();
const toolMetadata = new Map();
const loadedModules = new Map();
async function discoverTools(toolsDir = "src/tools") {
    const discovered = [];
    try {
        const fullPath = path.resolve(toolsDir);
        console.log(`🔍 Scanning directory: ${fullPath}`);
        await scanDirectory(fullPath, discovered);
        console.log(`📊 Discovered ${discovered.length} tools`);
    }
    catch (error) {
        console.error("❌ Tool discovery failed:", error);
    }
    return discovered;
}
async function scanDirectory(dirPath, discovered) {
    try {
        const entries = await fs.readdir(dirPath, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path.join(dirPath, entry.name);
            if (entry.isDirectory()) {
                await scanDirectory(fullPath, discovered);
            }
            else if (entry.isFile() && entry.name.endsWith('.ts')) {
                const metadata = await analyzeToolFile(fullPath);
                if (metadata) {
                    discovered.push(metadata);
                }
            }
        }
    }
    catch (error) {
        console.warn(`⚠️ Failed to scan directory '${dirPath}':`, error);
    }
}
async function analyzeToolFile(filePath) {
    try {
        const content = await fs.readFile(filePath, 'utf-8');
        const stats = await fs.stat(filePath);
        // Look for register function pattern
        const registerMatch = content.match(/export\s+function\s+(register\w+)\s*\(/);
        if (!registerMatch) {
            return null;
        }
        const registerFunction = registerMatch[1];
        const fileName = path.basename(filePath, '.ts');
        // Extract description from registerTool call
        const descriptionMatch = content.match(/description:\s*["'`]([^"'`]+)["'`]/);
        const description = descriptionMatch ? descriptionMatch[1] : `Tool from ${fileName}`;
        // Determine category from directory structure
        const category = determineCategory(filePath);
        return {
            name: `mcp_mcp-god-mode_${fileName}`,
            description,
            sourceFile: filePath,
            registerFunction,
            category,
            lastModified: stats.mtime,
            fileSize: stats.size
        };
    }
    catch (error) {
        console.warn(`⚠️ Failed to analyze file '${filePath}':`, error);
        return null;
    }
}
function determineCategory(filePath) {
    const pathParts = filePath.split(path.sep);
    const toolsIndex = pathParts.indexOf('tools');
    if (toolsIndex >= 0 && pathParts[toolsIndex + 1]) {
        return pathParts[toolsIndex + 1];
    }
    return 'uncategorized';
}
// ===========================================
// TOOL LOADING SYSTEM
// ===========================================
async function loadTool(toolName) {
    const metadata = toolMetadata.get(toolName);
    if (!metadata) {
        throw new Error(`Tool '${toolName}' not found in metadata cache`);
    }
    // Check if already loaded
    if (loadedModules.has(toolName)) {
        console.log(`🎯 Cache hit for tool: ${toolName}`);
        return loadedModules.get(toolName);
    }
    try {
        // Convert TypeScript path to JavaScript path for dynamic import
        const jsPath = metadata.sourceFile
            .replace('src/', 'dist/')
            .replace('.ts', '.js');
        console.log(`⚡ Loading tool: ${toolName} from ${jsPath}`);
        // Dynamically import the tool module
        const modulePath = path.resolve(jsPath);
        const module = await import(modulePath);
        const registerFunction = module[metadata.registerFunction];
        if (!registerFunction) {
            throw new Error(`Register function '${metadata.registerFunction}' not found in module`);
        }
        const toolData = { module, registerFunction, metadata };
        // Cache the loaded module
        loadedModules.set(toolName, toolData);
        console.log(`✅ Loaded and cached tool: ${toolName}`);
        return toolData;
    }
    catch (error) {
        console.error(`❌ Failed to load tool '${toolName}':`, error);
        throw error;
    }
}
async function registerToolWithServer(toolName) {
    try {
        const toolData = await loadTool(toolName);
        const { registerFunction } = toolData;
        // Call the register function with the server
        await registerFunction(server);
        loadedTools.add(toolName);
        console.log(`✅ Registered tool with server: ${toolName}`);
        return true;
    }
    catch (error) {
        console.error(`❌ Failed to register tool '${toolName}':`, error);
        return false;
    }
}
// ===========================================
// TOOL DISCOVERY TOOL
// ===========================================
async function registerToolDiscoveryTool() {
    server.registerTool("mcp_mcp-god-mode_tool_discovery", {
        description: "Discover and manage available tools with lazy loading",
        inputSchema: {
            action: z.enum(["list", "load", "metadata", "stats"]).describe("Action to perform"),
            tool_name: z.string().optional().describe("Tool name for specific operations"),
            category: z.string().optional().describe("Filter by tool category"),
            search: z.string().optional().describe("Search tools by name or description")
        }
    }, async (input) => {
        try {
            switch (input.action) {
                case "list":
                    return await handleListTools(input);
                case "load":
                    return await handleLoadTool(input);
                case "metadata":
                    return await handleGetMetadata(input);
                case "stats":
                    return await handleGetStats();
                default:
                    return {
                        content: [],
                        structuredContent: { ok: false, error: "Invalid action" }
                    };
            }
        }
        catch (error) {
            return {
                content: [],
                structuredContent: { ok: false, error: error.message }
            };
        }
    });
}
async function handleListTools(input) {
    const allTools = Array.from(toolMetadata.values());
    let filteredTools = allTools;
    if (input.category) {
        filteredTools = filteredTools.filter(tool => tool.category === input.category);
    }
    if (input.search) {
        const searchLower = input.search.toLowerCase();
        filteredTools = filteredTools.filter(tool => tool.name.toLowerCase().includes(searchLower) ||
            tool.description.toLowerCase().includes(searchLower));
    }
    // Group by category
    const grouped = filteredTools.reduce((acc, tool) => {
        const category = tool.category || 'uncategorized';
        if (!acc[category])
            acc[category] = [];
        acc[category].push({
            name: tool.name,
            description: tool.description,
            loaded: loadedTools.has(tool.name)
        });
        return acc;
    }, {});
    return {
        content: [],
        structuredContent: {
            ok: true,
            tools: grouped,
            total: filteredTools.length,
            loaded: loadedTools.size
        }
    };
}
async function handleLoadTool(input) {
    if (!input.tool_name) {
        return {
            content: [],
            structuredContent: { ok: false, error: "tool_name is required" }
        };
    }
    if (loadedTools.has(input.tool_name)) {
        return {
            content: [],
            structuredContent: {
                ok: true,
                message: `Tool '${input.tool_name}' is already loaded`,
                loaded: true
            }
        };
    }
    try {
        const success = await registerToolWithServer(input.tool_name);
        if (success) {
            return {
                content: [],
                structuredContent: {
                    ok: true,
                    message: `Tool '${input.tool_name}' loaded successfully`,
                    loaded: true
                }
            };
        }
        else {
            return {
                content: [],
                structuredContent: {
                    ok: false,
                    error: `Failed to load tool '${input.tool_name}'`
                }
            };
        }
    }
    catch (error) {
        return {
            content: [],
            structuredContent: {
                ok: false,
                error: `Error loading tool '${input.tool_name}': ${error.message}`
            }
        };
    }
}
async function handleGetMetadata(input) {
    if (!input.tool_name) {
        return {
            content: [],
            structuredContent: { ok: false, error: "tool_name is required" }
        };
    }
    const metadata = toolMetadata.get(input.tool_name);
    if (!metadata) {
        return {
            content: [],
            structuredContent: { ok: false, error: `Tool '${input.tool_name}' not found` }
        };
    }
    return {
        content: [],
        structuredContent: {
            ok: true,
            metadata: {
                name: metadata.name,
                description: metadata.description,
                category: metadata.category,
                sourceFile: metadata.sourceFile,
                registerFunction: metadata.registerFunction,
                lastModified: metadata.lastModified,
                fileSize: metadata.fileSize,
                loaded: loadedTools.has(metadata.name)
            }
        }
    };
}
async function handleGetStats() {
    const categories = Array.from(toolMetadata.values()).reduce((acc, tool) => {
        const category = tool.category || 'uncategorized';
        acc[category] = (acc[category] || 0) + 1;
        return acc;
    }, {});
    return {
        content: [],
        structuredContent: {
            ok: true,
            stats: {
                loadedTools: loadedTools.size,
                totalDiscovered: toolMetadata.size,
                cachedModules: loadedModules.size,
                categories
            }
        }
    };
}
// ===========================================
// DYNAMIC TOOL INTERCEPTOR
// ===========================================
const originalHandleCall = server.handleCall?.bind(server);
if (originalHandleCall) {
    server.handleCall = async (request) => {
        const toolName = request.params?.name;
        if (toolName && !loadedTools.has(toolName)) {
            console.log(`🔄 Tool '${toolName}' not loaded, attempting to load...`);
            try {
                const success = await registerToolWithServer(toolName);
                if (success) {
                    console.log(`✅ Tool '${toolName}' loaded on-demand`);
                }
                else {
                    console.error(`❌ Failed to load tool '${toolName}'`);
                    return {
                        error: {
                            code: -32601,
                            message: `Tool '${toolName}' not found or failed to load`
                        }
                    };
                }
            }
            catch (error) {
                console.error(`❌ Error loading tool '${toolName}':`, error);
                return {
                    error: {
                        code: -32601,
                        message: `Tool '${toolName}' not found: ${error.message}`
                    }
                };
            }
        }
        return originalHandleCall(request);
    };
}
// ===========================================
// START THE SERVER
// ===========================================
async function main() {
    console.log("🚀 **MCP GOD MODE - FIXED LAZY LOADING SERVER**");
    console.log("⚡ Starting with fixed lazy loading architecture...");
    // Discover tools
    console.log("🔍 Discovering available tools...");
    const discovered = await discoverTools();
    // Cache metadata
    for (const tool of discovered) {
        toolMetadata.set(tool.name, tool);
    }
    console.log(`📊 Cached metadata for ${discovered.length} tools`);
    // Register tool discovery tool first
    await registerToolDiscoveryTool();
    // Preload essential tools
    const essentialTools = [
        'mcp_mcp-god-mode_health',
        'mcp_mcp-god-mode_tool_burglar'
    ];
    console.log("🚀 Preloading essential tools...");
    for (const toolName of essentialTools) {
        if (toolMetadata.has(toolName)) {
            try {
                await registerToolWithServer(toolName);
                console.log(`✅ Preloaded: ${toolName}`);
            }
            catch (error) {
                console.warn(`⚠️ Failed to preload ${toolName}:`, error.message);
            }
        }
        else {
            console.warn(`⚠️ Essential tool not found: ${toolName}`);
        }
    }
    // Connect to transport
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.log("✅ **FIXED LAZY LOADING SERVER READY**");
    console.log(`📊 Total Tools Discovered: ${toolMetadata.size}`);
    console.log(`⚡ Tools Preloaded: ${loadedTools.size}`);
    console.log(`💾 Modules Cached: ${loadedModules.size}`);
    console.log("");
    console.log("🔧 **LAZY LOADING FEATURES**");
    console.log("📁 Tools load on-demand when called");
    console.log("⚙️ Faster startup times");
    console.log("💾 Reduced memory footprint");
    console.log("🔍 Tool discovery and metadata caching");
    console.log("📈 Module caching for performance");
    console.log("");
    console.log("🎯 Use 'mcp_mcp-god-mode_tool_discovery' to manage tools");
    console.log("💡 Tools automatically load when you call them");
}
// Start the server
main().catch((error) => {
    console.error("❌ Server startup failed:", error);
    process.exit(1);
});
