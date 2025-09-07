#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { exec } from "node:child_process";
import { promisify } from "node:util";
// Import utility modules
import { PLATFORM } from "./config/environment.js";
import { logServerStart } from "./utils/logger.js";
// Import all tools from the comprehensive index
import * as allTools from "./tools/index.js";
// Global variables for enhanced features
let browserInstance = null;
let webSocketServer = null;
let expressServer = null;
let cronJobs = new Map();
let fileWatchers = new Map();
let apiCache = new Map();
let webhookEndpoints = new Map();
const execAsync = promisify(exec);
// Log server startup
logServerStart(PLATFORM);
// Register additional tools
// ===========================================
// MODULAR SERVER: Imported Tools
// ===========================================
const server = new McpServer({ name: "MCP God Mode - Modular", version: "1.6.0" });
// Capture tool registrations dynamically to keep the list accurate
const registeredTools = new Set();
const _origRegisterTool = server.registerTool?.bind(server);
if (_origRegisterTool) {
    server.registerTool = (name, ...rest) => {
        try {
            registeredTools.add(name);
        }
        catch { }
        return _origRegisterTool(name, ...rest);
    };
}
// ===========================================
// REGISTER ALL 67 TOOLS FROM COMPREHENSIVE INDEX
// ===========================================
// Get all tool registration functions from the comprehensive index
const toolFunctions = Object.values(allTools);
// Register all tools dynamically
toolFunctions.forEach((toolFunction) => {
    if (typeof toolFunction === 'function' && toolFunction.name.startsWith('register')) {
        try {
            toolFunction(server);
        }
        catch (error) {
            console.warn(`Warning: Failed to register tool ${toolFunction.name}:`, error);
        }
    }
});
console.log(`✅ Successfully registered ${toolFunctions.length} tool functions`);
// ===========================================
// START THE SERVER
// ===========================================
const transport = new StdioServerTransport();
server.connect(transport);
console.log("🚀 **MCP GOD MODE - MODULAR SERVER STARTED**");
console.log(`📊 Total Tools Available: ${Array.from(registeredTools).length}`);
console.log("");
console.log("🔧 **COMPREHENSIVE TOOL SUITE LOADED**");
console.log("📁 File System Tools: File operations, search, and management");
console.log("⚙️ Process Tools: Process execution and management");
console.log("🌐 Network Tools: Network diagnostics, scanning, and security");
console.log("🔒 Security Tools: Penetration testing, vulnerability assessment");
console.log("📧 Email Tools: Email management and analysis");
console.log("🎨 Media Tools: Image, video, and audio processing");
console.log("📱 Mobile Tools: Mobile device management and security");
console.log("☁️ Cloud Tools: Cloud infrastructure security");
console.log("🔍 Forensics Tools: Digital forensics and analysis");
console.log("");
console.log("⚠️  **SECURITY NOTICE**: All tools are for authorized testing ONLY");
console.log("🔒 Use only on networks you own or have explicit permission to test");
