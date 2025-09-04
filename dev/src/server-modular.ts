#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as path from "node:path";
import * as os from "node:os";
import * as fs from "node:fs/promises";
import { spawn, exec } from "node:child_process";
import { promisify } from "node:util";
import simpleGit from "simple-git";
import { createWriteStream } from "node:fs";
import { pipeline } from "node:stream/promises";
import { Transform } from "node:stream";
import { createReadStream } from "node:fs";
import { Readable } from "node:stream";
import * as math from "mathjs";
import { ChartJSNodeCanvas } from "chartjs-node-canvas";
import * as crypto from "node:crypto";
import { createCanvas } from "canvas";

// Import utility modules
import { PLATFORM, IS_WINDOWS, IS_LINUX, IS_MACOS, IS_ANDROID, IS_IOS, IS_MOBILE, config, PROC_ALLOWLIST, MAX_BYTES, MOBILE_CONFIG, COMMAND_MAPPINGS } from "./config/environment.js";
import { ALLOWED_ROOTS_ARRAY, getPlatformCommand, getMobilePermissions, isMobileFeatureAvailable, getMobileDeviceInfo, getFileOperationCommand, getMobileProcessCommand, getMobileServiceCommand, getMobileNetworkCommand, getMobileStorageCommand, getMobileUserCommand } from "./utils/platform.js";
import { sanitizeCommand, isDangerousCommand, shouldPerformSecurityChecks } from "./utils/security.js";
import { ensureInsideRoot, limitString } from "./utils/fileSystem.js";
import { logger, logServerStart } from "./utils/logger.js";

// Import all tools from the comprehensive index
import * as allTools from "./tools/index.js";

// Global variables for enhanced features
let browserInstance: any = null;
let webSocketServer: any = null;
let expressServer: any = null;
let cronJobs: Map<string, any> = new Map();
let fileWatchers: Map<string, any> = new Map();
let apiCache: Map<string, any> = new Map();
let webhookEndpoints: Map<string, any> = new Map();

const execAsync = promisify(exec);

// Log server startup
logServerStart(PLATFORM);

// Register additional tools

// ===========================================
// MODULAR SERVER: Imported Tools
// ===========================================

const server = new McpServer({ name: "MCP God Mode - Modular", version: "1.4a" });

// Capture tool registrations dynamically to keep the list accurate
const registeredTools = new Set<string>();
const _origRegisterTool = (server as any).registerTool?.bind(server);
if (_origRegisterTool) {
  (server as any).registerTool = (name: string, ...rest: any[]) => {
    try { registeredTools.add(name); } catch {}
    return _origRegisterTool(name, ...rest);
  };
}


// ===========================================
// REGISTER ALL 67 TOOLS FROM COMPREHENSIVE INDEX
// ===========================================

// Get all tool registration functions from the comprehensive index
const toolFunctions = Object.values(allTools);

// Register all tools dynamically
toolFunctions.forEach((toolFunction: any) => {
  if (typeof toolFunction === 'function' && toolFunction.name.startsWith('register')) {
    try {
      toolFunction(server);
    } catch (error) {
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
