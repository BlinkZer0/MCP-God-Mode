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

const server = new McpServer({ name: "MCP God Mode - Modular Security & Network Analysis Platform", version: "1.6.0" });

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

console.log("🚀 **MCP GOD MODE - MODULAR SECURITY & NETWORK ANALYSIS PLATFORM STARTED**");
console.log(`📊 Total Tools Available: ${Array.from(registeredTools).length}`);
console.log("");
console.log("🔧 **COMPREHENSIVE PROFESSIONAL TOOL SUITE LOADED**");
console.log("📁 File System Tools: Advanced file operations, search, compression, and metadata extraction");
console.log("⚙️ Process Tools: Cross-platform process execution, monitoring, and elevated privilege management");
console.log("🌐 Network Tools: Advanced network diagnostics, port scanning, traffic analysis, and geolocation");
console.log("🔒 Security Tools: Professional penetration testing, vulnerability assessment, and security auditing");
console.log("📧 Email Tools: Advanced email management, parsing, and security analysis");
console.log("🎨 Media Tools: Professional audio/video editing, image processing, and OCR capabilities");
console.log("📱 Mobile Tools: Comprehensive mobile device management, security analysis, and app testing");
console.log("☁️ Cloud Tools: Multi-cloud security assessment and compliance validation");
console.log("🔍 Forensics Tools: Digital forensics, malware analysis, and incident response");
console.log("");
console.log("⚠️  **PROFESSIONAL SECURITY NOTICE**: All tools are for authorized testing and security assessment ONLY");
console.log("🔒 Use only on networks and systems you own or have explicit written permission to test");
