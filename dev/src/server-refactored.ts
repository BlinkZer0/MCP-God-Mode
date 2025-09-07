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

// ===========================================
// MONOLITHIC SERVER: Direct Tool Registration
// ===========================================

const server = new McpServer({ name: "MCP God Mode - Monolithic", version: "1.6.0" });

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
// REGISTER ALL TOOLS FROM COMPREHENSIVE INDEX
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

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("MCP God Mode - Monolithic Server started successfully");
  console.log("🚀 **MCP GOD MODE - MONOLITHIC SERVER STARTED**");
  console.log(`📊 Total Tools Available: ${Array.from(registeredTools).length}`);
  console.log("");
  console.log("🔧 **COMPREHENSIVE TOOL SUITE LOADED**");
  console.log("📁 File System Tools: File operations, search, and management");
  console.log("⚙️ Process Tools: Process execution and management");
  console.log("🌐 Network Tools: Network diagnostics, scanning, and security");
  console.log("🔒 Security Tools: Penetration testing, vulnerability assessment");
  console.log("📡 Wireless Tools: Wi-Fi, Bluetooth, and radio security");
  console.log("📧 Email Tools: Email management and processing");
  console.log("🎵 Media Tools: Audio, video, and image processing");
  console.log("🖥️ Web Tools: Browser automation and web scraping");
  console.log("📱 Mobile Tools: Mobile device management and analysis");
  console.log("🖥️ Virtualization: VM and container management");
  console.log("🧮 Utility Tools: Mathematical and data processing");
  console.log("🪟 Windows Tools: Windows-specific system management");
  console.log("");
  console.log("🎯 **READY FOR OPERATION**");
}

main().catch((error) => {
  logger.error("Failed to start server:", error);
  process.exit(1);
});
