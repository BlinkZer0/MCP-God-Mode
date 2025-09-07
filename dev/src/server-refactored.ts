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
import { legalCompliance, LegalComplianceConfig } from "./utils/legal-compliance.js";

// Import all tools from the comprehensive index
import * as allTools from "./tools/index.js";

// Import legal compliance tools
import { registerLegalComplianceManager } from "./tools/legal/legal_compliance_manager.js";

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

// Initialize legal compliance system
async function initializeLegalCompliance() {
  try {
    // Configure legal compliance from environment
    const legalConfig: LegalComplianceConfig = {
      enabled: config.legalCompliance.enabled,
      auditLogging: config.legalCompliance.auditLogging,
      evidencePreservation: config.legalCompliance.evidencePreservation,
      legalHold: config.legalCompliance.legalHold,
      chainOfCustody: config.legalCompliance.chainOfCustody,
      dataIntegrity: config.legalCompliance.dataIntegrity,
      complianceFrameworks: config.legalCompliance.complianceFrameworks
    };

    await legalCompliance.updateConfig(legalConfig);
    await legalCompliance.initialize();

    if (legalConfig.enabled) {
      console.log("🔒 Legal compliance system initialized and enabled");
      console.log(`   📊 Audit Logging: ${legalConfig.auditLogging.enabled ? '✅' : '❌'}`);
      console.log(`   🗃️ Evidence Preservation: ${legalConfig.evidencePreservation.enabled ? '✅' : '❌'}`);
      console.log(`   ⚖️ Legal Hold: ${legalConfig.legalHold.enabled ? '✅' : '❌'}`);
      console.log(`   🔗 Chain of Custody: ${legalConfig.chainOfCustody.enabled ? '✅' : '❌'}`);
      console.log(`   🔐 Data Integrity: ${legalConfig.dataIntegrity.enabled ? '✅' : '❌'}`);
      
      const frameworks = Object.entries(legalConfig.complianceFrameworks)
        .filter(([_, enabled]) => enabled)
        .map(([framework, _]) => framework.toUpperCase());
      
      if (frameworks.length > 0) {
        console.log(`   📋 Compliance Frameworks: ${frameworks.join(', ')}`);
      }
    } else {
      console.log("🔓 Legal compliance system disabled (default)");
    }
  } catch (error) {
    console.warn("⚠️ Failed to initialize legal compliance system:", error);
  }
}

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

// Register legal compliance manager
try {
  registerLegalComplianceManager(server);
  console.log("✅ Legal compliance manager registered");
} catch (error) {
  console.warn("Warning: Failed to register legal compliance manager:", error);
}

console.log(`✅ Successfully registered ${toolFunctions.length} tool functions + legal compliance manager`);

// ===========================================
// START THE SERVER
// ===========================================

async function main() {
  // Initialize legal compliance system first
  await initializeLegalCompliance();
  
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
  console.log("⚖️ Legal Tools: Legal compliance, audit logging, evidence preservation");
  console.log("");
  console.log("🎯 **READY FOR OPERATION**");
}

main().catch((error) => {
  logger.error("Failed to start server:", error);
  process.exit(1);
});
