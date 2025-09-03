#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const AVAILABLE_TOOLS = {
  // Core Tools
  health: './tools/core/health',
  system_info: './tools/core/system_info',
  
  // Email Tools
  send_email: './tools/email/send_email',
  parse_email: './tools/email/parse_email',
  
  // File System Tools
  fs_list: './tools/file_system/fs_list',
  
  // Security Tools (to be implemented)
  wifi_security_toolkit: './tools/security/wifi_security_toolkit',
  bluetooth_security_toolkit: './tools/security/bluetooth_security_toolkit',
  sdr_security_toolkit: './tools/security/sdr_security_toolkit',
  
  // Mobile Tools (to be implemented)
  mobile_device_info: './tools/mobile/mobile_device_info',
  mobile_file_ops: './tools/mobile/mobile_file_ops',
  mobile_system_tools: './tools/mobile/mobile_system_tools',
  mobile_hardware: './tools/mobile/mobile_hardware',
  
  // Network Tools (to be implemented)
  network_diagnostics: './tools/network/network_diagnostics',
  packet_sniffer: './tools/network/packet_sniffer',
  
  // Virtualization Tools (to be implemented)
  vm_management: './tools/virtualization/vm_management',
  docker_management: './tools/virtualization/docker_management',
  
  // Utility Tools (to be implemented)
  calculator: './tools/utilities/calculator',
  math_calculate: './tools/utilities/math_calculate',
  dice_rolling: './tools/utilities/dice_rolling',
  git_status: './tools/utilities/git_status',
  web_scraper: './tools/utilities/web_scraper',
  browser_control: './tools/utilities/browser_control',
  system_restore: './tools/utilities/system_restore'
};

function buildCustomServer(toolList, outputPath, serverName = 'Custom Server') {
  const serverTemplate = `#!/usr/bin/env node

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
import * as canvas from "canvas";
import * as crypto from "node:crypto";

// Import utility modules
import { PLATFORM, IS_WINDOWS, IS_LINUX, IS_MACOS, IS_ANDROID, IS_IOS, IS_MOBILE, config, PROC_ALLOWLIST, MAX_BYTES, MOBILE_CONFIG, COMMAND_MAPPINGS } from "./config/environment.js";
import { ALLOWED_ROOTS, getPlatformCommand, getMobilePermissions, isMobileFeatureAvailable, getMobileDeviceInfo, getFileOperationCommand, getMobileProcessCommand, getMobileServiceCommand, getMobileNetworkCommand, getMobileStorageCommand, getMobileUserCommand } from "./utils/platform.js";
import { sanitizeCommand, isDangerousCommand, shouldPerformSecurityChecks } from "./utils/security.js";
import { ensureInsideRoot, limitString } from "./utils/fileSystem.js";
import { logger, logServerStart } from "./utils/logger.js";

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
// CUSTOM SERVER: ${serverName}
// ===========================================

const server = new McpServer({ name: "custom-mcp-server", version: "1.0.0" });

// Import and register selected tools
${toolList.map(tool => `import { register${tool.charAt(0).toUpperCase() + tool.slice(1).replace(/_([a-z])/g, (g) => g[1].toUpperCase())} } from "${AVAILABLE_TOOLS[tool]}";`).join('\n')}

// Register all selected tools
${toolList.map(tool => `register${tool.charAt(0).toUpperCase() + tool.slice(1).replace(/_([a-z])/g, (g) => g[1].toUpperCase())}(server);`).join('\n')}

// ===========================================
// START THE SERVER
// ===========================================

const transport = new StdioServerTransport();
server.connect(transport);

console.log(\`${serverName} started with ${toolList.length} tools\`);
console.log('Available tools:', '${toolList.join(', ')}');
`;

  fs.writeFileSync(outputPath, serverTemplate);
  console.log(`✅ Custom server built: ${outputPath}`);
  console.log(`🔧 Tools included: ${toolList.length}`);
  console.log(`📋 Tool list: ${toolList.join(', ')}`);
}

// Example usage
if (require.main === module) {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.log('Usage: node build-server.js <tool1> <tool2> ... [output-path] [server-name]');
    console.log('Available tools:', Object.keys(AVAILABLE_TOOLS).join(', '));
    console.log('\nExamples:');
    console.log('  node build-server.js health system_info fs_list send_email');
    console.log('  node build-server.js health system_info fs_list send_email custom-server.ts "My Custom Server"');
    console.log('\nPredefined configurations:');
    console.log('  npm run build:email-only');
    console.log('  npm run build:minimal');
    console.log('  npm run build:core-only');
    process.exit(1);
  }
  
  const toolList = args.filter(arg => AVAILABLE_TOOLS[arg]);
  const outputPath = args.find(arg => arg.endsWith('.ts')) || 'custom-server.ts';
  const serverName = args.find(arg => !arg.endsWith('.ts') && !AVAILABLE_TOOLS[arg]) || 'Custom Server';
  
  if (toolList.length === 0) {
    console.log('❌ No valid tools specified. Available tools:');
    console.log(Object.keys(AVAILABLE_TOOLS).join(', '));
    process.exit(1);
  }
  
  buildCustomServer(toolList, outputPath, serverName);
}

module.exports = { buildCustomServer, AVAILABLE_TOOLS };
