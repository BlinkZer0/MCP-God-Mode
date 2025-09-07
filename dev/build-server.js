#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

const AVAILABLE_TOOLS = {
  // Core Tools
  health: './tools/core/health',
  system_info: './tools/core/system_info',
  
  // File System Tools
  fs_list: './tools/file_system/fs_list',
  fs_read_text: './tools/file_system/fs_read_text',
  fs_write_text: './tools/file_system/fs_write_text',
  fs_search: './tools/file_system/fs_search',
  file_ops: './tools/file_system/file_ops',
  file_watcher: './tools/file_system/file_watcher',
  
  // Process Tools
  proc_run: './tools/process/proc_run',
  proc_run_elevated: './tools/process/proc_run_elevated',
  
  // System Tools
  system_restore: './tools/system/system_restore',
  elevated_permissions_manager: './tools/system/elevated_permissions_manager',
  cron_job_manager: './tools/system/cron_job_manager',
  system_monitor: './tools/system/system_monitor',
  
  // Git Tools
  git_status: './tools/git/git_status',
  
  // Windows Tools
  win_services: './tools/windows/win_services',
  win_processes: './tools/windows/win_processes',
  
  // Network Tools
  packet_sniffer: './tools/network/packet_sniffer',
  port_scanner: './tools/network/port_scanner',
  network_diagnostics: './tools/network/network_diagnostics',
  download_file: './tools/network/download_file',
  network_traffic_analyzer: './tools/network/network_traffic_analyzer',
  ip_geolocation: './tools/network/ip_geolocation',
  network_triangulation: './tools/network/network_triangulation',
  osint_reconnaissance: './tools/network/osint_reconnaissance',
  latency_geolocation: './tools/network/latency_geolocation',
  network_discovery: './tools/network/network_discovery',
  vulnerability_assessment: './tools/network/vulnerability_assessment',
  traffic_analysis: './tools/network/traffic_analysis',
  network_utilities: './tools/network/network_utilities',
  social_account_ripper: './tools/network/social_account_ripper',
  social_account_ripper_modular: './tools/network/social_account_ripper_modular',
  
  // Security Tools
  vulnerability_scanner: './tools/security/vulnerability_scanner',
  password_cracker: './tools/security/password_cracker',
  exploit_framework: './tools/security/exploit_framework',
  network_security: './tools/security/network_security',
  blockchain_security: './tools/security/blockchain_security',
  quantum_security: './tools/security/quantum_security',
  iot_security: './tools/security/iot_security',
  social_engineering: './tools/security/social_engineering',
  threat_intelligence: './tools/security/threat_intelligence',
  compliance_assessment: './tools/security/compliance_assessment',
  social_network_ripper: './tools/security/social_network_ripper',
  metadata_extractor: './tools/security/metadata_extractor',
  encryption_tool: './tools/utilities/encryption_tool',
  malware_analysis: './tools/security/malware_analysis',
  
  // Penetration Tools
  hack_network: './tools/penetration/hack_network',
  security_testing: './tools/penetration/security_testing',
  network_penetration: './tools/penetration/network_penetration',
  penetration_testing_toolkit: './tools/penetration/penetration_testing_toolkit',
  social_engineering_toolkit: './tools/penetration/social_engineering_toolkit',
  
  // Wireless Tools
  wifi_security_toolkit: './tools/wireless/wifi_security_toolkit',
  wifi_hacking: './tools/wireless/wifi_hacking',
  wireless_security: './tools/wireless/wireless_security',
  wireless_network_scanner: './tools/wireless/wireless_network_scanner',
  
  // Bluetooth Tools
  bluetooth_security_toolkit: './tools/bluetooth/bluetooth_security_toolkit',
  bluetooth_hacking: './tools/bluetooth/bluetooth_hacking',
  bluetooth_device_manager: './tools/bluetooth/bluetooth_device_manager',
  
  // Radio Tools
  sdr_security_toolkit: './tools/radio/sdr_security_toolkit',
  radio_security: './tools/radio/radio_security',
  signal_analysis: './tools/radio/signal_analysis',
  
  // Web Tools
  web_scraper: './tools/web/web_scraper',
  browser_control: './tools/web/browser_control',
  web_automation: './tools/web/web_automation',
  webhook_manager: './tools/web/webhook_manager',
  universal_browser_operator: './tools/web/universal_browser_operator',
  web_search: './tools/web/web_search',
  captcha_defeating: './tools/web/captcha_defeating',
  form_completion: './tools/web/form_completion',
  
  // Email Tools
  send_email: './tools/email/send_email',
  read_emails: './tools/email/read_emails',
  parse_email: './tools/email/parse_email',
  delete_emails: './tools/email/delete_emails',
  sort_emails: './tools/email/sort_emails',
  manage_email_accounts: './tools/email/manage_email_accounts',
  
  // Media Tools
  video_editing: './tools/media/video_editing',
  ocr_tool: './tools/media/ocr_tool',
  image_editing: './tools/media/image_editing',
  audio_editing: './tools/audio_editing/index',
  
  // Screenshot Tools
  screenshot: './tools/screenshot/index',
  
  // Mobile Tools
  mobile_device_info: './tools/mobile/mobile_device_info',
  mobile_file_ops: './tools/mobile/mobile_file_ops',
  mobile_system_tools: './tools/mobile/mobile_system_tools',
  mobile_hardware: './tools/mobile/mobile_hardware',
  mobile_device_management: './tools/mobile/mobile_device_management',
  mobile_app_analytics_toolkit: './tools/mobile/mobile_app_analytics_toolkit',
  mobile_app_deployment_toolkit: './tools/mobile/mobile_app_deployment_toolkit',
  mobile_app_optimization_toolkit: './tools/mobile/mobile_app_optimization_toolkit',
  mobile_app_security_toolkit: './tools/mobile/mobile_app_security_toolkit',
  mobile_app_monitoring_toolkit: './tools/mobile/mobile_app_monitoring_toolkit',
  mobile_app_performance_toolkit: './tools/mobile/mobile_app_performance_toolkit',
  mobile_app_testing_toolkit: './tools/mobile/mobile_app_testing_toolkit',
  mobile_network_analyzer: './tools/mobile/mobile_network_analyzer',
  
  // Virtualization Tools
  vm_management: './tools/virtualization/vm_management',
  docker_management: './tools/virtualization/docker_management',
  
  // Utility Tools
  calculator: './tools/utilities/calculator',
  dice_rolling: './tools/utilities/dice_rolling',
  math_calculate: './tools/utilities/math_calculate',
  data_analysis: './tools/utilities/data_analysis',
  machine_learning: './tools/utilities/machine_learning',
  chart_generator: './tools/utilities/chart_generator',
  text_processor: './tools/utilities/text_processor',
  password_generator: './tools/utilities/password_generator',
  data_analyzer: './tools/utilities/data_analyzer',
  download_file: './tools/utilities/download_file',
  
  // Cloud Tools
  cloud_security: './tools/cloud/cloud_security',
  cloud_infrastructure_manager: './tools/cloud/cloud_infrastructure_manager',
  cloud_security_toolkit: './tools/cloud/cloud_security_toolkit',
  
  // Forensics Tools
  forensics_analysis: './tools/forensics/forensics_analysis',
  forensics_toolkit: './tools/forensics/forensics_toolkit',
  malware_analysis_toolkit: './tools/forensics/malware_analysis_toolkit',
  
  // Discovery Tools
  tool_discovery: './tools/discovery/tool_discovery',
  explore_categories: './tools/discovery/explore_categories',
  
  // Social Tools
  social_network_ripper: './tools/social/social_network_ripper'
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
if (process.argv[1] && process.argv[1].endsWith('build-server.js')) {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.log('Usage: node build-server.js <tool1> <tool2> ... [output-path] [server-name]');
    console.log(`Available tools (${Object.keys(AVAILABLE_TOOLS).length} total):`, Object.keys(AVAILABLE_TOOLS).join(', '));
    console.log('\nExamples:');
    console.log('  node build-server.js health system_info fs_list send_email');
    console.log('  node build-server.js health system_info fs_list send_email custom-server.ts "My Custom Server"');
    console.log('  node build-server.js machine_learning social_engineering_toolkit mobile_app_analytics_toolkit');
    console.log('\nPredefined configurations:');
    console.log('  npm run build:email-only');
    console.log('  npm run build:minimal');
    console.log('  npm run build:core-only');
    console.log('\n🎭 Fun Fact: With 96+ tools available, you can build anything from a simple file manager to a full cybersecurity suite!');
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

export { buildCustomServer, AVAILABLE_TOOLS };
