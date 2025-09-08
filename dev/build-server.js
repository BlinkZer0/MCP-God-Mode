#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// Auto-generated available tools based on actual files in src/tools/
// Generated on: 2025-09-07T08:28:51.174Z
// Total tools: 111

const AVAILABLE_TOOLS = {
  "bluetooth_device_manager": "./tools/bluetooth/bluetooth_device_manager",
  "bluetooth_hacking": "./tools/bluetooth/bluetooth_hacking",
  "bluetooth_security_toolkit": "./tools/bluetooth/bluetooth_security_toolkit",
  "cloud_infrastructure_manager": "./tools/cloud/cloud_infrastructure_manager",
  "cloud_security": "./tools/cloud/cloud_security",
  "cloud_security_toolkit": "./tools/cloud/cloud_security_toolkit",
  "health": "./tools/core/health",
  "system_info": "./tools/core/system_info",
  "explore_categories": "./tools/discovery/explore_categories",
  "tool_discovery": "./tools/discovery/tool_discovery",
  "delete_emails": "./tools/email/delete_emails",
  "email_utils": "./tools/email/email_utils",
  "manage_email_accounts": "./tools/email/manage_email_accounts",
  "parse_email": "./tools/email/parse_email",
  "read_emails": "./tools/email/read_emails",
  "send_email": "./tools/email/send_email",
  "sort_emails": "./tools/email/sort_emails",
  "file_ops": "./tools/file_system/file_ops",
  "file_watcher": "./tools/file_system/file_watcher",
  "fs_list": "./tools/file_system/fs_list",
  "fs_read_text": "./tools/file_system/fs_read_text",
  "fs_search": "./tools/file_system/fs_search",
  "fs_write_text": "./tools/file_system/fs_write_text",
  "forensics_analysis": "./tools/forensics/forensics_analysis",
  "forensics_toolkit": "./tools/forensics/forensics_toolkit",
  "malware_analysis_toolkit": "./tools/forensics/malware_analysis_toolkit",
  "git_status": "./tools/git/git_status",
  "legal_compliance_manager": "./tools/legal/legal_compliance_manager",
  "image_editing": "./tools/media/image_editing",
  "ocr_tool": "./tools/media/ocr_tool",
  "video_editing": "./tools/media/video_editing",
  "mobile_app_analytics_toolkit": "./tools/mobile/mobile_app_analytics_toolkit",
  "mobile_app_deployment_toolkit": "./tools/mobile/mobile_app_deployment_toolkit",
  "mobile_app_monitoring_toolkit": "./tools/mobile/mobile_app_monitoring_toolkit",
  "mobile_app_optimization_toolkit": "./tools/mobile/mobile_app_optimization_toolkit",
  "mobile_app_performance_toolkit": "./tools/mobile/mobile_app_performance_toolkit",
  "mobile_app_security_toolkit": "./tools/mobile/mobile_app_security_toolkit",
  "mobile_app_testing_toolkit": "./tools/mobile/mobile_app_testing_toolkit",
  "mobile_device_info": "./tools/mobile/mobile_device_info",
  "mobile_device_management": "./tools/mobile/mobile_device_management",
  "mobile_file_ops": "./tools/mobile/mobile_file_ops",
  "mobile_hardware": "./tools/mobile/mobile_hardware",
  "mobile_network_analyzer": "./tools/mobile/mobile_network_analyzer",
  "mobile_system_tools": "./tools/mobile/mobile_system_tools",
  "download_file": "./tools/utilities/download_file",
  "ip_geolocation": "./tools/network/ip_geolocation",
  "latency_geolocation": "./tools/network/latency_geolocation",
  "network_diagnostics": "./tools/network/network_diagnostics",
  "network_discovery": "./tools/network/network_discovery",
  "network_penetration": "./tools/penetration/network_penetration",
  "network_traffic_analyzer": "./tools/network/network_traffic_analyzer",
  "network_triangulation": "./tools/network/network_triangulation",
  "network_utilities": "./tools/network/network_utilities",
  "osint_reconnaissance": "./tools/network/osint_reconnaissance",
  "packet_sniffer": "./tools/security/packet_sniffer",
  "port_scanner": "./tools/security/port_scanner",
  "social_account_ripper": "./tools/network/social_account_ripper",
  "social_account_ripper_modular": "./tools/network/social_account_ripper_modular",
  "traffic_analysis": "./tools/network/traffic_analysis",
  "vulnerability_assessment": "./tools/network/vulnerability_assessment",
  "hack_network": "./tools/penetration/hack_network",
  "penetration_testing_toolkit": "./tools/penetration/penetration_testing_toolkit",
  "security_testing": "./tools/security/security_testing",
  "social_engineering_toolkit": "./tools/penetration/social_engineering_toolkit",
  "proc_run": "./tools/process/proc_run",
  "proc_run_elevated": "./tools/process/proc_run_elevated",
  "radio_security": "./tools/radio/radio_security",
  "sdr_security_toolkit": "./tools/radio/sdr_security_toolkit",
  "signal_analysis": "./tools/radio/signal_analysis",
  "blockchain_security": "./tools/security/blockchain_security",
  "compliance_assessment": "./tools/security/compliance_assessment",
  "exploit_framework": "./tools/security/exploit_framework",
  "iot_security": "./tools/security/iot_security",
  "malware_analysis": "./tools/security/malware_analysis",
  "metadata_extractor": "./tools/security/metadata_extractor",
  "network_security": "./tools/security/network_security",
  "password_cracker": "./tools/security/password_cracker",
  "quantum_security": "./tools/security/quantum_security",
  "social_engineering": "./tools/security/social_engineering",
  "social_network_ripper": "./tools/social/social_network_ripper",
  "threat_intelligence": "./tools/security/threat_intelligence",
  "vulnerability_scanner": "./tools/security/vulnerability_scanner",
  "cron_job_manager": "./tools/system/cron_job_manager",
  "elevated_permissions_manager": "./tools/system/elevated_permissions_manager",
  "system_monitor": "./tools/system/system_monitor",
  "system_restore": "./tools/system/system_restore",
  "calculator": "./tools/utilities/calculator",
  "chart_generator": "./tools/utilities/chart_generator",
  "data_analysis": "./tools/utilities/data_analysis",
  "data_analyzer": "./tools/utilities/data_analyzer",
  "dice_rolling": "./tools/utilities/dice_rolling",
  "encryption_tool": "./tools/utilities/encryption_tool",
  "machine_learning": "./tools/utilities/machine_learning",
  "math_calculate": "./tools/utilities/math_calculate",
  "password_generator": "./tools/utilities/password_generator",
  "text_processor": "./tools/utilities/text_processor",
  "docker_management": "./tools/virtualization/docker_management",
  "vm_management": "./tools/virtualization/vm_management",
  "browser_control": "./tools/web/browser_control",
  "form_completion": "./tools/web/form_completion",
  "universal_browser_operator": "./tools/web/universal_browser_operator",
  "webhook_manager": "./tools/web/webhook_manager",
  "web_automation": "./tools/web/web_automation",
  "web_scraper": "./tools/web/web_scraper",
  "web_search": "./tools/web/web_search",
  "win_processes": "./tools/windows/win_processes",
  "win_services": "./tools/windows/win_services",
  "wifi_hacking": "./tools/wireless/wifi_hacking",
  "wifi_security_toolkit": "./tools/wireless/wifi_security_toolkit",
  "wireless_network_scanner": "./tools/wireless/wireless_network_scanner",
  "wireless_security": "./tools/wireless/wireless_security"
};

// Tool categories for organization
const TOOL_CATEGORIES = {
  "bluetooth": {
    "name": "Bluetooth Security",
    "description": "Bluetooth device security and management",
    "features": [
      "Bluetooth security testing",
      "Bluetooth penetration testing",
      "Bluetooth device management",
      "Bluetooth vulnerability assessment"
    ],
    "tools": 3,
    "toolList": [
      "bluetooth_device_manager",
      "bluetooth_hacking",
      "bluetooth_security_toolkit"
    ]
  },
  "cloud": {
    "name": "Cloud Security",
    "description": "Cloud infrastructure security and management",
    "features": [
      "Cloud security assessment",
      "Cloud infrastructure management",
      "Multi-cloud security toolkit",
      "Cloud compliance validation"
    ],
    "tools": 3,
    "toolList": [
      "cloud_infrastructure_manager",
      "cloud_security",
      "cloud_security_toolkit"
    ]
  },
  "core": {
    "name": "Core System Tools",
    "description": "Essential system monitoring and health check tools",
    "features": [
      "System health monitoring",
      "Basic system information retrieval",
      "Essential for all server operations"
    ],
    "tools": 2,
    "toolList": [
      "health",
      "system_info"
    ]
  },
  "discovery": {
    "name": "Tool Discovery",
    "description": "Tool discovery and exploration capabilities",
    "features": [
      "Tool discovery and exploration",
      "Category exploration",
      "Tool capability analysis"
    ],
    "tools": 2,
    "toolList": [
      "explore_categories",
      "tool_discovery"
    ]
  },
  "email": {
    "name": "Email Management",
    "description": "Comprehensive email processing and management",
    "features": [
      "Email sending and receiving",
      "Email parsing and analysis",
      "Email account management",
      "Email organization and sorting",
      "Email deletion and cleanup"
    ],
    "tools": 7,
    "toolList": [
      "delete_emails",
      "email_utils",
      "manage_email_accounts",
      "parse_email",
      "read_emails",
      "send_email",
      "sort_emails"
    ]
  },
  "file_system": {
    "name": "File System Tools",
    "description": "Complete file and directory management capabilities",
    "features": [
      "Directory listing and navigation",
      "Text file reading and writing",
      "File search and discovery",
      "Advanced file operations",
      "Real-time file system monitoring"
    ],
    "tools": 6,
    "toolList": [
      "file_ops",
      "file_watcher",
      "fs_list",
      "fs_read_text",
      "fs_search",
      "fs_write_text"
    ]
  },
  "forensics": {
    "name": "Digital Forensics",
    "description": "Digital forensics and incident response",
    "features": [
      "Digital forensics analysis",
      "Evidence collection and preservation",
      "Malware analysis and reverse engineering",
      "Incident response capabilities"
    ],
    "tools": 3,
    "toolList": [
      "forensics_analysis",
      "forensics_toolkit",
      "malware_analysis_toolkit"
    ]
  },
  "git": {
    "name": "Git Integration",
    "description": "Version control and repository management",
    "features": [
      "Git repository status checking",
      "Version control integration"
    ],
    "tools": 1,
    "toolList": [
      "git_status"
    ]
  },
  "legal": {
    "name": "Legal Compliance",
    "description": "Legal compliance and audit management",
    "features": [
      "Legal compliance management",
      "Audit logging and evidence preservation",
      "Chain of custody tracking",
      "Regulatory compliance support"
    ],
    "tools": 1,
    "toolList": [
      "legal_compliance_manager"
    ]
  },
  "media": {
    "name": "Media Processing",
    "description": "Video, image, and audio editing capabilities",
    "features": [
      "Video editing and processing",
      "Optical Character Recognition (OCR)",
      "Image editing and manipulation",
      "Audio editing and processing"
    ],
    "tools": 3,
    "toolList": [
      "image_editing",
      "ocr_tool",
      "video_editing"
    ]
  },
  "mobile": {
    "name": "Mobile Tools",
    "description": "Comprehensive mobile device management and app development",
    "features": [
      "Mobile device information and management",
      "Mobile file operations",
      "Mobile app analytics and monitoring",
      "Mobile app deployment and optimization",
      "Mobile app security testing",
      "Mobile app performance analysis",
      "Mobile network analysis"
    ],
    "tools": 13,
    "toolList": [
      "mobile_app_analytics_toolkit",
      "mobile_app_deployment_toolkit",
      "mobile_app_monitoring_toolkit",
      "mobile_app_optimization_toolkit",
      "mobile_app_performance_toolkit",
      "mobile_app_security_toolkit",
      "mobile_app_testing_toolkit",
      "mobile_device_info",
      "mobile_device_management",
      "mobile_file_ops",
      "mobile_hardware",
      "mobile_network_analyzer",
      "mobile_system_tools"
    ]
  },
  "network": {
    "name": "Network Tools",
    "description": "Comprehensive network analysis and reconnaissance",
    "features": [
      "Network packet analysis",
      "Port scanning and discovery",
      "IP geolocation and triangulation",
      "OSINT reconnaissance",
      "Network vulnerability assessment",
      "Traffic analysis and monitoring",
      "Social media account discovery",
      "Modular social account ripper"
    ],
    "tools": 16,
    "toolList": [
      "download_file",
      "ip_geolocation",
      "latency_geolocation",
      "network_diagnostics",
      "network_discovery",
      "network_penetration",
      "network_traffic_analyzer",
      "network_triangulation",
      "network_utilities",
      "osint_reconnaissance",
      "packet_sniffer",
      "port_scanner",
      "social_account_ripper",
      "social_account_ripper_modular",
      "traffic_analysis",
      "vulnerability_assessment"
    ]
  },
  "penetration": {
    "name": "Penetration Testing",
    "description": "Comprehensive penetration testing and ethical hacking",
    "features": [
      "Network penetration testing",
      "Security assessment tools",
      "Network exploitation",
      "Penetration testing toolkit",
      "Social engineering toolkit"
    ],
    "tools": 5,
    "toolList": [
      "hack_network",
      "network_penetration",
      "penetration_testing_toolkit",
      "security_testing",
      "social_engineering_toolkit"
    ]
  },
  "process": {
    "name": "Process Management",
    "description": "Process execution and management tools",
    "features": [
      "Execute system commands",
      "Run processes with elevated privileges",
      "Cross-platform process management"
    ],
    "tools": 2,
    "toolList": [
      "proc_run",
      "proc_run_elevated"
    ]
  },
  "radio": {
    "name": "Radio & SDR Security",
    "description": "Software Defined Radio and signal analysis",
    "features": [
      "SDR security testing",
      "Radio signal analysis",
      "Signal decoding and analysis",
      "Radio frequency security"
    ],
    "tools": 3,
    "toolList": [
      "radio_security",
      "sdr_security_toolkit",
      "signal_analysis"
    ]
  },
  "security": {
    "name": "Security Tools",
    "description": "Advanced security testing and assessment",
    "features": [
      "Vulnerability scanning and assessment",
      "Password cracking and analysis",
      "Exploit development framework",
      "Network security testing",
      "Blockchain security analysis",
      "Quantum-resistant cryptography",
      "IoT security assessment",
      "Social engineering testing",
      "Threat intelligence gathering",
      "Compliance assessment",
      "Social network reconnaissance",
      "Metadata extraction and analysis",
      "Encryption and cryptographic operations",
      "Malware analysis and reverse engineering"
    ],
    "tools": 16,
    "toolList": [
      "blockchain_security",
      "compliance_assessment",
      "exploit_framework",
      "iot_security",
      "malware_analysis",
      "metadata_extractor",
      "network_security",
      "packet_sniffer",
      "password_cracker",
      "port_scanner",
      "quantum_security",
      "security_testing",
      "social_engineering",
      "social_network_ripper",
      "threat_intelligence",
      "vulnerability_scanner"
    ]
  },
  "social": {
    "tools": 1,
    "toolList": [
      "social_network_ripper"
    ]
  },
  "system": {
    "name": "System Administration",
    "description": "Advanced system management and monitoring",
    "features": [
      "System restore point management",
      "Elevated permissions handling",
      "Scheduled task management",
      "System performance monitoring"
    ],
    "tools": 4,
    "toolList": [
      "cron_job_manager",
      "elevated_permissions_manager",
      "system_monitor",
      "system_restore"
    ]
  },
  "utilities": {
    "name": "Utility Tools",
    "description": "Mathematical, data processing, and utility functions",
    "features": [
      "Mathematical calculations",
      "Data analysis and processing",
      "Chart and graph generation",
      "Text processing utilities",
      "Password generation",
      "Machine learning capabilities",
      "Dice rolling and gaming utilities"
    ],
    "tools": 11,
    "toolList": [
      "calculator",
      "chart_generator",
      "data_analysis",
      "data_analyzer",
      "dice_rolling",
      "download_file",
      "encryption_tool",
      "machine_learning",
      "math_calculate",
      "password_generator",
      "text_processor"
    ]
  },
  "virtualization": {
    "name": "Virtualization",
    "description": "Virtual machine and container management",
    "features": [
      "Virtual machine management",
      "Docker container management",
      "Container orchestration",
      "VM security and monitoring"
    ],
    "tools": 2,
    "toolList": [
      "docker_management",
      "vm_management"
    ]
  },
  "web": {
    "name": "Web Automation",
    "description": "Browser automation and web interaction tools",
    "features": [
      "Web scraping and data extraction",
      "Browser automation and control",
      "Web automation toolkit",
      "Webhook management",
      "Universal browser operations",
      "Web search capabilities",
      "Form completion and validation"
    ],
    "tools": 7,
    "toolList": [
      "browser_control",
      "form_completion",
      "universal_browser_operator",
      "webhook_manager",
      "web_automation",
      "web_scraper",
      "web_search"
    ]
  },
  "windows": {
    "name": "Windows Tools",
    "description": "Windows-specific system management",
    "features": [
      "Windows service management",
      "Windows process control",
      "Windows-specific operations"
    ],
    "tools": 2,
    "toolList": [
      "win_processes",
      "win_services"
    ]
  },
  "wireless": {
    "name": "Wireless Security",
    "description": "Wi-Fi and wireless network security testing",
    "features": [
      "Wi-Fi security assessment",
      "Wi-Fi penetration testing",
      "Wireless security testing",
      "Wireless network scanning",
      "Wireless network analysis"
    ],
    "tools": 4,
    "toolList": [
      "wifi_hacking",
      "wifi_security_toolkit",
      "wireless_network_scanner",
      "wireless_security"
    ]
  }
};

/**
 * Build a custom server with specified tools
 */
async function buildCustomServer(requestedTools, outputFile = 'custom-server.ts', serverName = 'Custom MCP Server') {
  console.log('🔧 Building Custom MCP Server...');
  console.log('================================');
  console.log('');
  
  // Validate requested tools
  const validTools = [];
  const invalidTools = [];
  
  requestedTools.forEach(tool => {
    if (AVAILABLE_TOOLS[tool]) {
      validTools.push(tool);
    } else {
      invalidTools.push(tool);
    }
  });
  
  if (invalidTools.length > 0) {
    console.log('❌ Invalid tools:');
    invalidTools.forEach(tool => console.log(`   - ${tool}`));
    console.log('');
  }
  
  if (validTools.length === 0) {
    console.log('❌ No valid tools specified!');
    console.log('');
    showAvailableTools();
    return;
  }
  
  console.log(`✅ Building server with ${validTools.length} tools:`);
  validTools.forEach(tool => console.log(`   - ${tool}`));
  console.log('');
  
  // Generate server content
  const serverContent = generateServerContent(validTools, serverName);
  
  // Write server file
  const outputPath = path.join(process.cwd(), outputFile);
  fs.writeFileSync(outputPath, serverContent);
  
  console.log(`✅ Custom server created: ${outputFile}`);
  console.log(`📁 Location: ${outputPath}`);
  console.log('');
  console.log('🚀 To use your custom server:');
  console.log(`   npx tsc ${outputFile} --outDir dist`);
  console.log(`   node dist/${outputFile.replace('.ts', '.js')}`);
  console.log('');
  console.log('💡 Alternative: Use the modular installer for better integration:');
  console.log(`   node install.js --modular --tools ${validTools.join(',')}`);
  console.log('');
}

/**
 * Generate server TypeScript content
 */
function generateServerContent(tools, serverName) {
  const imports = tools.map(tool => {
    const toolPath = AVAILABLE_TOOLS[tool];
    return `import { register${tool.charAt(0).toUpperCase() + tool.slice(1)} } from "${toolPath}.js";`;
  }).join('\n');
  
  const registrations = tools.map(tool => {
    return `  register${tool.charAt(0).toUpperCase() + tool.slice(1)}(server);`;
  }).join('\n');
  
  return `#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as path from "node:path";
import * as os from "node:os";
import * as fs from "node:fs/promises";
import { spawn, exec } from "node:child_process";
import { promisify } from "node:util";

// Import utility modules
import { PLATFORM, IS_WINDOWS, IS_LINUX, IS_MACOS, IS_ANDROID, IS_IOS, IS_MOBILE, config, PROC_ALLOWLIST, MAX_BYTES, MOBILE_CONFIG, COMMAND_MAPPINGS } from "./config/environment.js";
import { ALLOWED_ROOTS_ARRAY, getPlatformCommand, getMobilePermissions, isMobileFeatureAvailable, getMobileDeviceInfo, getFileOperationCommand, getMobileProcessCommand, getMobileServiceCommand, getMobileNetworkCommand, getMobileStorageCommand, getMobileUserCommand } from "./utils/platform.js";
import { sanitizeCommand, isDangerousCommand, shouldPerformSecurityChecks } from "./utils/security.js";
import { ensureInsideRoot, limitString } from "./utils/fileSystem.js";
import { logger, logServerStart } from "./utils/logger.js";

// Import selected tools
${imports}

const execAsync = promisify(exec);

// Log server startup
logServerStart(PLATFORM);

// ===========================================
// CUSTOM SERVER: ${serverName}
// ===========================================

const server = new McpServer({ name: "${serverName}", version: "1.6d" });

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
// REGISTER SELECTED TOOLS
// ===========================================

${registrations}

console.log(`✅ Successfully registered ${tools.length} tools`);

// ===========================================
// START THE SERVER
// ===========================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("${serverName} started successfully");
  console.log("🚀 **${serverName} STARTED**");
  console.log(`📊 Total Tools Available: ${Array.from(registeredTools).length}`);
  console.log("");
  console.log("🔧 **SELECTED TOOLS LOADED**");
  tools.forEach(tool => {
    console.log(`   - ${tool}`);
  });
  console.log("");
  console.log("🎯 **READY FOR OPERATION**");
}

main().catch((error) => {
  logger.error("Failed to start server:", error);
  process.exit(1);
});
`;
}

/**
 * Build modular server configuration from individual tools
 */
async function buildModularConfigFromTools(requestedTools) {
  console.log('🔧 Building Modular Server Configuration...');
  console.log('==========================================');
  console.log('');
  
  // Validate requested tools
  const validTools = [];
  const invalidTools = [];
  
  requestedTools.forEach(tool => {
    if (AVAILABLE_TOOLS[tool]) {
      validTools.push(tool);
    } else {
      invalidTools.push(tool);
    }
  });
  
  if (invalidTools.length > 0) {
    console.log('❌ Invalid tools:');
    invalidTools.forEach(tool => console.log(`   - ${tool}`));
    console.log('');
  }
  
  if (validTools.length === 0) {
    console.log('❌ No valid tools specified!');
    console.log('');
    showAvailableTools();
    return;
  }
  
  console.log(`✅ Creating modular configuration with ${validTools.length} tools:`);
  validTools.forEach(tool => console.log(`   - ${tool}`));
  console.log('');
  
  try {
    // Import the tool configuration system
    const { createConfigFromTools, saveToolConfig } = await import('./dist/config/tool-config.js');
    
    const config = createConfigFromTools(validTools);
    await saveToolConfig(config);
    
    console.log('✅ Modular server configuration created');
    console.log('📁 Configuration saved to: tool-config.json');
    console.log('');
    console.log('🚀 To use your modular server:');
    console.log('   npm run build && node dist/server-modular.js');
    console.log('');
  } catch (error) {
    console.error('❌ Failed to create modular configuration:', error);
    console.log('');
    console.log('💡 Fallback: Use the custom server builder instead');
    await buildCustomServer(validTools);
  }
}

/**
 * Show available tools organized by category
 */
function showAvailableTools() {
  console.log('📋 Available Tools by Category:');
  console.log('===============================');
  console.log('');
  
  Object.entries(TOOL_CATEGORIES).forEach(([category, data]) => {
    console.log(`🔹 ${data.name} (${data.tools} tools):`);
    data.toolList.forEach(tool => {
      console.log(`   - ${tool}`);
    });
    console.log('');
  });
  
  console.log('💡 Usage: node build-server.js <tool1> <tool2> ... <toolN>');
  console.log('Example: node build-server.js health system_info fs_list');
  console.log('');
  console.log('🔧 Modular Configuration:');
  console.log('   node build-server.js --modular <tool1> <tool2> ... <toolN>');
  console.log('Example: node build-server.js --modular health system_info fs_list');
  console.log('');
}

// Main execution
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    showAvailableTools();
    return;
  }
  
  if (args.includes('--list') || args.includes('-l')) {
    showAvailableTools();
    return;
  }
  
  // Check for modular configuration
  if (args.includes('--modular')) {
    // Extract tools (excluding --modular and other flags)
    const tools = args.filter(arg => !arg.startsWith('--') && !arg.startsWith('-'));
    
    if (tools.length === 0) {
      console.log('❌ No tools specified for modular configuration!');
      console.log('');
      showAvailableTools();
      return;
    }
    
    buildModularConfigFromTools(tools);
    return;
  }
  
  // Extract tools and options for custom server
  const tools = args.filter(arg => !arg.startsWith('--') && !arg.startsWith('-'));
  const outputFile = args.includes('--output') ? args[args.indexOf('--output') + 1] : 'custom-server.ts';
  const serverName = args.includes('--name') ? args[args.indexOf('--name') + 1] : 'Custom MCP Server';
  
  if (tools.length === 0) {
    console.log('❌ No tools specified!');
    console.log('');
    showAvailableTools();
    return;
  }
  
  buildCustomServer(tools, outputFile, serverName);
}

export { AVAILABLE_TOOLS, TOOL_CATEGORIES, buildCustomServer };
