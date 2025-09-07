#!/usr/bin/env node

import fs from 'fs';
import path from 'path';

/**
 * Dynamic Modular Installer Updater
 * Automatically discovers and populates tools based on the actual files in src/tools/
 */

// Tool category mappings
const CATEGORY_MAPPINGS = {
  'core': {
    name: 'Core System Tools',
    description: 'Essential system monitoring and health check tools',
    features: [
      'System health monitoring',
      'Basic system information retrieval',
      'Essential for all server operations'
    ]
  },
  'file_system': {
    name: 'File System Tools',
    description: 'Complete file and directory management capabilities',
    features: [
      'Directory listing and navigation',
      'Text file reading and writing',
      'File search and discovery',
      'Advanced file operations',
      'Real-time file system monitoring'
    ]
  },
  'process': {
    name: 'Process Management',
    description: 'Process execution and management tools',
    features: [
      'Execute system commands',
      'Run processes with elevated privileges',
      'Cross-platform process management'
    ]
  },
  'system': {
    name: 'System Administration',
    description: 'Advanced system management and monitoring',
    features: [
      'System restore point management',
      'Elevated permissions handling',
      'Scheduled task management',
      'System performance monitoring'
    ]
  },
  'git': {
    name: 'Git Integration',
    description: 'Version control and repository management',
    features: [
      'Git repository status checking',
      'Version control integration'
    ]
  },
  'windows': {
    name: 'Windows Tools',
    description: 'Windows-specific system management',
    features: [
      'Windows service management',
      'Windows process control',
      'Windows-specific operations'
    ]
  },
  'network': {
    name: 'Network Tools',
    description: 'Comprehensive network analysis and reconnaissance',
    features: [
      'Network packet analysis',
      'Port scanning and discovery',
      'IP geolocation and triangulation',
      'OSINT reconnaissance',
      'Network vulnerability assessment',
      'Traffic analysis and monitoring',
      'Social media account discovery',
      'Modular social account ripper'
    ]
  },
  'security': {
    name: 'Security Tools',
    description: 'Advanced security testing and assessment',
    features: [
      'Vulnerability scanning and assessment',
      'Password cracking and analysis',
      'Exploit development framework',
      'Network security testing',
      'Blockchain security analysis',
      'Quantum-resistant cryptography',
      'IoT security assessment',
      'Social engineering testing',
      'Threat intelligence gathering',
      'Compliance assessment',
      'Social network reconnaissance',
      'Metadata extraction and analysis',
      'Encryption and cryptographic operations',
      'Malware analysis and reverse engineering'
    ]
  },
  'penetration': {
    name: 'Penetration Testing',
    description: 'Comprehensive penetration testing and ethical hacking',
    features: [
      'Network penetration testing',
      'Security assessment tools',
      'Network exploitation',
      'Penetration testing toolkit',
      'Social engineering toolkit'
    ]
  },
  'wireless': {
    name: 'Wireless Security',
    description: 'Wi-Fi and wireless network security testing',
    features: [
      'Wi-Fi security assessment',
      'Wi-Fi penetration testing',
      'Wireless security testing',
      'Wireless network scanning',
      'Wireless network analysis'
    ]
  },
  'bluetooth': {
    name: 'Bluetooth Security',
    description: 'Bluetooth device security and management',
    features: [
      'Bluetooth security testing',
      'Bluetooth penetration testing',
      'Bluetooth device management',
      'Bluetooth vulnerability assessment'
    ]
  },
  'radio': {
    name: 'Radio & SDR Security',
    description: 'Software Defined Radio and signal analysis',
    features: [
      'SDR security testing',
      'Radio signal analysis',
      'Signal decoding and analysis',
      'Radio frequency security'
    ]
  },
  'web': {
    name: 'Web Automation',
    description: 'Browser automation and web interaction tools',
    features: [
      'Web scraping and data extraction',
      'Browser automation and control',
      'Web automation toolkit',
      'Webhook management',
      'Universal browser operations',
      'Web search capabilities',
      'Form completion and validation'
    ]
  },
  'email': {
    name: 'Email Management',
    description: 'Comprehensive email processing and management',
    features: [
      'Email sending and receiving',
      'Email parsing and analysis',
      'Email account management',
      'Email organization and sorting',
      'Email deletion and cleanup'
    ]
  },
  'media': {
    name: 'Media Processing',
    description: 'Video, image, and audio editing capabilities',
    features: [
      'Video editing and processing',
      'Optical Character Recognition (OCR)',
      'Image editing and manipulation',
      'Audio editing and processing'
    ]
  },
  'screenshot': {
    name: 'Screenshot Tools',
    description: 'Screen capture and screenshot capabilities',
    features: [
      'Screen capture functionality',
      'Window and region screenshot',
      'Cross-platform screenshot support'
    ]
  },
  'mobile': {
    name: 'Mobile Tools',
    description: 'Comprehensive mobile device management and app development',
    features: [
      'Mobile device information and management',
      'Mobile file operations',
      'Mobile app analytics and monitoring',
      'Mobile app deployment and optimization',
      'Mobile app security testing',
      'Mobile app performance analysis',
      'Mobile network analysis'
    ]
  },
  'virtualization': {
    name: 'Virtualization',
    description: 'Virtual machine and container management',
    features: [
      'Virtual machine management',
      'Docker container management',
      'Container orchestration',
      'VM security and monitoring'
    ]
  },
  'utilities': {
    name: 'Utility Tools',
    description: 'Mathematical, data processing, and utility functions',
    features: [
      'Mathematical calculations',
      'Data analysis and processing',
      'Chart and graph generation',
      'Text processing utilities',
      'Password generation',
      'Machine learning capabilities',
      'Dice rolling and gaming utilities'
    ]
  },
  'cloud': {
    name: 'Cloud Security',
    description: 'Cloud infrastructure security and management',
    features: [
      'Cloud security assessment',
      'Cloud infrastructure management',
      'Multi-cloud security toolkit',
      'Cloud compliance validation'
    ]
  },
  'forensics': {
    name: 'Digital Forensics',
    description: 'Digital forensics and incident response',
    features: [
      'Digital forensics analysis',
      'Evidence collection and preservation',
      'Malware analysis and reverse engineering',
      'Incident response capabilities'
    ]
  },
  'discovery': {
    name: 'Tool Discovery',
    description: 'Tool discovery and exploration capabilities',
    features: [
      'Tool discovery and exploration',
      'Category exploration',
      'Tool capability analysis'
    ]
  },
  'legal': {
    name: 'Legal Compliance',
    description: 'Legal compliance and audit management',
    features: [
      'Legal compliance management',
      'Audit logging and evidence preservation',
      'Chain of custody tracking',
      'Regulatory compliance support'
    ]
  }
};

/**
 * Discover all available tools in the src/tools directory
 */
function discoverTools() {
  const toolsDir = path.join(process.cwd(), 'src', 'tools');
  const tools = {};
  
  if (!fs.existsSync(toolsDir)) {
    console.error('❌ Tools directory not found:', toolsDir);
    return tools;
  }

  // Read all subdirectories in tools/
  const categories = fs.readdirSync(toolsDir, { withFileTypes: true })
    .filter(dirent => dirent.isDirectory())
    .map(dirent => dirent.name);

  for (const category of categories) {
    const categoryPath = path.join(toolsDir, category);
    const categoryTools = [];

    // Read all .ts files in the category directory
    const files = fs.readdirSync(categoryPath, { withFileTypes: true })
      .filter(dirent => dirent.isFile() && dirent.name.endsWith('.ts') && dirent.name !== 'index.ts')
      .map(dirent => dirent.name.replace('.ts', ''));

    for (const file of files) {
      const toolName = file;
      categoryTools.push(toolName);
    }

    if (categoryTools.length > 0) {
      tools[category] = {
        ...CATEGORY_MAPPINGS[category],
        tools: categoryTools.length,
        toolList: categoryTools
      };
    }
  }

  return tools;
}

/**
 * Generate the updated install.js content
 */
function generateInstallJS(tools) {
  const totalTools = Object.values(tools).reduce((sum, cat) => sum + cat.tools, 0);
  const currentDate = new Date().toISOString();
  
  return `#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// Auto-generated tool categories based on actual tools in src/tools/
// Generated on: ${currentDate}
// Total tools discovered: ${totalTools}

const TOOL_CATEGORIES = ${JSON.stringify(tools, null, 2)};

// Server configurations
const SERVER_CONFIGS = {
  'minimal': {
    name: 'Minimal Server',
    description: 'Essential tools for basic functionality',
    tools: 15,
    categories: ['core', 'file_system', 'process'],
    features: [
      'System health monitoring',
      'Basic file operations',
      'Process execution',
      'Essential for all operations'
    ]
  },
  'modular': {
    name: 'Modular Server',
    description: 'All available tools in modular architecture',
    tools: ${totalTools},
    categories: Object.keys(TOOL_CATEGORIES),
    features: [
      'Complete tool coverage',
      'Modular architecture',
      'All ${totalTools} tools available',
      'Professional security platform'
    ]
  },
  'full': {
    name: 'Full Server',
    description: 'Complete server with all tools',
    tools: ${totalTools + 5}, // +5 for additional tools in server-refactored
    categories: Object.keys(TOOL_CATEGORIES),
    features: [
      'Complete tool coverage',
      'Enhanced security tools',
      'Legal compliance features',
      'Professional-grade platform'
    ]
  }
};

// Interactive installer
async function runInstaller() {
  console.log('🚀 MCP God Mode - Dynamic Modular Installer');
  console.log('==========================================');
  console.log('');
  console.log('📊 Available Server Configurations:');
  console.log('');

  Object.entries(SERVER_CONFIGS).forEach(([key, config], index) => {
    console.log(\`\${index + 1}. \${config.name}\`);
    console.log(\`   Description: \${config.description}\`);
    console.log(\`   Tools: \${config.tools}\`);
    console.log(\`   Categories: \${config.categories.length}\`);
    console.log('');
  });

  console.log('🔧 Available Tool Categories:');
  console.log('');
  
  Object.entries(TOOL_CATEGORIES).forEach(([key, category], index) => {
    console.log(\`\${index + 1}. \${category.name} (\${category.tools} tools)\`);
    console.log(\`   \${category.description}\`);
    console.log('');
  });

  console.log('📋 Tool Details:');
  console.log('');
  
  Object.entries(TOOL_CATEGORIES).forEach(([key, category]) => {
    console.log(\`🔹 \${category.name}:\`);
    category.toolList.forEach(tool => {
      console.log(\`   - \${tool}\`);
    });
    console.log('');
  });

  console.log('✅ Installation Options:');
  console.log('');
  console.log('1. Install Minimal Server (15 tools)');
  console.log('2. Install Modular Server (${totalTools} tools)');
  console.log('3. Install Full Server (${totalTools + 5} tools)');
  console.log('4. Build Custom Server');
  console.log('5. Show Tool Information');
  console.log('6. Exit');
  console.log('');

  console.log('💡 To install, run one of these commands:');
  console.log('');
  console.log('npm run install:minimal    # Install minimal server');
  console.log('npm run install:modular    # Install modular server');
  console.log('npm run install:full       # Install full server');
  console.log('node build-server.js       # Build custom server');
  console.log('');
}

// Build custom server
async function buildCustomServer() {
  console.log('🔧 Custom Server Builder');
  console.log('========================');
  console.log('');
  console.log('Available tools by category:');
  console.log('');
  
  Object.entries(TOOL_CATEGORIES).forEach(([key, category]) => {
    console.log(\`📁 \${category.name}:\`);
    category.toolList.forEach(tool => {
      console.log(\`   \${tool}\`);
    });
    console.log('');
  });
  
  console.log('💡 Usage: node build-server.js <tool1> <tool2> ... <toolN>');
  console.log('Example: node build-server.js health system_info fs_list');
  console.log('');
}

// Main execution
if (import.meta.url === \`file://\${process.argv[1]}\`) {
  const args = process.argv.slice(2);
  
  if (args.includes('--custom') || args.includes('-c')) {
    buildCustomServer();
  } else {
    runInstaller();
  }
}

export { TOOL_CATEGORIES, SERVER_CONFIGS, discoverTools };
`;
}

/**
 * Generate the updated build-server.js content
 */
function generateBuildServerJS(tools) {
  const availableTools = {};
  
  // Build the AVAILABLE_TOOLS object
  Object.entries(tools).forEach(([category, categoryData]) => {
    categoryData.toolList.forEach(tool => {
      availableTools[tool] = `./tools/${category}/${tool}`;
    });
  });

  const currentDate = new Date().toISOString();
  const totalTools = Object.keys(availableTools).length;

  return `#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// Auto-generated available tools based on actual files in src/tools/
// Generated on: ${currentDate}
// Total tools: ${totalTools}

const AVAILABLE_TOOLS = ${JSON.stringify(availableTools, null, 2)};

// Tool categories for organization
const TOOL_CATEGORIES = ${JSON.stringify(tools, null, 2)};

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
    invalidTools.forEach(tool => console.log(\`   - \${tool}\`));
    console.log('');
  }
  
  if (validTools.length === 0) {
    console.log('❌ No valid tools specified!');
    console.log('');
    showAvailableTools();
    return;
  }
  
  console.log(\`✅ Building server with \${validTools.length} tools:\`);
  validTools.forEach(tool => console.log(\`   - \${tool}\`));
  console.log('');
  
  // Generate server content
  const serverContent = generateServerContent(validTools, serverName);
  
  // Write server file
  const outputPath = path.join(process.cwd(), outputFile);
  fs.writeFileSync(outputPath, serverContent);
  
  console.log(\`✅ Custom server created: \${outputFile}\`);
  console.log(\`📁 Location: \${outputPath}\`);
  console.log('');
  console.log('🚀 To use your custom server:');
  console.log(\`   npx tsc \${outputFile} --outDir dist\`);
  console.log(\`   node dist/\${outputFile.replace('.ts', '.js')}\`);
  console.log('');
}

/**
 * Generate server TypeScript content
 */
function generateServerContent(tools, serverName) {
  const imports = tools.map(tool => {
    const toolPath = AVAILABLE_TOOLS[tool];
    return \`import { register\${tool.charAt(0).toUpperCase() + tool.slice(1)} } from "\${toolPath}.js";\`;
  }).join('\\n');
  
  const registrations = tools.map(tool => {
    return \`  register\${tool.charAt(0).toUpperCase() + tool.slice(1)}(server);\`;
  }).join('\\n');
  
  return \`#!/usr/bin/env node

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
\${imports}

const execAsync = promisify(exec);

// Log server startup
logServerStart(PLATFORM);

// ===========================================
// CUSTOM SERVER: \${serverName}
// ===========================================

const server = new McpServer({ name: "\${serverName}", version: "1.6d" });

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

\${registrations}

console.log(\`✅ Successfully registered \${tools.length} tools\`);

// ===========================================
// START THE SERVER
// ===========================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("\${serverName} started successfully");
  console.log("🚀 **\${serverName} STARTED**");
  console.log(\`📊 Total Tools Available: \${Array.from(registeredTools).length}\`);
  console.log("");
  console.log("🔧 **SELECTED TOOLS LOADED**");
  tools.forEach(tool => {
    console.log(\`   - \${tool}\`);
  });
  console.log("");
  console.log("🎯 **READY FOR OPERATION**");
}

main().catch((error) => {
  logger.error("Failed to start server:", error);
  process.exit(1);
});
\`;
}

/**
 * Show available tools organized by category
 */
function showAvailableTools() {
  console.log('📋 Available Tools by Category:');
  console.log('===============================');
  console.log('');
  
  Object.entries(TOOL_CATEGORIES).forEach(([category, data]) => {
    console.log(\`🔹 \${data.name} (\${data.tools} tools):\`);
    data.toolList.forEach(tool => {
      console.log(\`   - \${tool}\`);
    });
    console.log('');
  });
  
  console.log('💡 Usage: node build-server.js <tool1> <tool2> ... <toolN>');
  console.log('Example: node build-server.js health system_info fs_list');
  console.log('');
}

// Main execution
if (import.meta.url === \`file://\${process.argv[1]}\`) {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    showAvailableTools();
    return;
  }
  
  if (args.includes('--list') || args.includes('-l')) {
    showAvailableTools();
    return;
  }
  
  // Extract tools and options
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
`;
}

/**
 * Update package.json scripts
 */
function updatePackageScripts(tools) {
  const totalTools = Object.values(tools).reduce((sum, cat) => sum + cat.tools, 0);
  
  const packageJsonPath = path.join(process.cwd(), 'package.json');
  
  if (fs.existsSync(packageJsonPath)) {
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    
    // Update scripts
    packageJson.scripts = {
      ...packageJson.scripts,
      'install:minimal': 'node install.js --minimal',
      'install:modular': 'node install.js --modular',
      'install:full': 'node install.js --full',
      'build:custom': 'node build-server.js',
      'update:installer': 'node update-modular-installer.js',
      'discover:tools': 'node update-modular-installer.js --discover'
    };
    
    // Update version info
    packageJson.mcpGodMode = {
      ...packageJson.mcpGodMode,
      totalTools: totalTools,
      lastUpdated: new Date().toISOString(),
      toolCategories: Object.keys(tools).length
    };
    
    fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2));
    console.log('✅ Updated package.json with new scripts and tool information');
  }
}

/**
 * Main execution
 */
async function main() {
  console.log('🔍 Discovering tools in src/tools/...');
  console.log('');
  
  const tools = discoverTools();
  const totalTools = Object.values(tools).reduce((sum, cat) => sum + cat.tools, 0);
  
  if (totalTools === 0) {
    console.log('❌ No tools discovered!');
    return;
  }
  
  console.log(`✅ Discovered ${totalTools} tools in ${Object.keys(tools).length} categories`);
  console.log('');
  
  // Show discovered tools
  console.log('📋 Discovered Tools:');
  Object.entries(tools).forEach(([category, data]) => {
    console.log(`🔹 ${data.name}: ${data.tools} tools`);
  });
  console.log('');
  
  // Generate updated files
  console.log('📝 Generating updated installer files...');
  
  // Update install.js
  const installJSContent = generateInstallJS(tools);
  fs.writeFileSync('install.js', installJSContent);
  console.log('✅ Updated install.js');
  
  // Update build-server.js
  const buildServerJSContent = generateBuildServerJS(tools);
  fs.writeFileSync('build-server.js', buildServerJSContent);
  console.log('✅ Updated build-server.js');
  
  // Update package.json
  updatePackageScripts(tools);
  
  console.log('');
  console.log('🎉 Modular installer successfully updated!');
  console.log('');
  console.log('📊 Summary:');
  console.log(`   - Total tools: ${totalTools}`);
  console.log(`   - Categories: ${Object.keys(tools).length}`);
  console.log(`   - Files updated: install.js, build-server.js, package.json`);
  console.log('');
  console.log('🚀 Usage:');
  console.log('   node install.js              # Interactive installer');
  console.log('   node build-server.js         # Custom server builder');
  console.log('   npm run install:modular      # Install modular server');
  console.log('   npm run build:custom         # Build custom server');
  console.log('');
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  
  if (args.includes('--discover') || args.includes('-d')) {
    const tools = discoverTools();
    console.log('🔍 Tool Discovery Results:');
    console.log('==========================');
    console.log('');
    Object.entries(tools).forEach(([category, data]) => {
      console.log(`📁 ${category} (${data.tools} tools):`);
      data.toolList.forEach(tool => {
        console.log(`   - ${tool}`);
      });
      console.log('');
    });
  } else {
    main().catch(console.error);
  }
}

export { discoverTools, generateInstallJS, generateBuildServerJS, updatePackageScripts };