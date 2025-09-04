#!/usr/bin/env node

/**
 * Tool Extraction Script for MCP God Mode
 * 
 * This script extracts all tools from server-refactored.ts and creates
 * modular versions in the dev/src/tools directory structure.
 * 
 * Usage: node dev/extract-tools.js
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Tool categories and their existing directories
const TOOL_CATEGORIES = {
  core: ['health', 'system_info'],
  file_system: ['fs_list', 'fs_read_text', 'fs_write_text', 'fs_search', 'file_ops'],
  process: ['proc_run', 'proc_run_elevated'],
  git: ['git_status'],
  windows: ['win_services', 'win_processes'],
  utilities: ['calculator', 'dice_rolling', 'math_calculate'],
  virtualization: ['vm_management', 'docker_management'],
  mobile: ['mobile_device_info', 'mobile_file_ops', 'mobile_system_tools', 'mobile_hardware'],
  system: ['system_restore'],
  wireless: ['wifi_security_toolkit', 'wifi_hacking', 'wireless_security'],
  network: ['packet_sniffer', 'port_scanner', 'network_diagnostics', 'download_file'],
  security: ['vulnerability_scanner', 'password_cracker', 'exploit_framework'],
  bluetooth: ['bluetooth_security_toolkit', 'bluetooth_hacking'],
  radio: ['sdr_security_toolkit', 'radio_security', 'signal_analysis'],
  penetration: ['hack_network', 'security_testing', 'network_penetration'],
  web: ['web_scraper', 'browser_control'],
  email: ['send_email', 'read_emails', 'parse_email', 'delete_emails', 'sort_emails', 'manage_email_accounts'],
  media: ['video_editing', 'audio_editing', 'screenshot', 'ocr_tool']
};

// Tools that are already modularized
const EXISTING_MODULAR_TOOLS = new Set([
  'health', 'system_info',
  'fs_list', 'fs_read_text', 'fs_write_text', 'fs_search', 'file_ops',
  'proc_run', 'proc_run_elevated',
  'git_status',
  'calculator', 'dice_rolling', 'math_calculate',
  'vulnerability_scanner', 'port_scanner', 'password_cracker', 'exploit_framework',
  'packet_sniffer',
  'network_diagnostics', 'download_file',
  'web_scraper',
  'send_email', 'read_emails', 'parse_email', 'delete_emails', 'sort_emails', 'manage_email_accounts',
  'video_editing', 'ocr_tool',
  'audio_editing', 'screenshot'
]);

// Tools that need to be extracted
const TOOLS_TO_EXTRACT = [
  'win_services', 'win_processes',
  'vm_management', 'docker_management',
  'mobile_device_info', 'mobile_file_ops', 'mobile_system_tools', 'mobile_hardware',
  'system_restore',
  'wifi_security_toolkit', 'wifi_hacking', 'wireless_security',
  'bluetooth_security_toolkit', 'bluetooth_hacking',
  'sdr_security_toolkit', 'radio_security', 'signal_analysis',
  'hack_network', 'security_testing', 'network_penetration',
  'browser_control'
];

// Template for tool files
const TOOL_TEMPLATE = (toolName, description, inputSchema, outputSchema, helperFunctions = '') => `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import * as os from "node:os";
import * as fs from "node:fs/promises";
import { spawn, exec } from "node:child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

export function register${toolName.charAt(0).toUpperCase() + toolName.slice(1).replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())}(server: McpServer) {
  server.registerTool("${toolName}", {
    description: "${description}",
    inputSchema: ${inputSchema},
    outputSchema: ${outputSchema}
  }, async (params) => {
    // TODO: Implement actual tool logic
    // This is a placeholder implementation
    console.log(\`${toolName} tool called with params:\`, params);
    
    return {
      content: [{ type: "text", text: \`${toolName} tool executed successfully\` }],
      structuredContent: {
        success: true,
        tool: "${toolName}",
        message: "Tool executed successfully (placeholder implementation)"
      }
    };
  });
}

${helperFunctions}
`;

// Template for index files
const INDEX_TEMPLATE = (category, tools) => {
  const imports = tools.map(tool => 
    `import { register${tool.charAt(0).toUpperCase() + tool.slice(1).replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())} } from "./${tool}.js";`
  ).join('\n');
  
  const exports = tools.map(tool => 
    `export { register${tool.charAt(0).toUpperCase() + tool.slice(1).replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())} } from "./${tool}.js";`
  ).join('\n');
  
  return `${imports}

${exports}
`;
};

// Extract tool information from server-refactored.ts
async function extractToolInfo() {
  try {
    const serverRefactoredPath = path.join(__dirname, 'src', 'server-refactored.ts');
    console.log('Reading file:', serverRefactoredPath);
    
    const content = await fs.readFile(serverRefactoredPath, 'utf8');
    console.log('File size:', content.length, 'characters');
    
    const toolInfo = {};
    
    // Find all tool registrations
    const toolRegex = /server\.registerTool\("([^"]+)",\s*\{([^}]+)\}/g;
    let match;
    let count = 0;
    
    while ((match = toolRegex.exec(content)) !== null) {
      count++;
      const toolName = match[1];
      const toolConfig = match[2];
      
      // Extract description
      const descMatch = toolConfig.match(/description:\s*"([^"]+)"/);
      const description = descMatch ? descMatch[1] : `Tool for ${toolName}`;
      
      // Extract input schema
      const inputMatch = toolConfig.match(/inputSchema:\s*(\{[^}]+\})/);
      const inputSchema = inputMatch ? inputMatch[1] : '{}';
      
      // Extract output schema
      const outputMatch = toolConfig.match(/outputSchema:\s*(\{[^}]+\})/);
      const outputSchema = outputMatch ? outputMatch[1] : '{}';
      
      toolInfo[toolName] = {
        description,
        inputSchema,
        outputSchema
      };
    }
    
    console.log('Found', count, 'tool registrations');
    return toolInfo;
  } catch (error) {
    console.error('Error extracting tool info:', error);
    return {};
  }
}

// Create tool files
async function createToolFiles(toolInfo) {
  for (const toolName of TOOLS_TO_EXTRACT) {
    if (toolInfo[toolName]) {
      const info = toolInfo[toolName];
      
      // Determine category
      let category = 'utilities';
      for (const [cat, tools] of Object.entries(TOOL_CATEGORIES)) {
        if (tools.includes(toolName)) {
          category = cat;
          break;
        }
      }
      
      // Create category directory if it doesn't exist
      const categoryDir = path.join(__dirname, 'src', 'tools', category);
      await fs.mkdir(categoryDir, { recursive: true });
      
      // Create tool file
      const toolFilePath = path.join(categoryDir, `${toolName}.ts`);
      const toolContent = TOOL_TEMPLATE(
        toolName,
        info.description,
        info.inputSchema,
        info.outputSchema
      );
      
      await fs.writeFile(toolFilePath, toolContent);
      console.log(`Created: ${toolFilePath}`);
      
      // Update or create index file
      const indexFilePath = path.join(categoryDir, 'index.ts');
      let indexContent = '';
      
      try {
        indexContent = await fs.readFile(indexFilePath, 'utf8');
      } catch (error) {
        // File doesn't exist, create new
        indexContent = '';
      }
      
      // Add new tool to index
      const toolsInCategory = TOOL_CATEGORIES[category] || [];
      const existingTools = toolsInCategory.filter(t => {
        try {
          return fs.existsSync(path.join(categoryDir, `${t}.ts`));
        } catch {
          return false;
        }
      });
      
      if (!existingTools.includes(toolName)) {
        existingTools.push(toolName);
      }
      
      const newIndexContent = INDEX_TEMPLATE(category, existingTools);
      await fs.writeFile(indexFilePath, newIndexContent);
      console.log(`Updated: ${indexFilePath}`);
    } else {
      console.log(`Warning: No info found for tool: ${toolName}`);
    }
  }
}

// Update server-modular.ts with new imports
async function updateModularServer() {
  try {
    const modularServerPath = path.join(__dirname, 'src', 'server-modular.ts');
    let content = await fs.readFile(modularServerPath, 'utf8');
    
    // Add new imports
    const newImports = [];
    
    for (const toolName of TOOLS_TO_EXTRACT) {
      let category = 'utilities';
      for (const [cat, tools] of Object.entries(TOOL_CATEGORIES)) {
        if (tools.includes(toolName)) {
          category = cat;
          break;
        }
      }
      
      const importName = `register${toolName.charAt(0).toUpperCase() + toolName.slice(1).replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())}`;
      newImports.push(`import { ${importName} } from "./tools/${category}/${toolName}.js";`);
    }
    
    // Find the import section and add new imports
    const importSectionEnd = content.indexOf('// Import tool modules');
    if (importSectionEnd !== -1) {
      const beforeImports = content.substring(0, importSectionEnd);
      const afterImports = content.substring(importSectionEnd);
      
      content = beforeImports + newImports.join('\n') + '\n\n' + afterImports;
    }
    
    // Add tool registrations
    const registrationSection = content.indexOf('// Register security tools');
    if (registrationSection !== -1) {
      const beforeReg = content.substring(0, registrationSection);
      const afterReg = content.substring(registrationSection);
      
      const newRegistrations = TOOLS_TO_EXTRACT.map(toolName => {
        const funcName = `register${toolName.charAt(0).toUpperCase() + toolName.slice(1).replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())}`;
        return `${funcName}(server);`;
      }).join('\n');
      
      content = beforeReg + '\n// Register new tools\n' + newRegistrations + '\n\n' + afterReg;
    }
    
    await fs.writeFile(modularServerPath, content);
    console.log('Updated: server-modular.ts');
    
  } catch (error) {
    console.error('Error updating modular server:', error);
  }
}

// Main execution
async function main() {
  console.log('🔧 MCP God Mode Tool Extraction Script');
  console.log('=====================================\n');
  
  console.log('📋 Extracting tool information...');
  const toolInfo = await extractToolInfo();
  console.log(`Found ${Object.keys(toolInfo).length} tools\n`);
  
  console.log('🛠️  Creating modular tool files...');
  await createToolFiles(toolInfo);
  console.log('');
  
  console.log('🔄 Updating modular server...');
  await updateModularServer();
  console.log('');
  
  console.log('✅ Tool extraction completed!');
  console.log(`📁 Created ${TOOLS_TO_EXTRACT.length} new modular tools`);
  console.log('🔗 Updated server-modular.ts with new imports');
  console.log('\n📝 Next steps:');
  console.log('1. Review the generated tool files');
  console.log('2. Implement actual tool logic in place of placeholders');
  console.log('3. Test the modular server');
  console.log('4. Update documentation as needed');
}

// Run the script
console.log('Script starting...');
main().catch(console.error);
