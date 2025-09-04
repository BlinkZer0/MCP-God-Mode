#!/usr/bin/env node

/**
 * Fix Index Files Script for MCP God Mode
 * 
 * This script fixes the index files to properly export all tools in each category.
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Tool categories and their tools
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
  security: ['vulnerability_scanner', 'port_scanner', 'password_cracker', 'exploit_framework'],
  bluetooth: ['bluetooth_security_toolkit', 'bluetooth_hacking'],
  radio: ['sdr_security_toolkit', 'radio_security', 'signal_analysis'],
  penetration: ['hack_network', 'security_testing', 'network_penetration'],
  web: ['web_scraper', 'browser_control'],
  email: ['send_email', 'read_emails', 'parse_email', 'delete_emails', 'sort_emails', 'manage_email_accounts'],
  media: ['video_editing', 'audio_editing', 'screenshot', 'ocr_tool']
};

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

// Fix index files
async function fixIndexFiles() {
  for (const [category, tools] of Object.entries(TOOL_CATEGORIES)) {
    const categoryDir = path.join(__dirname, 'src', 'tools', category);
    
    try {
      // Check if directory exists
      await fs.access(categoryDir);
      
      // Check which tools actually exist as files
      const existingTools = [];
      for (const tool of tools) {
        try {
          await fs.access(path.join(categoryDir, `${tool}.ts`));
          existingTools.push(tool);
        } catch (error) {
          // Tool file doesn't exist, skip it
        }
      }
      
      if (existingTools.length > 0) {
        // Create or update index file
        const indexFilePath = path.join(categoryDir, 'index.ts');
        const indexContent = INDEX_TEMPLATE(category, existingTools);
        
        await fs.writeFile(indexFilePath, indexContent);
        console.log(`✅ Fixed: ${category}/index.ts (${existingTools.length} tools)`);
      }
      
    } catch (error) {
      // Category directory doesn't exist, skip it
    }
  }
}

// Main execution
async function main() {
  console.log('🔧 Fixing Index Files Script');
  console.log('============================\n');
  
  console.log('🛠️  Fixing index files...');
  await fixIndexFiles();
  console.log('');
  
  console.log('✅ Index files fixed!');
}

main().catch(console.error);
