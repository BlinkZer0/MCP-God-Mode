#!/usr/bin/env node

/**
 * Fix Tool Format Script for MCP God Mode
 * 
 * This script fixes the tool format in existing tool files to match the correct MCP SDK format.
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Files that need fixing
const FILES_TO_FIX = [
  'src/tools/email/delete_emails.ts',
  'src/tools/email/read_emails.ts',
  'src/tools/email/sort_emails.ts',
  'src/tools/network/download_file.ts',
  'src/tools/network/network_diagnostics.ts',
  'src/tools/utilities/calculator.ts',
  'src/tools/utilities/math_calculate.ts'
];

// Fix tool format
async function fixToolFormat() {
  for (const filePath of FILES_TO_FIX) {
    const fullPath = path.join(__dirname, filePath);
    
    try {
      let content = await fs.readFile(fullPath, 'utf8');
      
      // Replace the old format with the new format
      // Old: }, async handler({ ... }) { ... }, });
      // New: }, async ({ ... }) => { ... });
      
      // Find the handler function and convert it to callback format
      const handlerRegex = /,\s*async\s+handler\s*\(\s*\{([^}]+)\}\s*\)\s*\{([^}]+)\}\s*,\s*\}\);?\s*$/;
      const match = content.match(handlerRegex);
      
      if (match) {
        const params = match[1].trim();
        const body = match[2].trim();
        
        // Convert to callback format
        const newCallback = `}, async ({ ${params} }) => {
      ${body}
    });`;
        
        // Replace the old format
        content = content.replace(handlerRegex, newCallback);
        
        await fs.writeFile(fullPath, content);
        console.log(`✅ Fixed: ${filePath}`);
      } else {
        console.log(`⚠️  No handler found in: ${filePath}`);
      }
      
    } catch (error) {
      console.error(`❌ Error fixing ${filePath}:`, error.message);
    }
  }
}

// Main execution
async function main() {
  console.log('🔧 Fixing Tool Format Script');
  console.log('============================\n');
  
  console.log('🛠️  Fixing tool format...');
  await fixToolFormat();
  console.log('');
  
  console.log('✅ Tool format fixes completed!');
}

main().catch(console.error);
