#!/usr/bin/env node

import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🔧 Fixing all tool formats...\n');

// Function to fix a single tool file
function fixToolFile(filePath) {
  try {
    let content = readFileSync(filePath, 'utf8');
    let modified = false;

    // Fix the old handler format
    if (content.includes('async handler({') && content.includes('},')) {
      // Replace the handler format with the new callback format
      content = content.replace(
        /},?\s*async handler\(\{([^}]+)\}\)\s*\{([^}]+)\},?\s*\);/gs,
        '}, async ({$1}) => {$2});'
      );
      modified = true;
    }

    // Fix return statements to include content and structuredContent
    if (content.includes('return {') && !content.includes('content: [{ type: "text"')) {
      // Find all return statements and wrap them
      content = content.replace(
        /return\s*\{([^}]+)\};/g,
        (match, returnContent) => {
          // Skip if already formatted
          if (returnContent.includes('content: [{ type: "text"')) {
            return match;
          }
          
          // Extract the success field if it exists
          const successMatch = returnContent.match(/success:\s*(true|false)/);
          const success = successMatch ? successMatch[1] : 'true';
          
          // Create a simple text message
          let message = 'Operation completed successfully';
          if (returnContent.includes('error:')) {
            message = 'Operation failed';
          }
          
          return `return {
            content: [{ type: "text", text: "${message}" }],
            structuredContent: {${returnContent}}
          };`;
        }
      );
      modified = true;
    }

    // Fix throw statements to return error objects
    if (content.includes('throw new Error(')) {
      content = content.replace(
        /throw new Error\(([^)]+)\);/g,
        'return {\n          content: [{ type: "text", text: `Error: ${$1}` }],\n          structuredContent: {\n            success: false,\n            error: `${$1}`\n          }\n        };'
      );
      modified = true;
    }

    if (modified) {
      writeFileSync(filePath, content, 'utf8');
      console.log(`✅ Fixed: ${filePath}`);
      return true;
    }
    
    return false;
  } catch (error) {
    console.error(`❌ Error fixing ${filePath}:`, error.message);
    return false;
  }
}

// Function to recursively find and fix all tool files
function fixAllTools(dir) {
  const items = readdirSync(dir);
  let fixedCount = 0;
  
  for (const item of items) {
    const fullPath = join(dir, item);
    const stat = statSync(fullPath);
    
    if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
      fixedCount += fixAllTools(fullPath);
    } else if (item.endsWith('.ts') && !item.includes('index.ts') && !item.includes('test')) {
      if (fixToolFile(fullPath)) {
        fixedCount++;
      }
    }
  }
  
  return fixedCount;
}

// Start fixing from the tools directory
const toolsDir = join(__dirname, 'src', 'tools');
console.log(`🔍 Scanning for tool files in: ${toolsDir}`);

const totalFixed = fixAllTools(toolsDir);

console.log(`\n🎉 Fixing complete!`);
console.log(`📝 Total files fixed: ${totalFixed}`);
console.log(`🔄 Please rebuild the modular server with: npm run build:modular`);
