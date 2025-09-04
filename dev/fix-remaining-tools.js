#!/usr/bin/env node

import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🔧 Fixing remaining tool formats...\n');

// Function to fix a specific tool file
function fixToolFile(filePath, description) {
  try {
    let content = readFileSync(filePath, 'utf8');
    let modified = false;

    // Fix the old handler format for process tools
    if (content.includes('async handler({') && content.includes('},')) {
      content = content.replace(
        /},?\s*async handler\(\{([^}]+)\}\)\s*\{([^}]+)\},?\s*\);/gs,
        '}, async ({$1}) => {$2});'
      );
      modified = true;
    }

    // Fix return statements that have content property in wrong place
    if (content.includes('content: [{ type: "text"') && content.includes('structuredContent:')) {
      // Find and fix malformed return statements
      content = content.replace(
        /return\s*\{\s*content:\s*\[\{([^}]+)\}\],\s*structuredContent:\s*\{([^}]+)\}\s*\};/g,
        'return {\n        content: [{ type: "text", text: "Operation completed successfully" }],\n        structuredContent: {\n          $2\n        }\n      };'
      );
      modified = true;
    }

    // Fix the sanitizeCommand function calls in process tools
    if (content.includes('sanitizeCommand(command)')) {
      content = content.replace(
        /sanitizeCommand\(command\)/g,
        'sanitizeCommand(command, args)'
      );
      modified = true;
    }

    if (content.includes('sanitizeCommand(arg)')) {
      content = content.replace(
        /sanitizeCommand\(arg\)/g,
        'sanitizeCommand(arg, [])'
      );
      modified = true;
    }

    // Fix getPlatformCommand calls
    if (content.includes('getPlatformCommand(sanitizedCommand)')) {
      content = content.replace(
        /getPlatformCommand\(sanitizedCommand\)/g,
        'getPlatformCommand("processManager")'
      );
      modified = true;
    }

    if (modified) {
      writeFileSync(filePath, content, 'utf8');
      console.log(`✅ Fixed: ${filePath} - ${description}`);
      return true;
    }
    
    return false;
  } catch (error) {
    console.error(`❌ Error fixing ${filePath}:`, error.message);
    return false;
  }
}

// Fix specific problematic files
const filesToFix = [
  {
    path: 'src/tools/process/proc_run.ts',
    description: 'Process run tool - handler format and function calls'
  },
  {
    path: 'src/tools/process/proc_run_elevated.ts',
    description: 'Elevated process run tool - handler format and function calls'
  },
  {
    path: 'src/tools/security/exploit_framework.ts',
    description: 'Exploit framework - return statement format'
  },
  {
    path: 'src/tools/security/password_cracker.ts',
    description: 'Password cracker - return statement format'
  },
  {
    path: 'src/tools/utilities/dice_rolling.ts',
    description: 'Dice rolling - return statement format'
  }
];

let totalFixed = 0;

for (const file of filesToFix) {
  const fullPath = join(__dirname, file.path);
  if (fixToolFile(fullPath, file.description)) {
    totalFixed++;
  }
}

console.log(`\n🎉 Fixing complete!`);
console.log(`📝 Total files fixed: ${totalFixed}`);
console.log(`🔄 Please rebuild the modular server with: npm run build:modular`);
