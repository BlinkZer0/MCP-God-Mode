#!/usr/bin/env node

import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🔧 Fixing return statement issues...\n');

// Function to fix return statements in a specific file
function fixReturnStatements(filePath, description) {
  try {
    let content = readFileSync(filePath, 'utf8');
    let modified = false;

    // Fix return statements that have content property in wrong place
    // This pattern: return { content: [...], structuredContent: {...} }
    // Should be: return { content: [...], structuredContent: {...} }
    if (content.includes('content: [{ type: "text"') && content.includes('structuredContent:')) {
      // Find and fix malformed return statements that have content property in wrong place
      content = content.replace(
        /return\s*\{\s*content:\s*\[\{([^}]+)\}\],\s*structuredContent:\s*\{([^}]+)\}\s*\};/g,
        'return {\n        content: [{ type: "text", text: "Operation completed successfully" }],\n        structuredContent: {\n          $2\n        }\n      };'
      );
      modified = true;
    }

    // Fix return statements that have content property but no structuredContent
    if (content.includes('content: [{ type: "text"') && !content.includes('structuredContent:')) {
      // Find return statements with just content and wrap them properly
      content = content.replace(
        /return\s*\{\s*content:\s*\[\{([^}]+)\}\],\s*([^}]+)\s*\};/g,
        'return {\n        content: [{ type: "text", text: "Operation completed successfully" }],\n        structuredContent: {\n          $2\n        }\n      };'
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
  if (fixReturnStatements(fullPath, file.description)) {
    totalFixed++;
  }
}

console.log(`\n🎉 Fixing complete!`);
console.log(`📝 Total files fixed: ${totalFixed}`);
console.log(`🔄 Please rebuild the modular server with: npm run build:modular`);
