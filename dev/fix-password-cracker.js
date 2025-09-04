#!/usr/bin/env node

import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🔧 Fixing password cracker return statements...\n');

// Read the password cracker file
const filePath = join(__dirname, 'src', 'tools', 'security', 'password_cracker.ts');
let content = readFileSync(filePath, 'utf8');

// Fix the return statements in helper functions
// These functions are declared to return { password?: string; attempts: number; status: string }
// but they're trying to return content/structuredContent objects

// Fix the return statements that have content property in wrong place
content = content.replace(
  /return\s*\{\s*content:\s*\[\{([^}]+)\}\],\s*structuredContent:\s*\{\s*([^}]+)\s*\}\s*\};/g,
  'return {\n        $2\n      };'
);

// Write the fixed file
writeFileSync(filePath, content, 'utf8');

console.log('✅ Fixed password cracker return statements!');
console.log('🔄 Please rebuild the modular server with: npm run build:modular');
