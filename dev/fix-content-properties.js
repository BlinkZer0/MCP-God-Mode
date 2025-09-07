#!/usr/bin/env node

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function fixContentProperties() {
  const toolsDir = path.join(__dirname, 'src', 'tools');
  const files = await getAllTsFiles(toolsDir);
  
  console.log(`Found ${files.length} TypeScript files to process`);
  
  for (const file of files) {
    try {
      await fixFileContentProperties(file);
      console.log(`✅ Fixed: ${path.relative(__dirname, file)}`);
    } catch (error) {
      console.error(`❌ Failed to fix ${path.relative(__dirname, file)}:`, error.message);
    }
  }
  
  console.log('🎉 Content property fixes completed!');
}

async function getAllTsFiles(dir) {
  const files = [];
  const entries = await fs.readdir(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...await getAllTsFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.ts')) {
      files.push(fullPath);
    }
  }
  
  return files;
}

async function fixFileContentProperties(filePath) {
  let content = await fs.readFile(filePath, 'utf-8');
  let modified = false;
  
  // Pattern 1: Fix resolve() calls that return objects without content property
  const resolvePattern = /resolve\(\s*\{\s*([^}]+)\s*\}\s*\)/g;
  content = content.replace(resolvePattern, (match, objContent) => {
    // Check if the object already has a content property
    if (objContent.includes('content:')) {
      return match;
    }
    
    // Extract the object properties
    const props = objContent.trim();
    
    // Create a content array with a text item
    const contentItem = `content: [{ type: "text", text: "Operation completed successfully" }]`;
    
    // Add the content property
    const newContent = `resolve({\n        ${contentItem},\n        ${props}\n      })`;
    modified = true;
    return newContent;
  });
  
  // Pattern 2: Fix return statements that return objects without content property
  const returnPattern = /return\s*\{\s*([^}]+)\s*\}/g;
  content = content.replace(returnPattern, (match, objContent) => {
    // Check if the object already has a content property
    if (objContent.includes('content:')) {
      return match;
    }
    
    // Skip if it's already a content array
    if (objContent.includes('type: "text"')) {
      return match;
    }
    
    // Extract the object properties
    const props = objContent.trim();
    
    // Create a content array with a text item
    const contentItem = `content: [{ type: "text", text: "Operation completed successfully" }]`;
    
    // Add the content property
    const newContent = `return {\n        ${contentItem},\n        ${props}\n      }`;
    modified = true;
    return newContent;
  });
  
  // Pattern 3: Fix error return statements
  const errorReturnPattern = /return\s*\{\s*content:\s*\[\],\s*structuredContent:\s*\{\s*([^}]+)\s*\}\s*\}/g;
  content = content.replace(errorReturnPattern, (match, objContent) => {
    // Check if it already has the right structure
    if (objContent.includes('success: false')) {
      return match;
    }
    
    // Extract the object properties
    const props = objContent.trim();
    
    // Create a proper error structure
    const newContent = `return {\n        content: [{ type: "text", text: "Operation failed" }],\n        structuredContent: {\n          success: false,\n          ${props}\n        }\n      }`;
    modified = true;
    return newContent;
  });
  
  // Pattern 4: Fix error.message access
  const errorMessagePattern = /error\.message/g;
  content = content.replace(errorMessagePattern, (match) => {
    modified = true;
    return '(error as Error).message';
  });
  
  // Pattern 5: Fix implicit any[] types
  const implicitAnyPattern = /let\s+(\w+)\s*=\s*\[\];/g;
  content = content.replace(implicitAnyPattern, (match, varName) => {
    modified = true;
    return `let ${varName}: any[] = [];`;
  });
  
  // Pattern 6: Fix variable used before assignment
  const usedBeforeAssignmentPattern = /if\s*\(\s*!\s*(\w+)\s*\)/g;
  content = content.replace(usedBeforeAssignmentPattern, (match, varName) => {
    // Check if this variable is used before assignment
    const beforeMatch = content.substring(0, content.indexOf(match));
    const varDecl = beforeMatch.lastIndexOf(`let ${varName}`);
    const varAssign = beforeMatch.lastIndexOf(`${varName} =`);
    
    if (varDecl > varAssign) {
      modified = true;
      return `if (!${varName})`;
    }
    return match;
  });
  
  if (modified) {
    await fs.writeFile(filePath, content, 'utf-8');
  }
}

// Run the fix
fixContentProperties().catch(console.error);
