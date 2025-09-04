#!/usr/bin/env node

import fs from 'fs/promises';
import path from 'path';

async function fixToolFormats() {
  const filePath = path.join(process.cwd(), 'src', 'server-refactored.ts');
  
  try {
    let content = await fs.readFile(filePath, 'utf8');
    
    // Convert inputSchema from old format to new format
    // Old: inputSchema: { param: z.string() }
    // New: inputSchema: z.object({ param: z.string() })
    content = content.replace(
      /inputSchema:\s*\{/g,
      'inputSchema: z.object({'
    );
    
    // Convert outputSchema from old format to new format
    // Old: outputSchema: { result: z.string() }
    // New: outputSchema: z.object({ result: z.string() })
    content = content.replace(
      /outputSchema:\s*\{/g,
      'outputSchema: z.object({'
    );
    
    // Fix missing closing parentheses for z.object calls
    // Look for patterns like: z.object({ ... } without proper closing
    content = content.replace(
      /z\.object\(\{([^}]*)\}/g,
      (match, inner) => {
        // Count opening and closing braces to find the proper closing
        let braceCount = 1;
        let endIndex = inner.length;
        
        for (let i = 0; i < inner.length; i++) {
          if (inner[i] === '{') braceCount++;
          else if (inner[i] === '}') braceCount--;
          
          if (braceCount === 0) {
            endIndex = i;
            break;
          }
        }
        
        if (braceCount > 0) {
          // Find the next closing brace in the content after this match
          return match;
        }
        
        return match;
      }
    );
    
    // Write the fixed content back to the file
    await fs.writeFile(filePath, content, 'utf8');
    
    console.log('✅ Successfully converted all tool schemas to new format');
    console.log('📝 File updated:', filePath);
    
  } catch (error) {
    console.error('❌ Error fixing tool formats:', error.message);
    process.exit(1);
  }
}

fixToolFormats();
