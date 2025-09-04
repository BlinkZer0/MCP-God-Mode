#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');

async function embedAllTools() {
  try {
    console.log('🔧 Starting comprehensive tool embedding process...');
    
    // Read the current server-refactored.ts file
    const serverFile = path.join(__dirname, 'src', 'server-refactored.ts');
    let serverContent = await fs.readFile(serverFile, 'utf8');
    
    // Remove all the import statements for tools
    const importStart = serverContent.indexOf('// Import tool registration functions');
    const importEnd = serverContent.indexOf('// Global variables for enhanced features');
    
    if (importStart !== -1 && importEnd !== -1) {
      const beforeImports = serverContent.substring(0, importStart);
      const afterImports = serverContent.substring(importEnd);
      serverContent = beforeImports + afterImports;
    }
    
    // Find where to insert tools (before helper functions)
    const helperStart = serverContent.indexOf('// ===========================================');
    const helperSection = serverContent.indexOf('// HELPER FUNCTIONS');
    
    if (helperStart === -1 || helperSection === -1) {
      throw new Error('Could not find helper functions section');
    }
    
    // Collect all tool implementations
    const toolsDir = path.join(__dirname, 'src', 'tools');
    const toolCategories = await fs.readdir(toolsDir);
    
    let allToolsContent = '\n// ===========================================\n// EMBEDDED TOOLS\n// ===========================================\n\n';
    
    for (const category of toolCategories) {
      const categoryPath = path.join(toolsDir, category);
      const stat = await fs.stat(categoryPath);
      
      if (stat.isDirectory()) {
        console.log(`📁 Processing category: ${category}`);
        
        try {
          // Read the index file to see what tools are available
          const indexFile = path.join(categoryPath, 'index.ts');
          const indexContent = await fs.readFile(indexFile, 'utf8');
          
          // Extract tool names from the index file
          const toolMatches = indexContent.match(/export function (register\w+)/g);
          
          if (toolMatches) {
            allToolsContent += `// ===========================================\n// ${category.toUpperCase()} TOOLS\n// ===========================================\n\n`;
            
            for (const toolMatch of toolMatches) {
              const toolName = toolMatch.replace('export function ', '');
              console.log(`  🔧 Processing tool: ${toolName}`);
              
              // Try to find the individual tool file
              const toolFileName = toolName.replace('register', '').toLowerCase();
              const possibleFiles = [
                `${toolFileName}.ts`,
                `${toolFileName.replace(/([A-Z])/g, '_$1').toLowerCase()}.ts`,
                `${toolFileName.replace(/([A-Z])/g, '_$1').toLowerCase()}_tool.ts`
              ];
              
              let toolContent = '';
              for (const fileName of possibleFiles) {
                try {
                  const toolFile = path.join(categoryPath, fileName);
                  const content = await fs.readFile(toolFile, 'utf8');
                  
                  // Extract the tool registration function
                  const functionMatch = content.match(new RegExp(`export function ${toolName}\\(server: McpServer\\) \\{[\\s\\S]*?\\n\\}`, 'g'));
                  
                  if (functionMatch) {
                    toolContent = functionMatch[0]
                      .replace(/export function /g, 'function ')
                      .replace(/import.*?from.*?;?\n?/g, '')
                      .replace(/import.*?from.*?;?\n?/g, '');
                    break;
                  }
                } catch (error) {
                  // File not found, try next one
                }
              }
              
              if (toolContent) {
                allToolsContent += toolContent + '\n\n';
              } else {
                console.log(`    ⚠️  Could not find implementation for ${toolName}`);
              }
            }
          }
        } catch (error) {
          console.log(`⚠️  Could not process ${category}: ${error.message}`);
        }
      }
    }
    
    // Add the tool registration calls
    allToolsContent += '// ===========================================\n// REGISTER ALL TOOLS\n// ===========================================\n\n';
    
    // Get all the tool registration function names
    const toolFunctionMatches = allToolsContent.match(/function (register\w+)/g);
    if (toolFunctionMatches) {
      for (const match of toolFunctionMatches) {
        const functionName = match.replace('function ', '');
        allToolsContent += `${functionName}(server);\n`;
      }
    }
    
    // Insert the tools content before helper functions
    const beforeHelper = serverContent.substring(0, helperStart);
    const afterHelper = serverContent.substring(helperStart);
    
    const newContent = beforeHelper + allToolsContent + afterHelper;
    
    // Write the updated file
    await fs.writeFile(serverFile, newContent, 'utf8');
    
    console.log('✅ Successfully embedded all tools into server-refactored.ts');
    console.log(`📊 Total file size: ${newContent.length} characters`);
    
  } catch (error) {
    console.error('❌ Error embedding tools:', error);
    process.exit(1);
  }
}

// Run the embedding process
embedAllTools();
