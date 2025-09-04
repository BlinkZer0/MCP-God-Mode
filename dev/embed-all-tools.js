#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');

async function embedAllTools() {
  try {
    console.log('🔧 Starting tool embedding process...');
    
    // Read the current server-refactored.ts file
    const serverFile = path.join(__dirname, 'src', 'server-refactored.ts');
    let serverContent = await fs.readFile(serverFile, 'utf8');
    
    // Remove all the import statements for tools (lines 32-47)
    const importStart = serverContent.indexOf('// Import tool registration functions');
    const importEnd = serverContent.indexOf('// Global variables for enhanced features');
    
    if (importStart !== -1 && importEnd !== -1) {
      const beforeImports = serverContent.substring(0, importStart);
      const afterImports = serverContent.substring(importEnd);
      serverContent = beforeImports + afterImports;
    }
    
    // Find where the existing tools end (before helper functions)
    const helperStart = serverContent.indexOf('// ===========================================');
    const helperSection = serverContent.indexOf('// HELPER FUNCTIONS');
    
    if (helperStart === -1 || helperSection === -1) {
      throw new Error('Could not find helper functions section');
    }
    
    // Find where the existing tools start (after server creation)
    const serverCreation = serverContent.indexOf('const server = new McpServer({ name: "MCP God Mode", version: "1.4a" });');
    const elevatedPermissions = serverContent.indexOf('// Register elevated permissions manager (parity with modular server)');
    
    if (serverCreation === -1 || elevatedPermissions === -1) {
      throw new Error('Could not find server creation section');
    }
    
    // Find the end of existing tools (before helper functions)
    let existingToolsEnd = helperStart;
    
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
          const indexFile = path.join(categoryPath, 'index.ts');
          const indexContent = await fs.readFile(indexFile, 'utf8');
          
          // Extract the tool registration functions
          const toolMatches = indexContent.match(/export function register\w+\(server: McpServer\) \{[\s\S]*?\n\}/g);
          
          if (toolMatches) {
            for (const toolMatch of toolMatches) {
              // Convert the tool registration to work without imports
              let toolContent = toolMatch
                .replace(/export function /g, 'function ')
                .replace(/import.*?from.*?;?\n?/g, '')
                .replace(/import.*?from.*?;?\n?/g, '');
              
              allToolsContent += toolContent + '\n\n';
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
    
    // Insert the tools content after the elevated permissions manager
    const elevatedEnd = serverContent.indexOf('server.registerTool("health"');
    
    if (elevatedEnd === -1) {
      throw new Error('Could not find health tool registration');
    }
    
    const beforeHealth = serverContent.substring(0, elevatedEnd);
    const afterHealth = serverContent.substring(elevatedEnd);
    
    const newContent = beforeHealth + allToolsContent + afterHealth;
    
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
