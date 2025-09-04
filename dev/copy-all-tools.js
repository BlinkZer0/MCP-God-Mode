#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');

async function copyAllTools() {
  try {
    console.log('🔧 Starting direct tool copy process...');
    
    // Read the current server-refactored.ts file
    const serverFile = path.join(__dirname, 'src', 'server-refactored.ts');
    let serverContent = await fs.readFile(serverFile, 'utf8');
    
    // Find where to insert tools (before helper functions)
    const helperStart = serverContent.indexOf('// ===========================================');
    const helperSection = serverContent.indexOf('// HELPER FUNCTIONS');
    
    if (helperStart === -1 || helperSection === -1) {
      throw new Error('Could not find helper functions section');
    }
    
    // Collect all tool implementations
    const toolsDir = path.join(__dirname, 'src', 'tools');
    const toolCategories = await fs.readdir(toolsDir);
    
    let allToolsContent = '\n// ===========================================\n// ALL TOOLS COPIED\n// ===========================================\n\n';
    
    for (const category of toolCategories) {
      const categoryPath = path.join(toolsDir, category);
      const stat = await fs.stat(categoryPath);
      
      if (stat.isDirectory()) {
        console.log(`📁 Processing category: ${category}`);
        
        try {
          // Read all .ts files in this category
          const files = await fs.readdir(categoryPath);
          const tsFiles = files.filter(f => f.endsWith('.ts'));
          
          if (tsFiles.length > 0) {
            allToolsContent += `// ===========================================\n// ${category.toUpperCase()} TOOLS\n// ===========================================\n\n`;
            
            for (const tsFile of tsFiles) {
              console.log(`  📄 Copying: ${tsFile}`);
              const filePath = path.join(categoryPath, tsFile);
              const content = await fs.readFile(filePath, 'utf8');
              
              // Remove imports and exports, keep everything else
              let cleanContent = content
                .replace(/import.*?from.*?;?\n?/g, '')
                .replace(/export /g, '')
                .replace(/import.*?from.*?;?\n?/g, '');
              
              allToolsContent += `// File: ${tsFile}\n`;
              allToolsContent += cleanContent + '\n\n';
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
    
    console.log('✅ Successfully copied all tools into server-refactored.ts');
    console.log(`📊 Total file size: ${newContent.length} characters`);
    
  } catch (error) {
    console.error('❌ Error copying tools:', error);
    process.exit(1);
  }
}

// Run the copy process
copyAllTools();
