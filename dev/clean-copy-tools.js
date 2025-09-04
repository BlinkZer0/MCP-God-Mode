#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');

async function cleanCopyTools() {
  try {
    console.log('🧹 Starting clean tool copy process...');
    
    // Read the current server-refactored.ts file
    const serverFile = path.join(__dirname, 'src', 'server-refactored.ts');
    let serverContent = await fs.readFile(serverFile, 'utf8');
    
    // Remove all the import statements and export keywords that are causing errors
    console.log('🧹 Cleaning up import statements and export keywords...');
    
    // Remove all import statements
    serverContent = serverContent.replace(/import\s*\{[^}]*\}\s*from\s*["'][^"']*["'];?\n?/g, '');
    serverContent = serverContent.replace(/import\s*[^;]*;?\n?/g, '');
    
    // Remove export keywords
    serverContent = serverContent.replace(/export\s+/g, '');
    
    // Remove any remaining problematic lines
    serverContent = serverContent.replace(/^\s*\{[^}]*\}\s*from\s*["'][^"']*["'];?\s*$/gm, '');
    
    // Write the cleaned file
    await fs.writeFile(serverFile, serverContent, 'utf8');
    
    console.log('✅ Successfully cleaned up the file');
    console.log(`📊 Total file size: ${serverContent.length} characters`);
    
  } catch (error) {
    console.error('❌ Error cleaning tools:', error);
    process.exit(1);
  }
}

// Run the cleanup process
cleanCopyTools();
