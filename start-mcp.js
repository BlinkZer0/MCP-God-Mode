#!/usr/bin/env node

// Cross-platform MCP server startup script
// This script handles different operating systems and provides better error handling

const path = require('path');
const fs = require('fs');
const os = require('os');

console.log(`🚀 Starting MCP God Mode Server on ${os.platform()} ${os.arch()}`);
console.log(`📁 Working directory: ${process.cwd()}`);

// Try multiple possible server locations in order of preference
const possiblePaths = [
  // Primary server files
  path.join(__dirname, 'dev', 'dist', 'server-refactored.js'),
  path.join(__dirname, 'dev', 'dist', 'server.js'),
  path.join(__dirname, 'dev', 'dist', 'server-minimal.js'),
  path.join(__dirname, 'dev', 'dist', 'server-ultra-minimal.js'),
  // Fallback to root level if dev/dist doesn't exist
  path.join(__dirname, 'server.js'),
  path.join(__dirname, 'server-refactored.js')
];

let serverPath = null;
let foundFiles = [];

// First, check what files are actually available
for (const testPath of possiblePaths) {
  if (fs.existsSync(testPath)) {
    foundFiles.push(testPath);
    if (!serverPath) {
      serverPath = testPath;
      console.log(`✅ Found server at: ${serverPath}`);
    }
  }
}

if (!serverPath) {
  console.error('❌ No server file found!');
  console.error('🔍 Searched in the following locations:');
  possiblePaths.forEach(p => {
    console.error(`   - ${p}`);
  });
  
  // Try to show what's actually available
  console.error('\n📂 Available files in project:');
  try {
    const distDir = path.join(__dirname, 'dev', 'dist');
    if (fs.existsSync(distDir)) {
      const files = fs.readdirSync(distDir);
      files.forEach(file => {
        if (file.endsWith('.js')) {
          console.error(`   - dev/dist/${file}`);
        }
      });
    }
    
    // Check root directory
    const rootFiles = fs.readdirSync(__dirname);
    rootFiles.forEach(file => {
      if (file.endsWith('.js') && file.includes('server')) {
        console.error(`   - ${file}`);
      }
    });
  } catch (err) {
    console.error('Could not read directories:', err.message);
  }
  
  console.error('\n💡 Make sure you have run: npm install && npm run build');
  process.exit(1);
}

try {
  console.log(`🔄 Loading server from: ${serverPath}`);
  require(serverPath);
  console.log('✅ Server loaded successfully!');
} catch (error) {
  console.error('❌ Failed to load server:', error.message);
  console.error('📚 Stack trace:', error.stack);
  process.exit(1);
}
