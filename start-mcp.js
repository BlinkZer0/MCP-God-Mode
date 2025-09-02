#!/usr/bin/env node

// Cross-platform MCP server startup script
// This script handles different operating systems and provides better error handling

const path = require('path');
const fs = require('fs');
const os = require('os');

console.log(`Starting MCP God Mode Server on ${os.platform()} ${os.arch()}`);

// Try multiple possible server locations
const possiblePaths = [
  path.join(__dirname, 'dev', 'dist', 'server.js'),
  path.join(__dirname, 'dev', 'dist', 'server-refactored.js'),
  path.join(__dirname, 'dev', 'dist', 'server-minimal.js'),
  path.join(__dirname, 'dev', 'dist', 'server-ultra-minimal.js')
];

let serverPath = null;

for (const testPath of possiblePaths) {
  if (fs.existsSync(testPath)) {
    serverPath = testPath;
    console.log(`Found server at: ${serverPath}`);
    break;
  }
}

if (!serverPath) {
  console.error('No server file found. Available files in dev/dist/:');
  try {
    const distDir = path.join(__dirname, 'dev', 'dist');
    if (fs.existsSync(distDir)) {
      const files = fs.readdirSync(distDir);
      files.forEach(file => {
        if (file.endsWith('.js')) {
          console.error(`  - ${file}`);
        }
      });
    }
  } catch (err) {
    console.error('Could not read dist directory:', err.message);
  }
  process.exit(1);
}

try {
  console.log(`Loading server from: ${serverPath}`);
  require(serverPath);
} catch (error) {
  console.error('Failed to load server:', error.message);
  console.error('Stack trace:', error.stack);
  process.exit(1);
}
