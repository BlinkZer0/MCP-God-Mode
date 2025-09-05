#!/usr/bin/env node

// Simple MCP server launcher for Cursor
const path = require('path');

console.log('🚀 MCP God Mode Launcher Starting...');
console.log(`📁 Current directory: ${process.cwd()}`);

// Resolve the server path
const serverPath = path.resolve(__dirname, 'dev', 'dist', 'server-refactored.js');
console.log(`📂 Server path: ${serverPath}`);

// Check if server exists
const fs = require('fs');
if (!fs.existsSync(serverPath)) {
  console.error(`❌ Server not found at: ${serverPath}`);
  process.exit(1);
}

console.log('✅ Server found, loading...');

try {
  // Load the server
  require(serverPath);
  console.log('✅ Server loaded successfully!');
} catch (error) {
  console.error('❌ Failed to load server:', error.message);
  console.error('📚 Stack trace:', error.stack);
  process.exit(1);
}
