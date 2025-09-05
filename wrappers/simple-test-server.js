#!/usr/bin/env node

// Simple MCP test server for Cursor connection testing
const { spawn } = require('child_process');
const path = require('path');

console.log('🚀 Simple MCP Test Server Starting...');

// Start the actual server
const serverPath = path.resolve(__dirname, '..', 'dev', 'dist', 'server-refactored.js');
console.log(`📂 Server path: ${serverPath}`);

if (!require('fs').existsSync(serverPath)) {
  console.error(`❌ Server not found at: ${serverPath}`);
  process.exit(1);
}

console.log('✅ Server found, starting...');

// Start the server
const server = spawn('node', [serverPath], {
  stdio: 'inherit',
  cwd: __dirname
});

server.on('error', (error) => {
  console.error('❌ Failed to start server:', error.message);
  process.exit(1);
});

server.on('exit', (code) => {
  console.log(`📤 Server exited with code ${code}`);
  process.exit(code);
});

// Handle process termination
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down...');
  server.kill();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Terminating...');
  server.kill();
  process.exit(0);
});

console.log('✅ Test server launcher ready!');
console.log('💡 This should work with Cursor MCP configuration.');
