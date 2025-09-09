#!/usr/bin/env node
// Simple MCP server - no external dependencies
const { spawn } = require('child_process');
const path = require('path');

console.log('Starting MCP Server...');

// Run the bundled server
const server = spawn('node', [path.join(__dirname, 'server-ultra-bundled.js')], {
  stdio: 'inherit'
});

server.on('error', (err) => {
  console.error('Error:', err);
  process.exit(1);
});

server.on('exit', (code) => {
  process.exit(code);
});
