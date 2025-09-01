#!/usr/bin/env node
// Ultra-minimal MCP server launcher
const { spawn } = require('child_process');
const path = require('path');

// Find the bundled server
const serverPath = path.join(__dirname, 'server-bundled.js');

// Start the server
const server = spawn('node', [serverPath], {
  stdio: 'inherit',
  cwd: __dirname
});

server.on('error', (err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

server.on('exit', (code) => {
  process.exit(code);
});
