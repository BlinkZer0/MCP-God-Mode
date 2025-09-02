#!/usr/bin/env node

// Entry point for LM Studio MCP plugin
// This file redirects to the actual server implementation

const path = require('path');
const fs = require('fs');

// Try to find the server file in the dev/dist directory
const serverPath = path.join(__dirname, 'dev', 'dist', 'server.js');

if (fs.existsSync(serverPath)) {
  // Load and run the actual server
  require(serverPath);
} else {
  console.error(`Server file not found at: ${serverPath}`);
  console.error('Please ensure the project has been built and the server files exist.');
  process.exit(1);
}
