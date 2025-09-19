#!/usr/bin/env node

// Wrapper to ensure MCP server writes ONLY JSON-RPC to stdout.
// All logs are redirected to stderr to keep Cursor happy.
const path = require('path');
const fs = require('fs');

// Redirect any stdout logging to stderr
console.log = console.error;

// Resolve server path relative to this file
const serverPath = path.resolve(__dirname, '..', 'dev', 'dist', 'server-refactored.js');

if (!fs.existsSync(serverPath)) {
  console.error(`[MCP Wrapper] Server not found at: ${serverPath}`);
  process.exit(1);
}

console.error(`[MCP Wrapper] Launching: ${serverPath}`);

try {
  require(serverPath);
} catch (err) {
  console.error('[MCP Wrapper] Failed to load server:', err && err.message ? err.message : String(err));
  if (err && err.stack) console.error(err.stack);
  process.exit(1);
}

