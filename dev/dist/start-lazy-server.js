#!/usr/bin/env node

// MCP God Mode - Lazy Loading Server Startup Script
import { spawn } from 'node:child_process';
import * as path from 'node:path';

const serverPath = path.join(__dirname, 'server-lazy.js');

console.log('🚀 Starting MCP God Mode - Lazy Loading Server...');
console.log('⚡ Using lazy loading architecture for optimal performance');

const child = spawn('node', [serverPath], {
  stdio: 'inherit',
  cwd: __dirname
});

child.on('error', (error) => {
  console.error('❌ Server startup failed:', error);
  process.exit(1);
});

child.on('exit', (code) => {
  console.log(`Server exited with code ${code}`);
  process.exit(code);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down server...');
  child.kill('SIGINT');
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Shutting down server...');
  child.kill('SIGTERM');
});
