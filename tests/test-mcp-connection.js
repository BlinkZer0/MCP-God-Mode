#!/usr/bin/env node

// Simple MCP protocol test to verify server communication
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🧪 Testing MCP Protocol Communication...');

// Start the server
const server = spawn('node', [join(__dirname, '../dev/dist/server-refactored.js')], {
  stdio: ['pipe', 'pipe', 'pipe']
});

let serverOutput = '';
let serverError = '';

server.stdout.on('data', (data) => {
  const output = data.toString();
  serverOutput += output;
  console.log('📤 Server Output:', output.trim());
});

server.stderr.on('data', (data) => {
  const error = data.toString();
  serverError += error;
  console.log('❌ Server Error:', error.trim());
});

server.on('close', (code) => {
  console.log(`\n🔚 Server process exited with code ${code}`);
  console.log('\n📊 Final Server Output:');
  console.log(serverOutput);
  if (serverError) {
    console.log('\n❌ Final Server Errors:');
    console.log(serverError);
  }
});

// Wait a bit for server to start, then send a simple MCP request
setTimeout(() => {
  console.log('\n📡 Sending MCP tools/list request...');
  
  const mcpRequest = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list",
    params: {}
  };
  
  console.log('📤 Sending:', JSON.stringify(mcpRequest, null, 2));
  server.stdin.write(JSON.stringify(mcpRequest) + '\n');
  
  // Wait a bit more then exit
  setTimeout(() => {
    console.log('\n⏰ Test completed, shutting down...');
    server.kill();
    process.exit(0);
  }, 3000);
  
}, 2000);

// Handle process termination
process.on('SIGINT', () => {
  console.log('\n🛑 Received SIGINT, shutting down...');
  server.kill();
  process.exit(0);
});
