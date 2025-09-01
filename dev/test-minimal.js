#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');

console.log('🧪 Testing minimal MCP server...');

// Test if the bundled server works
const serverPath = path.join(__dirname, 'dist', 'server-bundled.js');

if (!require('fs').existsSync(serverPath)) {
  console.error('❌ Bundled server not found. Run optimize-size.js first.');
  process.exit(1);
}

console.log('🚀 Starting minimal server...');

const server = spawn('node', [serverPath], {
  stdio: ['pipe', 'pipe', 'pipe']
});

let output = '';
let errorOutput = '';

server.stdout.on('data', (data) => {
  output += data.toString();
});

server.stderr.on('data', (data) => {
  errorOutput += data.toString();
});

server.on('close', (code) => {
  console.log(`\n📊 Server exited with code: ${code}`);
  
  if (output) {
    console.log('📤 Server output:');
    console.log(output);
  }
  
  if (errorOutput) {
    console.log('❌ Server errors:');
    console.log(errorOutput);
  }
  
  if (code === 0) {
    console.log('✅ Minimal server test completed successfully!');
  } else {
    console.log('❌ Minimal server test failed');
  }
});

// Send a test message after a short delay
setTimeout(() => {
  console.log('📨 Sending test message...');
  
  const testMessage = {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: {
      name: 'health',
      arguments: {}
    }
  };
  
  server.stdin.write(JSON.stringify(testMessage) + '\n');
  
  // Close after test
  setTimeout(() => {
    server.kill();
  }, 2000);
}, 1000);
