#!/usr/bin/env node

// Simple test script to verify MCP server functionality
const { spawn } = require('child_process');
const readline = require('readline');

console.log('🧪 Testing MCP Server with Parameter Descriptions...\n');

// Start the MCP server
const server = spawn('node', ['dist/server-minimal.js'], {
  stdio: ['pipe', 'pipe', 'pipe']
});

// Test messages to send to the server
const testMessages = [
  {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list"
  },
  {
    jsonrpc: "2.0", 
    id: 2,
    method: "tools/call",
    params: {
      name: "fs_list",
      arguments: { dir: "." }
    }
  }
];

let messageIndex = 0;

// Send test messages
function sendNextMessage() {
  if (messageIndex < testMessages.length) {
    const message = testMessages[messageIndex];
    console.log(`📤 Sending: ${message.method}`);
    server.stdin.write(JSON.stringify(message) + '\n');
    messageIndex++;
  } else {
    // All messages sent, close server
    setTimeout(() => {
      console.log('\n✅ Testing complete. Closing server...');
      server.kill();
      process.exit(0);
    }, 2000);
  }
}

// Handle server output
server.stdout.on('data', (data) => {
  const output = data.toString().trim();
  if (output) {
    try {
      const response = JSON.parse(output);
      console.log(`📥 Received: ${JSON.stringify(response, null, 2)}`);
      
      // Send next message after a short delay
      setTimeout(sendNextMessage, 500);
    } catch (e) {
      console.log(`📥 Raw output: ${output}`);
    }
  }
});

// Handle server errors
server.stderr.on('data', (data) => {
  console.log(`❌ Server error: ${data.toString()}`);
});

// Handle server close
server.on('close', (code) => {
  console.log(`\n🔒 Server closed with code ${code}`);
});

// Start testing
console.log('🚀 Starting server test...\n');
setTimeout(sendNextMessage, 1000);
