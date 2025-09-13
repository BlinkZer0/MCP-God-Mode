#!/usr/bin/env node

/**
 * Simple test to check if tool_burglar is available and working
 */

import { spawn } from 'node:child_process';

async function testToolBurglar() {
  console.log('🧪 Testing tool_burglar availability...');
  
  // Test if we can call the tool_burglar
  const testCommand = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: "mcp_mcp-god-mode_tool_burglar",
      arguments: {
        action: "list_sources"
      }
    }
  };
  
  console.log('📋 Test command:', JSON.stringify(testCommand, null, 2));
  
  // Try to start the server and test
  console.log('🚀 Starting MCP server to test tool_burglar...');
  
  const server = spawn('node', ['dist/server-refactored.js'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: process.cwd()
  });
  
  let output = '';
  let errorOutput = '';
  
  server.stdout.on('data', (data) => {
    output += data.toString();
    console.log('📤 Server output:', data.toString().trim());
  });
  
  server.stderr.on('data', (data) => {
    errorOutput += data.toString();
    console.log('❌ Server error:', data.toString().trim());
  });
  
  // Wait a bit for server to start
  await new Promise(resolve => setTimeout(resolve, 3000));
  
  // Send test command
  console.log('📨 Sending test command...');
  server.stdin.write(JSON.stringify(testCommand) + '\n');
  
  // Wait for response
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  // Kill server
  server.kill();
  
  console.log('✅ Test completed');
  console.log('📊 Output:', output);
  if (errorOutput) {
    console.log('❌ Errors:', errorOutput);
  }
}

testToolBurglar().catch(console.error);
