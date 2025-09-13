#!/usr/bin/env node

/**
 * Debug test to see exactly what's happening with tool_burglar registration
 */

import { spawn } from 'node:child_process';
import { setTimeout } from 'node:timers/promises';

async function testToolBurglarDebug() {
  console.log('🔍 **DEBUGGING TOOL_BURGLAR REGISTRATION**');
  console.log('==========================================\n');

  // Start the MCP server with debug output
  console.log('🚀 Starting MCP server with debug output...');
  const server = spawn('node', ['dist/server-refactored.js'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: process.cwd(),
    env: { ...process.env, LOG_TOOL_REGISTRY: '1' }
  });

  let serverOutput = '';
  let serverError = '';

  server.stdout.on('data', (data) => {
    const output = data.toString();
    serverOutput += output;
    
    // Look for tool_burglar specific messages
    if (output.includes('tool_burglar') || output.includes('ToolBurglar') || output.includes('registerToolBurglar')) {
      console.log('🔍 TOOL_BURGLAR:', output.trim());
    } else {
      console.log('📤 Server:', output.trim());
    }
  });

  server.stderr.on('data', (data) => {
    const error = data.toString();
    serverError += error;
    console.log('❌ Error:', error.trim());
  });

  // Wait for server to start
  console.log('⏳ Waiting for server to initialize...');
  await setTimeout(8000);

  // Test if we can list tools
  console.log('\n🎯 Testing tools/list...');
  const listToolsCommand = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list",
    params: {}
  };

  server.stdin.write(JSON.stringify(listToolsCommand) + '\n');
  await setTimeout(3000);

  // Test tool_burglar directly
  console.log('\n🎯 Testing tool_burglar directly...');
  const burglarCommand = {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: {
      name: "tool_burglar",
      arguments: {
        action: "list_sources"
      }
    }
  };

  server.stdin.write(JSON.stringify(burglarCommand) + '\n');
  await setTimeout(2000);

  // Kill server
  console.log('\n🛑 Stopping server...');
  server.kill();

  console.log('\n✅ **DEBUG COMPLETE**');
  console.log('📊 Full Server Output:', serverOutput);
  if (serverError) {
    console.log('❌ Server Errors:', serverError);
  }
}

testToolBurglarDebug().catch(console.error);
