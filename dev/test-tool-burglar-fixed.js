#!/usr/bin/env node

/**
 * Test tool_burglar with the fixed naming
 */

import { spawn } from 'node:child_process';
import { setTimeout } from 'node:timers/promises';

async function testToolBurglarFixed() {
  console.log('🧪 **TESTING TOOL_BURGLAR WITH FIXED NAMING**');
  console.log('=============================================\n');

  // Start the MCP server
  console.log('🚀 Starting MCP server...');
  const server = spawn('node', ['dist/server-refactored.js'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: process.cwd()
  });

  let serverOutput = '';
  let serverError = '';

  server.stdout.on('data', (data) => {
    serverOutput += data.toString();
    console.log('📤 Server:', data.toString().trim());
  });

  server.stderr.on('data', (data) => {
    serverError += data.toString();
    console.log('❌ Error:', data.toString().trim());
  });

  // Wait for server to start
  console.log('⏳ Waiting for server to initialize...');
  await setTimeout(5000);

  // Test tool_burglar with list_sources
  console.log('\n🎯 Testing tool_burglar with list_sources...');
  const listSourcesCommand = {
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

  server.stdin.write(JSON.stringify(listSourcesCommand) + '\n');
  await setTimeout(2000);

  // Test tool_burglar with list_local
  console.log('\n🎯 Testing tool_burglar with list_local...');
  const listLocalCommand = {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: {
      name: "mcp_mcp-god-mode_tool_burglar",
      arguments: {
        action: "list_local"
      }
    }
  };

  server.stdin.write(JSON.stringify(listLocalCommand) + '\n');
  await setTimeout(2000);

  // Test natural language command
  console.log('\n🎯 Testing tool_burglar with natural language...');
  const nlCommand = {
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: {
      name: "mcp_mcp-god-mode_tool_burglar",
      arguments: {
        nl_command: "list all available tools"
      }
    }
  };

  server.stdin.write(JSON.stringify(nlCommand) + '\n');
  await setTimeout(2000);

  // Kill server
  console.log('\n🛑 Stopping server...');
  server.kill();

  console.log('\n✅ **TEST COMPLETE**');
  console.log('📊 Server Output:', serverOutput);
  if (serverError) {
    console.log('❌ Server Errors:', serverError);
  }
}

testToolBurglarFixed().catch(console.error);
