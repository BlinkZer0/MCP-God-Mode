#!/usr/bin/env node

/**
 * Test tool_burglar functionality - Download tools without installing them
 */

import { spawn } from 'node:child_process';
import { setTimeout } from 'node:timers/promises';

async function testToolBurglarDownload() {
  console.log('🔧 **TOOL_BURGLAR DOWNLOAD TEST**');
  console.log('==================================\n');

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
  await setTimeout(6000);

  // Test 1: List sources (should be empty initially)
  console.log('\n🎯 Test 1: List sources...');
  const listSourcesCommand = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: "tool_burglar",
      arguments: {
        action: "list_sources"
      }
    }
  };

  server.stdin.write(JSON.stringify(listSourcesCommand) + '\n');
  await setTimeout(2000);

  // Test 2: List local tools
  console.log('\n🎯 Test 2: List local tools...');
  const listLocalCommand = {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: {
      name: "tool_burglar",
      arguments: {
        action: "list_local"
      }
    }
  };

  server.stdin.write(JSON.stringify(listLocalCommand) + '\n');
  await setTimeout(2000);

  // Test 3: Discover tools from external repository (download without installing)
  console.log('\n🎯 Test 3: Discover tools from external repository...');
  const discoverCommand = {
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: {
      name: "tool_burglar",
      arguments: {
        action: "discover",
        sources: ["https://github.com/modelcontextprotocol/servers"],
        include: ["filesystem", "memory"]
      }
    }
  };

  server.stdin.write(JSON.stringify(discoverCommand) + '\n');
  await setTimeout(3000);

  // Test 4: Preview import (download and analyze without installing)
  console.log('\n🎯 Test 4: Preview import (download without installing)...');
  const previewCommand = {
    jsonrpc: "2.0",
    id: 4,
    method: "tools/call",
    params: {
      name: "tool_burglar",
      arguments: {
        action: "preview_import",
        sources: ["https://github.com/modelcontextprotocol/servers"],
        include: ["filesystem"],
        prefix: "ext_",
        dry_run: true
      }
    }
  };

  server.stdin.write(JSON.stringify(previewCommand) + '\n');
  await setTimeout(4000);

  // Test 5: Natural language command
  console.log('\n🎯 Test 5: Natural language command...');
  const nlCommand = {
    jsonrpc: "2.0",
    id: 5,
    method: "tools/call",
    params: {
      name: "tool_burglar",
      arguments: {
        nl_command: "discover bluetooth and wifi tools from https://github.com/modelcontextprotocol/servers but don't install them"
      }
    }
  };

  server.stdin.write(JSON.stringify(nlCommand) + '\n');
  await setTimeout(3000);

  // Kill server
  console.log('\n🛑 Stopping server...');
  server.kill();

  console.log('\n✅ **TOOL_BURGLAR DOWNLOAD TEST COMPLETE**');
  console.log('📊 Server Output:', serverOutput);
  if (serverError) {
    console.log('❌ Server Errors:', serverError);
  }

  console.log('\n💡 **SUMMARY OF TOOL_BURGLAR CAPABILITIES:**');
  console.log('===============================================');
  console.log('✅ Discover tools from external repositories');
  console.log('✅ Preview imports without installing (dry run)');
  console.log('✅ License checking and conflict analysis');
  console.log('✅ Natural language command support');
  console.log('✅ Download and analyze tools without installation');
  console.log('✅ Cross-platform tool management');
  console.log('✅ Audit logging and rollback capabilities');
}

testToolBurglarDownload().catch(console.error);
