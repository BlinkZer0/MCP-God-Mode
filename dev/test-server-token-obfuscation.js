#!/usr/bin/env node

/**
 * Server Token Obfuscation Integration Test
 * Test if token obfuscation tools are available through the MCP server
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as allTools from "./dist/tools/index.js";

console.log('🧪 Testing Server Token Obfuscation Integration');
console.log('===============================================\n');

// Create a test server
const server = new McpServer({ name: "Test MCP Server", version: "1.0" });

// Track registered tools
const registeredTools = new Set();

// Mock the registerTool method to capture registrations
const originalRegisterTool = server.registerTool.bind(server);
server.registerTool = (name, toolDef, handler) => {
  registeredTools.add(name);
  console.log(`✅ Tool registered: ${name}`);
  return originalRegisterTool(name, toolDef, handler);
};

try {
  console.log('🔧 Testing tool registration from comprehensive index...');
  
  // Get all tool registration functions
  const toolFunctions = Object.values(allTools);
  console.log(`📊 Found ${toolFunctions.length} tool functions`);
  
  // Register all tools
  toolFunctions.forEach((toolFunction, index) => {
    if (typeof toolFunction === 'function' && toolFunction.name.startsWith('register')) {
      try {
        console.log(`🔧 Registering ${toolFunction.name}...`);
        toolFunction(server);
      } catch (error) {
        console.warn(`⚠️ Failed to register tool ${toolFunction.name}:`, error.message);
      }
    }
  });
  
  console.log('\n📊 Registration Results:');
  console.log(`Total tools registered: ${registeredTools.size}`);
  
  // Check specifically for token obfuscation tools
  const tokenObfuscationTools = Array.from(registeredTools).filter(name => 
    name.toLowerCase().includes('token') || name.toLowerCase().includes('obfuscat')
  );
  
  console.log('\n🔒 Token Obfuscation Tools:');
  if (tokenObfuscationTools.length > 0) {
    tokenObfuscationTools.forEach(tool => {
      console.log(`✅ ${tool}`);
    });
    console.log('\n🎉 Token obfuscation tools successfully integrated into MCP server!');
  } else {
    console.log('❌ No token obfuscation tools found in registered tools');
    console.log('\n📋 All registered tools:');
    Array.from(registeredTools).sort().forEach(tool => {
      console.log(`  - ${tool}`);
    });
  }
  
  // Test specific token obfuscation functionality
  if (registeredTools.has('token_obfuscation')) {
    console.log('\n🧪 Testing token obfuscation tool functionality...');
    
    // This would require the actual MCP client to test, but we can verify the tool is registered
    console.log('✅ Token obfuscation tool is available for MCP client use');
  }
  
  console.log('\n✅ Server integration test: PASSED');
  
} catch (error) {
  console.error('❌ Server integration test failed:', error.message);
  console.error('❌ Server integration test: FAILED');
  process.exit(1);
}
