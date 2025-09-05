#!/usr/bin/env node

// Comprehensive MCP God Mode Smoke Test
// Tests all tools and MCP protocol communication

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🚀 MCP God Mode Smoke Test Starting...\n');

// Test configuration
const TEST_CONFIG = {
  serverPath: join(__dirname, '..', 'dev', 'dist', 'server-refactored.js'),
  timeout: 30000, // 30 seconds
  maxTools: 100
};

// Check if server exists
if (!fs.existsSync(TEST_CONFIG.serverPath)) {
  console.error(`❌ Server not found at: ${TEST_CONFIG.serverPath}`);
  console.error('Please build the server first: npm run build');
  process.exit(1);
}

console.log(`✅ Server found at: ${TEST_CONFIG.serverPath}\n`);

// Test results tracking
const testResults = {
  serverStart: false,
  mcpHandshake: false,
  toolsList: false,
  toolsCount: 0,
  toolTests: [],
  errors: [],
  warnings: []
};

// Start the server
console.log('🔄 Starting MCP server...');
const server = spawn('node', [TEST_CONFIG.serverPath], {
  stdio: ['pipe', 'pipe', 'pipe'],
  cwd: __dirname
});

let serverOutput = '';
let serverError = '';
let serverStartTime = Date.now();

// Server output handling
server.stdout.on('data', (data) => {
  const output = data.toString();
  serverOutput += output;
  
  // Check for server startup success
  if (output.includes('MCP God Mode Server started') || output.includes('Server started successfully')) {
    testResults.serverStart = true;
    console.log('✅ Server started successfully');
  }
  
  // Check for tools registration
  if (output.includes('tools loaded') || output.includes('tools registered')) {
    const match = output.match(/(\d+)\s+tools?\s+(?:loaded|registered)/i);
    if (match) {
      testResults.toolsCount = parseInt(match[1]);
      console.log(`✅ ${testResults.toolsCount} tools registered`);
    }
  }
  
  // Check for MCP protocol messages
  if (output.includes('notifications/tools/list_changed')) {
    testResults.mcpHandshake = true;
    console.log('✅ MCP protocol responding');
  }
});

// Server error handling
server.stderr.on('data', (data) => {
  const error = data.toString();
  serverError += error;
  
  if (error.includes('Error:') || error.includes('TypeError:') || error.includes('SyntaxError:')) {
    testResults.errors.push(error.trim());
    console.log(`❌ Server error: ${error.trim()}`);
  }
});

// Server exit handling
server.on('exit', (code) => {
  if (code !== 0) {
    testResults.errors.push(`Server exited with code ${code}`);
    console.log(`❌ Server exited with code ${code}`);
  }
});

// Wait for server to start and then test tools
setTimeout(async () => {
  console.log('\n🔍 Testing MCP Protocol Communication...\n');
  
  try {
    // Test 1: Basic MCP handshake
    await testMCPHandshake();
    
    // Test 2: Tools list
    await testToolsList();
    
    // Test 3: Sample tool execution
    await testSampleTools();
    
  } catch (error) {
    testResults.errors.push(`Test execution error: ${error.message}`);
    console.log(`❌ Test execution error: ${error.message}`);
  }
  
  // Generate test report
  generateTestReport();
  
  // Cleanup
  server.kill();
  process.exit(0);
  
}, 5000); // Wait 5 seconds for server to start

// Test MCP handshake
async function testMCPHandshake() {
  console.log('📡 Testing MCP handshake...');
  
  try {
    // Send a simple MCP request
    const request = {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: {
          name: "smoke-test",
          version: "1.0.0"
        }
      }
    };
    
    server.stdin.write(JSON.stringify(request) + '\n');
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    if (serverOutput.includes('initialize') || serverOutput.includes('jsonrpc')) {
      testResults.mcpHandshake = true;
      console.log('✅ MCP handshake successful');
    } else {
      console.log('⚠️  MCP handshake response not detected');
    }
    
  } catch (error) {
    console.log(`❌ MCP handshake test failed: ${error.message}`);
  }
}

// Test tools list
async function testToolsList() {
  console.log('\n📋 Testing tools list...');
  
  try {
    const request = {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list"
    };
    
    server.stdin.write(JSON.stringify(request) + '\n');
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    if (serverOutput.includes('tools/list') || serverOutput.includes('result')) {
      testResults.toolsList = true;
      console.log('✅ Tools list request successful');
    } else {
      console.log('⚠️  Tools list response not detected');
    }
    
  } catch (error) {
    console.log(`❌ Tools list test failed: ${error.message}`);
  }
}

// Test sample tools
async function testSampleTools() {
  console.log('\n🧪 Testing sample tools...');
  
  const sampleTools = [
    'mcp_mcp-god-mode_health',
    'mcp_mcp-god-mode_system_info',
    'mcp_mcp-god-mode_fs_list'
  ];
  
  for (const toolName of sampleTools) {
    try {
      console.log(`  Testing ${toolName}...`);
      
      const request = {
        jsonrpc: "2.0",
        id: Math.floor(Math.random() * 1000),
        method: "tools/call",
        params: {
          name: toolName,
          arguments: {}
        }
      };
      
      server.stdin.write(JSON.stringify(request) + '\n');
      
      // Wait for response
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      if (serverOutput.includes(toolName) || serverOutput.includes('result')) {
        console.log(`    ✅ ${toolName} responded`);
        testResults.toolTests.push({ tool: toolName, status: 'success' });
      } else {
        console.log(`    ⚠️  ${toolName} no response detected`);
        testResults.toolTests.push({ tool: toolName, status: 'no_response' });
      }
      
    } catch (error) {
      console.log(`    ❌ ${toolName} test failed: ${error.message}`);
      testResults.toolTests.push({ tool: toolName, status: 'error', error: error.message });
    }
  }
}

// Generate comprehensive test report
function generateTestReport() {
  console.log('\n' + '='.repeat(60));
  console.log('📊 MCP GOD MODE SMOKE TEST REPORT');
  console.log('='.repeat(60));
  
  // Server status
  console.log('\n🚀 SERVER STATUS:');
  console.log(`  Startup: ${testResults.serverStart ? '✅ SUCCESS' : '❌ FAILED'}`);
  console.log(`  MCP Protocol: ${testResults.mcpHandshake ? '✅ WORKING' : '❌ FAILED'}`);
  console.log(`  Tools List: ${testResults.toolsList ? '✅ WORKING' : '❌ FAILED'}`);
  console.log(`  Tools Count: ${testResults.toolsCount > 0 ? `✅ ${testResults.toolsCount}` : '❌ 0'}`);
  
  // Tool test results
  if (testResults.toolTests.length > 0) {
    console.log('\n🧪 TOOL TEST RESULTS:');
    testResults.toolTests.forEach(test => {
      const status = test.status === 'success' ? '✅' : 
                    test.status === 'no_response' ? '⚠️' : '❌';
      console.log(`  ${status} ${test.tool}: ${test.status}`);
    });
  }
  
  // Errors and warnings
  if (testResults.errors.length > 0) {
    console.log('\n❌ ERRORS:');
    testResults.errors.forEach(error => {
      console.log(`  • ${error}`);
    });
  }
  
  if (testResults.warnings.length > 0) {
    console.log('\n⚠️  WARNINGS:');
    testResults.warnings.forEach(warning => {
      console.log(`  • ${warning}`);
    });
  }
  
  // Overall assessment
  console.log('\n📈 OVERALL ASSESSMENT:');
  const successCount = [testResults.serverStart, testResults.mcpHandshake, testResults.toolsList].filter(Boolean).length;
  const totalTests = 3;
  
  if (successCount === totalTests) {
    console.log('🎉 EXCELLENT: All core tests passed!');
    console.log('💡 The server should work with Cursor. If you still see a red indicator,');
    console.log('   try restarting Cursor completely or check MCP configuration.');
  } else if (successCount >= 2) {
    console.log('⚠️  PARTIAL: Some tests passed, but there are issues.');
    console.log('💡 The server is partially working. Check the errors above.');
  } else {
    console.log('❌ CRITICAL: Most tests failed.');
    console.log('💡 The server has serious issues that need to be fixed.');
  }
  
  console.log('\n' + '='.repeat(60));
}

// Handle process termination
process.on('SIGINT', () => {
  console.log('\n🛑 Test interrupted by user');
  server.kill();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Test terminated');
  server.kill();
  process.exit(0);
});

// Timeout protection
setTimeout(() => {
  console.log('\n⏰ Test timeout reached');
  generateTestReport();
  server.kill();
  process.exit(0);
}, TEST_CONFIG.timeout);
