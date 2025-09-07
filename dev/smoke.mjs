#!/usr/bin/env node

import { spawn } from 'node:child_process';

console.log('🧪 MCP God Mode - Comprehensive Smoke Test');
console.log('==========================================');

// Test configuration
const SERVER_PATH = './dist/server-refactored.js';
const TEST_TIMEOUT = 30000; // 30 seconds
const TOOLS_TO_TEST = [
  'mcp_mcp-god-mode_health',
  'mcp_mcp-god-mode_system_info',
  'mcp_mcp-god-mode_fs_list',
  'mcp_mcp-god-mode_calculator',
  'mcp_mcp-god-mode_rag_toolkit',
  'mcp_mcp-god-mode_captcha_defeating',
  'mcp_mcp-god-mode_web_search',
  'mcp_mcp-god-mode_network_diagnostics',
  'mcp_mcp-god-mode_password_generator',
  'mcp_mcp-god-mode_screenshot'
];

// Test results tracking
const testResults = {
  passed: 0,
  failed: 0,
  errors: []
};

// Utility function to send MCP request
function sendMCPRequest(server, request) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Request timeout'));
    }, 10000);

    server.stdin.write(JSON.stringify(request) + '\n');
    
    let response = '';
    const onData = (data) => {
      response += data.toString();
      if (response.includes('\n')) {
        clearTimeout(timeout);
        server.stdout.removeListener('data', onData);
        try {
          const parsed = JSON.parse(response.trim());
          resolve(parsed);
        } catch (error) {
          reject(new Error(`Failed to parse response: ${error.message}`));
        }
      }
    };
    
    server.stdout.on('data', onData);
  });
}

// Test individual tool
async function testTool(server, toolName) {
  console.log(`\n🔧 Testing ${toolName}...`);
  
  try {
    // Initialize request
    const initRequest = {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {
          tools: {}
        },
        clientInfo: {
          name: 'smoke-test',
          version: '1.0.0'
        }
      }
    };

    await sendMCPRequest(server, initRequest);
    
    // List tools request
    const listToolsRequest = {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list',
      params: {}
    };

    const toolsResponse = await sendMCPRequest(server, listToolsRequest);
    
    if (!toolsResponse.result || !toolsResponse.result.tools) {
      throw new Error('No tools returned from server');
    }

    const toolExists = toolsResponse.result.tools.some(tool => tool.name === toolName);
    
    if (!toolExists) {
      throw new Error(`Tool ${toolName} not found in server`);
    }

    console.log(`✅ ${toolName} - Tool registered successfully`);
    testResults.passed++;
    return true;

  } catch (error) {
    console.log(`❌ ${toolName} - ${error.message}`);
    testResults.failed++;
    testResults.errors.push(`${toolName}: ${error.message}`);
    return false;
  }
}

// Test server startup
async function testServerStartup() {
  console.log('\n🚀 Testing server startup...');
  
  return new Promise((resolve) => {
    const server = spawn('node', [SERVER_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: process.cwd()
    });

    let startupOutput = '';
    let startupError = '';
    
    const timeout = setTimeout(() => {
      server.kill();
      console.log('❌ Server startup timeout');
      testResults.failed++;
      testResults.errors.push('Server startup: Timeout');
      resolve(false);
    }, 15000);

    server.stdout.on('data', (data) => {
      startupOutput += data.toString();
      if (startupOutput.includes('MCP God Mode') && startupOutput.includes('started successfully')) {
        clearTimeout(timeout);
        console.log('✅ Server started successfully');
        testResults.passed++;
        server.kill();
        resolve(true);
      }
    });

    server.stderr.on('data', (data) => {
      startupError += data.toString();
    });

    server.on('close', (code) => {
      clearTimeout(timeout);
      if (code !== 0 && !startupOutput.includes('started successfully')) {
        console.log('❌ Server failed to start');
        console.log('Error output:', startupError);
        testResults.failed++;
        testResults.errors.push(`Server startup: Exit code ${code}`);
        resolve(false);
      }
    });
  });
}

// Test tool registration
async function testToolRegistration() {
  console.log('\n📋 Testing tool registration...');
  
  return new Promise((resolve) => {
    const server = spawn('node', [SERVER_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: process.cwd()
    });

    let output = '';
    let errorOutput = '';
    
    const timeout = setTimeout(() => {
      server.kill();
      console.log('❌ Tool registration test timeout');
      testResults.failed++;
      testResults.errors.push('Tool registration: Timeout');
      resolve(false);
    }, 20000);

    server.stdout.on('data', (data) => {
      output += data.toString();
    });

    server.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    server.on('close', (code) => {
      clearTimeout(timeout);
      
      // Check for successful tool registration
      const toolCountMatch = output.match(/Total Tools Available: (\d+)/);
      const registeredToolsMatch = output.match(/Successfully registered (\d+) tool functions/);
      
      if (toolCountMatch && registeredToolsMatch) {
        const toolCount = parseInt(toolCountMatch[1]);
        const registeredCount = parseInt(registeredToolsMatch[1]);
        
        if (toolCount > 100 && registeredCount > 100) {
          console.log(`✅ Tool registration successful - ${toolCount} tools available, ${registeredCount} functions registered`);
          testResults.passed++;
          resolve(true);
        } else {
          console.log(`❌ Insufficient tools registered - ${toolCount} tools, ${registeredCount} functions`);
          testResults.failed++;
          testResults.errors.push(`Tool registration: Only ${toolCount} tools registered`);
          resolve(false);
        }
      } else {
        console.log('❌ Tool registration indicators not found');
        console.log('Output:', output.substring(0, 500));
        testResults.failed++;
        testResults.errors.push('Tool registration: Indicators not found');
        resolve(false);
      }
    });
  });
}

// Test RAG tool specifically
async function testRAGTool() {
  console.log('\n🤖 Testing RAG Toolkit...');
  
  return new Promise((resolve) => {
    const server = spawn('node', [SERVER_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: process.cwd()
    });

    let output = '';
    
    const timeout = setTimeout(() => {
      server.kill();
      console.log('❌ RAG tool test timeout');
      testResults.failed++;
      testResults.errors.push('RAG tool: Timeout');
      resolve(false);
    }, 15000);

    server.stdout.on('data', (data) => {
      output += data.toString();
    });

    server.on('close', (code) => {
      clearTimeout(timeout);
      
      if (output.includes('rag_toolkit') || output.includes('RAG')) {
        console.log('✅ RAG Toolkit detected in server output');
        testResults.passed++;
        resolve(true);
      } else {
        console.log('❌ RAG Toolkit not found');
        testResults.failed++;
        testResults.errors.push('RAG tool: Not found in server');
        resolve(false);
      }
    });
  });
}

// Main test runner
async function runSmokeTest() {
  console.log('Starting comprehensive smoke test...\n');
  
  // Test 1: Server startup
  await testServerStartup();
  await new Promise(resolve => setTimeout(resolve, 2000)); // Wait between tests
  
  // Test 2: Tool registration
  await testToolRegistration();
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  // Test 3: RAG tool specifically
  await testRAGTool();
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  // Test 4: Individual tool tests (simplified)
  console.log('\n🔍 Testing individual tools...');
  for (const tool of TOOLS_TO_TEST.slice(0, 5)) { // Test first 5 tools only
    await testTool(null, tool); // Simplified test
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  // Print results
  console.log('\n📊 SMOKE TEST RESULTS');
  console.log('====================');
  console.log(`✅ Passed: ${testResults.passed}`);
  console.log(`❌ Failed: ${testResults.failed}`);
  console.log(`📈 Success Rate: ${((testResults.passed / (testResults.passed + testResults.failed)) * 100).toFixed(1)}%`);
  
  if (testResults.errors.length > 0) {
    console.log('\n🚨 Errors:');
    testResults.errors.forEach(error => console.log(`  - ${error}`));
  }
  
  if (testResults.failed === 0) {
    console.log('\n🎉 All tests passed! Server is ready for production.');
    process.exit(0);
  } else {
    console.log('\n⚠️  Some tests failed. Please review the errors above.');
    process.exit(1);
  }
}

// Handle process termination
process.on('SIGINT', () => {
  console.log('\n🛑 Smoke test interrupted');
  process.exit(1);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Smoke test terminated');
  process.exit(1);
});

// Run the smoke test
runSmokeTest().catch(error => {
  console.error('💥 Smoke test failed:', error);
  process.exit(1);
});
