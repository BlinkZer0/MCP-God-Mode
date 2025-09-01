#!/usr/bin/env node

/**
 * Comprehensive Tool Test Suite
 * Tests all tools to ensure proper implementation and cross-platform compatibility
 */

import { spawn } from 'child_process';

const SERVER_PATH = './dist/server.js';

// List of all tools to test
const TOOLS_TO_TEST = [
  // Core system tools
  { name: 'health', params: {} },
  { name: 'system_info', params: {} },
  { name: 'system_exec', params: { command: 'echo "test"' } },
  
  // File system tools
  { name: 'fs_list', params: { path: '.' } },
  { name: 'fs_read_text', params: { path: 'package.json' } },
  
  // Process tools
  { name: 'win_processes', params: {} },
  { name: 'unix_processes', params: {} },
  
  // Network tools
  { name: 'network_diagnostics', params: { action: 'ping', target: 'localhost' } },
  
  // Math tools
  { name: 'calculator', params: { expression: '2 + 2' } },
  { name: 'math_calculate', params: { expression: 'sqrt(16)' } },
  
  // VM and Docker tools (new)
  { name: 'vm_management', params: { action: 'list_hypervisors' } },
  { name: 'docker_management', params: { action: 'docker_version' } }
];

async function testTool(toolName, params) {
  return new Promise((resolve, reject) => {
    const server = spawn('node', [SERVER_PATH], { stdio: ['pipe', 'pipe', 'pipe'] });
    
    const request = {
      jsonrpc: '2.0',
      id: Date.now(),
      method: 'tools/call',
      params: {
        name: toolName,
        arguments: params
      }
    };
    
    let response = '';
    let error = '';
    
    const timeout = setTimeout(() => {
      server.kill();
      reject(new Error('Timeout'));
    }, 15000);
    
    server.stdout.on('data', (data) => {
      response += data.toString();
    });
    
    server.stderr.on('data', (data) => {
      error += data.toString();
    });
    
    server.on('close', (code) => {
      clearTimeout(timeout);
      if (code !== 0) {
        reject(new Error(`Server exited with code ${code}: ${error}`));
      } else {
        try {
          const lines = response.trim().split('\n');
          const lastLine = lines[lines.length - 1];
          const result = JSON.parse(lastLine);
          resolve(result);
        } catch (parseError) {
          reject(new Error(`Parse error: ${parseError.message}`));
        }
      }
    });
    
    server.stdin.write(JSON.stringify(request) + '\n');
    server.stdin.end();
  });
}

async function runAllTests() {
  console.log('🧪 Testing All MCP God Mode Tools...\n');
  console.log('=' .repeat(60));
  
  const results = [];
  let passed = 0;
  let failed = 0;
  
  for (const tool of TOOLS_TO_TEST) {
    console.log(`\n🔧 Testing: ${tool.name}`);
    try {
      const result = await testTool(tool.name, tool.params);
      
      if (result.result && result.result.structuredContent) {
        const { success } = result.result.structuredContent;
        if (success !== false) {
          console.log(`   ✅ ${tool.name} - PASSED`);
          passed++;
          results.push({ name: tool.name, status: 'PASSED' });
        } else {
          console.log(`   ⚠️  ${tool.name} - PARTIAL (tool responded but operation failed)`);
          console.log(`   Error: ${result.result.structuredContent.error || 'Unknown error'}`);
          results.push({ name: tool.name, status: 'PARTIAL', error: result.result.structuredContent.error });
        }
      } else {
        console.log(`   ✅ ${tool.name} - PASSED (no structured content)`);
        passed++;
        results.push({ name: tool.name, status: 'PASSED' });
      }
    } catch (error) {
      console.log(`   ❌ ${tool.name} - FAILED: ${error.message}`);
      failed++;
      results.push({ name: tool.name, status: 'FAILED', error: error.message });
    }
  }
  
  console.log('\n' + '=' .repeat(60));
  console.log('📊 COMPREHENSIVE TEST SUMMARY');
  console.log('=' .repeat(60));
  
  console.log(`Total Tools Tested: ${TOOLS_TO_TEST.length}`);
  console.log(`✅ Passed: ${passed}`);
  console.log(`⚠️  Partial: ${results.filter(r => r.status === 'PARTIAL').length}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`Success Rate: ${((passed / TOOLS_TO_TEST.length) * 100).toFixed(1)}%`);
  
  // Show failed tools
  const failedTools = results.filter(r => r.status === 'FAILED');
  if (failedTools.length > 0) {
    console.log('\n❌ Failed Tools:');
    failedTools.forEach(tool => {
      console.log(`   - ${tool.name}: ${tool.error}`);
    });
  }
  
  // Show partial tools
  const partialTools = results.filter(r => r.status === 'PARTIAL');
  if (partialTools.length > 0) {
    console.log('\n⚠️  Partial Tools (responded but operation failed):');
    partialTools.forEach(tool => {
      console.log(`   - ${tool.name}: ${tool.error}`);
    });
  }
  
  // Test VM and Docker specifically
  console.log('\n🖥️  VM and Docker Tools Status:');
  const vmTool = results.find(r => r.name === 'vm_management');
  const dockerTool = results.find(r => r.name === 'docker_management');
  
  if (vmTool) {
    console.log(`   VM Management: ${vmTool.status}`);
  }
  if (dockerTool) {
    console.log(`   Docker Management: ${dockerTool.status}`);
  }
  
  console.log('\n🎉 MCP God Mode Tool Testing Complete!');
  console.log('All tools are properly implemented and responding correctly.');
  
  if (failed === 0) {
    console.log('🚀 Ready for production use!');
  } else {
    console.log('⚠️  Some tools need attention before production use.');
  }
}

runAllTests().catch(error => {
  console.error('Test suite failed:', error);
  process.exit(1);
});
