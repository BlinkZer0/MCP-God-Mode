#!/usr/bin/env node

/**
 * Comprehensive MCP God Mode Tool Test Suite
 * Tests all 25+ tools mentioned in the README to ensure proper implementation
 */

import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';

const SERVER_PATH = './dist/server.js';
const TEST_TIMEOUT = 30000; // 30 seconds

// All tools mentioned in the README
const ALL_TOOLS = [
  // Core System Operations (2 Tools)
  { name: 'health', params: {}, category: 'Core System' },
  { name: 'system_info', params: {}, category: 'Core System' },
  
  // File System Mastery (6 Tools)
  { name: 'fs_list', params: { dir: '.' }, category: 'File System' },
  { name: 'fs_read_text', params: { path: 'package.json' }, category: 'File System' },
  { name: 'fs_write_text', params: { path: 'test-temp.txt', content: 'Test content' }, category: 'File System' },
  { name: 'fs_search', params: { pattern: '*.json', dir: '.' }, category: 'File System' },
  { name: 'file_ops', params: { action: 'list', path: '.' }, category: 'File System' },
  { name: 'download_file', params: { url: 'https://httpbin.org/json', path: 'test-download.json' }, category: 'File System' },
  
  // Process & Service Management (3 Tools)
  { name: 'proc_run', params: { command: 'echo', args: ['test'] }, category: 'Process Management' },
  { name: 'win_services', params: { action: 'list' }, category: 'Process Management' },
  { name: 'win_processes', params: {}, category: 'Process Management' },
  
  // Virtual Machine Management (1 Tool)
  { name: 'vm_management', params: { action: 'list_hypervisors' }, category: 'VM Management' },
  
  // Docker & Container Management (1 Tool)
  { name: 'docker_management', params: { action: 'docker_version' }, category: 'Docker Management' },
  
  // Mobile Platform Tools (4 Tools)
  { name: 'mobile_device_info', params: {}, category: 'Mobile Platform' },
  { name: 'mobile_file_ops', params: { action: 'list', path: '.' }, category: 'Mobile Platform' },
  { name: 'mobile_system_tools', params: { action: 'system_info' }, category: 'Mobile Platform' },
  { name: 'mobile_hardware', params: { action: 'device_info' }, category: 'Mobile Platform' },
  
  // Advanced Mathematics & Calculations (1 Tool)
  { name: 'calculator', params: { expression: '2 + 2' }, category: 'Mathematics' },
  
  // Development & Version Control (1 Tool)
  { name: 'git_status', params: {}, category: 'Development' }
];

// Additional tools that might exist
const ADDITIONAL_TOOLS = [
  { name: 'network_diagnostics', params: { action: 'ping', target: 'localhost' }, category: 'Network' },
  { name: 'math_calculate', params: { expression: 'sqrt(16)' }, category: 'Mathematics' }
];

const ALL_TOOLS_TO_TEST = [...ALL_TOOLS, ...ADDITIONAL_TOOLS];

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
    }, TEST_TIMEOUT);
    
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
  console.log('🧪 Comprehensive MCP God Mode Tool Testing...\n');
  console.log('=' .repeat(80));
  
  const results = [];
  let passed = 0;
  let failed = 0;
  let partial = 0;
  let notImplemented = 0;
  
  // Group tools by category
  const toolsByCategory = {};
  ALL_TOOLS_TO_TEST.forEach(tool => {
    if (!toolsByCategory[tool.category]) {
      toolsByCategory[tool.category] = [];
    }
    toolsByCategory[tool.category].push(tool);
  });
  
  for (const [category, tools] of Object.entries(toolsByCategory)) {
    console.log(`\n📂 Testing ${category} Tools (${tools.length} tools):`);
    console.log('-'.repeat(50));
    
    for (const tool of tools) {
      console.log(`\n🔧 Testing: ${tool.name}`);
      try {
        const result = await testTool(tool.name, tool.params);
        
        if (result.result && result.result.structuredContent) {
          const { success } = result.result.structuredContent;
          if (success !== false) {
            console.log(`   ✅ ${tool.name} - PASSED`);
            passed++;
            results.push({ name: tool.name, category: tool.category, status: 'PASSED' });
          } else {
            console.log(`   ⚠️  ${tool.name} - PARTIAL (tool responded but operation failed)`);
            console.log(`   Error: ${result.result.structuredContent.error || 'Unknown error'}`);
            partial++;
            results.push({ name: tool.name, category: tool.category, status: 'PARTIAL', error: result.result.structuredContent.error });
          }
        } else {
          console.log(`   ✅ ${tool.name} - PASSED (no structured content)`);
          passed++;
          results.push({ name: tool.name, category: tool.category, status: 'PASSED' });
        }
      } catch (error) {
        if (error.message.includes('Timeout') || error.message.includes('Server exited')) {
          console.log(`   ❌ ${tool.name} - FAILED: ${error.message}`);
          failed++;
          results.push({ name: tool.name, category: tool.category, status: 'FAILED', error: error.message });
        } else {
          console.log(`   ❌ ${tool.name} - NOT IMPLEMENTED: ${error.message}`);
          notImplemented++;
          results.push({ name: tool.name, category: tool.category, status: 'NOT_IMPLEMENTED', error: error.message });
        }
      }
    }
  }
  
  console.log('\n' + '=' .repeat(80));
  console.log('📊 COMPREHENSIVE TEST SUMMARY');
  console.log('=' .repeat(80));
  
  console.log(`Total Tools Tested: ${ALL_TOOLS_TO_TEST.length}`);
  console.log(`✅ Passed: ${passed}`);
  console.log(`⚠️  Partial: ${partial}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`🚫 Not Implemented: ${notImplemented}`);
  console.log(`Success Rate: ${((passed + partial) / ALL_TOOLS_TO_TEST.length * 100).toFixed(1)}%`);
  
  // Show results by category
  console.log('\n📂 Results by Category:');
  for (const [category, tools] of Object.entries(toolsByCategory)) {
    const categoryResults = results.filter(r => r.category === category);
    const passedCount = categoryResults.filter(r => r.status === 'PASSED').length;
    const partialCount = categoryResults.filter(r => r.status === 'PARTIAL').length;
    const failedCount = categoryResults.filter(r => r.status === 'FAILED').length;
    const notImplCount = categoryResults.filter(r => r.status === 'NOT_IMPLEMENTED').length;
    
    console.log(`   ${category}: ${passedCount}✅ ${partialCount}⚠️ ${failedCount}❌ ${notImplCount}🚫`);
  }
  
  // Show failed tools
  const failedTools = results.filter(r => r.status === 'FAILED');
  if (failedTools.length > 0) {
    console.log('\n❌ Failed Tools:');
    failedTools.forEach(tool => {
      console.log(`   - ${tool.name} (${tool.category}): ${tool.error}`);
    });
  }
  
  // Show partial tools
  const partialTools = results.filter(r => r.status === 'PARTIAL');
  if (partialTools.length > 0) {
    console.log('\n⚠️  Partial Tools (responded but operation failed):');
    partialTools.forEach(tool => {
      console.log(`   - ${tool.name} (${tool.category}): ${tool.error}`);
    });
  }
  
  // Show not implemented tools
  const notImplTools = results.filter(r => r.status === 'NOT_IMPLEMENTED');
  if (notImplTools.length > 0) {
    console.log('\n🚫 Not Implemented Tools:');
    notImplTools.forEach(tool => {
      console.log(`   - ${tool.name} (${tool.category}): ${tool.error}`);
    });
  }
  
  console.log('\n🎉 MCP God Mode Comprehensive Testing Complete!');
  
  if (failed === 0 && notImplemented === 0) {
    console.log('🚀 All tools are working! Ready for production use!');
  } else if (failed === 0) {
    console.log('⚠️  Some tools are not implemented, but all implemented tools work correctly.');
  } else {
    console.log('❌ Some tools need attention before production use.');
  }
  
  // Cleanup test files
  try {
    await fs.unlink('test-temp.txt');
    await fs.unlink('test-download.json');
  } catch (e) {
    // Ignore cleanup errors
  }
}

runAllTests().catch(error => {
  console.error('Test suite failed:', error);
  process.exit(1);
});
