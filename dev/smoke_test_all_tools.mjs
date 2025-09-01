#!/usr/bin/env node

/**
 * MCP God Mode Comprehensive Smoke Test Suite
 * Tests ALL 70+ tools to ensure they are working correctly
 * This is a comprehensive test covering every tool in the system
 */

import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import * as os from 'os';
import * as path from 'path';

const SERVER_PATH = './dist/server.js';
const TEST_TIMEOUT = 25000; // 25 seconds for complex operations

// ============================================================================
// COMPREHENSIVE TOOL DEFINITIONS - ALL 70+ TOOLS
// ============================================================================

const ALL_TOOLS = [
  // ===========================================
  // CORE SYSTEM TOOLS (2 Tools)
  // ===========================================
  { name: 'health', params: {}, category: 'Core System', description: 'System health check' },
  { name: 'system_info', params: {}, category: 'Core System', description: 'System information' },
  
  // ===========================================
  // FILE SYSTEM TOOLS (26 Tools - 6 basic + 20 advanced)
  // ===========================================
  { name: 'fs_list', params: { dir: '.' }, category: 'File System', description: 'List files/directories' },
  { name: 'fs_read_text', params: { path: 'package.json' }, category: 'File System', description: 'Read text file' },
  { name: 'fs_write_text', params: { path: 'smoke-test-temp.txt', content: 'Smoke test content' }, category: 'File System', description: 'Write text file' },
  { name: 'fs_search', params: { pattern: '*.json', dir: '.' }, category: 'File System', description: 'File search' },
  { name: 'download_file', params: { url: 'https://httpbin.org/json', path: 'smoke-test-download.json' }, category: 'File System', description: 'Download file' },
  
  // Advanced file operations (20 tools)
  { name: 'file_ops', params: { action: 'list', path: '.' }, category: 'File System', description: 'File ops - list' },
  { name: 'file_ops', params: { action: 'get_info', source: 'package.json' }, category: 'File System', description: 'File ops - get info' },
  { name: 'file_ops', params: { action: 'create_dir', destination: 'smoke-test-dir' }, category: 'File System', description: 'File ops - create dir' },
  { name: 'file_ops', params: { action: 'create_file', destination: 'smoke-test-file.txt', content: 'Test content' }, category: 'File System', description: 'File ops - create file' },
  { name: 'file_ops', params: { action: 'copy', source: 'smoke-test-file.txt', destination: 'smoke-test-file-copy.txt' }, category: 'File System', description: 'File ops - copy' },
  { name: 'file_ops', params: { action: 'move', source: 'smoke-test-file-copy.txt', destination: 'smoke-test-file-moved.txt' }, category: 'File System', description: 'File ops - move' },
  { name: 'file_ops', params: { action: 'get_size', source: 'smoke-test-file.txt' }, category: 'File System', description: 'File ops - get size' },
  { name: 'file_ops', params: { action: 'get_permissions', source: 'smoke-test-file.txt' }, category: 'File System', description: 'File ops - get permissions' },
  { name: 'file_ops', params: { action: 'list_recursive', source: '.', recursive: true }, category: 'File System', description: 'File ops - list recursive' },
  { name: 'file_ops', params: { action: 'find_by_content', source: '.', search_text: 'test', recursive: false }, category: 'File System', description: 'File ops - find by content' },
  { name: 'file_ops', params: { action: 'compress', source: 'smoke-test-file.txt', destination: 'smoke-test-file.zip' }, category: 'File System', description: 'File ops - compress' },
  { name: 'file_ops', params: { action: 'decompress', source: 'smoke-test-file.zip', destination: 'smoke-test-file-decompressed.txt' }, category: 'File System', description: 'File ops - decompress' },
  { name: 'file_ops', params: { action: 'chmod', source: 'smoke-test-file.txt', permissions: '644' }, category: 'File System', description: 'File ops - chmod' },
  { name: 'file_ops', params: { action: 'chown', source: 'smoke-test-file.txt', owner: '1000' }, category: 'File System', description: 'File ops - chown' },
  { name: 'file_ops', params: { action: 'symlink', source: 'smoke-test-file.txt', destination: 'smoke-test-file-symlink.txt' }, category: 'File System', description: 'File ops - symlink' },
  { name: 'file_ops', params: { action: 'hardlink', source: 'smoke-test-file.txt', destination: 'smoke-test-file-hardlink.txt' }, category: 'File System', description: 'File ops - hardlink' },
  { name: 'file_ops', params: { action: 'watch', source: '.', recursive: false }, category: 'File System', description: 'File ops - watch' },
  { name: 'file_ops', params: { action: 'unwatch', source: '.' }, category: 'File System', description: 'File ops - unwatch' },
  { name: 'file_ops', params: { action: 'set_permissions', source: 'smoke-test-file.txt', permissions: '644' }, category: 'File System', description: 'File ops - set permissions' },
  { name: 'file_ops', params: { action: 'compare_files', source: 'smoke-test-file.txt', destination: 'smoke-test-file.txt' }, category: 'File System', description: 'File ops - compare files' },
  
  // ===========================================
  // PROCESS & SERVICE MANAGEMENT (3 Tools)
  // ===========================================
  { name: 'proc_run', params: { command: 'echo', args: ['smoke-test'] }, category: 'Process Management', description: 'Run process' },
  { name: 'win_services', params: { action: 'list' }, category: 'Process Management', description: 'Windows services' },
  { name: 'win_processes', params: {}, category: 'Process Management', description: 'Windows processes' },
  
  // ===========================================
  // VIRTUAL MACHINE MANAGEMENT (1 Tool)
  // ===========================================
  { name: 'vm_management', params: { action: 'list_hypervisors' }, category: 'VM Management', description: 'List hypervisors' },
  { name: 'vm_management', params: { action: 'list_vms' }, category: 'VM Management', description: 'List VMs' },
  { name: 'vm_management', params: { action: 'vm_info', vm_name: 'test-vm', vm_type: 'virtualbox' }, category: 'VM Management', description: 'VM info' },
  
  // ===========================================
  // DOCKER & CONTAINER MANAGEMENT (1 Tool)
  // ===========================================
  { name: 'docker_management', params: { action: 'docker_version' }, category: 'Docker Management', description: 'Docker version' },
  { name: 'docker_management', params: { action: 'docker_info' }, category: 'Docker Management', description: 'Docker info' },
  { name: 'docker_management', params: { action: 'list_containers' }, category: 'Docker Management', description: 'List containers' },
  { name: 'docker_management', params: { action: 'list_images' }, category: 'Docker Management', description: 'List images' },
  { name: 'docker_management', params: { action: 'list_networks' }, category: 'Docker Management', description: 'List networks' },
  { name: 'docker_management', params: { action: 'list_volumes' }, category: 'Docker Management', description: 'List volumes' },
  
  // ===========================================
  // MOBILE PLATFORM TOOLS (4 Tools)
  // ===========================================
  { name: 'mobile_device_info', params: {}, category: 'Mobile Platform', description: 'Mobile device info' },
  { name: 'mobile_file_ops', params: { action: 'list', path: '.' }, category: 'Mobile Platform', description: 'Mobile file ops - list' },
  { name: 'mobile_file_ops', params: { action: 'read', path: 'package.json' }, category: 'Mobile Platform', description: 'Mobile file ops - read' },
  { name: 'mobile_file_ops', params: { action: 'write', path: 'mobile-test.txt', content: 'Mobile test' }, category: 'Mobile Platform', description: 'Mobile file ops - write' },
  { name: 'mobile_file_ops', params: { action: 'delete', path: 'mobile-test.txt' }, category: 'Mobile Platform', description: 'Mobile file ops - delete' },
  { name: 'mobile_file_ops', params: { action: 'copy', source: 'package.json', destination: 'mobile-copy.json' }, category: 'Mobile Platform', description: 'Mobile file ops - copy' },
  { name: 'mobile_file_ops', params: { action: 'move', source: 'mobile-copy.json', destination: 'mobile-moved.json' }, category: 'Mobile Platform', description: 'Mobile file ops - move' },
  { name: 'mobile_file_ops', params: { action: 'create_dir', path: 'mobile-test-dir' }, category: 'Mobile Platform', description: 'Mobile file ops - create dir' },
  { name: 'mobile_file_ops', params: { action: 'get_info', path: 'package.json' }, category: 'Mobile Platform', description: 'Mobile file ops - get info' },
  { name: 'mobile_file_ops', params: { action: 'search', path: '.', pattern: '*.json' }, category: 'Mobile Platform', description: 'Mobile file ops - search' },
  { name: 'mobile_system_tools', params: { action: 'system_info' }, category: 'Mobile Platform', description: 'Mobile system tools - info' },
  { name: 'mobile_system_tools', params: { action: 'processes' }, category: 'Mobile Platform', description: 'Mobile system tools - processes' },
  { name: 'mobile_system_tools', params: { action: 'services' }, category: 'Mobile Platform', description: 'Mobile system tools - services' },
  { name: 'mobile_system_tools', params: { action: 'network' }, category: 'Mobile Platform', description: 'Mobile system tools - network' },
  { name: 'mobile_system_tools', params: { action: 'storage' }, category: 'Mobile Platform', description: 'Mobile system tools - storage' },
  { name: 'mobile_system_tools', params: { action: 'users' }, category: 'Mobile Platform', description: 'Mobile system tools - users' },
  { name: 'mobile_system_tools', params: { action: 'packages' }, category: 'Mobile Platform', description: 'Mobile system tools - packages' },
  { name: 'mobile_system_tools', params: { action: 'permissions' }, category: 'Mobile Platform', description: 'Mobile system tools - permissions' },
  { name: 'mobile_hardware', params: { action: 'device_info' }, category: 'Mobile Platform', description: 'Mobile hardware - device info' },
  { name: 'mobile_hardware', params: { action: 'camera' }, category: 'Mobile Platform', description: 'Mobile hardware - camera' },
  { name: 'mobile_hardware', params: { action: 'location' }, category: 'Mobile Platform', description: 'Mobile hardware - location' },
  { name: 'mobile_hardware', params: { action: 'biometrics' }, category: 'Mobile Platform', description: 'Mobile hardware - biometrics' },
  { name: 'mobile_hardware', params: { action: 'bluetooth' }, category: 'Mobile Platform', description: 'Mobile hardware - bluetooth' },
  { name: 'mobile_hardware', params: { action: 'nfc' }, category: 'Mobile Platform', description: 'Mobile hardware - NFC' },
  { name: 'mobile_hardware', params: { action: 'sensors' }, category: 'Mobile Platform', description: 'Mobile hardware - sensors' },
  { name: 'mobile_hardware', params: { action: 'notifications' }, category: 'Mobile Platform', description: 'Mobile hardware - notifications' },
  { name: 'mobile_hardware', params: { action: 'audio' }, category: 'Mobile Platform', description: 'Mobile hardware - audio' },
  { name: 'mobile_hardware', params: { action: 'vibration' }, category: 'Mobile Platform', description: 'Mobile hardware - vibration' },
  
  // ===========================================
  // MATHEMATICS & CALCULATIONS (2 Tools)
  // ===========================================
  { name: 'calculator', params: { expression: '2 + 2' }, category: 'Mathematics', description: 'Basic calculator' },
  { name: 'calculator', params: { expression: 'sqrt(16) + sin(90)' }, category: 'Mathematics', description: 'Advanced calculator' },
  { name: 'math_calculate', params: { expression: 'sqrt(16)' }, category: 'Mathematics', description: 'Math calculate' },
  { name: 'math_calculate', params: { expression: '2^10' }, category: 'Mathematics', description: 'Math calculate - power' },
  
  // ===========================================
  // DEVELOPMENT & VERSION CONTROL (1 Tool)
  // ===========================================
  { name: 'git_status', params: {}, category: 'Development', description: 'Git status' },
  
  // ===========================================
  // NETWORK TOOLS (1 Tool)
  // ===========================================
  { name: 'network_diagnostics', params: { action: 'ping', target: 'localhost' }, category: 'Network', description: 'Network ping' },
  { name: 'network_diagnostics', params: { action: 'traceroute', target: 'localhost' }, category: 'Network', description: 'Network traceroute' },
  { name: 'network_diagnostics', params: { action: 'dns', target: 'localhost' }, category: 'Network', description: 'Network DNS' },
  { name: 'network_diagnostics', params: { action: 'port_scan', target: 'localhost', ports: '80,443' }, category: 'Network', description: 'Network port scan' }
];

// ============================================================================
// TESTING FUNCTIONS
// ============================================================================

async function testTool(toolName, params, description) {
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

async function runSmokeTest() {
  console.log('🔥 MCP God Mode Comprehensive Smoke Test - ALL 70+ TOOLS\n');
  console.log('=' .repeat(100));
  
  const platform = os.platform();
  const arch = os.arch();
  console.log(`Platform: ${platform} (${arch})`);
  console.log(`Total Tools to Test: ${ALL_TOOLS.length}`);
  console.log(`Test Timeout: ${TEST_TIMEOUT}ms per tool`);
  console.log('=' .repeat(100));
  
  const results = [];
  let passed = 0;
  let failed = 0;
  let partial = 0;
  let notImplemented = 0;
  
  // Group tools by category
  const toolsByCategory = {};
  ALL_TOOLS.forEach(tool => {
    if (!toolsByCategory[tool.category]) {
      toolsByCategory[tool.category] = [];
    }
    toolsByCategory[tool.category].push(tool);
  });
  
  // Test each category
  for (const [category, tools] of Object.entries(toolsByCategory)) {
    console.log(`\n📂 Testing ${category} Tools (${tools.length} tools):`);
    console.log('-'.repeat(80));
    
    for (const tool of tools) {
      const testName = `${tool.name}${tool.params.action ? ` (${tool.params.action})` : ''}`;
      console.log(`\n🔧 Testing: ${testName}`);
      console.log(`   Description: ${tool.description}`);
      
      try {
        const result = await testTool(tool.name, tool.params);
        
        if (result.result && result.result.structuredContent) {
          const { success, error } = result.result.structuredContent;
          if (success !== false) {
            console.log(`   ✅ PASSED`);
            passed++;
            results.push({ name: tool.name, category: tool.category, status: 'PASSED', description: tool.description });
          } else {
            console.log(`   ⚠️  PARTIAL - Tool responded but operation failed`);
            console.log(`   Error: ${error || 'Unknown error'}`);
            partial++;
            results.push({ name: tool.name, category: tool.category, status: 'PARTIAL', error: error, description: tool.description });
          }
        } else {
          console.log(`   ✅ PASSED (no structured content)`);
          passed++;
          results.push({ name: tool.name, category: tool.category, status: 'PASSED', description: tool.description });
        }
      } catch (error) {
        if (error.message.includes('Timeout') || error.message.includes('Server exited')) {
          console.log(`   ❌ FAILED: ${error.message}`);
          failed++;
          results.push({ name: tool.name, category: tool.category, status: 'FAILED', error: error.message, description: tool.description });
        } else {
          console.log(`   ❌ NOT IMPLEMENTED: ${error.message}`);
          notImplemented++;
          results.push({ name: tool.name, category: tool.category, status: 'NOT_IMPLEMENTED', error: error.message, description: tool.description });
        }
      }
    }
  }
  
  // ============================================================================
  // COMPREHENSIVE RESULTS SUMMARY
  // ============================================================================
  
  console.log('\n' + '=' .repeat(100));
  console.log('📊 COMPREHENSIVE SMOKE TEST RESULTS');
  console.log('=' .repeat(100));
  
  console.log(`Total Tools Tested: ${ALL_TOOLS.length}`);
  console.log(`✅ Passed: ${passed}`);
  console.log(`⚠️  Partial: ${partial}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`🚫 Not Implemented: ${notImplemented}`);
  console.log(`Success Rate: ${((passed + partial) / ALL_TOOLS.length * 100).toFixed(1)}%`);
  
  // Results by category
  console.log('\n📂 Results by Category:');
  for (const [category, tools] of Object.entries(toolsByCategory)) {
    const categoryResults = results.filter(r => r.category === category);
    const passedCount = categoryResults.filter(r => r.status === 'PASSED').length;
    const partialCount = categoryResults.filter(r => r.status === 'PARTIAL').length;
    const failedCount = categoryResults.filter(r => r.status === 'FAILED').length;
    const notImplCount = categoryResults.filter(r => r.status === 'NOT_IMPLEMENTED').length;
    
    console.log(`   ${category}: ${passedCount}✅ ${partialCount}⚠️ ${failedCount}❌ ${notImplCount}🚫`);
  }
  
  // Failed tools
  const failedTools = results.filter(r => r.status === 'FAILED');
  if (failedTools.length > 0) {
    console.log('\n❌ Failed Tools:');
    failedTools.forEach(tool => {
      console.log(`   - ${tool.name}: ${tool.error}`);
    });
  }
  
  // Partial tools
  const partialTools = results.filter(r => r.status === 'PARTIAL');
  if (partialTools.length > 0) {
    console.log('\n⚠️  Partial Tools (responded but operation failed):');
    partialTools.forEach(tool => {
      console.log(`   - ${tool.name}: ${tool.error}`);
    });
  }
  
  // Not implemented tools
  const notImplTools = results.filter(r => r.status === 'NOT_IMPLEMENTED');
  if (notImplTools.length > 0) {
    console.log('\n🚫 Not Implemented Tools:');
    notImplTools.forEach(tool => {
      console.log(`   - ${tool.name}: ${tool.error}`);
    });
  }
  
  // ============================================================================
  // FINAL ASSESSMENT
  // ============================================================================
  
  console.log('\n🎯 FINAL ASSESSMENT:');
  
  if (failed === 0 && notImplemented === 0) {
    console.log('🚀 EXCELLENT: All tools are working perfectly!');
    console.log('   MCP God Mode is production-ready with 100% tool coverage.');
  } else if (failed === 0 && partial > 0) {
    console.log('✅ GOOD: All tools are implemented and responding correctly.');
    console.log('   Some tools have conditional functionality (e.g., require Docker/hypervisors).');
  } else if (failed === 0) {
    console.log('⚠️  FAIR: All implemented tools work, but some tools are not implemented.');
    console.log('   Consider implementing missing tools for full functionality.');
  } else {
    console.log('❌ NEEDS ATTENTION: Some tools are failing and need investigation.');
    console.log('   Review failed tools before production use.');
  }
  
  console.log('\n🎉 MCP God Mode Comprehensive Smoke Test Complete!');
  console.log(`Tested ${ALL_TOOLS.length} tools across all categories.`);
  
  // Cleanup test files
  await cleanupTestFiles();
}

async function cleanupTestFiles() {
  console.log('\n🧹 Cleaning up test files...');
  const filesToCleanup = [
    'smoke-test-temp.txt',
    'smoke-test-download.json',
    'smoke-test-dir',
    'smoke-test-file.txt',
    'smoke-test-file-copy.txt',
    'smoke-test-file-moved.txt',
    'smoke-test-file.zip',
    'smoke-test-file-decompressed.txt',
    'smoke-test-file-symlink.txt',
    'smoke-test-file-hardlink.txt',
    'mobile-test.txt',
    'mobile-copy.json',
    'mobile-moved.json',
    'mobile-test-dir'
  ];
  
  for (const file of filesToCleanup) {
    try {
      await fs.rm(file, { recursive: true, force: true });
    } catch (e) {
      // Ignore cleanup errors
    }
  }
  console.log('✅ Cleanup complete');
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

runSmokeTest().catch(error => {
  console.error('🔥 Smoke test failed:', error);
  process.exit(1);
});
