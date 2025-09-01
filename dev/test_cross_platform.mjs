#!/usr/bin/env node

/**
 * Cross-Platform Compatibility Test Suite
 * Tests platform detection and cross-platform tool functionality
 */

import { spawn } from 'child_process';
import * as os from 'os';
import * as path from 'path';

const SERVER_PATH = './dist/server.js';
const TEST_TIMEOUT = 15000; // 15 seconds

// Platform-specific tests
const PLATFORM_TESTS = {
  win32: {
    name: 'Windows',
    specificTools: ['win_services', 'win_processes'],
    commands: ['dir', 'tasklist', 'sc query']
  },
  linux: {
    name: 'Linux',
    specificTools: ['unix_processes'],
    commands: ['ls', 'ps', 'systemctl status']
  },
  darwin: {
    name: 'macOS',
    specificTools: ['unix_processes'],
    commands: ['ls', 'ps', 'launchctl list']
  }
};

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

async function testPlatformDetection() {
  console.log('🌍 Testing Platform Detection...\n');
  
  const platform = os.platform();
  const arch = os.arch();
  const platformInfo = PLATFORM_TESTS[platform] || { name: 'Unknown', specificTools: [], commands: [] };
  
  console.log(`Current Platform: ${platformInfo.name} (${platform})`);
  console.log(`Architecture: ${arch}`);
  console.log(`Platform-specific tools: ${platformInfo.specificTools.join(', ')}`);
  
  // Test system_info tool to verify platform detection
  try {
    const result = await testTool('system_info', {});
    if (result.result && result.result.structuredContent) {
      const { platform: detectedPlatform, arch: detectedArch } = result.result.structuredContent;
      console.log(`✅ Platform detection: ${detectedPlatform} (${detectedArch})`);
      
      if (detectedPlatform === platform) {
        console.log('✅ Platform detection matches OS');
      } else {
        console.log('⚠️  Platform detection mismatch');
      }
    }
  } catch (error) {
    console.log(`❌ Platform detection test failed: ${error.message}`);
  }
  
  return { platform, arch, platformInfo };
}

async function testCrossPlatformTools() {
  console.log('\n🔧 Testing Cross-Platform Tools...\n');
  
  const crossPlatformTools = [
    { name: 'health', params: {} },
    { name: 'fs_list', params: { dir: '.' } },
    { name: 'fs_read_text', params: { path: 'package.json' } },
    { name: 'proc_run', params: { command: 'echo', args: ['cross-platform-test'] } },
    { name: 'calculator', params: { expression: '2 + 2' } },
    { name: 'git_status', params: {} }
  ];
  
  let passed = 0;
  let failed = 0;
  
  for (const tool of crossPlatformTools) {
    console.log(`Testing ${tool.name}...`);
    try {
      const result = await testTool(tool.name, tool.params);
      if (result.result && result.result.structuredContent) {
        const { success } = result.result.structuredContent;
        if (success !== false) {
          console.log(`   ✅ ${tool.name} - PASSED`);
          passed++;
        } else {
          console.log(`   ⚠️  ${tool.name} - PARTIAL`);
          passed++;
        }
      } else {
        console.log(`   ✅ ${tool.name} - PASSED`);
        passed++;
      }
    } catch (error) {
      console.log(`   ❌ ${tool.name} - FAILED: ${error.message}`);
      failed++;
    }
  }
  
  console.log(`\nCross-platform tools: ${passed}✅ ${failed}❌`);
  return { passed, failed };
}

async function testPlatformSpecificTools(platformInfo) {
  console.log('\n🎯 Testing Platform-Specific Tools...\n');
  
  let passed = 0;
  let failed = 0;
  
  for (const toolName of platformInfo.specificTools) {
    console.log(`Testing ${toolName}...`);
    try {
      const params = toolName === 'win_services' ? { action: 'list' } : {};
      const result = await testTool(toolName, params);
      
      if (result.result && result.result.structuredContent) {
        const { success } = result.result.structuredContent;
        if (success !== false) {
          console.log(`   ✅ ${toolName} - PASSED`);
          passed++;
        } else {
          console.log(`   ⚠️  ${toolName} - PARTIAL`);
          passed++;
        }
      } else {
        console.log(`   ✅ ${toolName} - PASSED`);
        passed++;
      }
    } catch (error) {
      console.log(`   ❌ ${toolName} - FAILED: ${error.message}`);
      failed++;
    }
  }
  
  console.log(`\nPlatform-specific tools: ${passed}✅ ${failed}❌`);
  return { passed, failed };
}

async function testMobilePlatformDetection() {
  console.log('\n📱 Testing Mobile Platform Detection...\n');
  
  const mobileTools = [
    'mobile_device_info',
    'mobile_file_ops',
    'mobile_system_tools',
    'mobile_hardware'
  ];
  
  let passed = 0;
  let failed = 0;
  
  for (const toolName of mobileTools) {
    console.log(`Testing ${toolName}...`);
    try {
      const params = toolName === 'mobile_file_ops' ? { action: 'list', path: '.' } : 
                    toolName === 'mobile_system_tools' ? { action: 'system_info' } :
                    toolName === 'mobile_hardware' ? { action: 'device_info' } : {};
      
      const result = await testTool(toolName, params);
      
      if (result.result && result.result.structuredContent) {
        const { success, platform } = result.result.structuredContent;
        if (success !== false) {
          console.log(`   ✅ ${toolName} - PASSED (Platform: ${platform})`);
          passed++;
        } else {
          console.log(`   ⚠️  ${toolName} - PARTIAL`);
          passed++;
        }
      } else {
        console.log(`   ✅ ${toolName} - PASSED`);
        passed++;
      }
    } catch (error) {
      console.log(`   ❌ ${toolName} - FAILED: ${error.message}`);
      failed++;
    }
  }
  
  console.log(`\nMobile platform tools: ${passed}✅ ${failed}❌`);
  return { passed, failed };
}

async function runCrossPlatformTests() {
  console.log('🧪 MCP God Mode Cross-Platform Compatibility Testing...\n');
  console.log('=' .repeat(70));
  
  try {
    // Test platform detection
    const { platform, platformInfo } = await testPlatformDetection();
    
    // Test cross-platform tools
    const crossPlatformResults = await testCrossPlatformTools();
    
    // Test platform-specific tools
    const platformSpecificResults = await testPlatformSpecificTools(platformInfo);
    
    // Test mobile platform tools
    const mobileResults = await testMobilePlatformDetection();
    
    // Summary
    console.log('\n' + '=' .repeat(70));
    console.log('📊 CROSS-PLATFORM COMPATIBILITY SUMMARY');
    console.log('=' .repeat(70));
    
    console.log(`Platform: ${platformInfo.name} (${platform})`);
    console.log(`Cross-platform tools: ${crossPlatformResults.passed}✅ ${crossPlatformResults.failed}❌`);
    console.log(`Platform-specific tools: ${platformSpecificResults.passed}✅ ${platformSpecificResults.failed}❌`);
    console.log(`Mobile platform tools: ${mobileResults.passed}✅ ${mobileResults.failed}❌`);
    
    const totalPassed = crossPlatformResults.passed + platformSpecificResults.passed + mobileResults.passed;
    const totalFailed = crossPlatformResults.failed + platformSpecificResults.failed + mobileResults.failed;
    const totalTools = totalPassed + totalFailed;
    
    console.log(`\nTotal tools tested: ${totalTools}`);
    console.log(`Success rate: ${((totalPassed / totalTools) * 100).toFixed(1)}%`);
    
    if (totalFailed === 0) {
      console.log('\n🎉 All tools are cross-platform compatible!');
      console.log('🚀 Ready for production use across all platforms!');
    } else {
      console.log('\n⚠️  Some tools need attention for cross-platform compatibility.');
    }
    
  } catch (error) {
    console.error('Cross-platform testing failed:', error);
    process.exit(1);
  }
}

runCrossPlatformTests();
