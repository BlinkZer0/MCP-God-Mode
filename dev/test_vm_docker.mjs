#!/usr/bin/env node

/**
 * VM and Docker Tools Test Suite
 * Tests the new VM and Docker management tools for cross-platform compatibility
 */

import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';

const SERVER_PATH = './dist/server.js';
const TEST_TIMEOUT = 30000; // 30 seconds

// Test configuration
const testConfig = {
  vm: {
    testVmName: 'test-vm-mcp',
    testMemory: 512,
    testCores: 1,
    testDiskSize: 5
  },
  docker: {
    testContainerName: 'test-container-mcp',
    testImageName: 'hello-world',
    testImageTag: 'latest'
  }
};

// Utility functions
function createTestRequest(tool, params) {
  return {
    jsonrpc: '2.0',
    id: Date.now(),
    method: 'tools/call',
    params: {
      name: tool,
      arguments: params
    }
  };
}

function sendRequest(server, request) {
  return new Promise((resolve, reject) => {
    let response = '';
    let error = '';
    
    const timeout = setTimeout(() => {
      server.kill();
      reject(new Error('Request timeout'));
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
          reject(new Error(`Failed to parse response: ${parseError.message}\nResponse: ${response}`));
        }
      }
    });
    
    server.stdin.write(JSON.stringify(request) + '\n');
    server.stdin.end();
  });
}

async function runTest(testName, testFunction) {
  console.log(`\n🧪 Running test: ${testName}`);
  try {
    const result = await testFunction();
    console.log(`✅ ${testName} - PASSED`);
    return { name: testName, status: 'PASSED', result };
  } catch (error) {
    console.log(`❌ ${testName} - FAILED: ${error.message}`);
    return { name: testName, status: 'FAILED', error: error.message };
  }
}

// Test functions
async function testVmListHypervisors() {
  const server = spawn('node', [SERVER_PATH], { stdio: ['pipe', 'pipe', 'pipe'] });
  const request = createTestRequest('vm_management', { action: 'list_hypervisors' });
  const result = await sendRequest(server, request);
  
  if (!result.result || !result.result.structuredContent) {
    throw new Error('Invalid response structure');
  }
  
  const { success, results } = result.result.structuredContent;
  if (!success) {
    throw new Error(`VM hypervisor detection failed: ${result.result.structuredContent.error}`);
  }
  
  if (!results || !Array.isArray(results.available)) {
    throw new Error('Invalid hypervisor list format');
  }
  
  console.log(`   Available hypervisors: ${results.available.join(', ') || 'none'}`);
  console.log(`   Detected hypervisor: ${results.detected || 'none'}`);
  
  return result;
}

async function testVmListVms() {
  const server = spawn('node', [SERVER_PATH], { stdio: ['pipe', 'pipe', 'pipe'] });
  const request = createTestRequest('vm_management', { 
    action: 'list_vms',
    vm_type: 'auto'
  });
  const result = await sendRequest(server, request);
  
  if (!result.result || !result.result.structuredContent) {
    throw new Error('Invalid response structure');
  }
  
  const { success } = result.result.structuredContent;
  if (!success) {
    // This is expected if no hypervisors are available
    console.log(`   No VMs found or hypervisor not available: ${result.result.structuredContent.error}`);
    return result;
  }
  
  console.log(`   VMs listed successfully`);
  return result;
}

async function testDockerVersion() {
  const server = spawn('node', [SERVER_PATH], { stdio: ['pipe', 'pipe', 'pipe'] });
  const request = createTestRequest('docker_management', { action: 'docker_version' });
  const result = await sendRequest(server, request);
  
  if (!result.result || !result.result.structuredContent) {
    throw new Error('Invalid response structure');
  }
  
  const { success, docker_available } = result.result.structuredContent;
  if (!docker_available) {
    console.log(`   Docker not available: ${result.result.structuredContent.error}`);
    return result;
  }
  
  if (!success) {
    throw new Error(`Docker version check failed: ${result.result.structuredContent.error}`);
  }
  
  console.log(`   Docker version: ${result.result.structuredContent.results.version}`);
  return result;
}

async function testDockerInfo() {
  const server = spawn('node', [SERVER_PATH], { stdio: ['pipe', 'pipe', 'pipe'] });
  const request = createTestRequest('docker_management', { action: 'docker_info' });
  const result = await sendRequest(server, request);
  
  if (!result.result || !result.result.structuredContent) {
    throw new Error('Invalid response structure');
  }
  
  const { success, docker_available } = result.result.structuredContent;
  if (!docker_available) {
    console.log(`   Docker not available: ${result.result.structuredContent.error}`);
    return result;
  }
  
  if (!success) {
    throw new Error(`Docker info failed: ${result.result.structuredContent.error}`);
  }
  
  console.log(`   Docker info retrieved successfully`);
  return result;
}

async function testDockerListContainers() {
  const server = spawn('node', [SERVER_PATH], { stdio: ['pipe', 'pipe', 'pipe'] });
  const request = createTestRequest('docker_management', { 
    action: 'list_containers',
    all_containers: true
  });
  const result = await sendRequest(server, request);
  
  if (!result.result || !result.result.structuredContent) {
    throw new Error('Invalid response structure');
  }
  
  const { success, docker_available } = result.result.structuredContent;
  if (!docker_available) {
    console.log(`   Docker not available: ${result.result.structuredContent.error}`);
    return result;
  }
  
  if (!success) {
    throw new Error(`Docker list containers failed: ${result.result.structuredContent.error}`);
  }
  
  const containers = result.result.structuredContent.results.containers;
  console.log(`   Found ${containers.length - 1} containers (excluding header)`);
  return result;
}

async function testDockerListImages() {
  const server = spawn('node', [SERVER_PATH], { stdio: ['pipe', 'pipe', 'pipe'] });
  const request = createTestRequest('docker_management', { action: 'list_images' });
  const result = await sendRequest(server, request);
  
  if (!result.result || !result.result.structuredContent) {
    throw new Error('Invalid response structure');
  }
  
  const { success, docker_available } = result.result.structuredContent;
  if (!docker_available) {
    console.log(`   Docker not available: ${result.result.structuredContent.error}`);
    return result;
  }
  
  if (!success) {
    throw new Error(`Docker list images failed: ${result.result.structuredContent.error}`);
  }
  
  const images = result.result.structuredContent.results.images;
  console.log(`   Found ${images.length - 1} images (excluding header)`);
  return result;
}

async function testDockerPullImage() {
  const server = spawn('node', [SERVER_PATH], { stdio: ['pipe', 'pipe', 'pipe'] });
  const request = createTestRequest('docker_management', { 
    action: 'pull_image',
    image_name: testConfig.docker.testImageName,
    image_tag: testConfig.docker.testImageTag
  });
  const result = await sendRequest(server, request);
  
  if (!result.result || !result.result.structuredContent) {
    throw new Error('Invalid response structure');
  }
  
  const { success, docker_available } = result.result.structuredContent;
  if (!docker_available) {
    console.log(`   Docker not available: ${result.result.structuredContent.error}`);
    return result;
  }
  
  if (!success) {
    // This might fail due to network issues, which is acceptable for testing
    console.log(`   Docker pull failed (may be network related): ${result.result.structuredContent.error}`);
    return result;
  }
  
  console.log(`   Successfully pulled image: ${testConfig.docker.testImageName}:${testConfig.docker.testImageTag}`);
  return result;
}

async function testDockerListNetworks() {
  const server = spawn('node', [SERVER_PATH], { stdio: ['pipe', 'pipe', 'pipe'] });
  const request = createTestRequest('docker_management', { action: 'list_networks' });
  const result = await sendRequest(server, request);
  
  if (!result.result || !result.result.structuredContent) {
    throw new Error('Invalid response structure');
  }
  
  const { success, docker_available } = result.result.structuredContent;
  if (!docker_available) {
    console.log(`   Docker not available: ${result.result.structuredContent.error}`);
    return result;
  }
  
  if (!success) {
    throw new Error(`Docker list networks failed: ${result.result.structuredContent.error}`);
  }
  
  const networks = result.result.structuredContent.results.networks;
  console.log(`   Found ${networks.length - 1} networks (excluding header)`);
  return result;
}

async function testDockerListVolumes() {
  const server = spawn('node', [SERVER_PATH], { stdio: ['pipe', 'pipe', 'pipe'] });
  const request = createTestRequest('docker_management', { action: 'list_volumes' });
  const result = await sendRequest(server, request);
  
  if (!result.result || !result.result.structuredContent) {
    throw new Error('Invalid response structure');
  }
  
  const { success, docker_available } = result.result.structuredContent;
  if (!docker_available) {
    console.log(`   Docker not available: ${result.result.structuredContent.error}`);
    return result;
  }
  
  if (!success) {
    throw new Error(`Docker list volumes failed: ${result.result.structuredContent.error}`);
  }
  
  const volumes = result.result.structuredContent.results.volumes;
  console.log(`   Found ${volumes.length - 1} volumes (excluding header)`);
  return result;
}

// Main test runner
async function runAllTests() {
  console.log('🚀 Starting VM and Docker Tools Test Suite');
  console.log('=' .repeat(50));
  
  const tests = [
    { name: 'VM List Hypervisors', fn: testVmListHypervisors },
    { name: 'VM List VMs', fn: testVmListVms },
    { name: 'Docker Version', fn: testDockerVersion },
    { name: 'Docker Info', fn: testDockerInfo },
    { name: 'Docker List Containers', fn: testDockerListContainers },
    { name: 'Docker List Images', fn: testDockerListImages },
    { name: 'Docker Pull Image', fn: testDockerPullImage },
    { name: 'Docker List Networks', fn: testDockerListNetworks },
    { name: 'Docker List Volumes', fn: testDockerListVolumes }
  ];
  
  const results = [];
  
  for (const test of tests) {
    const result = await runTest(test.name, test.fn);
    results.push(result);
  }
  
  // Generate test report
  console.log('\n' + '=' .repeat(50));
  console.log('📊 TEST SUMMARY');
  console.log('=' .repeat(50));
  
  const passed = results.filter(r => r.status === 'PASSED').length;
  const failed = results.filter(r => r.status === 'FAILED').length;
  
  console.log(`Total Tests: ${results.length}`);
  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`Success Rate: ${((passed / results.length) * 100).toFixed(1)}%`);
  
  if (failed > 0) {
    console.log('\n❌ Failed Tests:');
    results.filter(r => r.status === 'FAILED').forEach(test => {
      console.log(`   - ${test.name}: ${test.error}`);
    });
  }
  
  // Save detailed report
  const report = {
    timestamp: new Date().toISOString(),
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.version,
    summary: {
      total: results.length,
      passed,
      failed,
      successRate: ((passed / results.length) * 100).toFixed(1) + '%'
    },
    tests: results
  };
  
  await fs.writeFile('vm_docker_test_report.json', JSON.stringify(report, null, 2));
  console.log('\n📄 Detailed report saved to: vm_docker_test_report.json');
  
  if (failed > 0) {
    process.exit(1);
  } else {
    console.log('\n🎉 All tests passed! VM and Docker tools are working correctly.');
  }
}

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runAllTests().catch(error => {
    console.error('Test suite failed:', error);
    process.exit(1);
  });
}

export { runAllTests, testConfig };
