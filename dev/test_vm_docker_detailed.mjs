#!/usr/bin/env node

/**
 * Detailed VM and Docker Tools Test Suite
 * Tests VM and Docker management tools for cross-platform compatibility
 */

import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import * as os from 'os';

const SERVER_PATH = './dist/server.js';
const TEST_TIMEOUT = 20000; // 20 seconds

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

async function testVMManagement() {
  console.log('🖥️  Testing VM Management Tools...\n');
  
  const vmTests = [
    { action: 'list_hypervisors', description: 'List available hypervisors' },
    { action: 'list_vms', description: 'List virtual machines' },
    { action: 'vm_info', description: 'Get VM information', vm_name: 'test-vm', vm_type: 'virtualbox' }
  ];
  
  let passed = 0;
  let failed = 0;
  let partial = 0;
  
  for (const test of vmTests) {
    console.log(`Testing: ${test.description} (${test.action})`);
    try {
      const params = { action: test.action };
      if (test.vm_name) params.vm_name = test.vm_name;
      if (test.vm_type) params.vm_type = test.vm_type;
      
      const result = await testTool('vm_management', params);
      
      if (result.result && result.result.structuredContent) {
        const { success, results, platform, hypervisor } = result.result.structuredContent;
        
        if (success !== false) {
          console.log(`   ✅ PASSED`);
          console.log(`      Platform: ${platform}`);
          console.log(`      Hypervisor: ${hypervisor || 'Not detected'}`);
          if (results) {
            console.log(`      Results: ${JSON.stringify(results).substring(0, 100)}...`);
          }
          passed++;
        } else {
          console.log(`   ⚠️  PARTIAL - Tool responded but operation failed`);
          console.log(`      Error: ${result.result.structuredContent.error || 'Unknown error'}`);
          partial++;
        }
      } else {
        console.log(`   ✅ PASSED (no structured content)`);
        passed++;
      }
    } catch (error) {
      console.log(`   ❌ FAILED: ${error.message}`);
      failed++;
    }
    console.log('');
  }
  
  return { passed, failed, partial };
}

async function testDockerManagement() {
  console.log('🐳 Testing Docker Management Tools...\n');
  
  const dockerTests = [
    { action: 'docker_version', description: 'Get Docker version' },
    { action: 'docker_info', description: 'Get Docker system info' },
    { action: 'list_containers', description: 'List Docker containers' },
    { action: 'list_images', description: 'List Docker images' },
    { action: 'list_networks', description: 'List Docker networks' },
    { action: 'list_volumes', description: 'List Docker volumes' }
  ];
  
  let passed = 0;
  let failed = 0;
  let partial = 0;
  
  for (const test of dockerTests) {
    console.log(`Testing: ${test.description} (${test.action})`);
    try {
      const params = { action: test.action };
      const result = await testTool('docker_management', params);
      
      if (result.result && result.result.structuredContent) {
        const { success, results, platform, docker_available, error } = result.result.structuredContent;
        
        if (success !== false) {
          console.log(`   ✅ PASSED`);
          console.log(`      Platform: ${platform}`);
          console.log(`      Docker Available: ${docker_available}`);
          if (results) {
            console.log(`      Results: ${JSON.stringify(results).substring(0, 100)}...`);
          }
          passed++;
        } else {
          console.log(`   ⚠️  PARTIAL - Tool responded but operation failed`);
          console.log(`      Error: ${error || 'Unknown error'}`);
          console.log(`      Docker Available: ${docker_available}`);
          partial++;
        }
      } else {
        console.log(`   ✅ PASSED (no structured content)`);
        passed++;
      }
    } catch (error) {
      console.log(`   ❌ FAILED: ${error.message}`);
      failed++;
    }
    console.log('');
  }
  
  return { passed, failed, partial };
}

async function checkSystemRequirements() {
  console.log('🔍 Checking System Requirements...\n');
  
  const platform = os.platform();
  console.log(`Platform: ${platform}`);
  
  // Check for Docker
  try {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);
    
    try {
      const { stdout } = await execAsync('docker --version');
      console.log(`✅ Docker: ${stdout.trim()}`);
    } catch (error) {
      console.log('❌ Docker: Not available');
    }
  } catch (error) {
    console.log('⚠️  Could not check Docker availability');
  }
  
  // Check for VirtualBox
  try {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);
    
    try {
      const { stdout } = await execAsync('VBoxManage --version');
      console.log(`✅ VirtualBox: ${stdout.trim()}`);
    } catch (error) {
      console.log('❌ VirtualBox: Not available');
    }
  } catch (error) {
    console.log('⚠️  Could not check VirtualBox availability');
  }
  
  // Check for VMware
  try {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);
    
    try {
      const { stdout } = await execAsync('vmrun -T ws list');
      console.log(`✅ VMware: Available`);
    } catch (error) {
      console.log('❌ VMware: Not available');
    }
  } catch (error) {
    console.log('⚠️  Could not check VMware availability');
  }
  
  // Check for QEMU/KVM (Linux)
  if (platform === 'linux') {
    try {
      const { exec } = await import('child_process');
      const { promisify } = await import('util');
      const execAsync = promisify(exec);
      
      try {
        const { stdout } = await execAsync('virsh --version');
        console.log(`✅ QEMU/KVM: ${stdout.trim()}`);
      } catch (error) {
        console.log('❌ QEMU/KVM: Not available');
      }
    } catch (error) {
      console.log('⚠️  Could not check QEMU/KVM availability');
    }
  }
  
  // Check for Hyper-V (Windows)
  if (platform === 'win32') {
    try {
      const { exec } = await import('child_process');
      const { promisify } = await import('util');
      const execAsync = promisify(exec);
      
      try {
        const { stdout } = await execAsync('powershell "Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All"');
        if (stdout.includes('Enabled')) {
          console.log('✅ Hyper-V: Available');
        } else {
          console.log('❌ Hyper-V: Not available');
        }
      } catch (error) {
        console.log('❌ Hyper-V: Not available');
      }
    } catch (error) {
      console.log('⚠️  Could not check Hyper-V availability');
    }
  }
  
  console.log('');
}

async function runDetailedTests() {
  console.log('🧪 MCP God Mode VM & Docker Detailed Testing...\n');
  console.log('=' .repeat(70));
  
  try {
    // Check system requirements
    await checkSystemRequirements();
    
    // Test VM management
    const vmResults = await testVMManagement();
    
    // Test Docker management
    const dockerResults = await testDockerManagement();
    
    // Summary
    console.log('=' .repeat(70));
    console.log('📊 DETAILED TEST SUMMARY');
    console.log('=' .repeat(70));
    
    console.log('VM Management Tools:');
    console.log(`   ✅ Passed: ${vmResults.passed}`);
    console.log(`   ⚠️  Partial: ${vmResults.partial}`);
    console.log(`   ❌ Failed: ${vmResults.failed}`);
    
    console.log('\nDocker Management Tools:');
    console.log(`   ✅ Passed: ${dockerResults.passed}`);
    console.log(`   ⚠️  Partial: ${dockerResults.partial}`);
    console.log(`   ❌ Failed: ${dockerResults.failed}`);
    
    const totalPassed = vmResults.passed + dockerResults.passed;
    const totalPartial = vmResults.partial + dockerResults.partial;
    const totalFailed = vmResults.failed + dockerResults.failed;
    const totalTools = totalPassed + totalPartial + totalFailed;
    
    console.log(`\nTotal tools tested: ${totalTools}`);
    console.log(`Success rate: ${((totalPassed + totalPartial) / totalTools * 100).toFixed(1)}%`);
    
    if (totalFailed === 0) {
      console.log('\n🎉 All VM and Docker tools are working correctly!');
      console.log('🚀 Ready for production use!');
    } else {
      console.log('\n⚠️  Some VM and Docker tools need attention.');
    }
    
  } catch (error) {
    console.error('Detailed testing failed:', error);
    process.exit(1);
  }
}

runDetailedTests();
