#!/usr/bin/env node

// Test script to verify tool counts in both server builds
import { spawn } from 'child_process';
import { setTimeout } from 'timers/promises';

async function testServerToolCount(serverPath, serverName) {
  console.log(`\n🔧 Testing ${serverName}...`);
  
  return new Promise((resolve) => {
    const server = spawn('node', [serverPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: process.cwd()
    });
    
    let output = '';
    let resolved = false;
    
    server.stdout.on('data', (data) => {
      output += data.toString();
    });
    
    server.stderr.on('data', (data) => {
      output += data.toString();
    });
    
    // Wait for server to start and show tool count
    setTimeout(3000).then(() => {
      if (!resolved) {
        resolved = true;
        server.kill();
        
        // Extract tool count from output
        const toolCountMatch = output.match(/Total Tools Available: (\d+)|Tools Available: (\d+)|(\d+) tools registered/);
        const toolCount = toolCountMatch ? 
          parseInt(toolCountMatch[1] || toolCountMatch[2] || toolCountMatch[3]) : 
          'Unknown';
        
        console.log(`✅ ${serverName} - Tools Available: ${toolCount}`);
        console.log(`📊 Output preview: ${output.substring(0, 200)}...`);
        
        resolve(toolCount);
      }
    });
    
    server.on('error', (error) => {
      if (!resolved) {
        resolved = true;
        console.log(`❌ ${serverName} - Error: ${error.message}`);
        resolve('Error');
      }
    });
  });
}

async function main() {
  console.log('🚀 MCP God Mode - Tool Count Verification Test');
  console.log('===============================================');
  
  try {
    // Test both server builds
    const modularCount = await testServerToolCount('dist/server-modular.js', 'Modular Server');
    const refactoredCount = await testServerToolCount('dist/server-refactored.js', 'Refactored Server');
    
    console.log('\n📊 Test Results:');
    console.log('================');
    console.log(`Modular Server: ${modularCount} tools`);
    console.log(`Refactored Server: ${refactoredCount} tools`);
    
    if (modularCount >= 184 && refactoredCount >= 184) {
      console.log('\n✅ SUCCESS: Both servers have 184+ tools available!');
    } else {
      console.log('\n⚠️  WARNING: One or both servers may not have all 184 tools');
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

main();
