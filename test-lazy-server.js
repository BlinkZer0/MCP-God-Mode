#!/usr/bin/env node

// Test script to verify lazy loading server functionality
import { spawn } from 'child_process';

async function testLazyServer() {
  console.log('🚀 Testing MCP God Mode Lazy Loading Server');
  console.log('==========================================');
  
  return new Promise((resolve) => {
    const server = spawn('node', ['dist/server-lazy.js'], {
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
    
    // Wait for server to start and show lazy loading info
    setTimeout(() => {
      if (!resolved) {
        resolved = true;
        server.kill();
        
        console.log('\n📊 Lazy Server Output:');
        console.log('======================');
        console.log(output);
        
        // Check for key lazy loading indicators
        const hasLazyLoading = output.includes('LAZY LOADING');
        const hasToolCount = output.includes('Total Tools Available');
        const hasPreloaded = output.includes('Preloaded Tools');
        const hasAvailable = output.includes('Available for Lazy Loading');
        const hasDiscovery = output.includes('tool_discovery');
        
        console.log('\n✅ Lazy Loading Features Test:');
        console.log('==============================');
        console.log(`Lazy Loading Architecture: ${hasLazyLoading ? '✅' : '❌'}`);
        console.log(`Tool Count Display: ${hasToolCount ? '✅' : '❌'}`);
        console.log(`Preloaded Tools: ${hasPreloaded ? '✅' : '❌'}`);
        console.log(`Available for Lazy Loading: ${hasAvailable ? '✅' : '❌'}`);
        console.log(`Tool Discovery: ${hasDiscovery ? '✅' : '❌'}`);
        
        // Extract tool count if available
        const toolCountMatch = output.match(/Total Tools Available: (\d+)/);
        const toolCount = toolCountMatch ? parseInt(toolCountMatch[1]) : 'Unknown';
        
        console.log(`\n📈 Tool Count: ${toolCount}`);
        
        if (hasLazyLoading && hasToolCount && toolCount >= 180) {
          console.log('\n🎉 SUCCESS: Lazy loading server is working properly!');
          console.log('✅ All 180+ tools are available for lazy loading');
        } else {
          console.log('\n⚠️  WARNING: Lazy loading server may have issues');
        }
        
        resolve({
          success: hasLazyLoading && hasToolCount && toolCount >= 180,
          toolCount,
          features: {
            lazyLoading: hasLazyLoading,
            toolCount: hasToolCount,
            preloaded: hasPreloaded,
            available: hasAvailable,
            discovery: hasDiscovery
          }
        });
      }
    });
    
    server.on('error', (error) => {
      if (!resolved) {
        resolved = true;
        console.log(`❌ Server error: ${error.message}`);
        resolve({ success: false, error: error.message });
      }
    });
  });
}

async function main() {
  try {
    const result = await testLazyServer();
    
    console.log('\n📋 Test Summary:');
    console.log('================');
    console.log(`Success: ${result.success ? '✅' : '❌'}`);
    if (result.toolCount) {
      console.log(`Tool Count: ${result.toolCount}`);
    }
    if (result.features) {
      console.log('Features:', result.features);
    }
    
    process.exit(result.success ? 0 : 1);
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    process.exit(1);
  }
}

main();
