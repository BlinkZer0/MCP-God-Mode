#!/usr/bin/env node

/**
 * Simple Smoke Test for MCP God Mode
 * Tests server startup and tool registration without MCP protocol
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🚀 MCP God Mode - Simple Smoke Test');
console.log('===================================\n');

// Test configuration
const SERVER_PATH = join(__dirname, 'dist', 'server-refactored.js');

// Check if server exists
if (!fs.existsSync(SERVER_PATH)) {
  console.error(`❌ Server not found at: ${SERVER_PATH}`);
  console.error('Please build the server first: npm run build');
  process.exit(1);
}

console.log(`✅ Server found at: ${SERVER_PATH}\n`);

// Test results
const results = {
  serverStart: false,
  toolRegistration: false,
  toolCount: 0,
  errors: [],
  warnings: []
};

// Test server startup and tool registration
async function testServer() {
  console.log('🚀 Testing server startup and tool registration...\n');
  
  return new Promise((resolve) => {
    const server = spawn('node', [SERVER_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: __dirname
    });

    let output = '';
    let errorOutput = '';
    let startupComplete = false;
    
    const timeout = setTimeout(() => {
      if (!startupComplete) {
        server.kill();
        console.log('❌ Server startup timeout');
        results.errors.push('Server startup timeout');
        resolve(false);
      }
    }, 15000);

    server.stdout.on('data', (data) => {
      const text = data.toString();
      output += text;
      
      // Log important output
      if (text.includes('MCP God Mode') || 
          text.includes('Tools Available') || 
          text.includes('registered') ||
          text.includes('READY FOR PROFESSIONAL')) {
        console.log('📝', text.trim());
      }
      
      // Check for successful startup
      if (text.includes('MCP God Mode') && text.includes('started successfully')) {
        results.serverStart = true;
        console.log('✅ Server started successfully');
      }
      
      // Check for tool registration
      if (text.includes('Total Tools Available:')) {
        const match = text.match(/Total Tools Available: (\d+)/);
        if (match) {
          results.toolCount = parseInt(match[1]);
          results.toolRegistration = true;
          console.log(`✅ ${results.toolCount} tools registered successfully`);
        }
      }
      
      // Check if startup is complete
      if (text.includes('READY FOR PROFESSIONAL') || 
          text.includes('Total Tools Available:')) {
        if (!startupComplete) {
          startupComplete = true;
          clearTimeout(timeout);
          server.kill();
          console.log('\n✅ Server startup and tool registration completed');
          resolve(true);
        }
      }
    });

    server.stderr.on('data', (data) => {
      const text = data.toString();
      errorOutput += text;
      
      // Log warnings but don't fail the test
      if (text.includes('Warning:') || text.includes('Failed to register')) {
        console.log('⚠️', text.trim());
        results.warnings.push(text.trim());
      } else if (text.includes('Error:') && !text.includes('Failed to initialize Express')) {
        console.log('❌', text.trim());
        results.errors.push(text.trim());
      }
    });

    server.on('close', (code) => {
      clearTimeout(timeout);
      if (!startupComplete) {
        if (code !== 0) {
          console.log(`❌ Server exited with code ${code}`);
          results.errors.push(`Server exited with code ${code}`);
        }
        resolve(false);
      }
    });
  });
}

// Generate test report
function generateReport() {
  console.log('\n' + '='.repeat(50));
  console.log('📊 SIMPLE SMOKE TEST REPORT');
  console.log('='.repeat(50));
  
  console.log('\n🚀 SERVER STATUS:');
  console.log(`  Startup: ${results.serverStart ? '✅ SUCCESS' : '❌ FAILED'}`);
  console.log(`  Tool Registration: ${results.toolRegistration ? '✅ SUCCESS' : '❌ FAILED'}`);
  console.log(`  Tools Count: ${results.toolCount > 0 ? `✅ ${results.toolCount}` : '❌ 0'}`);
  
  if (results.warnings.length > 0) {
    console.log('\n⚠️  WARNINGS:');
    results.warnings.forEach(warning => {
      console.log(`  • ${warning}`);
    });
  }
  
  if (results.errors.length > 0) {
    console.log('\n❌ ERRORS:');
    results.errors.forEach(error => {
      console.log(`  • ${error}`);
    });
  }
  
  console.log('\n📈 OVERALL ASSESSMENT:');
  const successCount = [results.serverStart, results.toolRegistration, results.toolCount > 100].filter(Boolean).length;
  
  if (successCount === 3) {
    console.log('🎉 EXCELLENT: Server is working perfectly!');
    console.log('💡 All core functionality is operational.');
  } else if (successCount >= 2) {
    console.log('✅ GOOD: Server is mostly working with minor issues.');
    console.log('💡 Core functionality is operational.');
  } else if (successCount >= 1) {
    console.log('⚠️  FAIR: Server has some issues but basic functionality works.');
    console.log('💡 Some features may not work properly.');
  } else {
    console.log('❌ POOR: Server has significant issues.');
    console.log('💡 Major problems need to be addressed.');
  }
  
  console.log('\n' + '='.repeat(50));
  
  // Save report
  const reportData = {
    timestamp: new Date().toISOString(),
    results: results,
    summary: {
      serverStart: results.serverStart,
      toolRegistration: results.toolRegistration,
      toolCount: results.toolCount,
      successRate: Math.round((successCount / 3) * 100)
    }
  };
  
  const reportFile = `simple-smoke-test-report-${Date.now()}.json`;
  fs.writeFileSync(reportFile, JSON.stringify(reportData, null, 2));
  console.log(`\n📄 Report saved to: ${reportFile}`);
  
  return successCount >= 2;
}

// Main test runner
async function runTest() {
  try {
    const success = await testServer();
    
    const overallSuccess = generateReport();
    
    if (overallSuccess) {
      console.log('\n🎉 Simple smoke test PASSED!');
      process.exit(0);
    } else {
      console.log('\n❌ Simple smoke test FAILED!');
      process.exit(1);
    }
  } catch (error) {
    console.error('💥 Test failed:', error);
    process.exit(1);
  }
}

// Handle interruption
process.on('SIGINT', () => {
  console.log('\n🛑 Test interrupted');
  process.exit(1);
});

// Run the test
runTest();
