#!/usr/bin/env node

/**
 * Test script for the website-based cellular triangulation workflow
 * This script tests the complete flow from SMS trigger to location collection
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

// Test configuration
const SERVER_PORT = 3000;
const SERVER_URL = `http://localhost:${SERVER_PORT}`;

// Colors for console output
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

// Test functions
async function testServerHealth() {
  log('\n🔍 Testing server health...', 'blue');
  
  try {
    const response = await fetch(`${SERVER_URL}/api/cellular/health`);
    const data = await response.json();
    
    if (data.status === 'healthy') {
      log('✅ Server health check passed', 'green');
      return true;
    } else {
      log('❌ Server health check failed', 'red');
      return false;
    }
  } catch (error) {
    log(`❌ Server health check failed: ${error.message}`, 'red');
    return false;
  }
}

async function testWebpageAccess() {
  log('\n🌐 Testing webpage access...', 'blue');
  
  try {
    const response = await fetch(`${SERVER_URL}/collect?t=test123`);
    const html = await response.text();
    
    if (html.includes('Location Collection') && html.includes('collectLocation()')) {
      log('✅ Webpage access test passed', 'green');
      return true;
    } else {
      log('❌ Webpage access test failed - invalid content', 'red');
      return false;
    }
  } catch (error) {
    log(`❌ Webpage access test failed: ${error.message}`, 'red');
    return false;
  }
}

async function testGPSDataCollection() {
  log('\n📍 Testing GPS data collection...', 'blue');
  
  const testToken = 'test-gps-' + Date.now();
  const testGPSData = {
    lat: 43.0731,
    lon: -89.4012,
    error_radius_m: 10,
    timestamp: Date.now(),
    method: 'gps'
  };
  
  try {
    const response = await fetch(`${SERVER_URL}/api/cellular/collect?t=${testToken}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        token: testToken,
        towers: [testGPSData]
      })
    });
    
    const result = await response.json();
    
    if (result.status === 'success' && result.data_type === 'gps') {
      log('✅ GPS data collection test passed', 'green');
      
      // Test status endpoint
      const statusResponse = await fetch(`${SERVER_URL}/api/cellular/status/${testToken}`);
      const statusData = await statusResponse.json();
      
      if (statusData.data_type === 'gps' && statusData.gps_data) {
        log('✅ GPS data status check passed', 'green');
        return true;
      } else {
        log('❌ GPS data status check failed', 'red');
        return false;
      }
    } else {
      log('❌ GPS data collection test failed', 'red');
      return false;
    }
  } catch (error) {
    log(`❌ GPS data collection test failed: ${error.message}`, 'red');
    return false;
  }
}

async function testTowerDataCollection() {
  log('\n📡 Testing tower data collection...', 'blue');
  
  const testToken = 'test-towers-' + Date.now();
  const testTowerData = [
    {
      cid: '1234',
      lac: '5678',
      mcc: '310',
      mnc: '410',
      rssi: -70
    },
    {
      cid: '1235',
      lac: '5679',
      mcc: '310',
      mnc: '410',
      rssi: -75
    },
    {
      cid: '1236',
      lac: '5680',
      mcc: '310',
      mnc: '410',
      rssi: -80
    }
  ];
  
  try {
    const response = await fetch(`${SERVER_URL}/api/cellular/collect?t=${testToken}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        token: testToken,
        towers: testTowerData
      })
    });
    
    const result = await response.json();
    
    if (result.status === 'success' && result.data_type === 'towers') {
      log('✅ Tower data collection test passed', 'green');
      
      // Test towers endpoint
      const towersResponse = await fetch(`${SERVER_URL}/api/cellular/towers/${testToken}`);
      const towersData = await towersResponse.json();
      
      if (towersData.data_type === 'towers' && towersData.towers.length === 3) {
        log('✅ Tower data retrieval test passed', 'green');
        return true;
      } else {
        log('❌ Tower data retrieval test failed', 'red');
        return false;
      }
    } else {
      log('❌ Tower data collection test failed', 'red');
      return false;
    }
  } catch (error) {
    log(`❌ Tower data collection test failed: ${error.message}`, 'red');
    return false;
  }
}

async function testTokenCleanup() {
  log('\n🧹 Testing token cleanup...', 'blue');
  
  try {
    const response = await fetch(`${SERVER_URL}/api/cellular/tokens`, {
      headers: {
        'x-admin-key': 'test-admin-key'
      }
    });
    
    if (response.status === 403) {
      log('✅ Admin access protection test passed', 'green');
      return true;
    } else {
      log('❌ Admin access protection test failed', 'red');
      return false;
    }
  } catch (error) {
    log(`❌ Token cleanup test failed: ${error.message}`, 'red');
    return false;
  }
}

// Main test function
async function runTests() {
  log('🚀 Starting Cellular Triangulation Website Tests', 'blue');
  log('=' .repeat(50), 'blue');
  
  const tests = [
    { name: 'Server Health', fn: testServerHealth },
    { name: 'Webpage Access', fn: testWebpageAccess },
    { name: 'GPS Data Collection', fn: testGPSDataCollection },
    { name: 'Tower Data Collection', fn: testTowerDataCollection },
    { name: 'Token Cleanup', fn: testTokenCleanup }
  ];
  
  let passed = 0;
  let failed = 0;
  
  for (const test of tests) {
    try {
      const result = await test.fn();
      if (result) {
        passed++;
      } else {
        failed++;
      }
    } catch (error) {
      log(`❌ ${test.name} test crashed: ${error.message}`, 'red');
      failed++;
    }
  }
  
  log('\n' + '=' .repeat(50), 'blue');
  log(`📊 Test Results: ${passed} passed, ${failed} failed`, failed === 0 ? 'green' : 'red');
  
  if (failed === 0) {
    log('🎉 All tests passed! Website-based cellular triangulation is working correctly.', 'green');
  } else {
    log('⚠️ Some tests failed. Please check the server configuration.', 'yellow');
  }
  
  return failed === 0;
}

// Check if server is running
async function checkServerRunning() {
  try {
    const response = await fetch(`${SERVER_URL}/api/cellular/health`);
    return response.ok;
  } catch (error) {
    return false;
  }
}

// Main execution
async function main() {
  log('🔍 Checking if server is running...', 'blue');
  
  const serverRunning = await checkServerRunning();
  
  if (!serverRunning) {
    log('❌ Server is not running. Please start the server first:', 'red');
    log('   node dist/server-refactored.js', 'yellow');
    log('   or', 'yellow');
    log('   npm start', 'yellow');
    process.exit(1);
  }
  
  log('✅ Server is running', 'green');
  
  const success = await runTests();
  process.exit(success ? 0 : 1);
}

// Handle fetch polyfill for Node.js
if (typeof fetch === 'undefined') {
  global.fetch = require('node-fetch');
}

main().catch(error => {
  log(`💥 Test runner crashed: ${error.message}`, 'red');
  process.exit(1);
});
