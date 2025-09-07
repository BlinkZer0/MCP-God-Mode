#!/usr/bin/env node

/**
 * Flipper Zero Integration Smoke Tests
 * Tests Flipper Zero integration without requiring actual hardware
 */

import { spawn } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

// Test configuration
const TEST_TIMEOUT = 30000; // 30 seconds
const SERVER_PATH = './dist/server-refactored.js';

/**
 * Run a smoke test
 */
async function runSmokeTest(testName, testFn) {
  console.log(`🧪 Running ${testName}...`);
  
  try {
    const result = await Promise.race([
      testFn(),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Test timeout')), TEST_TIMEOUT)
      )
    ]);
    
    console.log(`✅ ${testName} passed`);
    return { success: true, result };
  } catch (error) {
    console.log(`❌ ${testName} failed: ${error.message}`);
    return { success: false, error: error.message };
  }
}

/**
 * Test Flipper Zero tool registration
 */
async function testToolRegistration() {
  return new Promise((resolve, reject) => {
    const server = spawn('node', [SERVER_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        MCPGM_FLIPPER_ENABLED: 'true',
        MCPGM_FLIPPER_USB_ENABLED: 'true',
        MCPGM_FLIPPER_BLE_ENABLED: 'true'
      }
    });

    let output = '';
    let errorOutput = '';

    server.stdout.on('data', (data) => {
      output += data.toString();
    });

    server.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    // Wait for server to start and register tools
    setTimeout(() => {
      server.kill();
      
      // Check if Flipper tools were registered
      if (output.includes('Flipper Zero tools') && output.includes('flipper_list_devices')) {
        resolve({ registered: true, output });
      } else {
        reject(new Error('Flipper tools not registered properly'));
      }
    }, 5000);
  });
}

/**
 * Test Flipper Zero device listing (no hardware required)
 */
async function testDeviceListing() {
  return new Promise((resolve, reject) => {
    const server = spawn('node', [SERVER_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        MCPGM_FLIPPER_ENABLED: 'true',
        MCPGM_FLIPPER_USB_ENABLED: 'true',
        MCPGM_FLIPPER_BLE_ENABLED: 'true'
      }
    });

    let output = '';
    let errorOutput = '';

    server.stdout.on('data', (data) => {
      output += data.toString();
    });

    server.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    // Send MCP request to list devices
    setTimeout(() => {
      const request = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'flipper_list_devices',
          arguments: {
            scan_ble: true,
            scan_usb: true
          }
        }
      };
      
      server.stdin.write(JSON.stringify(request) + '\n');
    }, 2000);

    // Wait for response
    setTimeout(() => {
      server.kill();
      
      if (output.includes('flipper_list_devices') || output.includes('devices')) {
        resolve({ success: true, output });
      } else {
        reject(new Error('Device listing test failed'));
      }
    }, 8000);
  });
}

/**
 * Test Flipper Zero configuration
 */
async function testConfiguration() {
  const config = {
    enabled: process.env.MCPGM_FLIPPER_ENABLED === 'true',
    usbEnabled: process.env.MCPGM_FLIPPER_USB_ENABLED === 'true',
    bleEnabled: process.env.MCPGM_FLIPPER_BLE_ENABLED === 'true',
    allowTx: process.env.MCPGM_FLIPPER_ALLOW_TX === 'true',
    txMaxSeconds: Number(process.env.MCPGM_FLIPPER_TX_MAX_SECONDS || 10),
    logStreams: process.env.MCPGM_FLIPPER_LOG_STREAMS === 'true'
  };

  // Test default configuration
  if (config.txMaxSeconds === 10 && !config.allowTx) {
    return { success: true, config };
  } else {
    throw new Error('Default configuration not correct');
  }
}

/**
 * Test Flipper Zero session management
 */
async function testSessionManagement() {
  // This test would require importing the session module directly
  // For now, we'll just verify the module can be imported
  try {
    const { getConfig } = await import('../dist/tools/flipper/session.js');
    const config = getConfig();
    
    if (typeof config === 'object' && 'enabled' in config) {
      return { success: true, config };
    } else {
      throw new Error('Session management not working');
    }
  } catch (error) {
    throw new Error(`Session management test failed: ${error.message}`);
  }
}

/**
 * Test Flipper Zero transport modules
 */
async function testTransportModules() {
  try {
    // Test USB transport import
    const usbModule = await import('../dist/tools/flipper/transport/usbSerial.js');
    if (!usbModule.usbTransport) {
      throw new Error('USB transport not exported');
    }

    // Test BLE transport import (may fail if noble not available)
    try {
      const bleModule = await import('../dist/tools/flipper/transport/ble.js');
      if (!bleModule.bleTransport) {
        throw new Error('BLE transport not exported');
      }
    } catch (bleError) {
      console.log('⚠️  BLE transport not available (expected in some environments)');
    }

    return { success: true };
  } catch (error) {
    throw new Error(`Transport modules test failed: ${error.message}`);
  }
}

/**
 * Main smoke test runner
 */
async function main() {
  console.log('🚀 Starting Flipper Zero Integration Smoke Tests...\n');

  const tests = [
    { name: 'Configuration Test', fn: testConfiguration },
    { name: 'Session Management Test', fn: testSessionManagement },
    { name: 'Transport Modules Test', fn: testTransportModules },
    { name: 'Tool Registration Test', fn: testToolRegistration },
    { name: 'Device Listing Test', fn: testDeviceListing }
  ];

  const results = [];
  let passed = 0;
  let failed = 0;

  for (const test of tests) {
    const result = await runSmokeTest(test.name, test.fn);
    results.push({ ...test, ...result });
    
    if (result.success) {
      passed++;
    } else {
      failed++;
    }
    
    console.log(''); // Empty line for readability
  }

  // Summary
  console.log('📊 Smoke Test Summary:');
  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`📈 Success Rate: ${Math.round((passed / tests.length) * 100)}%`);

  if (failed === 0) {
    console.log('\n🎉 All Flipper Zero smoke tests passed!');
    process.exit(0);
  } else {
    console.log('\n⚠️  Some Flipper Zero smoke tests failed. Check the output above.');
    process.exit(1);
  }
}

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (error) => {
  console.error('❌ Unhandled rejection:', error);
  process.exit(1);
});

// Run the smoke tests
main().catch((error) => {
  console.error('❌ Smoke test runner failed:', error);
  process.exit(1);
});
