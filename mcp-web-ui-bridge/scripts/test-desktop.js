#!/usr/bin/env node

/**
 * Desktop testing script for MCP Web UI Bridge
 * Tests basic functionality on desktop platforms
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

async function runTest(testName, testFunction) {
  console.log(`\n🧪 Running test: ${testName}`);
  try {
    await testFunction();
    console.log(`✅ ${testName} passed`);
  } catch (error) {
    console.error(`❌ ${testName} failed:`, error.message);
    throw error;
  }
}

async function testProviderConfig() {
  const { providerManager } = await import('../dist/providers/registry.js');
  await providerManager.loadProviders();
  
  const providers = providerManager.listProviders();
  if (providers.length === 0) {
    throw new Error('No providers loaded');
  }
  
  console.log(`   Loaded ${providers.length} providers`);
}

async function testDriverInitialization() {
  const { getDriver } = await import('../dist/drivers/driver-bridge.js');
  
  const driver = await getDriver({
    platform: 'desktop',
    headless: true
  });
  
  if (!driver) {
    throw new Error('Failed to initialize driver');
  }
  
  await driver.close();
  console.log('   Driver initialized and closed successfully');
}

async function testSessionManagement() {
  const { sessionManager } = await import('../dist/core/session.js');
  
  await sessionManager.initializeEncryption();
  
  // Test session save/load
  const testData = {
    provider: 'test',
    platform: 'desktop',
    cookies: [{ name: 'test', value: 'value' }],
    timestamp: Date.now()
  };
  
  await sessionManager.saveSession('test', 'desktop', testData);
  const loaded = await sessionManager.loadSession('test', 'desktop');
  
  if (!loaded || loaded.provider !== 'test') {
    throw new Error('Session save/load failed');
  }
  
  await sessionManager.clearSession('test', 'desktop');
  console.log('   Session management working');
}

async function testMacroSystem() {
  const { macroRunner } = await import('../dist/core/macro.js');
  
  // Test macro listing
  const macros = await macroRunner.listMacros();
  console.log(`   Found ${macros.length} existing macros`);
  
  // Test macro validation
  const testMacro = {
    id: 'test-macro',
    version: '1',
    name: 'Test Macro',
    target: {
      url: 'https://example.com',
      platform: 'desktop'
    },
    steps: [
      { type: 'goto', url: 'https://example.com' },
      { type: 'sleep', ms: 1000 }
    ],
    createdAt: Date.now(),
    updatedAt: Date.now()
  };
  
  await macroRunner.saveMacro(testMacro);
  const loaded = await macroRunner.loadMacro('test-macro');
  
  if (!loaded || loaded.id !== 'test-macro') {
    throw new Error('Macro save/load failed');
  }
  
  await macroRunner.deleteMacro('test-macro');
  console.log('   Macro system working');
}

async function testMCPTools() {
  // Test that MCP tools are properly defined
  const { default: server } = await import('../dist/index.js');
  
  // This is a basic test - in a real scenario, we'd test the actual tool execution
  console.log('   MCP server loaded successfully');
}

async function main() {
  console.log('🚀 Starting desktop tests for MCP Web UI Bridge\n');
  
  try {
    // Build the project first
    console.log('📦 Building project...');
    await new Promise((resolve, reject) => {
      const build = spawn('npm', ['run', 'build'], {
        cwd: projectRoot,
        stdio: 'inherit'
      });
      
      build.on('close', (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Build failed with code ${code}`));
        }
      });
    });
    
    // Run tests
    await runTest('Provider Configuration', testProviderConfig);
    await runTest('Driver Initialization', testDriverInitialization);
    await runTest('Session Management', testSessionManagement);
    await runTest('Macro System', testMacroSystem);
    await runTest('MCP Tools', testMCPTools);
    
    console.log('\n🎉 All desktop tests passed!');
    process.exit(0);
    
  } catch (error) {
    console.error('\n💥 Test suite failed:', error.message);
    process.exit(1);
  }
}

main();
