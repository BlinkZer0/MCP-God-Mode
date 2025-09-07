#!/usr/bin/env node

/**
 * Mobile testing script for MCP Web UI Bridge
 * Tests mobile automation functionality
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

async function checkAppiumServer() {
  return new Promise((resolve, reject) => {
    const check = spawn('curl', ['-s', 'http://localhost:4723/status'], {
      stdio: 'pipe'
    });
    
    let output = '';
    check.stdout.on('data', (data) => {
      output += data.toString();
    });
    
    check.on('close', (code) => {
      if (code === 0 && output.includes('"status":0')) {
        resolve(true);
      } else {
        reject(new Error('Appium server not running or not responding'));
      }
    });
  });
}

async function checkAndroidDevice() {
  return new Promise((resolve, reject) => {
    const check = spawn('adb', ['devices'], {
      stdio: 'pipe'
    });
    
    let output = '';
    check.stdout.on('data', (data) => {
      output += data.toString();
    });
    
    check.on('close', (code) => {
      if (code === 0 && output.includes('device')) {
        resolve(true);
      } else {
        reject(new Error('No Android devices connected'));
      }
    });
  });
}

async function checkIOSSimulator() {
  return new Promise((resolve, reject) => {
    const check = spawn('xcrun', ['simctl', 'list', 'devices'], {
      stdio: 'pipe'
    });
    
    let output = '';
    check.stdout.on('data', (data) => {
      output += data.toString();
    });
    
    check.on('close', (code) => {
      if (code === 0 && output.includes('Booted')) {
        resolve(true);
      } else {
        reject(new Error('No iOS simulators running'));
      }
    });
  });
}

async function testAndroidDriver() {
  const { getDriver } = await import('../dist/drivers/driver-bridge.js');
  
  const driver = await getDriver({
    platform: 'android',
    deviceName: process.env.ANDROID_DEVICE_NAME || 'emulator-5554'
  });
  
  if (!driver) {
    throw new Error('Failed to initialize Android driver');
  }
  
  // Test basic navigation
  await driver.open('https://www.google.com');
  await driver.close();
  
  console.log('   Android driver working');
}

async function testIOSDriver() {
  const { getDriver } = await import('../dist/drivers/driver-bridge.js');
  
  const driver = await getDriver({
    platform: 'ios',
    deviceName: process.env.IOS_DEVICE_NAME || 'iPhone 15 Pro'
  });
  
  if (!driver) {
    throw new Error('Failed to initialize iOS driver');
  }
  
  // Test basic navigation
  await driver.open('https://www.google.com');
  await driver.close();
  
  console.log('   iOS driver working');
}

async function testMobileProviders() {
  const { providerManager } = await import('../dist/providers/registry.js');
  await providerManager.loadProviders();
  
  const androidProviders = providerManager.getProvidersForPlatform('android');
  const iosProviders = providerManager.getProvidersForPlatform('ios');
  
  if (androidProviders.length === 0) {
    throw new Error('No Android providers configured');
  }
  
  if (iosProviders.length === 0) {
    throw new Error('No iOS providers configured');
  }
  
  console.log(`   Found ${androidProviders.length} Android providers`);
  console.log(`   Found ${iosProviders.length} iOS providers`);
}

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

async function main() {
  console.log('📱 Starting mobile tests for MCP Web UI Bridge\n');
  
  const platform = process.env.PLATFORM || 'android';
  
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
    
    // Check prerequisites
    await runTest('Appium Server Check', checkAppiumServer);
    
    if (platform === 'android') {
      await runTest('Android Device Check', checkAndroidDevice);
      await runTest('Android Driver', testAndroidDriver);
    } else if (platform === 'ios') {
      await runTest('iOS Simulator Check', checkIOSSimulator);
      await runTest('iOS Driver', testIOSDriver);
    }
    
    await runTest('Mobile Providers', testMobileProviders);
    
    console.log('\n🎉 All mobile tests passed!');
    process.exit(0);
    
  } catch (error) {
    console.error('\n💥 Test suite failed:', error.message);
    console.error('\n💡 Make sure to:');
    console.error('   1. Start Appium server: npm run appium:start');
    if (platform === 'android') {
      console.error('   2. Connect Android device or start emulator');
      console.error('   3. Enable USB debugging');
    } else if (platform === 'ios') {
      console.error('   2. Start iOS simulator: npm run ios:sim');
      console.error('   3. Install Xcode and iOS simulators');
    }
    process.exit(1);
  }
}

main();
