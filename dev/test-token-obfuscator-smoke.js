#!/usr/bin/env node

/**
 * Token Obfuscator Smoke Test
 * Comprehensive test suite for token obfuscation functionality
 */

import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🧪 Token Obfuscator Smoke Test');
console.log('================================\n');

// Test configuration
const testConfig = {
  testPort: 8081, // Use different port to avoid conflicts
  timeout: 30000, // 30 second timeout for tests
  testContent: "This is a comprehensive test message to verify token obfuscation functionality across multiple scenarios.",
  testTokens: 150,
  platforms: ['cursor', 'claude', 'gpt', 'codex', 'copilot'],
  obfuscationLevels: ['minimal', 'moderate', 'aggressive', 'stealth']
};

// Test results tracking
const testResults = {
  total: 0,
  passed: 0,
  failed: 0,
  errors: [],
  startTime: Date.now()
};

// Utility functions
function logTest(testName, status, message = '') {
  testResults.total++;
  if (status === 'PASS') {
    testResults.passed++;
    console.log(`✅ ${testName}: ${message}`);
  } else {
    testResults.failed++;
    testResults.errors.push({ test: testName, message });
    console.log(`❌ ${testName}: ${message}`);
  }
}

function runMCPCommand(command, params = {}) {
  return new Promise((resolve, reject) => {
    // Create a temporary test script that imports from the correct path
    const testScript = `
      import { registerTokenObfuscation } from './src/tools/security/token_obfuscation.js';
      
      const mockServer = {
        registerTool: (name, tool) => {
          if (name === 'token_obfuscation') {
            tool.handler({ action: '${command}', ...${JSON.stringify(params)} })
              .then(result => {
                console.log(JSON.stringify(result));
                process.exit(0);
              })
              .catch(error => {
                console.error(JSON.stringify({ error: error.message }));
                process.exit(1);
              });
          }
        }
      };
      
      registerTokenObfuscation(mockServer);
    `;
    
    const tempScriptPath = path.join(__dirname, 'temp-test-script.js');
    fs.writeFileSync(tempScriptPath, testScript);
    
    const child = spawn('node', [tempScriptPath], {
      cwd: __dirname,
      timeout: testConfig.timeout,
      env: { ...process.env, NODE_ENV: 'test' }
    });
    
    let output = '';
    let errorOutput = '';
    
    child.stdout.on('data', (data) => {
      output += data.toString();
    });
    
    child.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });
    
    child.on('close', (code) => {
      // Clean up temp file
      try {
        fs.unlinkSync(tempScriptPath);
      } catch (e) {
        // Ignore cleanup errors
      }
      
      if (code === 0) {
        try {
          const result = JSON.parse(output.trim());
          resolve(result);
        } catch (e) {
          reject(new Error(`Failed to parse output: ${output}`));
        }
      } else {
        reject(new Error(`Process exited with code ${code}: ${errorOutput}`));
      }
    });
    
    child.on('error', (error) => {
      reject(error);
    });
  });
}

// Test 1: Engine Initialization
async function testEngineInitialization() {
  try {
    console.log('\n🔧 Test 1: Engine Initialization');
    
    const result = await runMCPCommand('get_status');
    
    if (result && result.content && result.content[0]) {
      const statusText = result.content[0].text;
      if (statusText.includes('Token Obfuscation Status')) {
        logTest('Engine Initialization', 'PASS', 'Engine initialized successfully');
      } else {
        logTest('Engine Initialization', 'FAIL', 'Invalid status response');
      }
    } else {
      logTest('Engine Initialization', 'FAIL', 'No valid response received');
    }
  } catch (error) {
    logTest('Engine Initialization', 'FAIL', error.message);
  }
}

// Test 2: Platform Detection
async function testPlatformDetection() {
  try {
    console.log('\n🔍 Test 2: Platform Detection');
    
    const result = await runMCPCommand('detect_platform');
    
    if (result && result.content && result.content[0]) {
      const detectionText = result.content[0].text;
      if (detectionText.includes('Platform Detection Results') || detectionText.includes('No AI platform detected')) {
        logTest('Platform Detection', 'PASS', 'Platform detection working');
      } else {
        logTest('Platform Detection', 'FAIL', 'Invalid detection response');
      }
    } else {
      logTest('Platform Detection', 'FAIL', 'No valid response received');
    }
  } catch (error) {
    logTest('Platform Detection', 'FAIL', error.message);
  }
}

// Test 3: Platform Listing
async function testPlatformListing() {
  try {
    console.log('\n📋 Test 3: Platform Listing');
    
    const result = await runMCPCommand('list_platforms');
    
    if (result && result.content && result.content[0]) {
      const platformsText = result.content[0].text;
      const expectedPlatforms = testConfig.platforms;
      const allPlatformsPresent = expectedPlatforms.every(platform => 
        platformsText.toLowerCase().includes(platform.toLowerCase())
      );
      
      if (allPlatformsPresent) {
        logTest('Platform Listing', 'PASS', `All ${expectedPlatforms.length} platforms listed`);
      } else {
        logTest('Platform Listing', 'FAIL', 'Not all expected platforms found');
      }
    } else {
      logTest('Platform Listing', 'FAIL', 'No valid response received');
    }
  } catch (error) {
    logTest('Platform Listing', 'FAIL', error.message);
  }
}

// Test 4: Obfuscation Testing
async function testObfuscationLevels() {
  try {
    console.log('\n🧪 Test 4: Obfuscation Testing');
    
    for (const level of testConfig.obfuscationLevels) {
      const result = await runMCPCommand('test_obfuscation', {
        test_content: testConfig.testContent,
        test_tokens: testConfig.testTokens,
        obfuscation_level: level
      });
      
      if (result && result.content && result.content[0]) {
        const testText = result.content[0].text;
        if (testText.includes('Obfuscation Test Results') && testText.includes('Reduction:')) {
          logTest(`Obfuscation Level: ${level}`, 'PASS', 'Obfuscation working');
        } else {
          logTest(`Obfuscation Level: ${level}`, 'FAIL', 'Invalid test response');
        }
      } else {
        logTest(`Obfuscation Level: ${level}`, 'FAIL', 'No valid response received');
      }
    }
  } catch (error) {
    logTest('Obfuscation Testing', 'FAIL', error.message);
  }
}

// Test 5: Configuration Generation
async function testConfigurationGeneration() {
  try {
    console.log('\n⚙️ Test 5: Configuration Generation');
    
    // Test Cursor config generation
    const cursorResult = await runMCPCommand('generate_cursor_config');
    
    if (cursorResult && cursorResult.content && cursorResult.content[0]) {
      const configText = cursorResult.content[0].text;
      if (configText.includes('Cursor Configuration') && configText.includes('proxy')) {
        logTest('Cursor Config Generation', 'PASS', 'Config generated successfully');
      } else {
        logTest('Cursor Config Generation', 'FAIL', 'Invalid config format');
      }
    } else {
      logTest('Cursor Config Generation', 'FAIL', 'No valid response received');
    }
    
    // Test platform config generation
    const platformResult = await runMCPCommand('generate_platform_config');
    
    if (platformResult && platformResult.content && platformResult.content[0]) {
      const platformConfigText = platformResult.content[0].text;
      if (platformConfigText.includes('Platform-Specific Configuration')) {
        logTest('Platform Config Generation', 'PASS', 'Platform config generated');
      } else {
        logTest('Platform Config Generation', 'FAIL', 'Invalid platform config');
      }
    } else {
      logTest('Platform Config Generation', 'FAIL', 'No valid response received');
    }
  } catch (error) {
    logTest('Configuration Generation', 'FAIL', error.message);
  }
}

// Test 6: Natural Language Processing
async function testNaturalLanguageProcessing() {
  try {
    console.log('\n🗣️ Test 6: Natural Language Processing');
    
    const testCommands = [
      'start the proxy with moderate obfuscation',
      'show me the current status',
      'test obfuscation with 100 tokens',
      'generate cursor configuration'
    ];
    
    for (const command of testCommands) {
      const result = await runMCPCommand('natural_language_command', {
        natural_language_command: command
      });
      
      if (result && result.content && result.content[0]) {
        const responseText = result.content[0].text;
        if (responseText.includes('✅') || responseText.includes('📋') || responseText.includes('🔧')) {
          logTest(`NL Command: "${command.substring(0, 30)}..."`, 'PASS', 'Command processed');
        } else {
          logTest(`NL Command: "${command.substring(0, 30)}..."`, 'FAIL', 'Invalid response');
        }
      } else {
        logTest(`NL Command: "${command.substring(0, 30)}..."`, 'FAIL', 'No response');
      }
    }
  } catch (error) {
    logTest('Natural Language Processing', 'FAIL', error.message);
  }
}

// Test 7: Statistics and Health Checks
async function testStatisticsAndHealth() {
  try {
    console.log('\n📊 Test 7: Statistics and Health Checks');
    
    // Test statistics
    const statsResult = await runMCPCommand('get_stats');
    
    if (statsResult && statsResult.content && statsResult.content[0]) {
      const statsText = statsResult.content[0].text;
      if (statsText.includes('Token Obfuscation Statistics')) {
        logTest('Statistics Retrieval', 'PASS', 'Stats retrieved successfully');
      } else {
        logTest('Statistics Retrieval', 'FAIL', 'Invalid stats format');
      }
    } else {
      logTest('Statistics Retrieval', 'FAIL', 'No valid response received');
    }
    
    // Test health status
    const healthResult = await runMCPCommand('get_health_status');
    
    if (healthResult && healthResult.content && healthResult.content[0]) {
      const healthText = healthResult.content[0].text;
      if (healthText.includes('Health Status')) {
        logTest('Health Status Check', 'PASS', 'Health check working');
      } else {
        logTest('Health Status Check', 'FAIL', 'Invalid health response');
      }
    } else {
      logTest('Health Status Check', 'FAIL', 'No valid response received');
    }
  } catch (error) {
    logTest('Statistics and Health', 'FAIL', error.message);
  }
}

// Test 8: Default Status Check
async function testDefaultStatus() {
  try {
    console.log('\n🔍 Test 8: Default Status Check');
    
    const result = await runMCPCommand('check_default_status');
    
    if (result && result.content && result.content[0]) {
      const statusText = result.content[0].text;
      if (statusText.includes('Default Status Check')) {
        logTest('Default Status Check', 'PASS', 'Default status retrieved');
      } else {
        logTest('Default Status Check', 'FAIL', 'Invalid default status');
      }
    } else {
      logTest('Default Status Check', 'FAIL', 'No valid response received');
    }
  } catch (error) {
    logTest('Default Status Check', 'FAIL', error.message);
  }
}

// Test 9: Circuit Breaker and Fallback
async function testCircuitBreakerAndFallback() {
  try {
    console.log('\n🔄 Test 9: Circuit Breaker and Fallback');
    
    // Test circuit breaker reset
    const resetResult = await runMCPCommand('reset_circuit_breaker');
    
    if (resetResult && resetResult.content && resetResult.content[0]) {
      const resetText = resetResult.content[0].text;
      if (resetText.includes('Circuit breaker reset successfully')) {
        logTest('Circuit Breaker Reset', 'PASS', 'Circuit breaker reset working');
      } else {
        logTest('Circuit Breaker Reset', 'FAIL', 'Invalid reset response');
      }
    } else {
      logTest('Circuit Breaker Reset', 'FAIL', 'No valid response received');
    }
    
    // Test fallback mode
    const fallbackResult = await runMCPCommand('enable_fallback');
    
    if (fallbackResult && fallbackResult.content && fallbackResult.content[0]) {
      const fallbackText = fallbackResult.content[0].text;
      if (fallbackText.includes('Fallback mode enabled')) {
        logTest('Fallback Mode Enable', 'PASS', 'Fallback mode working');
      } else {
        logTest('Fallback Mode Enable', 'FAIL', 'Invalid fallback response');
      }
    } else {
      logTest('Fallback Mode Enable', 'FAIL', 'No valid response received');
    }
  } catch (error) {
    logTest('Circuit Breaker and Fallback', 'FAIL', error.message);
  }
}

// Test 10: Background Mode
async function testBackgroundMode() {
  try {
    console.log('\n🌙 Test 10: Background Mode');
    
    // Test enabling background mode
    const enableResult = await runMCPCommand('enable_background_mode');
    
    if (enableResult && enableResult.content && enableResult.content[0]) {
      const enableText = enableResult.content[0].text;
      if (enableText.includes('Background mode enabled')) {
        logTest('Background Mode Enable', 'PASS', 'Background mode enabled');
      } else {
        logTest('Background Mode Enable', 'FAIL', 'Invalid enable response');
      }
    } else {
      logTest('Background Mode Enable', 'FAIL', 'No valid response received');
    }
    
    // Test disabling background mode
    const disableResult = await runMCPCommand('disable_background_mode');
    
    if (disableResult && disableResult.content && disableResult.content[0]) {
      const disableText = disableResult.content[0].text;
      if (disableText.includes('Background mode disabled')) {
        logTest('Background Mode Disable', 'PASS', 'Background mode disabled');
      } else {
        logTest('Background Mode Disable', 'FAIL', 'Invalid disable response');
      }
    } else {
      logTest('Background Mode Disable', 'FAIL', 'No valid response received');
    }
  } catch (error) {
    logTest('Background Mode', 'FAIL', error.message);
  }
}

// Test 11: Log Export
async function testLogExport() {
  try {
    console.log('\n📄 Test 11: Log Export');
    
    const result = await runMCPCommand('export_logs');
    
    if (result && result.content && result.content[0]) {
      const logText = result.content[0].text;
      if (logText.includes('Log Export') && logText.includes('timestamp')) {
        logTest('Log Export', 'PASS', 'Logs exported successfully');
      } else {
        logTest('Log Export', 'FAIL', 'Invalid log format');
      }
    } else {
      logTest('Log Export', 'FAIL', 'No valid response received');
    }
  } catch (error) {
    logTest('Log Export', 'FAIL', error.message);
  }
}

// Test 12: Configuration File Validation
async function testConfigurationFileValidation() {
  try {
    console.log('\n📁 Test 12: Configuration File Validation');
    
    // Check if setup script exists
    const setupScriptPath = path.join(__dirname, 'scripts', 'setup-token-obfuscation.js');
    if (fs.existsSync(setupScriptPath)) {
      logTest('Setup Script Exists', 'PASS', 'Setup script found');
    } else {
      logTest('Setup Script Exists', 'FAIL', 'Setup script not found');
    }
    
    // Check if token obfuscation setup directory exists
    const setupDirPath = path.join(__dirname, 'token-obfuscation-setup');
    if (fs.existsSync(setupDirPath)) {
      logTest('Setup Directory Exists', 'PASS', 'Setup directory found');
      
      // Check for required files
      const requiredFiles = ['cursor-config.json', 'environment.env', 'start-proxy.bat', 'README.md'];
      for (const file of requiredFiles) {
        const filePath = path.join(setupDirPath, file);
        if (fs.existsSync(filePath)) {
          logTest(`Setup File: ${file}`, 'PASS', 'File exists');
        } else {
          logTest(`Setup File: ${file}`, 'FAIL', 'File missing');
        }
      }
    } else {
      logTest('Setup Directory Exists', 'FAIL', 'Setup directory not found');
    }
    
    // Check if main tool file exists
    const toolPath = path.join(__dirname, 'src', 'tools', 'security', 'token_obfuscation.ts');
    if (fs.existsSync(toolPath)) {
      logTest('Main Tool File Exists', 'PASS', 'Tool file found');
    } else {
      logTest('Main Tool File Exists', 'FAIL', 'Tool file not found');
    }
    
    // Check if compiled version exists
    const compiledPath = path.join(__dirname, 'dist', 'tools', 'security', 'token_obfuscation.js');
    if (fs.existsSync(compiledPath)) {
      logTest('Compiled Tool File Exists', 'PASS', 'Compiled file found');
    } else {
      logTest('Compiled Tool File Exists', 'FAIL', 'Compiled file not found');
    }
  } catch (error) {
    logTest('Configuration File Validation', 'FAIL', error.message);
  }
}

// Main test runner
async function runSmokeTests() {
  try {
    console.log(`🚀 Starting smoke tests at ${new Date().toISOString()}\n`);
    
    // Run all tests
    await testEngineInitialization();
    await testPlatformDetection();
    await testPlatformListing();
    await testObfuscationLevels();
    await testConfigurationGeneration();
    await testNaturalLanguageProcessing();
    await testStatisticsAndHealth();
    await testDefaultStatus();
    await testCircuitBreakerAndFallback();
    await testBackgroundMode();
    await testLogExport();
    await testConfigurationFileValidation();
    
    // Calculate results
    const endTime = Date.now();
    const duration = endTime - testResults.startTime;
    const successRate = (testResults.passed / testResults.total) * 100;
    
    console.log('\n📊 Smoke Test Results Summary');
    console.log('============================');
    console.log(`Total Tests: ${testResults.total}`);
    console.log(`Passed: ${testResults.passed}`);
    console.log(`Failed: ${testResults.failed}`);
    console.log(`Success Rate: ${successRate.toFixed(2)}%`);
    console.log(`Duration: ${(duration / 1000).toFixed(2)} seconds`);
    
    if (testResults.errors.length > 0) {
      console.log('\n❌ Failed Tests:');
      testResults.errors.forEach(error => {
        console.log(`  - ${error.test}: ${error.message}`);
      });
    }
    
    // Generate report
    const report = {
      timestamp: new Date().toISOString(),
      duration: duration,
      summary: {
        total: testResults.total,
        passed: testResults.passed,
        failed: testResults.failed,
        successRate: successRate
      },
      errors: testResults.errors,
      config: testConfig
    };
    
    const reportPath = path.join(__dirname, `smoke-test-results-${Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`\n📄 Detailed report saved to: ${reportPath}`);
    
    // Exit with appropriate code
    process.exit(testResults.failed > 0 ? 1 : 0);
    
  } catch (error) {
    console.error('❌ Smoke test runner failed:', error.message);
    process.exit(1);
  }
}

// Run the smoke tests
runSmokeTests();
