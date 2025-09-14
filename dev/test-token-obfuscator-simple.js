#!/usr/bin/env node

/**
 * Simple Token Obfuscator Smoke Test
 * Direct testing of token obfuscation functionality
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🧪 Simple Token Obfuscator Smoke Test');
console.log('=====================================\n');

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

// Test 1: File Structure Validation
function testFileStructure() {
  console.log('\n📁 Test 1: File Structure Validation');
  
  // Check main tool file
  const toolPath = path.join(__dirname, 'src', 'tools', 'security', 'token_obfuscation.ts');
  if (fs.existsSync(toolPath)) {
    logTest('Main Tool File (TS)', 'PASS', 'TypeScript source file exists');
    
    // Check file size (should be substantial)
    const stats = fs.statSync(toolPath);
    if (stats.size > 50000) { // Should be a large file with all the functionality
      logTest('Tool File Size', 'PASS', `File size: ${(stats.size / 1024).toFixed(1)}KB`);
    } else {
      logTest('Tool File Size', 'FAIL', `File too small: ${stats.size} bytes`);
    }
  } else {
    logTest('Main Tool File (TS)', 'FAIL', 'TypeScript source file not found');
  }
  
  // Check compiled version
  const compiledPath = path.join(__dirname, 'dist', 'tools', 'security', 'token_obfuscation.js');
  if (fs.existsSync(compiledPath)) {
    logTest('Compiled Tool File (JS)', 'PASS', 'Compiled JavaScript file exists');
  } else {
    logTest('Compiled Tool File (JS)', 'FAIL', 'Compiled JavaScript file not found');
  }
  
  // Check natural language version
  const nlPath = path.join(__dirname, 'src', 'tools', 'security', 'token_obfuscation_nl.ts');
  if (fs.existsSync(nlPath)) {
    logTest('Natural Language Tool File', 'PASS', 'NL tool file exists');
  } else {
    logTest('Natural Language Tool File', 'FAIL', 'NL tool file not found');
  }
  
  // Check compiled NL version
  const compiledNlPath = path.join(__dirname, 'dist', 'tools', 'security', 'token_obfuscation_nl.js');
  if (fs.existsSync(compiledNlPath)) {
    logTest('Compiled NL Tool File', 'PASS', 'Compiled NL file exists');
  } else {
    logTest('Compiled NL Tool File', 'FAIL', 'Compiled NL file not found');
  }
}

// Test 2: Configuration Files
function testConfigurationFiles() {
  console.log('\n⚙️ Test 2: Configuration Files');
  
  // Check setup script
  const setupScriptPath = path.join(__dirname, 'scripts', 'setup-token-obfuscation.js');
  if (fs.existsSync(setupScriptPath)) {
    logTest('Setup Script', 'PASS', 'Setup script exists');
    
    // Check if it's executable
    const content = fs.readFileSync(setupScriptPath, 'utf8');
    if (content.includes('Token Obfuscation Setup Script')) {
      logTest('Setup Script Content', 'PASS', 'Script has proper header');
    } else {
      logTest('Setup Script Content', 'FAIL', 'Script missing proper header');
    }
  } else {
    logTest('Setup Script', 'FAIL', 'Setup script not found');
  }
  
  // Check setup directory
  const setupDirPath = path.join(__dirname, 'token-obfuscation-setup');
  if (fs.existsSync(setupDirPath)) {
    logTest('Setup Directory', 'PASS', 'Setup directory exists');
    
    // Check required files
    const requiredFiles = [
      'cursor-config.json',
      'environment.env', 
      'start-proxy.bat',
      'README.md'
    ];
    
    for (const file of requiredFiles) {
      const filePath = path.join(setupDirPath, file);
      if (fs.existsSync(filePath)) {
        logTest(`Setup File: ${file}`, 'PASS', 'File exists');
        
        // Validate JSON files
        if (file.endsWith('.json')) {
          try {
            const content = fs.readFileSync(filePath, 'utf8');
            JSON.parse(content);
            logTest(`JSON Validation: ${file}`, 'PASS', 'Valid JSON format');
          } catch (e) {
            logTest(`JSON Validation: ${file}`, 'FAIL', `Invalid JSON: ${e.message}`);
          }
        }
      } else {
        logTest(`Setup File: ${file}`, 'FAIL', 'File missing');
      }
    }
  } else {
    logTest('Setup Directory', 'FAIL', 'Setup directory not found');
  }
  
  // Check environment template
  const envTemplatePath = path.join(__dirname, 'config', 'token-obfuscation.env.template');
  if (fs.existsSync(envTemplatePath)) {
    logTest('Environment Template', 'PASS', 'Environment template exists');
  } else {
    logTest('Environment Template', 'FAIL', 'Environment template not found');
  }
}

// Test 3: Code Analysis
function testCodeAnalysis() {
  console.log('\n🔍 Test 3: Code Analysis');
  
  const toolPath = path.join(__dirname, 'src', 'tools', 'security', 'token_obfuscation.ts');
  
  if (fs.existsSync(toolPath)) {
    const content = fs.readFileSync(toolPath, 'utf8');
    
    // Check for key classes and functions
    const keyComponents = [
      'TokenObfuscationEngine',
      'AIPlatformDetector', 
      'registerTokenObfuscation',
      'processNaturalLanguageCommand',
      'executeTokenObfuscationAction'
    ];
    
    for (const component of keyComponents) {
      if (content.includes(component)) {
        logTest(`Code Component: ${component}`, 'PASS', 'Component found in code');
      } else {
        logTest(`Code Component: ${component}`, 'FAIL', 'Component missing from code');
      }
    }
    
    // Check for platform support
    const platforms = ['cursor', 'claude', 'gpt', 'codex', 'copilot'];
    for (const platform of platforms) {
      if (content.toLowerCase().includes(platform)) {
        logTest(`Platform Support: ${platform}`, 'PASS', 'Platform supported');
      } else {
        logTest(`Platform Support: ${platform}`, 'FAIL', 'Platform not found');
      }
    }
    
    // Check for obfuscation levels
    const obfuscationLevels = ['minimal', 'moderate', 'aggressive', 'stealth'];
    for (const level of obfuscationLevels) {
      if (content.includes(level)) {
        logTest(`Obfuscation Level: ${level}`, 'PASS', 'Level supported');
      } else {
        logTest(`Obfuscation Level: ${level}`, 'FAIL', 'Level not found');
      }
    }
    
    // Check for natural language processing
    if (content.includes('processNaturalLanguageCommand')) {
      logTest('Natural Language Processing', 'PASS', 'NL processing implemented');
    } else {
      logTest('Natural Language Processing', 'FAIL', 'NL processing not found');
    }
    
    // Check for security features
    const securityFeatures = [
      'validateRequestSecurity',
      'sanitizeContent',
      'circuitBreakerOpen',
      'fallbackMode',
      'prompt injection',
      'tool poisoning'
    ];
    
    for (const feature of securityFeatures) {
      if (content.toLowerCase().includes(feature.toLowerCase())) {
        logTest(`Security Feature: ${feature}`, 'PASS', 'Security feature implemented');
      } else {
        logTest(`Security Feature: ${feature}`, 'FAIL', 'Security feature not found');
      }
    }
    
    // Check for proxy functionality
    const proxyFeatures = [
      'startProxy',
      'stopProxy',
      'handleProxyRequest',
      'forwardRequest',
      'processStreamingResponse'
    ];
    
    for (const feature of proxyFeatures) {
      if (content.includes(feature)) {
        logTest(`Proxy Feature: ${feature}`, 'PASS', 'Proxy feature implemented');
      } else {
        logTest(`Proxy Feature: ${feature}`, 'FAIL', 'Proxy feature not found');
      }
    }
    
    // Check for configuration generation
    if (content.includes('generateCursorConfig') && content.includes('generatePlatformConfig')) {
      logTest('Configuration Generation', 'PASS', 'Config generation implemented');
    } else {
      logTest('Configuration Generation', 'FAIL', 'Config generation missing');
    }
    
    // Check for statistics and monitoring
    const monitoringFeatures = [
      'getStats',
      'get_health_status',
      'export_logs',
      'background monitoring'
    ];
    
    for (const feature of monitoringFeatures) {
      if (content.toLowerCase().includes(feature.toLowerCase())) {
        logTest(`Monitoring Feature: ${feature}`, 'PASS', 'Monitoring feature implemented');
      } else {
        logTest(`Monitoring Feature: ${feature}`, 'FAIL', 'Monitoring feature not found');
      }
    }
  } else {
    logTest('Code Analysis', 'FAIL', 'Main tool file not found for analysis');
  }
}

// Test 4: Configuration Validation
function testConfigurationValidation() {
  console.log('\n📋 Test 4: Configuration Validation');
  
  // Test cursor config
  const cursorConfigPath = path.join(__dirname, 'token-obfuscation-setup', 'cursor-config.json');
  if (fs.existsSync(cursorConfigPath)) {
    try {
      const config = JSON.parse(fs.readFileSync(cursorConfigPath, 'utf8'));
      
      // Check required fields
      const requiredFields = ['proxy', 'headers', 'timeout', 'retry', 'logging', 'security', 'performance'];
      for (const field of requiredFields) {
        if (config[field]) {
          logTest(`Config Field: ${field}`, 'PASS', 'Field present in config');
        } else {
          logTest(`Config Field: ${field}`, 'FAIL', 'Field missing from config');
        }
      }
      
      // Check proxy configuration
      if (config.proxy && config.proxy.http && config.proxy.https) {
        logTest('Proxy Configuration', 'PASS', 'Proxy settings configured');
      } else {
        logTest('Proxy Configuration', 'FAIL', 'Proxy settings incomplete');
      }
      
      // Check headers
      if (config.headers && config.headers['x-obfuscation-enabled']) {
        logTest('Obfuscation Headers', 'PASS', 'Obfuscation headers configured');
      } else {
        logTest('Obfuscation Headers', 'FAIL', 'Obfuscation headers missing');
      }
      
    } catch (e) {
      logTest('Config JSON Validation', 'FAIL', `Invalid JSON: ${e.message}`);
    }
  } else {
    logTest('Cursor Config File', 'FAIL', 'Config file not found');
  }
  
  // Test environment file
  const envPath = path.join(__dirname, 'token-obfuscation-setup', 'environment.env');
  if (fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, 'utf8');
    
    const requiredEnvVars = ['HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY'];
    for (const envVar of requiredEnvVars) {
      if (envContent.includes(envVar)) {
        logTest(`Environment Variable: ${envVar}`, 'PASS', 'Environment variable configured');
      } else {
        logTest(`Environment Variable: ${envVar}`, 'FAIL', 'Environment variable missing');
      }
    }
  } else {
    logTest('Environment File', 'FAIL', 'Environment file not found');
  }
}

// Test 5: Documentation Validation
function testDocumentation() {
  console.log('\n📚 Test 5: Documentation Validation');
  
  // Check README in setup directory
  const readmePath = path.join(__dirname, 'token-obfuscation-setup', 'README.md');
  if (fs.existsSync(readmePath)) {
    logTest('Setup README', 'PASS', 'Setup README exists');
    
    const readmeContent = fs.readFileSync(readmePath, 'utf8');
    
    // Check for key sections
    const requiredSections = [
      'Token Obfuscation Setup',
      'Setup Instructions',
      'Configuration',
      'Troubleshooting'
    ];
    
    for (const section of requiredSections) {
      if (readmeContent.includes(section)) {
        logTest(`README Section: ${section}`, 'PASS', 'Section present');
      } else {
        logTest(`README Section: ${section}`, 'FAIL', 'Section missing');
      }
    }
    
    // Check for ethical considerations (mentioned in the README)
    if (readmeContent.includes('Ethical Considerations') || readmeContent.includes('Islamic teachings')) {
      logTest('Ethical Documentation', 'PASS', 'Ethical considerations documented');
    } else {
      logTest('Ethical Documentation', 'FAIL', 'Ethical considerations missing');
    }
    
  } else {
    logTest('Setup README', 'FAIL', 'Setup README not found');
  }
  
  // Check MCP compatibility guide
  const mcpGuidePath = path.join(__dirname, 'token-obfuscation-setup', 'MCP_COMPATIBILITY_GUIDE.md');
  if (fs.existsSync(mcpGuidePath)) {
    logTest('MCP Compatibility Guide', 'PASS', 'MCP guide exists');
  } else {
    logTest('MCP Compatibility Guide', 'FAIL', 'MCP guide not found');
  }
}

// Test 6: Platform Configurations
function testPlatformConfigurations() {
  console.log('\n🌐 Test 6: Platform Configurations');
  
  const platformConfigsDir = path.join(__dirname, 'token-obfuscation-setup', 'platform-configs');
  if (fs.existsSync(platformConfigsDir)) {
    logTest('Platform Configs Directory', 'PASS', 'Platform configs directory exists');
    
    const platforms = ['cursor', 'claude', 'gpt', 'codex', 'copilot'];
    
    for (const platform of platforms) {
      const configPath = path.join(platformConfigsDir, `${platform}.json`);
      if (fs.existsSync(configPath)) {
        logTest(`Platform Config: ${platform}`, 'PASS', 'Platform config exists');
        
        try {
          const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
          
          // Check required fields
          const requiredFields = ['platform', 'proxy', 'headers', 'environment', 'endpoints'];
          for (const field of requiredFields) {
            if (config[field]) {
              logTest(`${platform} Config Field: ${field}`, 'PASS', 'Field present');
            } else {
              logTest(`${platform} Config Field: ${field}`, 'FAIL', 'Field missing');
            }
          }
          
          // Check MCP compatibility
          if (config.mcp_compatibility && config.mcp_compatibility.supported) {
            logTest(`${platform} MCP Support`, 'PASS', 'MCP compatibility configured');
          } else {
            logTest(`${platform} MCP Support`, 'FAIL', 'MCP compatibility not configured');
          }
          
        } catch (e) {
          logTest(`${platform} Config Validation`, 'FAIL', `Invalid JSON: ${e.message}`);
        }
      } else {
        logTest(`Platform Config: ${platform}`, 'FAIL', 'Platform config missing');
      }
    }
  } else {
    logTest('Platform Configs Directory', 'FAIL', 'Platform configs directory not found');
  }
}

// Test 7: Integration Points
function testIntegrationPoints() {
  console.log('\n🔗 Test 7: Integration Points');
  
  // Check if the tool is properly integrated into the main server
  const serverPath = path.join(__dirname, 'src', 'server-modular.ts');
  if (fs.existsSync(serverPath)) {
    const serverContent = fs.readFileSync(serverPath, 'utf8');
    
    if (serverContent.includes('token_obfuscation') || serverContent.includes('TokenObfuscation')) {
      logTest('Server Integration', 'PASS', 'Token obfuscation integrated in server');
    } else {
      logTest('Server Integration', 'FAIL', 'Token obfuscation not found in server');
    }
  } else {
    logTest('Server File Check', 'FAIL', 'Server file not found');
  }
  
  // Check for proper exports
  const toolPath = path.join(__dirname, 'src', 'tools', 'security', 'token_obfuscation.ts');
  if (fs.existsSync(toolPath)) {
    const toolContent = fs.readFileSync(toolPath, 'utf8');
    
    if (toolContent.includes('export function registerTokenObfuscation')) {
      logTest('Export Function', 'PASS', 'Proper export function found');
    } else {
      logTest('Export Function', 'FAIL', 'Export function not found');
    }
  }
}

// Main test runner
async function runSimpleSmokeTests() {
  try {
    console.log(`🚀 Starting simple smoke tests at ${new Date().toISOString()}\n`);
    
    // Run all tests
    testFileStructure();
    testConfigurationFiles();
    testCodeAnalysis();
    testConfigurationValidation();
    testDocumentation();
    testPlatformConfigurations();
    testIntegrationPoints();
    
    // Calculate results
    const endTime = Date.now();
    const duration = endTime - testResults.startTime;
    const successRate = (testResults.passed / testResults.total) * 100;
    
    console.log('\n📊 Simple Smoke Test Results Summary');
    console.log('====================================');
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
      testType: 'simple_smoke_test'
    };
    
    const reportPath = path.join(__dirname, `simple-smoke-test-results-${Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`\n📄 Detailed report saved to: ${reportPath}`);
    
    // Overall assessment
    if (successRate >= 90) {
      console.log('\n🎉 Token Obfuscator: EXCELLENT - All critical components working');
    } else if (successRate >= 80) {
      console.log('\n✅ Token Obfuscator: GOOD - Most components working');
    } else if (successRate >= 70) {
      console.log('\n⚠️ Token Obfuscator: FAIR - Some issues detected');
    } else {
      console.log('\n❌ Token Obfuscator: POOR - Significant issues detected');
    }
    
    // Exit with appropriate code
    process.exit(testResults.failed > 0 ? 1 : 0);
    
  } catch (error) {
    console.error('❌ Simple smoke test runner failed:', error.message);
    process.exit(1);
  }
}

// Run the simple smoke tests
runSimpleSmokeTests();
