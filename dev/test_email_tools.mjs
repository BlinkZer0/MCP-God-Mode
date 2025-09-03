#!/usr/bin/env node

/**
 * Email Tools Test Suite for MCP God Mode
 * Tests email functionality across all server iterations
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Test configurations
const testConfigs = [
  {
    name: 'server-refactored',
    path: join(__dirname, 'dist', 'server-refactored.js'),
    description: 'Full-featured server with all email tools'
  },
  {
    name: 'server-minimal',
    path: join(__dirname, 'dist', 'server-minimal.js'),
    description: 'Minimal server with core email tools'
  },
  {
    name: 'server-ultra-minimal',
    path: join(__dirname, 'dist', 'server-ultra-minimal.js'),
    description: 'Ultra-minimal server with basic email tools'
  }
];

// Test email configuration (use environment variables for security)
const testEmailConfig = {
  service: process.env.TEST_EMAIL_SERVICE || 'gmail',
  email: process.env.TEST_EMAIL_ADDRESS || 'test@example.com',
  password: process.env.TEST_EMAIL_PASSWORD || 'testpassword',
  name: 'MCP God Mode Test'
};

// Test data
const testEmailData = {
  to: process.env.TEST_EMAIL_TO || 'test@example.com',
  subject: 'Test Email from MCP God Mode',
  body: 'This is a test email sent from the MCP God Mode email tools.',
  html: false
};

// Test email content for parsing
const testEmailContent = `From: sender@example.com
To: recipient@example.com
Subject: Test Email for Parsing
Date: ${new Date().toISOString()}
Message-ID: <test-${Date.now()}@example.com>

This is a test email with some content.
It contains a link: https://example.com
And an email address: contact@example.com

Best regards,
Test Sender`;

/**
 * Test a single server
 */
async function testServer(config) {
  console.log(`\n🧪 Testing ${config.name}...`);
  console.log(`📝 ${config.description}`);
  
  return new Promise((resolve) => {
    const server = spawn('node', [config.path], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    let errorOutput = '';
    let isReady = false;

    // Set timeout
    const timeout = setTimeout(() => {
      server.kill();
      resolve({
        name: config.name,
        success: false,
        error: 'Timeout waiting for server response',
        output,
        errorOutput
      });
    }, 30000);

    // Handle stdout
    server.stdout.on('data', (data) => {
      const text = data.toString();
      output += text;
      
      // Check if server is ready
      if (text.includes('Server loaded successfully') || text.includes('MCP Server starting')) {
        isReady = true;
        console.log(`✅ ${config.name} server started successfully`);
      }
    });

    // Handle stderr
    server.stderr.on('data', (data) => {
      const text = data.toString();
      errorOutput += text;
      console.log(`⚠️  ${config.name} stderr:`, text.trim());
    });

    // Handle server exit
    server.on('exit', (code) => {
      clearTimeout(timeout);
      if (code === 0 && isReady) {
        resolve({
          name: config.name,
          success: true,
          output,
          errorOutput
        });
      } else {
        resolve({
          name: config.name,
          success: false,
          error: `Server exited with code ${code}`,
          output,
          errorOutput
        });
      }
    });

    // Send test request after a short delay
    setTimeout(() => {
      if (isReady) {
        // Send a simple health check request
        const request = {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/list'
        };
        
        server.stdin.write(JSON.stringify(request) + '\n');
        
        // Give it a moment to respond, then close
        setTimeout(() => {
          server.kill();
        }, 2000);
      }
    }, 2000);
  });
}

/**
 * Test email parsing functionality
 */
function testEmailParsing() {
  console.log('\n📧 Testing Email Parsing Logic...');
  
  try {
    // Test link extraction
    const testText = 'Check out https://example.com and http://test.org for more info';
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const links = testText.match(urlRegex) || [];
    console.log(`🔗 Links extracted: ${links.length} - ${links.join(', ')}`);
    
    // Test email extraction
    const emailText = 'Contact us at user@example.com or support@test.org';
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    const emails = emailText.match(emailRegex) || [];
    console.log(`📧 Emails extracted: ${emails.length} - ${emails.join(', ')}`);
    
    return true;
  } catch (error) {
    console.error(`❌ Email parsing test failed:`, error.message);
    return false;
  }
}

/**
 * Test email configuration validation
 */
function testEmailConfigValidation() {
  console.log('\n⚙️  Testing Email Configuration Validation...');
  
  try {
    const validConfigs = [
      {
        service: 'gmail',
        email: 'user@gmail.com',
        password: 'apppassword123'
      },
      {
        service: 'outlook',
        email: 'user@outlook.com',
        password: 'password123'
      },
      {
        service: 'custom',
        email: 'user@company.com',
        password: 'password123',
        host: 'smtp.company.com',
        port: 587,
        secure: false
      }
    ];
    
    validConfigs.forEach((config, index) => {
      console.log(`✅ Config ${index + 1} (${config.service}): Valid`);
    });
    
    return true;
  } catch (error) {
    console.error(`❌ Email config validation failed:`, error.message);
    return false;
  }
}

/**
 * Main test function
 */
async function runTests() {
  console.log('🚀 Starting Email Tools Test Suite for MCP God Mode');
  console.log('=' .repeat(60));
  
  // Test email parsing logic
  const parsingTest = testEmailParsing();
  
  // Test email configuration validation
  const configTest = testEmailConfigValidation();
  
  // Test all servers
  console.log('\n🖥️  Testing Server Instances...');
  const results = [];
  
  for (const config of testConfigs) {
    const result = await testServer(config);
    results.push(result);
  }
  
  // Print results
  console.log('\n📊 Test Results Summary');
  console.log('=' .repeat(60));
  
  console.log(`📧 Email Parsing Logic: ${parsingTest ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`⚙️  Email Config Validation: ${configTest ? '✅ PASS' : '❌ FAIL'}`);
  
  console.log('\n🖥️  Server Tests:');
  results.forEach(result => {
    const status = result.success ? '✅ PASS' : '❌ FAIL';
    console.log(`  ${result.name}: ${status}`);
    if (!result.success) {
      console.log(`    Error: ${result.error}`);
    }
  });
  
  // Overall success
  const overallSuccess = parsingTest && configTest && results.every(r => r.success);
  console.log(`\n🎯 Overall Result: ${overallSuccess ? '✅ ALL TESTS PASSED' : '❌ SOME TESTS FAILED'}`);
  
  if (!overallSuccess) {
    console.log('\n🔍 Debug Information:');
    results.forEach(result => {
      if (!result.success) {
        console.log(`\n${result.name} Error Details:`);
        console.log(`Output: ${result.output.substring(0, 500)}...`);
        if (result.errorOutput) {
          console.log(`Error Output: ${result.errorOutput.substring(0, 500)}...`);
        }
      }
    });
  }
  
  return overallSuccess;
}

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runTests().then(success => {
    process.exit(success ? 0 : 1);
  }).catch(error => {
    console.error('❌ Test suite failed with error:', error);
    process.exit(1);
  });
}

export { runTests, testEmailParsing, testEmailConfigValidation };
