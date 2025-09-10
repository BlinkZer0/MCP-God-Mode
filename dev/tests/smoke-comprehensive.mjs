#!/usr/bin/env node

/**
 * Comprehensive Smoke Test for MCP God Mode Tools
 * Tests a broader range of tools to validate fixes
 */

import { spawn } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Test results
const results = {
  passed: [],
  failed: [],
  errors: []
};

// Simple test function
const testTool = async (toolName, testArgs = {}) => {
  console.log(`🧪 Testing: ${toolName}`);
  
  try {
    // Create test request
    const request = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: toolName,
        arguments: testArgs
      }
    };

    // Start server process
    const server = spawn('node', ['../dist/server-refactored.js'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: __dirname
    });

    let output = '';
    let error = '';

    server.stdout.on('data', (data) => {
      output += data.toString();
    });

    server.stderr.on('data', (data) => {
      error += data.toString();
    });

    // Wait for server to start
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Send request
    server.stdin.write(JSON.stringify(request) + '\n');
    server.stdin.end();

    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 5000));

    // Kill server
    if (!server.killed) {
      server.kill();
    }

    // Check results
    if (error.includes('Error') || error.includes('error') || error.includes('TypeError')) {
      results.failed.push({ tool: toolName, error, output });
      console.log(`❌ ${toolName}: FAILED`);
      console.log(`   Error: ${error.substring(0, 200)}...`);
    } else {
      results.passed.push({ tool: toolName, output });
      console.log(`✅ ${toolName}: PASSED`);
    }

  } catch (err) {
    results.errors.push({ tool: toolName, error: err.message });
    console.log(`💥 ${toolName}: ERROR - ${err.message}`);
  }
};

// Test comprehensive set of tools
const runTests = async () => {
  console.log('🚀 Starting comprehensive smoke test...\n');

  // Test a broader range of tools
  const comprehensiveTests = [
    // Core tools
    { name: 'mcp_mcp-god-mode_health', args: { random_string: 'test' } },
    { name: 'mcp_mcp-god-mode_calculator', args: { operation: 'add', a: 1, b: 2 } },
    { name: 'mcp_mcp-god-mode_dice_rolling', args: { dice_notation: '1d6' } },
    { name: 'mcp_mcp-god-mode_password_generator', args: { length: 8 } },
    
    // File system tools
    { name: 'mcp_mcp-god-mode_fs_list', args: { dir: '.' } },
    { name: 'mcp_mcp-god-mode_fs_read_text', args: { path: 'package.json' } },
    { name: 'mcp_mcp-god-mode_fs_search', args: { pattern: '*.json', dir: '.' } },
    { name: 'mcp_mcp-god-mode_fs_write_text', args: { path: 'test-output.txt', content: 'test content' } },
    { name: 'mcp_mcp-god-mode_file_ops', args: { action: 'copy', source: 'package.json', destination: 'package-copy.json' } },
    { name: 'mcp_mcp-god-mode_file_watcher', args: { action: 'list_watchers' } },
    
    // Process and system tools
    { name: 'mcp_mcp-god-mode_proc_run', args: { command: 'echo', args: ['hello'] } },
    { name: 'mcp_mcp-god-mode_git_status', args: { repository_path: '.' } },
    { name: 'mcp_mcp-god-mode_docker_management', args: { action: 'list_containers' } },
    { name: 'mcp_mcp-god-mode_cron_job_manager', args: { random_string: 'test' } },
    
    // Data analysis tools
    { name: 'mcp_mcp-god-mode_math_calculate', args: { expression: '2 + 2' } },
    { name: 'mcp_mcp-god-mode_data_analyzer', args: { action: 'analyze', data: [1, 2, 3, 4, 5] } },
    { name: 'mcp_mcp-god-mode_chart_generator', args: { chart_type: 'bar', data: [{ label: 'A', value: 10 }, { label: 'B', value: 20 }], title: 'Test Chart' } },
    
    // Encryption and security tools
    { name: 'mcp_mcp-god-mode_encryption_tool', args: { action: 'hash', algorithm: 'sha256', input_data: 'test' } },
    
    // Email tools (basic tests)
    { name: 'mcp_mcp-god-mode_manage_email_accounts', args: { action: 'list' } },
    { name: 'mcp_mcp-god-mode_parse_email', args: { email_content: 'Subject: Test\n\nTest content', parse_type: 'headers' } },
    
    // Browser tools
    { name: 'mcp_mcp-god-mode_browser_control', args: { action: 'launch' } },
    
    // Download tools
    { name: 'mcp_mcp-god-mode_download_file', args: { url: 'https://httpbin.org/json' } },
    
    // Machine learning
    { name: 'mcp_mcp-god-mode_machine_learning', args: { action: 'train', model_type: 'classification' } },
    
    // Compliance
    { name: 'mcp_mcp-god-mode_compliance_assessment', args: { action: 'assess', framework: 'iso27001', scope: 'test' } },
    
    // Cloud tools
    { name: 'mcp_mcp-god-mode_cloud_infrastructure_manager', args: { action: 'list_resources', cloud_provider: 'aws' } },
    
    // IoT tools
    { name: 'mcp_mcp-god-mode_iot_security', args: { action: 'scan', device_type: 'sensor', protocol: 'wifi' } }
  ];

  for (const test of comprehensiveTests) {
    await testTool(test.name, test.args);
    await new Promise(resolve => setTimeout(resolve, 1000)); // Small delay between tests
  }

  // Generate report
  console.log('\n' + '='.repeat(60));
  console.log('📊 COMPREHENSIVE SMOKE TEST RESULTS');
  console.log('='.repeat(60));
  
  console.log(`\n✅ PASSED: ${results.passed.length}`);
  results.passed.forEach(r => console.log(`   - ${r.tool}`));

  console.log(`\n❌ FAILED: ${results.failed.length}`);
  results.failed.forEach(r => {
    console.log(`   - ${r.tool}`);
    console.log(`     Error: ${r.error.substring(0, 100)}...`);
  });

  console.log(`\n💥 ERRORS: ${results.errors.length}`);
  results.errors.forEach(r => console.log(`   - ${r.tool}: ${r.error}`));

  const total = results.passed.length + results.failed.length + results.errors.length;
  const successRate = total > 0 ? (results.passed.length / total * 100).toFixed(1) : 0;
  
  console.log(`\n📈 SUCCESS RATE: ${successRate}% (${results.passed.length}/${total})`);

  // Save results
  const reportPath = `comprehensive-smoke-test-results-${Date.now()}.json`;
  await fs.writeFile(reportPath, JSON.stringify(results, null, 2));
  console.log(`\n💾 Results saved to: ${reportPath}`);

  process.exit(results.failed.length + results.errors.length > 0 ? 1 : 0);
};

// Run tests
runTests().catch(console.error);
