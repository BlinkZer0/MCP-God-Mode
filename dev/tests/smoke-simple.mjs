#!/usr/bin/env node

/**
 * Simple Smoke Test for MCP God Mode Tools
 * Tests basic functionality of key tools
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

// Test basic tools
const runTests = async () => {
  console.log('🚀 Starting simple smoke test...\n');

  // Test basic tools that should work
  const basicTests = [
    { name: 'mcp_mcp-god-mode_health', args: { random_string: 'test' } },
    { name: 'mcp_mcp-god-mode_calculator', args: { operation: 'add', a: 1, b: 2 } },
    { name: 'mcp_mcp-god-mode_dice_rolling', args: { dice_notation: '1d6' } },
    { name: 'mcp_mcp-god-mode_password_generator', args: { length: 8 } },
    { name: 'mcp_mcp-god-mode_fs_list', args: { dir: '.' } },
    { name: 'mcp_mcp-god-mode_fs_read_text', args: { path: 'package.json' } },
    { name: 'mcp_mcp-god-mode_math_calculate', args: { expression: '2 + 2' } },
    { name: 'mcp_mcp-god-mode_git_status', args: { repository_path: '.' } },
    { name: 'mcp_mcp-god-mode_proc_run', args: { command: 'echo', args: ['hello'] } },
    { name: 'mcp_mcp-god-mode_encryption_tool', args: { action: 'hash', algorithm: 'sha256', input_data: 'test' } }
  ];

  for (const test of basicTests) {
    await testTool(test.name, test.args);
    await new Promise(resolve => setTimeout(resolve, 1000)); // Small delay between tests
  }

  // Generate report
  console.log('\n' + '='.repeat(60));
  console.log('📊 SMOKE TEST RESULTS');
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
  const reportPath = `smoke-test-results-${Date.now()}.json`;
  await fs.writeFile(reportPath, JSON.stringify(results, null, 2));
  console.log(`\n💾 Results saved to: ${reportPath}`);

  process.exit(results.failed.length + results.errors.length > 0 ? 1 : 0);
};

// Run tests
runTests().catch(console.error);
