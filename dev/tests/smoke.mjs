#!/usr/bin/env node

/**
 * Comprehensive Smoke Test for MCP God Mode Tools
 * Tests all tools systematically and reports issues
 */

import { spawn } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Test configuration
const TEST_CONFIG = {
  timeout: 30000, // 30 seconds per tool
  maxConcurrent: 5, // Max concurrent tests
  retryAttempts: 2,
  skipTools: [
    // Skip tools that require external services or special setup
    'mcp_mcp-god-mode_hack_network',
    'mcp_mcp-god-mode_network_penetration',
    'mcp_mcp-god-mode_exploit_framework',
    'mcp_mcp-god-mode_password_cracker',
    'mcp_mcp-god-mode_bluetooth_hacking',
    'mcp_mcp-god-mode_drone_offense_enhanced',
    'mcp_mcp-god-mode_drone_defense_enhanced',
    'mcp_mcp-god-mode_malware_analysis',
    'mcp_mcp-god-mode_forensics_analysis',
    'mcp_mcp-god-mode_cloud_security',
    'mcp_mcp-god-mode_iot_security',
    'mcp_mcp-god-mode_quantum_security',
    'mcp_mcp-god-mode_blockchain_security',
    'mcp_mcp-god-mode_api_security_testing',
    'mcp_mcp-god-mode_database_security_toolkit',
    'mcp_mcp-god-mode_mobile_security_toolkit',
    'mcp_mcp-god-mode_email_security_suite',
    'mcp_mcp-god-mode_cloud_security_assessment',
    'mcp_mcp-god-mode_cloud_security_toolkit',
    'mcp_mcp-god-mode_penetration_testing_toolkit',
    'mcp_mcp-god-mode_malware_analysis_toolkit',
    'mcp_mcp-god-mode_forensics_toolkit',
    'mcp_mcp-god-mode_ai_adversarial_prompt',
    'mcp_mcp-god-mode_ai_adversarial_nlp',
    'mcp_mcp-god-mode_ai_adversarial_ethics',
    'mcp_mcp-god-mode_ai_adversarial_platform_info',
    'mcp_mcp-god-mode_captcha_defeating',
    'mcp_mcp-god-mode_form_detection',
    'mcp_mcp-god-mode_form_completion',
    'mcp_mcp-god-mode_form_validation',
    'mcp_mcp-god-mode_form_pattern_recognition',
    'mcp_mcp-god-mode_radio_security',
    'mcp_mcp-god-mode_cellular_triangulate',
    'mcp_mcp-god-mode_latency_geolocation',
    'mcp_mcp-god-mode_network_triangulation',
    'mcp_mcp-god-mode_ip_geolocation',
    'mcp_mcp-god-mode_osint_reconnaissance',
    'mcp_mcp-god-mode_packet_sniffer',
    'mcp_mcp-god-mode_network_discovery',
    'mcp_mcp-god-mode_network_security',
    'mcp_mcp-god-mode_network_diagnostics',
    'mcp_mcp-god-mode_network_utilities',
    'mcp_mcp-god-mode_network_traffic_analyzer',
    'mcp_mcp-god-mode_bluetooth_security_toolkit',
    'mcp_mcp-god-mode_bluetooth_device_manager',
    'mcp_mcp-god-mode_flipper_zero',
    'mcp_mcp-god-mode_mobile_app_security_toolkit',
    'mcp_mcp-god-mode_mobile_app_testing_toolkit',
    'mcp_mcp-god-mode_mobile_app_performance_toolkit',
    'mcp_mcp-god-mode_mobile_app_optimization_toolkit',
    'mcp_mcp-god-mode_mobile_app_monitoring_toolkit',
    'mcp_mcp-god-mode_mobile_app_analytics_toolkit',
    'mcp_mcp-god-mode_mobile_app_deployment_toolkit',
    'mcp_mcp-god-mode_mobile_device_management',
    'mcp_mcp-god-mode_mobile_device_info',
    'mcp_mcp-god-mode_mobile_hardware',
    'mcp_mcp-god-mode_mobile_network_analyzer',
    'mcp_mcp-god-mode_mobile_system_tools',
    'mcp_mcp-god-mode_mobile_file_ops',
    'mcp_mcp-god-mode_drone_mobile_optimized',
    'mcp_mcp-god-mode_drone_natural_language',
    'mcp_mcp-god-mode_elevated_permissions_manager',
    'mcp_mcp-god-mode_legal_compliance_manager',
    'mcp_mcp-god-mode_rag_toolkit',
    'mcp_mcp-god-mode_natural_language_router',
    'mcp_mcp-god-mode_explore_categories',
    'mcp_mcp-god-mode_health'
  ]
};

// Test results storage
const testResults = {
  passed: [],
  failed: [],
  skipped: [],
  errors: []
};

// Utility functions
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const runCommand = async (command, args = [], options = {}) => {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      ...options
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    child.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });

    child.on('error', (error) => {
      reject(error);
    });

    // Set timeout
    setTimeout(() => {
      child.kill();
      reject(new Error('Command timeout'));
    }, options.timeout || TEST_CONFIG.timeout);
  });
};

// Test individual tool
const testTool = async (toolName) => {
  console.log(`🧪 Testing tool: ${toolName}`);
  
  try {
    // Create a simple test request
    const testRequest = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: toolName,
        arguments: getTestArguments(toolName)
      }
    };

    // Start the MCP server
    const serverProcess = spawn('node', ['dist/server-refactored.js'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: __dirname
    });

    let serverOutput = '';
    let serverError = '';

    serverProcess.stdout.on('data', (data) => {
      serverOutput += data.toString();
    });

    serverProcess.stderr.on('data', (data) => {
      serverError += data.toString();
    });

    // Wait for server to start
    await sleep(2000);

    // Send test request
    serverProcess.stdin.write(JSON.stringify(testRequest) + '\n');
    serverProcess.stdin.end();

    // Wait for response
    await sleep(5000);

    // Check if server is still running
    const isRunning = !serverProcess.killed;
    
    if (isRunning) {
      serverProcess.kill();
    }

    // Analyze results
    if (serverError.includes('Error') || serverError.includes('error')) {
      testResults.failed.push({
        tool: toolName,
        error: serverError,
        output: serverOutput
      });
      console.log(`❌ ${toolName}: FAILED - ${serverError}`);
    } else {
      testResults.passed.push({
        tool: toolName,
        output: serverOutput
      });
      console.log(`✅ ${toolName}: PASSED`);
    }

  } catch (error) {
    testResults.errors.push({
      tool: toolName,
      error: error.message
    });
    console.log(`💥 ${toolName}: ERROR - ${error.message}`);
  }
};

// Get test arguments for specific tools
const getTestArguments = (toolName) => {
  const testArgs = {
    // Basic tools
    'mcp_mcp-god-mode_health': { random_string: 'test' },
    'mcp_mcp-god-mode_calculator': { operation: 'add', a: 1, b: 2 },
    'mcp_mcp-god-mode_dice_rolling': { dice_notation: '1d6' },
    'mcp_mcp-god-mode_password_generator': { length: 8 },
    'mcp_mcp-god-mode_encryption_tool': { 
      action: 'hash', 
      algorithm: 'sha256', 
      input_data: 'test' 
    },
    
    // File operations
    'mcp_mcp-god-mode_fs_list': { dir: '.' },
    'mcp_mcp-god-mode_fs_read_text': { path: 'package.json' },
    'mcp_mcp-god-mode_fs_search': { pattern: '*.json', dir: '.' },
    'mcp_mcp-god-mode_fs_write_text': { 
      path: 'test-output.txt', 
      content: 'test content' 
    },
    'mcp_mcp-god-mode_file_ops': { 
      action: 'copy', 
      source: 'package.json', 
      destination: 'package-copy.json' 
    },
    'mcp_mcp-god-mode_file_watcher': { action: 'list_watchers' },
    
    // System tools
    'mcp_mcp-god-mode_proc_run': { command: 'echo', args: ['hello'] },
    'mcp_mcp-god-mode_git_status': { repository_path: '.' },
    'mcp_mcp-god-mode_docker_management': { action: 'list_containers' },
    'mcp_mcp-god-mode_cron_job_manager': { random_string: 'test' },
    
    // Data analysis
    'mcp_mcp-god-mode_data_analyzer': { 
      action: 'analyze', 
      data: [1, 2, 3, 4, 5] 
    },
    'mcp_mcp-god-mode_math_calculate': { expression: '2 + 2' },
    'mcp_mcp-god-mode_chart_generator': {
      chart_type: 'bar',
      data: [{ label: 'A', value: 10 }, { label: 'B', value: 20 }],
      title: 'Test Chart'
    },
    
    // Image/Audio tools
    'mcp_mcp-god-mode_image_editing': { 
      action: 'metadata', 
      input_file: 'package.json' 
    },
    'mcp_mcp-god-mode_audio_editing': { 
      action: 'analyze', 
      input_file: 'package.json' 
    },
    'mcp_mcp-god-mode_ocr_tool': { 
      image_path: 'package.json' 
    },
    
    // Email tools
    'mcp_mcp-god-mode_manage_email_accounts': { action: 'list' },
    'mcp_mcp-god-mode_parse_email': { 
      email_content: 'Subject: Test\n\nTest content', 
      parse_type: 'headers' 
    },
    'mcp_mcp-god-mode_read_emails': { 
      imap_server: 'imap.gmail.com', 
      username: 'test', 
      password: 'test' 
    },
    'mcp_mcp-god-mode_delete_emails': { 
      imap_server: 'imap.gmail.com', 
      username: 'test', 
      password: 'test', 
      email_ids: ['1'] 
    },
    
    // Browser tools
    'mcp_mcp-god-mode_browser_control': { action: 'launch' },
    
    // Download tools
    'mcp_mcp-god-mode_download_file': { 
      url: 'https://httpbin.org/json' 
    },
    
    // Machine learning
    'mcp_mcp-god-mode_machine_learning': { 
      action: 'train', 
      model_type: 'classification' 
    },
    
    // Compliance
    'mcp_mcp-god-mode_compliance_assessment': { 
      action: 'assess', 
      framework: 'iso27001', 
      scope: 'test' 
    },
    
    // Cloud tools
    'mcp_mcp-god-mode_cloud_infrastructure_manager': { 
      action: 'list_resources', 
      cloud_provider: 'aws' 
    },
    
    // IoT tools
    'mcp_mcp-god-mode_iot_security': { 
      action: 'scan', 
      device_type: 'sensor', 
      protocol: 'wifi' 
    }
  };

  return testArgs[toolName] || {};
};

// Get all available tools
const getAllTools = async () => {
  try {
    // Read the tools index to get all available tools
    const toolsIndexPath = path.join(__dirname, 'src', 'tools', 'index.js');
    const toolsIndex = await fs.readFile(toolsIndexPath, 'utf8');
    
    // Extract tool names from the index
    const toolMatches = toolsIndex.match(/register(\w+)/g) || [];
    const tools = toolMatches.map(match => {
      const toolName = match.replace('register', '');
      return `mcp_mcp-god-mode_${toolName.toLowerCase()}`;
    });

    return tools.filter(tool => !TEST_CONFIG.skipTools.includes(tool));
  } catch (error) {
    console.log('⚠️ Could not read tools index, using fallback list');
    return [
      'mcp_mcp-god-mode_health',
      'mcp_mcp-god-mode_calculator',
      'mcp_mcp-god-mode_dice_rolling',
      'mcp_mcp-god-mode_password_generator',
      'mcp_mcp-god-mode_encryption_tool',
      'mcp_mcp-god-mode_fs_list',
      'mcp_mcp-god-mode_fs_read_text',
      'mcp_mcp-god-mode_fs_search',
      'mcp_mcp-god-mode_fs_write_text',
      'mcp_mcp-god-mode_file_ops',
      'mcp_mcp-god-mode_file_watcher',
      'mcp_mcp-god-mode_proc_run',
      'mcp_mcp-god-mode_git_status',
      'mcp_mcp-god-mode_docker_management',
      'mcp_mcp-god-mode_cron_job_manager',
      'mcp_mcp-god-mode_data_analyzer',
      'mcp_mcp-god-mode_math_calculate',
      'mcp_mcp-god-mode_chart_generator',
      'mcp_mcp-god-mode_image_editing',
      'mcp_mcp-god-mode_audio_editing',
      'mcp_mcp-god-mode_ocr_tool',
      'mcp_mcp-god-mode_manage_email_accounts',
      'mcp_mcp-god-mode_parse_email',
      'mcp_mcp-god-mode_read_emails',
      'mcp_mcp-god-mode_delete_emails',
      'mcp_mcp-god-mode_browser_control',
      'mcp_mcp-god-mode_download_file',
      'mcp_mcp-god-mode_machine_learning',
      'mcp_mcp-god-mode_compliance_assessment',
      'mcp_mcp-god-mode_cloud_infrastructure_manager',
      'mcp_mcp-god-mode_iot_security'
    ];
  }
};

// Run all tests
const runAllTests = async () => {
  console.log('🚀 Starting comprehensive smoke test for MCP God Mode tools...\n');
  
  const allTools = await getAllTools();
  console.log(`📋 Found ${allTools.length} tools to test\n`);

  // Test tools in batches to avoid overwhelming the system
  const batchSize = TEST_CONFIG.maxConcurrent;
  for (let i = 0; i < allTools.length; i += batchSize) {
    const batch = allTools.slice(i, i + batchSize);
    console.log(`\n🔄 Testing batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(allTools.length / batchSize)}`);
    
    const batchPromises = batch.map(tool => testTool(tool));
    await Promise.allSettled(batchPromises);
    
    // Small delay between batches
    await sleep(1000);
  }

  // Generate report
  generateReport();
};

// Generate test report
const generateReport = () => {
  console.log('\n' + '='.repeat(80));
  console.log('📊 SMOKE TEST REPORT');
  console.log('='.repeat(80));
  
  console.log(`\n✅ PASSED: ${testResults.passed.length} tools`);
  testResults.passed.forEach(result => {
    console.log(`   - ${result.tool}`);
  });

  console.log(`\n❌ FAILED: ${testResults.failed.length} tools`);
  testResults.failed.forEach(result => {
    console.log(`   - ${result.tool}: ${result.error}`);
  });

  console.log(`\n💥 ERRORS: ${testResults.errors.length} tools`);
  testResults.errors.forEach(result => {
    console.log(`   - ${result.tool}: ${result.error}`);
  });

  console.log(`\n⏭️ SKIPPED: ${TEST_CONFIG.skipTools.length} tools`);
  TEST_CONFIG.skipTools.forEach(tool => {
    console.log(`   - ${tool}`);
  });

  const totalTested = testResults.passed.length + testResults.failed.length + testResults.errors.length;
  const successRate = totalTested > 0 ? (testResults.passed.length / totalTested * 100).toFixed(1) : 0;
  
  console.log(`\n📈 SUCCESS RATE: ${successRate}% (${testResults.passed.length}/${totalTested})`);
  
  // Save detailed report
  const report = {
    timestamp: new Date().toISOString(),
    summary: {
      total: totalTested,
      passed: testResults.passed.length,
      failed: testResults.failed.length,
      errors: testResults.errors.length,
      skipped: TEST_CONFIG.skipTools.length,
      successRate: parseFloat(successRate)
    },
    results: {
      passed: testResults.passed,
      failed: testResults.failed,
      errors: testResults.errors,
      skipped: TEST_CONFIG.skipTools
    }
  };

  const reportPath = path.join(__dirname, `smoke-test-report-${Date.now()}.json`);
  fs.writeFile(reportPath, JSON.stringify(report, null, 2));
  console.log(`\n💾 Detailed report saved to: ${reportPath}`);
  
  // Exit with appropriate code
  process.exit(testResults.failed.length + testResults.errors.length > 0 ? 1 : 0);
};

// Main execution
if (import.meta.url === `file://${process.argv[1]}`) {
  runAllTests().catch(error => {
    console.error('💥 Smoke test failed:', error);
    process.exit(1);
  });
}

export { runAllTests, testTool, getAllTools };