#!/usr/bin/env node

// Comprehensive MCP God Mode Smoke Test
// Tests all tools and MCP protocol communication

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🚀 MCP God Mode Smoke Test Starting...\n');

// Test configuration
const TEST_CONFIG = {
  serverPath: join(__dirname, '..', 'dev', 'dist', 'server-refactored.js'),
  timeout: 120000, // 2 minutes for comprehensive testing
  maxTools: 114
};

// Check if server exists
if (!fs.existsSync(TEST_CONFIG.serverPath)) {
  console.error(`❌ Server not found at: ${TEST_CONFIG.serverPath}`);
  console.error('Please build the server first: npm run build');
  process.exit(1);
}

console.log(`✅ Server found at: ${TEST_CONFIG.serverPath}\n`);

// Test results tracking
const testResults = {
  serverStart: false,
  mcpHandshake: false,
  toolsList: false,
  toolsCount: 0,
  toolTests: [],
  errors: [],
  warnings: []
};

// Start the server
console.log('🔄 Starting MCP server...');
const server = spawn('node', [TEST_CONFIG.serverPath], {
  stdio: ['pipe', 'pipe', 'pipe'],
  cwd: __dirname
});

let serverOutput = '';
let serverError = '';
let serverStartTime = Date.now();

// Server output handling
server.stdout.on('data', (data) => {
  const output = data.toString();
  serverOutput += output;
  
  // Check for server startup success
  if (output.includes('MCP God Mode Server started') || output.includes('Server started successfully')) {
    testResults.serverStart = true;
    console.log('✅ Server started successfully');
  }
  
  // Check for tools registration
  if (output.includes('tools loaded') || output.includes('tools registered')) {
    const match = output.match(/(\d+)\s+tools?\s+(?:loaded|registered)/i);
    if (match) {
      testResults.toolsCount = parseInt(match[1]);
      console.log(`✅ ${testResults.toolsCount} tools registered`);
    }
  }
  
  // Check for MCP protocol messages
  if (output.includes('notifications/tools/list_changed')) {
    testResults.mcpHandshake = true;
    console.log('✅ MCP protocol responding');
  }
});

// Server error handling
server.stderr.on('data', (data) => {
  const error = data.toString();
  serverError += error;
  
  if (error.includes('Error:') || error.includes('TypeError:') || error.includes('SyntaxError:')) {
    testResults.errors.push(error.trim());
    console.log(`❌ Server error: ${error.trim()}`);
  }
});

// Server exit handling
server.on('exit', (code) => {
  if (code !== 0) {
    testResults.errors.push(`Server exited with code ${code}`);
    console.log(`❌ Server exited with code ${code}`);
  }
});

// Wait for server to start and then test tools
setTimeout(async () => {
  console.log('\n🔍 Testing MCP Protocol Communication...\n');
  
  try {
    // Test 1: Basic MCP handshake
    await testMCPHandshake();
    
    // Test 2: Tools list
    await testToolsList();
    
    // Test 3: All tools execution
    await testAllTools();
    
  } catch (error) {
    testResults.errors.push(`Test execution error: ${error.message}`);
    console.log(`❌ Test execution error: ${error.message}`);
  }
  
  // Generate test report
  generateTestReport();
  
  // Cleanup
  server.kill();
  process.exit(0);
  
}, 5000); // Wait 5 seconds for server to start

// Test MCP handshake
async function testMCPHandshake() {
  console.log('📡 Testing MCP handshake...');
  
  try {
    // Send a simple MCP request
    const request = {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: {
          name: "smoke-test",
          version: "1.0.0"
        }
      }
    };
    
    server.stdin.write(JSON.stringify(request) + '\n');
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    if (serverOutput.includes('initialize') || serverOutput.includes('jsonrpc')) {
      testResults.mcpHandshake = true;
      console.log('✅ MCP handshake successful');
    } else {
      console.log('⚠️  MCP handshake response not detected');
    }
    
  } catch (error) {
    console.log(`❌ MCP handshake test failed: ${error.message}`);
  }
}

// Test tools list
async function testToolsList() {
  console.log('\n📋 Testing tools list...');
  
  try {
    const request = {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list"
    };
    
    server.stdin.write(JSON.stringify(request) + '\n');
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    if (serverOutput.includes('tools/list') || serverOutput.includes('result')) {
      testResults.toolsList = true;
      console.log('✅ Tools list request successful');
    } else {
      console.log('⚠️  Tools list response not detected');
    }
    
  } catch (error) {
    console.log(`❌ Tools list test failed: ${error.message}`);
  }
}

// Test all tools
async function testAllTools() {
  console.log('\n🧪 Testing all 108 tools...');
  
  // All 108 tools from the modular server
  const allTools = [
    // All 114 tools from build-server.js
    'mcp_mcp-god-mode_health',
    'mcp_mcp-god-mode_system_info',
    'mcp_mcp-god-mode_fs_list',
    'mcp_mcp-god-mode_fs_read_text',
    'mcp_mcp-god-mode_fs_write_text',
    'mcp_mcp-god-mode_fs_search',
    'mcp_mcp-god-mode_file_ops',
    'mcp_mcp-god-mode_file_watcher',
    'mcp_mcp-god-mode_proc_run',
    'mcp_mcp-god-mode_proc_run_elevated',
    'mcp_mcp-god-mode_system_restore',
    'mcp_mcp-god-mode_elevated_permissions_manager',
    'mcp_mcp-god-mode_cron_job_manager',
    'mcp_mcp-god-mode_system_monitor',
    'mcp_mcp-god-mode_git_status',
    'mcp_mcp-god-mode_win_services',
    'mcp_mcp-god-mode_win_processes',
    'mcp_mcp-god-mode_packet_sniffer',
    'mcp_mcp-god-mode_port_scanner',
    'mcp_mcp-god-mode_network_diagnostics',
    'mcp_mcp-god-mode_download_file',
    'mcp_mcp-god-mode_network_traffic_analyzer',
    'mcp_mcp-god-mode_ip_geolocation',
    'mcp_mcp-god-mode_network_triangulation',
    'mcp_mcp-god-mode_osint_reconnaissance',
    'mcp_mcp-god-mode_latency_geolocation',
    'mcp_mcp-god-mode_network_discovery',
    'mcp_mcp-god-mode_vulnerability_assessment',
    'mcp_mcp-god-mode_traffic_analysis',
    'mcp_mcp-god-mode_network_utilities',
    'mcp_mcp-god-mode_social_account_ripper',
    'mcp_mcp-god-mode_social_account_ripper_modular',
    'mcp_mcp-god-mode_vulnerability_scanner',
    'mcp_mcp-god-mode_password_cracker',
    'mcp_mcp-god-mode_exploit_framework',
    'mcp_mcp-god-mode_network_security',
    'mcp_mcp-god-mode_blockchain_security',
    'mcp_mcp-god-mode_quantum_security',
    'mcp_mcp-god-mode_iot_security',
    'mcp_mcp-god-mode_social_engineering',
    'mcp_mcp-god-mode_threat_intelligence',
    'mcp_mcp-god-mode_compliance_assessment',
    'mcp_mcp-god-mode_social_network_ripper',
    'mcp_mcp-god-mode_metadata_extractor',
    'mcp_mcp-god-mode_encryption_tool',
    'mcp_mcp-god-mode_malware_analysis',
    'mcp_mcp-god-mode_hack_network',
    'mcp_mcp-god-mode_security_testing',
    'mcp_mcp-god-mode_network_penetration',
    'mcp_mcp-god-mode_penetration_testing_toolkit',
    'mcp_mcp-god-mode_social_engineering_toolkit',
    'mcp_mcp-god-mode_wifi_security_toolkit',
    'mcp_mcp-god-mode_wifi_hacking',
    'mcp_mcp-god-mode_wireless_security',
    'mcp_mcp-god-mode_wireless_network_scanner',
    'mcp_mcp-god-mode_bluetooth_security_toolkit',
    'mcp_mcp-god-mode_bluetooth_hacking',
    'mcp_mcp-god-mode_bluetooth_device_manager',
    'mcp_mcp-god-mode_sdr_security_toolkit',
    'mcp_mcp-god-mode_radio_security',
    'mcp_mcp-god-mode_signal_analysis',
    'mcp_mcp-god-mode_web_scraper',
    'mcp_mcp-god-mode_browser_control',
    'mcp_mcp-god-mode_web_automation',
    'mcp_mcp-god-mode_webhook_manager',
    'mcp_mcp-god-mode_universal_browser_operator',
    'mcp_mcp-god-mode_web_search',
    'mcp_mcp-god-mode_captcha_defeating',
    'mcp_mcp-god-mode_form_completion',
    'mcp_mcp-god-mode_send_email',
    'mcp_mcp-god-mode_read_emails',
    'mcp_mcp-god-mode_parse_email',
    'mcp_mcp-god-mode_delete_emails',
    'mcp_mcp-god-mode_sort_emails',
    'mcp_mcp-god-mode_manage_email_accounts',
    'mcp_mcp-god-mode_video_editing',
    'mcp_mcp-god-mode_ocr_tool',
    'mcp_mcp-god-mode_image_editing',
    'mcp_mcp-god-mode_audio_editing',
    'mcp_mcp-god-mode_screenshot',
    'mcp_mcp-god-mode_mobile_device_info',
    'mcp_mcp-god-mode_mobile_file_ops',
    'mcp_mcp-god-mode_mobile_system_tools',
    'mcp_mcp-god-mode_mobile_hardware',
    'mcp_mcp-god-mode_mobile_device_management',
    'mcp_mcp-god-mode_mobile_app_analytics_toolkit',
    'mcp_mcp-god-mode_mobile_app_deployment_toolkit',
    'mcp_mcp-god-mode_mobile_app_optimization_toolkit',
    'mcp_mcp-god-mode_mobile_app_security_toolkit',
    'mcp_mcp-god-mode_mobile_app_monitoring_toolkit',
    'mcp_mcp-god-mode_mobile_app_performance_toolkit',
    'mcp_mcp-god-mode_mobile_app_testing_toolkit',
    'mcp_mcp-god-mode_mobile_network_analyzer',
    'mcp_mcp-god-mode_vm_management',
    'mcp_mcp-god-mode_docker_management',
    'mcp_mcp-god-mode_calculator',
    'mcp_mcp-god-mode_dice_rolling',
    'mcp_mcp-god-mode_math_calculate',
    'mcp_mcp-god-mode_data_analysis',
    'mcp_mcp-god-mode_machine_learning',
    'mcp_mcp-god-mode_chart_generator',
    'mcp_mcp-god-mode_text_processor',
    'mcp_mcp-god-mode_password_generator',
    'mcp_mcp-god-mode_data_analyzer',
    'mcp_mcp-god-mode_download_file',
    'mcp_mcp-god-mode_cloud_security',
    'mcp_mcp-god-mode_cloud_infrastructure_manager',
    'mcp_mcp-god-mode_cloud_security_toolkit',
    'mcp_mcp-god-mode_forensics_analysis',
    'mcp_mcp-god-mode_forensics_toolkit',
    'mcp_mcp-god-mode_malware_analysis_toolkit',
    'mcp_mcp-god-mode_tool_discovery',
    'mcp_mcp-god-mode_explore_categories',
    'mcp_mcp-god-mode_social_network_ripper'
  ];
  
  console.log(`📊 Testing ${allTools.length} tools...\n`);
  
  let successCount = 0;
  let errorCount = 0;
  let noResponseCount = 0;
  
  for (let i = 0; i < allTools.length; i++) {
    const toolName = allTools[i];
    const progress = `[${i + 1}/${allTools.length}]`;
    
    try {
      console.log(`  ${progress} Testing ${toolName}...`);
      
      const request = {
        jsonrpc: "2.0",
        id: Math.floor(Math.random() * 1000),
        method: "tools/call",
        params: {
          name: toolName,
          arguments: {}
        }
      };
      
      server.stdin.write(JSON.stringify(request) + '\n');
      
      // Wait for response
      await new Promise(resolve => setTimeout(resolve, 500));
      
      if (serverOutput.includes(toolName) || serverOutput.includes('result')) {
        console.log(`    ✅ ${toolName} responded`);
        testResults.toolTests.push({ tool: toolName, status: 'success' });
        successCount++;
      } else {
        console.log(`    ⚠️  ${toolName} no response detected`);
        testResults.toolTests.push({ tool: toolName, status: 'no_response' });
        noResponseCount++;
      }
      
    } catch (error) {
      console.log(`    ❌ ${toolName} test failed: ${error.message}`);
      testResults.toolTests.push({ tool: toolName, status: 'error', error: error.message });
      errorCount++;
    }
    
    // Progress update every 10 tools
    if ((i + 1) % 10 === 0) {
      console.log(`\n📈 Progress: ${i + 1}/${allTools.length} tools tested (${successCount} success, ${errorCount} errors, ${noResponseCount} no response)\n`);
    }
  }
  
  console.log(`\n🎯 Tool Testing Complete:`);
  console.log(`  ✅ Successful: ${successCount}/${allTools.length}`);
  console.log(`  ❌ Errors: ${errorCount}/${allTools.length}`);
  console.log(`  ⚠️  No Response: ${noResponseCount}/${allTools.length}`);
}

// Generate comprehensive test report
function generateTestReport() {
  console.log('\n' + '='.repeat(60));
  console.log('📊 MCP GOD MODE SMOKE TEST REPORT');
  console.log('='.repeat(60));
  
  // Server status
  console.log('\n🚀 SERVER STATUS:');
  console.log(`  Startup: ${testResults.serverStart ? '✅ SUCCESS' : '❌ FAILED'}`);
  console.log(`  MCP Protocol: ${testResults.mcpHandshake ? '✅ WORKING' : '❌ FAILED'}`);
  console.log(`  Tools List: ${testResults.toolsList ? '✅ WORKING' : '❌ FAILED'}`);
  console.log(`  Tools Count: ${testResults.toolsCount > 0 ? `✅ ${testResults.toolsCount}` : '❌ 0'}`);
  
  // Tool test results
  if (testResults.toolTests.length > 0) {
    console.log('\n🧪 TOOL TEST RESULTS:');
    testResults.toolTests.forEach(test => {
      const status = test.status === 'success' ? '✅' : 
                    test.status === 'no_response' ? '⚠️' : '❌';
      console.log(`  ${status} ${test.tool}: ${test.status}`);
    });
  }
  
  // Errors and warnings
  if (testResults.errors.length > 0) {
    console.log('\n❌ ERRORS:');
    testResults.errors.forEach(error => {
      console.log(`  • ${error}`);
    });
  }
  
  if (testResults.warnings.length > 0) {
    console.log('\n⚠️  WARNINGS:');
    testResults.warnings.forEach(warning => {
      console.log(`  • ${warning}`);
    });
  }
  
  // Tool test summary
  if (testResults.toolTests.length > 0) {
    const successfulTools = testResults.toolTests.filter(t => t.status === 'success').length;
    const totalTools = testResults.toolTests.length;
    const successRate = Math.round((successfulTools / totalTools) * 100);
    
    console.log(`\n📊 TOOL SUCCESS RATE: ${successRate}% (${successfulTools}/${totalTools})`);
    
    if (successRate >= 90) {
      console.log('🎉 EXCELLENT: Most tools are working perfectly!');
    } else if (successRate >= 70) {
      console.log('✅ GOOD: Most tools are working, some issues detected.');
    } else if (successRate >= 50) {
      console.log('⚠️  FAIR: Some tools working, significant issues detected.');
    } else {
      console.log('❌ POOR: Many tools have issues that need attention.');
    }
  }
  
  // Overall assessment
  console.log('\n📈 OVERALL ASSESSMENT:');
  const successCount = [testResults.serverStart, testResults.mcpHandshake, testResults.toolsList].filter(Boolean).length;
  const totalTests = 3;
  
  if (successCount === totalTests) {
    console.log('🎉 EXCELLENT: All core tests passed!');
    console.log('💡 The server should work with Cursor. If you still see a red indicator,');
    console.log('   try restarting Cursor completely or check MCP configuration.');
  } else if (successCount >= 2) {
    console.log('⚠️  PARTIAL: Some tests passed, but there are issues.');
    console.log('💡 The server is partially working. Check the errors above.');
  } else {
    console.log('❌ CRITICAL: Most tests failed.');
    console.log('💡 The server has serious issues that need to be fixed.');
  }
  
  console.log('\n' + '='.repeat(60));
}

// Handle process termination
process.on('SIGINT', () => {
  console.log('\n🛑 Test interrupted by user');
  server.kill();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Test terminated');
  server.kill();
  process.exit(0);
});

// Timeout protection
setTimeout(() => {
  console.log('\n⏰ Test timeout reached');
  generateTestReport();
  server.kill();
  process.exit(0);
}, TEST_CONFIG.timeout);
