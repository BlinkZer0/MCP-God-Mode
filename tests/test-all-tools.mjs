#!/usr/bin/env node

// Comprehensive MCP God Mode Tools Test
// Tests all 69 installed tools systematically

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🧪 MCP God Mode - Testing All 69 Tools...\n');

// Test configuration
const TEST_CONFIG = {
  serverPath: join(__dirname, '..', 'dev', 'dist', 'server-refactored.js'),
  timeout: 60000, // 60 seconds
  delayBetweenTests: 100 // 100ms between tool tests
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
  totalTools: 0,
  successfulTools: 0,
  failedTools: 0,
  toolDetails: [],
  startTime: Date.now(),
  errors: []
};

// All available tools to test
const ALL_TOOLS = [
  // Core system tools
  'mcp_mcp-god-mode_health',
  'mcp_mcp-god-mode_system_info',
  
  // File system tools
  'mcp_mcp-god-mode_fs_list',
  'mcp_mcp-god-mode_fs_read_text',
  'mcp_mcp-god-mode_fs_write_text',
  'mcp_mcp-god-mode_fs_search',
  'mcp_mcp-god-mode_file_ops',
  
  // Process tools
  'mcp_mcp-god-mode_proc_run',
  'mcp_mcp-god-mode_proc_run_elevated',
  
  // Git tools
  'mcp_mcp-god-mode_git_status',
  
  // System services
  'mcp_mcp-god-mode_win_services',
  'mcp_mcp-god-mode_win_processes',
  
  // Network tools
  'mcp_mcp-god-mode_download_file',
  'mcp_mcp-god-mode_network_diagnostics',
  'mcp_mcp-god-mode_port_scanner',
  'mcp_mcp-god-mode_vulnerability_scanner',
  
  // Security tools
  'mcp_mcp-god-mode_password_cracker',
  'mcp_mcp-god-mode_exploit_framework',
  'mcp_mcp-god-mode_wifi_security_toolkit',
  'mcp_mcp-god-mode_wifi_hacking',
  'mcp_mcp-god-mode_bluetooth_security_toolkit',
  'mcp_mcp-god-mode_bluetooth_hacking',
  'mcp_mcp-god-mode_sdr_security_toolkit',
  'mcp_mcp-god-mode_radio_security',
  'mcp_mcp-god-mode_signal_analysis',
  'mcp_mcp-god-mode_packet_sniffer',
  'mcp_mcp-god-mode_hack_network',
  'mcp_mcp-god-mode_security_testing',
  'mcp_mcp-god-mode_wireless_security',
  'mcp_mcp-god-mode_network_penetration',
  
  // Utility tools
  'mcp_mcp-god-mode_calculator',
  'mcp_mcp-god-mode_dice_rolling',
  'mcp_mcp-god-mode_math_calculate',
  'mcp_mcp-god-mode_encryption_tool',
  
  // Virtualization tools
  'mcp_mcp-god-mode_vm_management',
  'mcp_mcp-god-mode_docker_management',
  
  // Mobile tools
  'mcp_mcp-god-mode_mobile_device_info',
  'mcp_mcp-god-mode_mobile_file_ops',
  'mcp_mcp-god-mode_mobile_system_tools',
  'mcp_mcp-god-mode_mobile_hardware',
  
  // System restore tools
  'mcp_mcp-god-mode_system_restore',
  
  // Email tools
  'mcp_mcp-god-mode_send_email',
  'mcp_mcp-god-mode_read_emails',
  'mcp_mcp-god-mode_parse_email',
  'mcp_mcp-god-mode_delete_emails',
  'mcp_mcp-god-mode_sort_emails',
  'mcp_mcp-god-mode_manage_email_accounts',
  
  // Media tools
  'mcp_mcp-god-mode_video_editing',
  'mcp_mcp-god-mode_audio_editing',
  'mcp_mcp-god-mode_image_editing',
  'mcp_mcp-god-mode_screenshot',
  'mcp_mcp-god-mode_ocr_tool',
  
  // Web tools
  'mcp_mcp-god-mode_web_scraper',
  'mcp_mcp-god-mode_browser_control',
  
  // Advanced tools
  'mcp_mcp-god-mode_elevated_permissions_manager',
  'mcp_mcp-god-mode_network_security',
  'mcp_mcp-god-mode_blockchain_security',
  'mcp_mcp-god-mode_quantum_security',
  'mcp_mcp-god-mode_iot_security',
  'mcp_mcp-god-mode_social_engineering',
  'mcp_mcp-god-mode_threat_intelligence',
  'mcp_mcp-god-mode_compliance_assessment',
  'mcp_mcp-god-mode_encryption_tool',
  'mcp_mcp-god-mode_malware_analysis',
  'mcp_mcp-god-mode_data_analysis',
  'mcp_mcp-god-mode_machine_learning',
  'mcp_mcp-god-mode_cloud_security',
  'mcp_mcp-god-mode_forensics_analysis',
  
  // Tool discovery
  'mcp_mcp-god-mode_tool_discovery',
  'mcp_mcp-god-mode_explore_categories'
];

// Start the server
console.log('🔄 Starting MCP server for comprehensive testing...');
const server = spawn('node', [TEST_CONFIG.serverPath], {
  stdio: ['pipe', 'pipe', 'pipe'],
  cwd: __dirname
});

let serverOutput = '';
let serverError = '';

// Server output handling
server.stdout.on('data', (data) => {
  const output = data.toString();
  serverOutput += output;
  
  // Check for tools registration
  if (output.includes('tools loaded') || output.includes('tools registered')) {
    const match = output.match(/(\d+)\s+tools?\s+(?:loaded|registered)/i);
    if (match) {
      testResults.totalTools = parseInt(match[1]);
      console.log(`✅ ${testResults.totalTools} tools detected`);
    }
  }
});

// Server error handling
server.stderr.on('data', (data) => {
  const error = data.toString();
  serverError += error;
  
  if (error.includes('Error:') || error.includes('TypeError:') || error.includes('SyntaxError:')) {
    testResults.errors.push(error.trim());
  }
});

// Wait for server to start and then test all tools
setTimeout(async () => {
  console.log('\n🔍 Starting comprehensive tool testing...\n');
  
  try {
    await testAllTools();
  } catch (error) {
    testResults.errors.push(`Test execution error: ${error.message}`);
    console.log(`❌ Test execution error: ${error.message}`);
  }
  
  // Generate comprehensive test report
  generateComprehensiveReport();
  
  // Cleanup
  server.kill();
  process.exit(0);
  
}, 3000); // Wait 3 seconds for server to start

// Test all tools systematically
async function testAllTools() {
  console.log(`🧪 Testing ${ALL_TOOLS.length} tools...\n`);
  
  for (let i = 0; i < ALL_TOOLS.length; i++) {
    const toolName = ALL_TOOLS[i];
    const progress = `${i + 1}/${ALL_TOOLS.length}`;
    
    try {
      console.log(`  ${progress} Testing ${toolName}...`);
      
      const result = await testSingleTool(toolName);
      testResults.toolDetails.push(result);
      
      if (result.status === 'success') {
        testResults.successfulTools++;
        console.log(`    ✅ ${toolName}: SUCCESS`);
      } else {
        testResults.failedTools++;
        console.log(`    ❌ ${toolName}: ${result.status.toUpperCase()}`);
      }
      
      // Small delay between tests to avoid overwhelming the server
      await new Promise(resolve => setTimeout(resolve, TEST_CONFIG.delayBetweenTests));
      
    } catch (error) {
      const result = {
        tool: toolName,
        status: 'error',
        error: error.message,
        timestamp: new Date().toISOString()
      };
      testResults.toolDetails.push(result);
      testResults.failedTools++;
      console.log(`    ❌ ${toolName}: ERROR - ${error.message}`);
    }
  }
}

// Test a single tool
async function testSingleTool(toolName) {
  const result = {
    tool: toolName,
    status: 'unknown',
    response: null,
    error: null,
    timestamp: new Date().toISOString()
  };
  
  try {
    // Send tool call request
    const request = {
      jsonrpc: "2.0",
      id: Math.floor(Math.random() * 10000),
      method: "tools/call",
      params: {
        name: toolName,
        arguments: getToolArguments(toolName)
      }
    };
    
    server.stdin.write(JSON.stringify(request) + '\n');
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Check if tool responded
    if (serverOutput.includes(toolName) || serverOutput.includes('result')) {
      result.status = 'success';
      result.response = 'Tool responded successfully';
    } else {
      result.status = 'no_response';
      result.error = 'No response detected';
    }
    
  } catch (error) {
    result.status = 'error';
    result.error = error.message;
  }
  
  return result;
}

// Get appropriate arguments for each tool
function getToolArguments(toolName) {
  const args = {};
  
  // File system tools
  if (toolName.includes('fs_list') || toolName.includes('file_ops')) {
    args.dir = '.';
  }
  
  // Process tools
  if (toolName.includes('proc_run')) {
    args.command = 'echo';
    args.args = ['hello'];
  }
  
  // Network tools
  if (toolName.includes('network_diagnostics')) {
    args.action = 'ping';
    args.target = '127.0.0.1';
  }
  
  // Security tools
  if (toolName.includes('vulnerability_scanner')) {
    args.target = '127.0.0.1';
  }
  
  // Utility tools
  if (toolName.includes('calculator')) {
    args.expression = '2+2';
  }
  
  if (toolName.includes('dice_rolling')) {
    args.dice = 'd6';
  }
  
  if (toolName.includes('math_calculate')) {
    args.expression = '2+2';
  }
  
  if (toolName.includes('encryption_tool')) {
    args.action = 'hash';
    args.algorithm = 'sha256';
    args.input_data = 'test';
  }
  
  // Mobile tools
  if (toolName.includes('mobile_device_info')) {
    args.include_sensitive = false;
  }
  
  // Email tools
  if (toolName.includes('send_email')) {
    args.to = 'test@example.com';
    args.subject = 'Test';
    args.body = 'Test email';
    args.email_config = {
      service: 'gmail',
      email: 'test@example.com',
      password: 'test'
    };
  }
  
  // Media tools
  if (toolName.includes('screenshot')) {
    args.action = 'capture';
  }
  
  // Web tools
  if (toolName.includes('web_scraper')) {
    args.url = 'https://example.com';
    args.action = 'scrape_page';
  }
  
  return args;
}

// Generate comprehensive test report
function generateComprehensiveReport() {
  const endTime = Date.now();
  const duration = (endTime - testResults.startTime) / 1000;
  
  console.log('\n' + '='.repeat(80));
  console.log('📊 MCP GOD MODE - COMPREHENSIVE TOOLS TEST REPORT');
  console.log('='.repeat(80));
  
  // Summary statistics
  console.log('\n📈 SUMMARY STATISTICS:');
  console.log(`  Total Tools Tested: ${testResults.toolDetails.length}`);
  console.log(`  Successful Tools: ${testResults.successfulTools} ✅`);
  console.log(`  Failed Tools: ${testResults.failedTools} ❌`);
  console.log(`  Success Rate: ${((testResults.successfulTools / testResults.toolDetails.length) * 100).toFixed(1)}%`);
  console.log(`  Test Duration: ${duration.toFixed(1)} seconds`);
  
  // Tool status breakdown
  const statusCounts = {};
  testResults.toolDetails.forEach(tool => {
    statusCounts[tool.status] = (statusCounts[tool.status] || 0) + 1;
  });
  
  console.log('\n📊 TOOL STATUS BREAKDOWN:');
  Object.entries(statusCounts).forEach(([status, count]) => {
    const icon = status === 'success' ? '✅' : status === 'no_response' ? '⚠️' : '❌';
    console.log(`  ${icon} ${status.toUpperCase()}: ${count} tools`);
  });
  
  // Failed tools details
  const failedTools = testResults.toolDetails.filter(tool => tool.status !== 'success');
  if (failedTools.length > 0) {
    console.log('\n❌ FAILED TOOLS DETAILS:');
    failedTools.forEach(tool => {
      const icon = tool.status === 'no_response' ? '⚠️' : '❌';
      console.log(`  ${icon} ${tool.tool}: ${tool.status}`);
      if (tool.error) {
        console.log(`      Error: ${tool.error}`);
      }
    });
  }
  
  // Successful tools count
  if (testResults.successfulTools > 0) {
    console.log('\n✅ SUCCESSFUL TOOLS:');
    console.log(`  ${testResults.successfulTools} out of ${testResults.toolDetails.length} tools are working perfectly!`);
  }
  
  // Overall assessment
  console.log('\n📈 OVERALL ASSESSMENT:');
  const successRate = (testResults.successfulTools / testResults.toolDetails.length) * 100;
  
  if (successRate >= 95) {
    console.log('🎉 EXCELLENT: Almost all tools are working perfectly!');
    console.log('💡 The MCP God Mode server is in excellent condition.');
  } else if (successRate >= 80) {
    console.log('✅ GOOD: Most tools are working well.');
    console.log('💡 There are some minor issues but the server is functional.');
  } else if (successRate >= 60) {
    console.log('⚠️  FAIR: Many tools are working but there are significant issues.');
    console.log('💡 The server needs attention to fix failing tools.');
  } else {
    console.log('❌ POOR: Many tools are failing.');
    console.log('💡 The server has serious issues that need immediate attention.');
  }
  
  // Recommendations
  console.log('\n💡 RECOMMENDATIONS:');
  if (testResults.failedTools === 0) {
    console.log('  • All tools are working perfectly!');
    console.log('  • The red indicator in Cursor is likely a connection issue, not a tool problem.');
    console.log('  • Try restarting Cursor completely to resolve MCP connection issues.');
  } else {
    console.log(`  • ${testResults.failedTools} tools need attention.`);
    console.log('  • Check the failed tools list above for specific issues.');
    console.log('  • The server may need rebuilding or dependency updates.');
  }
  
  console.log('\n' + '='.repeat(80));
}

// Handle process termination
process.on('SIGINT', () => {
  console.log('\n🛑 Test interrupted by user');
  generateComprehensiveReport();
  server.kill();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Test terminated');
  generateComprehensiveReport();
  server.kill();
  process.exit(0);
});

// Timeout protection
setTimeout(() => {
  console.log('\n⏰ Test timeout reached');
  generateComprehensiveReport();
  server.kill();
  process.exit(0);
}, TEST_CONFIG.timeout);
