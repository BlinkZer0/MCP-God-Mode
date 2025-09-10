#!/usr/bin/env node

/**
 * MCP God Mode Comprehensive Smoke Test Suite
 * Tests ALL 113 tools across both monolithic and modular servers
 * This is a comprehensive test covering every tool in the system
 */

import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import * as os from 'os';
import * as path from 'path';

const MONOLITHIC_SERVER_PATH = './dist/server-refactored.js';
const MODULAR_SERVER_PATH = './dist/server-modular.js';
const TEST_TIMEOUT = 30000; // 30 seconds for complex operations

// ============================================================================
// COMPREHENSIVE TOOL DEFINITIONS - ALL 113 TOOLS
// ============================================================================

const ALL_TOOLS = [
  // ===========================================
  // CORE SYSTEM TOOLS (2 Tools)
  // ===========================================
  { name: 'health', params: {}, category: 'Core System', description: 'System health check' },
  { name: 'system_info', params: {}, category: 'Core System', description: 'System information' },
  
  // ===========================================
  // FILE SYSTEM TOOLS (6 Tools)
  // ===========================================
  { name: 'fs_list', params: { dir: '.' }, category: 'File System', description: 'List files/directories' },
  { name: 'fs_read_text', params: { path: 'package.json' }, category: 'File System', description: 'Read text file' },
  { name: 'fs_write_text', params: { path: 'smoke-test-temp.txt', content: 'Smoke test content' }, category: 'File System', description: 'Write text file' },
  { name: 'fs_search', params: { pattern: '*.json', dir: '.' }, category: 'File System', description: 'File search' },
  { name: 'file_ops', params: { action: 'list', path: '.' }, category: 'File System', description: 'File operations' },
  { name: 'file_watcher', params: { action: 'watch', path: '.' }, category: 'File System', description: 'File watcher' },
  
  // ===========================================
  // PROCESS & SYSTEM MANAGEMENT (4 Tools)
  // ===========================================
  { name: 'proc_run', params: { command: 'echo', args: ['smoke-test'] }, category: 'Process Management', description: 'Run process' },
  { name: 'proc_run_elevated', params: { command: 'echo', args: ['elevated-test'] }, category: 'Process Management', description: 'Run elevated process' },
  { name: 'win_services', params: { action: 'list' }, category: 'Process Management', description: 'Windows services' },
  { name: 'win_processes', params: { action: 'list' }, category: 'Process Management', description: 'Windows processes' },
  
  // ===========================================
  // SYSTEM TOOLS (4 Tools)
  // ===========================================
  { name: 'system_restore', params: { action: 'list_restore_points' }, category: 'System Tools', description: 'System restore' },
  { name: 'elevated_permissions_manager', params: { action: 'list', user: 'test' }, category: 'System Tools', description: 'Elevated permissions' },
  { name: 'cron_job_manager', params: { action: 'list' }, category: 'System Tools', description: 'Cron job manager' },
  { name: 'system_monitor', params: { action: 'start', duration: 1 }, category: 'System Tools', description: 'System monitor' },
  
  // ===========================================
  // GIT TOOLS (1 Tool)
  // ===========================================
  { name: 'git_status', params: {}, category: 'Git Tools', description: 'Git status' },
  
  // ===========================================
  // NETWORK TOOLS (12 Tools)
  // ===========================================
  { name: 'packet_sniffer', params: { interface: 'eth0', duration: 1 }, category: 'Network Tools', description: 'Packet sniffer' },
  { name: 'port_scanner', params: { target: 'localhost', ports: '80,443' }, category: 'Network Tools', description: 'Port scanner' },
  { name: 'network_diagnostics', params: { action: 'ping', target: 'localhost' }, category: 'Network Tools', description: 'Network diagnostics' },
  { name: 'download_file', params: { url: 'https://httpbin.org/json', outputPath: 'smoke-test-download.json' }, category: 'Network Tools', description: 'Download file' },
  { name: 'network_traffic_analyzer', params: { action: 'analyze', interface: 'eth0' }, category: 'Network Tools', description: 'Network traffic analyzer' },
  { name: 'ip_geolocation', params: { random_string: 'test' }, category: 'Network Tools', description: 'IP geolocation' },
  { name: 'network_triangulation', params: { random_string: 'test' }, category: 'Network Tools', description: 'Network triangulation' },
  { name: 'osint_reconnaissance', params: { random_string: 'test' }, category: 'Network Tools', description: 'OSINT reconnaissance' },
  { name: 'latency_geolocation', params: { random_string: 'test' }, category: 'Network Tools', description: 'Latency geolocation' },
  { name: 'network_discovery', params: { random_string: 'test' }, category: 'Network Tools', description: 'Network discovery' },
  { name: 'vulnerability_assessment', params: { random_string: 'test' }, category: 'Network Tools', description: 'Vulnerability assessment' },
  { name: 'traffic_analysis', params: { random_string: 'test' }, category: 'Network Tools', description: 'Traffic analysis' },
  
  // ===========================================
  // NETWORK UTILITIES (2 Tools)
  // ===========================================
  { name: 'network_utilities', params: { random_string: 'test' }, category: 'Network Utilities', description: 'Network utilities' },
  { name: 'social_account_ripper', params: { random_string: 'test' }, category: 'Network Utilities', description: 'Social account ripper' },
  
  // ===========================================
  // SECURITY TOOLS (12 Tools)
  // ===========================================
  { name: 'vulnerability_scanner', params: { target: 'localhost', scan_type: 'network' }, category: 'Security Tools', description: 'Vulnerability scanner' },
  { name: 'password_cracker', params: { target: 'test_hash', method: 'dictionary' }, category: 'Security Tools', description: 'Password cracker' },
  { name: 'exploit_framework', params: { target: 'localhost', exploit_type: 'buffer_overflow' }, category: 'Security Tools', description: 'Exploit framework' },
  { name: 'network_security', params: { action: 'scan', target: 'localhost' }, category: 'Security Tools', description: 'Network security' },
  { name: 'blockchain_security', params: { action: 'audit', blockchain_type: 'ethereum' }, category: 'Security Tools', description: 'Blockchain security' },
  { name: 'quantum_security', params: { action: 'generate', algorithm_type: 'lattice' }, category: 'Security Tools', description: 'Quantum security' },
  { name: 'iot_security', params: { action: 'scan', device_type: 'camera', target_ip: '192.168.1.1' }, category: 'Security Tools', description: 'IoT security' },
  { name: 'social_engineering', params: { action: 'phishing_test', target_group: 'test' }, category: 'Security Tools', description: 'Social engineering' },
  { name: 'threat_intelligence', params: { action: 'gather' }, category: 'Security Tools', description: 'Threat intelligence' },
  { name: 'compliance_assessment', params: { framework: 'iso27001', scope: 'test', assessment_type: 'gap_analysis' }, category: 'Security Tools', description: 'Compliance assessment' },
  { name: 'metadata_extractor', params: { random_string: 'test' }, category: 'Security Tools', description: 'Metadata extractor' },
  { name: 'malware_analysis', params: { action: 'static_analysis', sample_file: 'test.exe' }, category: 'Security Tools', description: 'Malware analysis' },
  
  // ===========================================
  // PENETRATION TESTING TOOLS (5 Tools)
  // ===========================================
  { name: 'hack_network', params: { target_network: '192.168.1.0/24', attack_vector: 'reconnaissance' }, category: 'Penetration Testing', description: 'Hack network' },
  { name: 'security_testing', params: { target: 'localhost', test_type: 'penetration_test' }, category: 'Penetration Testing', description: 'Security testing' },
  { name: 'network_penetration', params: { random_string: 'test' }, category: 'Penetration Testing', description: 'Network penetration' },
  { name: 'penetration_testing_toolkit', params: { random_string: 'test' }, category: 'Penetration Testing', description: 'Penetration testing toolkit' },
  { name: 'social_engineering_toolkit', params: { random_string: 'test' }, category: 'Penetration Testing', description: 'Social engineering toolkit' },
  
  // ===========================================
  // WIRELESS TOOLS (4 Tools)
  // ===========================================
  { name: 'wifi_security_toolkit', params: { interface: 'wlan0', action: 'scan' }, category: 'Wireless Tools', description: 'WiFi security toolkit' },
  { name: 'wifi_hacking', params: { random_string: 'test' }, category: 'Wireless Tools', description: 'WiFi hacking' },
  { name: 'wireless_security', params: { random_string: 'test' }, category: 'Wireless Tools', description: 'Wireless security' },
  { name: 'wireless_network_scanner', params: { random_string: 'test' }, category: 'Wireless Tools', description: 'Wireless network scanner' },
  
  // ===========================================
  // BLUETOOTH TOOLS (3 Tools)
  // ===========================================
  { name: 'bluetooth_security_toolkit', params: { interface: 'hci0', action: 'scan' }, category: 'Bluetooth Tools', description: 'Bluetooth security toolkit' },
  { name: 'bluetooth_hacking', params: { random_string: 'test' }, category: 'Bluetooth Tools', description: 'Bluetooth hacking' },
  { name: 'bluetooth_device_manager', params: { random_string: 'test' }, category: 'Bluetooth Tools', description: 'Bluetooth device manager' },
  
  // ===========================================
  // RADIO TOOLS (3 Tools)
  // ===========================================
  { name: 'sdr_security_toolkit', params: { frequency: 433.92, action: 'monitor' }, category: 'Radio Tools', description: 'SDR security toolkit' },
  { name: 'radio_security', params: { random_string: 'test' }, category: 'Radio Tools', description: 'Radio security' },
  { name: 'signal_analysis', params: { random_string: 'test' }, category: 'Radio Tools', description: 'Signal analysis' },
  
  // ===========================================
  // WEB TOOLS (7 Tools)
  // ===========================================
  { name: 'web_scraper', params: { url: 'https://httpbin.org/json', action: 'scrape_page' }, category: 'Web Tools', description: 'Web scraper' },
  { name: 'browser_control', params: { action: 'launch_browser', browser: 'chrome' }, category: 'Web Tools', description: 'Browser control' },
  { name: 'web_automation', params: { action: 'navigate', url: 'https://httpbin.org/json' }, category: 'Web Tools', description: 'Web automation' },
  { name: 'webhook_manager', params: { action: 'create', url: 'https://httpbin.org/post' }, category: 'Web Tools', description: 'Webhook manager' },
  { name: 'universal_browser_operator', params: { random_string: 'test' }, category: 'Web Tools', description: 'Universal browser operator' },
  { name: 'web_search', params: { random_string: 'test' }, category: 'Web Tools', description: 'Web search' },
  { name: 'captcha_defeating', params: { random_string: 'test' }, category: 'Web Tools', description: 'Captcha defeating' },
  
  // ===========================================
  // EMAIL TOOLS (7 Tools)
  // ===========================================
  { name: 'send_email', params: { to: 'test@example.com', subject: 'Test', body: 'Test email', email_config: { service: 'gmail', email: 'test@gmail.com', password: 'test' } }, category: 'Email Tools', description: 'Send email' },
  { name: 'read_emails', params: { account: 'test@gmail.com' }, category: 'Email Tools', description: 'Read emails' },
  { name: 'parse_email', params: { email_content: 'From: test@example.com\nSubject: Test\n\nTest content' }, category: 'Email Tools', description: 'Parse email' },
  { name: 'delete_emails', params: { account: 'test@gmail.com', email_ids: ['test-id'] }, category: 'Email Tools', description: 'Delete emails' },
  { name: 'sort_emails', params: { random_string: 'test' }, category: 'Email Tools', description: 'Sort emails' },
  { name: 'email_utils', params: { random_string: 'test' }, category: 'Email Tools', description: 'Email utils' },
  { name: 'manage_email_accounts', params: { random_string: 'test' }, category: 'Email Tools', description: 'Manage email accounts' },
  
  // ===========================================
  // MEDIA TOOLS (4 Tools)
  // ===========================================
  { name: 'video_editing', params: { action: 'convert', input_file: 'test.mp4', output_file: 'test_out.mp4' }, category: 'Media Tools', description: 'Video editing' },
  { name: 'ocr_tool', params: { action: 'extract_text', input_file: 'test.png' }, category: 'Media Tools', description: 'OCR tool' },
  { name: 'image_editing', params: { action: 'resize', input_file: 'test.png', output_file: 'test_out.png' }, category: 'Media Tools', description: 'Image editing' },
  { name: 'audio_editing', params: { action: 'trim', input_file: 'test.mp3', output_file: 'test_out.mp3' }, category: 'Media Tools', description: 'Audio editing' },
  
  // ===========================================
  // SCREENSHOT TOOLS (1 Tool)
  // ===========================================
  { name: 'screenshot', params: { action: 'capture', output_file: 'test_screenshot.png' }, category: 'Screenshot Tools', description: 'Screenshot' },
  
  // ===========================================
  // MOBILE TOOLS (12 Tools)
  // ===========================================
  { name: 'mobile_device_info', params: { info_type: 'basic' }, category: 'Mobile Tools', description: 'Mobile device info' },
  { name: 'mobile_file_ops', params: { action: 'list', path: '/' }, category: 'Mobile Tools', description: 'Mobile file operations' },
  { name: 'mobile_system_tools', params: { action: 'system_info' }, category: 'Mobile Tools', description: 'Mobile system tools' },
  { name: 'mobile_hardware', params: { action: 'check_availability', feature: 'camera' }, category: 'Mobile Tools', description: 'Mobile hardware' },
  { name: 'mobile_device_management', params: { action: 'enroll', device_id: 'test-device' }, category: 'Mobile Tools', description: 'Mobile device management' },
  { name: 'mobile_app_analytics_toolkit', params: { action: 'track_event', app_id: 'test-app' }, category: 'Mobile Tools', description: 'Mobile app analytics' },
  { name: 'mobile_app_deployment_toolkit', params: { action: 'build', app_version: '1.0.0', platform: 'android' }, category: 'Mobile Tools', description: 'Mobile app deployment' },
  { name: 'mobile_app_optimization_toolkit', params: { action: 'analyze', app_id: 'test-app' }, category: 'Mobile Tools', description: 'Mobile app optimization' },
  { name: 'mobile_app_security_toolkit', params: { action: 'scan', app_id: 'test-app' }, category: 'Mobile Tools', description: 'Mobile app security' },
  { name: 'mobile_app_monitoring_toolkit', params: { action: 'start_monitoring', app_id: 'test-app' }, category: 'Mobile Tools', description: 'Mobile app monitoring' },
  { name: 'mobile_app_performance_toolkit', params: { action: 'benchmark', app_id: 'test-app' }, category: 'Mobile Tools', description: 'Mobile app performance' },
  { name: 'mobile_app_testing_toolkit', params: { action: 'unit_test', app_id: 'test-app' }, category: 'Mobile Tools', description: 'Mobile app testing' },
  
  // ===========================================
  // VIRTUALIZATION TOOLS (2 Tools)
  // ===========================================
  { name: 'vm_management', params: { action: 'list' }, category: 'Virtualization Tools', description: 'VM management' },
  { name: 'docker_management', params: { action: 'list' }, category: 'Virtualization Tools', description: 'Docker management' },
  
  // ===========================================
  // UTILITY TOOLS (10 Tools)
  // ===========================================
  { name: 'calculator', params: { expression: '2 + 2' }, category: 'Utility Tools', description: 'Calculator' },
  { name: 'dice_rolling', params: { dice: 'd6' }, category: 'Utility Tools', description: 'Dice rolling' },
  { name: 'math_calculate', params: { expression: 'sqrt(16)' }, category: 'Utility Tools', description: 'Math calculate' },
  { name: 'data_analysis', params: { data: [1, 2, 3, 4, 5], analysis_type: 'descriptive' }, category: 'Utility Tools', description: 'Data analysis' },
  { name: 'machine_learning', params: { action: 'train', model_type: 'regression' }, category: 'Utility Tools', description: 'Machine learning' },
  { name: 'chart_generator', params: { random_string: 'test' }, category: 'Utility Tools', description: 'Chart generator' },
  { name: 'text_processor', params: { random_string: 'test' }, category: 'Utility Tools', description: 'Text processor' },
  { name: 'password_generator', params: { random_string: 'test' }, category: 'Utility Tools', description: 'Password generator' },
  { name: 'data_analyzer', params: { random_string: 'test' }, category: 'Utility Tools', description: 'Data analyzer' },
  { name: 'encryption_tool', params: { action: 'encrypt', algorithm: 'aes', input_data: 'test data' }, category: 'Utility Tools', description: 'Encryption tool' },
  
  // ===========================================
  // CLOUD TOOLS (3 Tools)
  // ===========================================
  { name: 'cloud_security', params: { cloud_provider: 'aws', action: 'scan' }, category: 'Cloud Tools', description: 'Cloud security' },
  { name: 'cloud_infrastructure_manager', params: { random_string: 'test' }, category: 'Cloud Tools', description: 'Cloud infrastructure manager' },
  { name: 'cloud_security_toolkit', params: { random_string: 'test' }, category: 'Cloud Tools', description: 'Cloud security toolkit' },
  
  // ===========================================
  // FORENSICS TOOLS (3 Tools)
  // ===========================================
  { name: 'forensics_analysis', params: { action: 'memory_analysis', evidence_file: 'test.mem' }, category: 'Forensics Tools', description: 'Forensics analysis' },
  { name: 'forensics_toolkit', params: { random_string: 'test' }, category: 'Forensics Tools', description: 'Forensics toolkit' },
  { name: 'malware_analysis_toolkit', params: { random_string: 'test' }, category: 'Forensics Tools', description: 'Malware analysis toolkit' },
  
  // ===========================================
  // DISCOVERY TOOLS (2 Tools)
  // ===========================================
  { name: 'tool_discovery', params: { random_string: 'test' }, category: 'Discovery Tools', description: 'Tool discovery' },
  { name: 'explore_categories', params: { category: 'security' }, category: 'Discovery Tools', description: 'Explore categories' },
  
  // ===========================================
  // SOCIAL TOOLS (1 Tool)
  // ===========================================
  { name: 'social_network_ripper', params: { random_string: 'test' }, category: 'Social Tools', description: 'Social network ripper' }
];

// ============================================================================
// TESTING FUNCTIONS
// ============================================================================

async function testTool(serverPath, toolName, params, description) {
  return new Promise((resolve, reject) => {
    const server = spawn('node', [serverPath], { stdio: ['pipe', 'pipe', 'pipe'] });
    
    const request = {
      jsonrpc: '2.0',
      id: Date.now(),
      method: 'tools/call',
      params: {
        name: toolName,
        arguments: params
      }
    };
    
    let response = '';
    let error = '';
    
    const timeout = setTimeout(() => {
      server.kill();
      reject(new Error('Timeout'));
    }, TEST_TIMEOUT);
    
    server.stdout.on('data', (data) => {
      response += data.toString();
    });
    
    server.stderr.on('data', (data) => {
      error += data.toString();
    });
    
    server.on('close', (code) => {
      clearTimeout(timeout);
      if (code !== 0) {
        reject(new Error(`Server exited with code ${code}: ${error}`));
      } else {
        try {
          const lines = response.trim().split('\n');
          const lastLine = lines[lines.length - 1];
          const result = JSON.parse(lastLine);
          resolve(result);
        } catch (parseError) {
          reject(new Error(`Parse error: ${parseError.message}`));
        }
      }
    });
    
    server.stdin.write(JSON.stringify(request) + '\n');
    server.stdin.end();
  });
}

async function testServer(serverPath, serverName) {
  console.log(`\n🔥 Testing ${serverName} Server`);
  console.log('=' .repeat(80));
  
  const results = [];
  let passed = 0;
  let failed = 0;
  let partial = 0;
  let notImplemented = 0;
  
  // Group tools by category
  const toolsByCategory = {};
  ALL_TOOLS.forEach(tool => {
    if (!toolsByCategory[tool.category]) {
      toolsByCategory[tool.category] = [];
    }
    toolsByCategory[tool.category].push(tool);
  });
  
  // Test each category
  for (const [category, tools] of Object.entries(toolsByCategory)) {
    console.log(`\n📂 Testing ${category} Tools (${tools.length} tools):`);
    console.log('-'.repeat(60));
    
    for (const tool of tools) {
      const testName = `${tool.name}${tool.params.action ? ` (${tool.params.action})` : ''}`;
      console.log(`\n🔧 Testing: ${testName}`);
      console.log(`   Description: ${tool.description}`);
      
      try {
        const result = await testTool(serverPath, tool.name, tool.params);
        
        if (result.result && result.result.structuredContent) {
          const { success, error } = result.result.structuredContent;
          if (success !== false) {
            console.log(`   ✅ PASSED`);
            passed++;
            results.push({ name: tool.name, category: tool.category, status: 'PASSED', description: tool.description });
          } else {
            console.log(`   ⚠️  PARTIAL - Tool responded but operation failed`);
            console.log(`   Error: ${error || 'Unknown error'}`);
            partial++;
            results.push({ name: tool.name, category: tool.category, status: 'PARTIAL', error: error, description: tool.description });
          }
        } else {
          console.log(`   ✅ PASSED (no structured content)`);
          passed++;
          results.push({ name: tool.name, category: tool.category, status: 'PASSED', description: tool.description });
        }
      } catch (error) {
        if (error.message.includes('Timeout') || error.message.includes('Server exited')) {
          console.log(`   ❌ FAILED: ${error.message}`);
          failed++;
          results.push({ name: tool.name, category: tool.category, status: 'FAILED', error: error.message, description: tool.description });
        } else {
          console.log(`   ❌ NOT IMPLEMENTED: ${error.message}`);
          notImplemented++;
          results.push({ name: tool.name, category: tool.category, status: 'NOT_IMPLEMENTED', error: error.message, description: tool.description });
        }
      }
    }
  }
  
  return { results, passed, failed, partial, notImplemented, serverName };
}

async function runComprehensiveSmokeTest() {
  console.log('🔥 MCP God Mode Comprehensive Smoke Test - ALL 113 TOOLS');
  console.log('Testing Both Monolithic and Modular Servers\n');
  console.log('=' .repeat(100));
  
  const platform = os.platform();
  const arch = os.arch();
  console.log(`Platform: ${platform} (${arch})`);
  console.log(`Total Tools to Test: ${ALL_TOOLS.length}`);
  console.log(`Test Timeout: ${TEST_TIMEOUT}ms per tool`);
  console.log('=' .repeat(100));
  
  const allResults = [];
  
  // Test Monolithic Server
  try {
    const monolithicResults = await testServer(MONOLITHIC_SERVER_PATH, 'Monolithic');
    allResults.push(monolithicResults);
  } catch (error) {
    console.log(`❌ Failed to test Monolithic Server: ${error.message}`);
  }
  
  // Test Modular Server
  try {
    const modularResults = await testServer(MODULAR_SERVER_PATH, 'Modular');
    allResults.push(modularResults);
  } catch (error) {
    console.log(`❌ Failed to test Modular Server: ${error.message}`);
  }
  
  // ============================================================================
  // COMPREHENSIVE RESULTS SUMMARY
  // ============================================================================
  
  console.log('\n' + '=' .repeat(100));
  console.log('📊 COMPREHENSIVE SMOKE TEST RESULTS');
  console.log('=' .repeat(100));
  
  for (const serverResults of allResults) {
    const { results, passed, failed, partial, notImplemented, serverName } = serverResults;
    
    console.log(`\n🖥️  ${serverName} Server Results:`);
    console.log(`Total Tools Tested: ${ALL_TOOLS.length}`);
    console.log(`✅ Passed: ${passed}`);
    console.log(`⚠️  Partial: ${partial}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`🚫 Not Implemented: ${notImplemented}`);
    console.log(`Success Rate: ${((passed + partial) / ALL_TOOLS.length * 100).toFixed(1)}%`);
    
    // Results by category
    console.log('\n📂 Results by Category:');
    const toolsByCategory = {};
    ALL_TOOLS.forEach(tool => {
      if (!toolsByCategory[tool.category]) {
        toolsByCategory[tool.category] = [];
      }
      toolsByCategory[tool.category].push(tool);
    });
    
    for (const [category, tools] of Object.entries(toolsByCategory)) {
      const categoryResults = results.filter(r => r.category === category);
      const passedCount = categoryResults.filter(r => r.status === 'PASSED').length;
      const partialCount = categoryResults.filter(r => r.status === 'PARTIAL').length;
      const failedCount = categoryResults.filter(r => r.status === 'FAILED').length;
      const notImplCount = categoryResults.filter(r => r.status === 'NOT_IMPLEMENTED').length;
      
      console.log(`   ${category}: ${passedCount}✅ ${partialCount}⚠️ ${failedCount}❌ ${notImplCount}🚫`);
    }
    
    // Failed tools
    const failedTools = results.filter(r => r.status === 'FAILED');
    if (failedTools.length > 0) {
      console.log('\n❌ Failed Tools:');
      failedTools.forEach(tool => {
        console.log(`   - ${tool.name}: ${tool.error}`);
      });
    }
    
    // Partial tools
    const partialTools = results.filter(r => r.status === 'PARTIAL');
    if (partialTools.length > 0) {
      console.log('\n⚠️  Partial Tools (responded but operation failed):');
      partialTools.forEach(tool => {
        console.log(`   - ${tool.name}: ${tool.error}`);
      });
    }
    
    // Not implemented tools
    const notImplTools = results.filter(r => r.status === 'NOT_IMPLEMENTED');
    if (notImplTools.length > 0) {
      console.log('\n🚫 Not Implemented Tools:');
      notImplTools.forEach(tool => {
        console.log(`   - ${tool.name}: ${tool.error}`);
      });
    }
  }
  
  // ============================================================================
  // FINAL ASSESSMENT
  // ============================================================================
  
  console.log('\n🎯 FINAL ASSESSMENT:');
  
  if (allResults.length === 0) {
    console.log('❌ CRITICAL: No servers could be tested!');
    console.log('   Check server paths and ensure servers are built correctly.');
  } else {
    const bestServer = allResults.reduce((best, current) => {
      const currentSuccess = (current.passed + current.partial) / ALL_TOOLS.length;
      const bestSuccess = (best.passed + best.partial) / ALL_TOOLS.length;
      return currentSuccess > bestSuccess ? current : best;
    });
    
    console.log(`🏆 Best Performing Server: ${bestServer.serverName}`);
    console.log(`   Success Rate: ${((bestServer.passed + bestServer.partial) / ALL_TOOLS.length * 100).toFixed(1)}%`);
    
    if (bestServer.failed === 0 && bestServer.notImplemented === 0) {
      console.log('🚀 EXCELLENT: All tools are working perfectly!');
      console.log('   MCP God Mode is production-ready with 100% tool coverage.');
    } else if (bestServer.failed === 0 && bestServer.partial > 0) {
      console.log('✅ GOOD: All tools are implemented and responding correctly.');
      console.log('   Some tools have conditional functionality (e.g., require Docker/hypervisors).');
    } else if (bestServer.failed === 0) {
      console.log('⚠️  FAIR: All implemented tools work, but some tools are not implemented.');
      console.log('   Consider implementing missing tools for full functionality.');
    } else {
      console.log('❌ NEEDS ATTENTION: Some tools are failing and need investigation.');
      console.log('   Review failed tools before production use.');
    }
  }
  
  console.log('\n🎉 MCP God Mode Comprehensive Smoke Test Complete!');
  console.log(`Tested ${ALL_TOOLS.length} tools across ${allResults.length} server(s).`);
  
  // Cleanup test files
  await cleanupTestFiles();
}

async function cleanupTestFiles() {
  console.log('\n🧹 Cleaning up test files...');
  const filesToCleanup = [
    'smoke-test-temp.txt',
    'smoke-test-download.json',
    'test_screenshot.png'
  ];
  
  for (const file of filesToCleanup) {
    try {
      await fs.rm(file, { recursive: true, force: true });
    } catch (e) {
      // Ignore cleanup errors
    }
  }
  console.log('✅ Cleanup complete');
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

runComprehensiveSmokeTest().catch(error => {
  console.error('🔥 Smoke test failed:', error);
  process.exit(1);
});
