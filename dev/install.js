#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Server configurations with accurate tool counts and descriptions
const SERVER_CONFIGS = {
  'ultra-minimal': {
    name: 'Ultra-Minimal Server',
    description: 'Essential tools only - perfect for embedded systems and resource-constrained environments',
    tools: 15,
    features: [
      'Core system operations (health, system_info)',
      'Basic file operations (fs_list, fs_read_text, fs_write_text)',
      'Process management (proc_run)',
      'Mobile device support (file_ops, system_tools, hardware)',
      'Web tools (scraper, browser control)',
      'System restore capabilities',
      'Email tools (send_email, parse_email)',
      'Dice rolling utility'
    ],
    useCase: 'Embedded systems, IoT devices, minimal deployments',
    size: 'Small, lightweight'
  },
  'minimal': {
    name: 'Minimal Server',
    description: 'Core system administration tools - balanced functionality for production use',
    tools: 25,
    features: [
      'All ultra-minimal features',
      'Advanced file operations (fs_search, download_file)',
      'Enhanced mobile support',
      'Additional web capabilities',
      'Extended system restore features',
      'Git integration',
      'Calculator functionality',
      'Dice rolling utility'
    ],
    useCase: 'Basic system administration, lightweight deployments',
    size: 'Medium, focused'
  },
  'full': {
    name: 'Full-Featured Server',
    description: 'Complete MCP God Mode with all tools and capabilities including comprehensive penetration testing tools, audio editing, video editing with recording, and screenshot capabilities',
    tools: 55,
    features: [
      'All minimal features',
      'Complete Wi-Fi security toolkit (25+ actions)',
      'Complete Bluetooth security toolkit (30+ actions)',
      'Complete SDR security toolkit (56+ actions)',
      'Advanced mobile platform tools (29 tools)',
      'Natural language interface for all tools',
      'Comprehensive security testing capabilities',
      'Advanced email management (9 email tools)',
      'Network diagnostics and penetration testing',
      'Virtual machine and Docker management',
      'Advanced mathematics and calculations',
      'Dice rolling utility',
      'Port scanner tool for network reconnaissance',
      'Vulnerability scanner for security assessment',
      'Password cracker for authentication testing',
      'Exploit framework for vulnerability testing',
      'Packet sniffer for network analysis',
      'Audio editing tool with recording capabilities (25+ actions)',
      'Video editing tool with recording capabilities (16+ actions)',
      'Screenshot tool for window and screen capture (9+ actions)',
      'Image editing tool with comprehensive manipulation capabilities (30+ actions)'
    ],
    useCase: 'Power users, security professionals, developers, penetration testers, media creators',
    size: 'Large, comprehensive with media capabilities'
  },
  'modular': {
    name: 'Modular Server',
    description: 'Complete modular server with all 67 tools including comprehensive penetration testing, media processing, cloud security, and forensics capabilities',
    tools: 67,
    features: [
      'Core system tools (health, system_info)',
      'File system operations (fs_list, fs_read_text, fs_write_text, fs_search, file_ops)',
      'Process management (proc_run, proc_run_elevated)',
      'System tools (system_restore, elevated_permissions_manager)',
      'Git integration (git_status)',
      'Windows tools (win_services, win_processes)',
      'Network tools (packet_sniffer, port_scanner, network_diagnostics, download_file)',
      'Security tools (vulnerability_scanner, password_cracker, exploit_framework, network_security, blockchain_security, quantum_security, iot_security, social_engineering, threat_intelligence, compliance_assessment, malware_analysis)',
      'Penetration tools (hack_network, security_testing, network_penetration)',
      'Wireless tools (wifi_security_toolkit, wifi_hacking, wireless_security)',
      'Bluetooth tools (bluetooth_security_toolkit, bluetooth_hacking)',
      'Radio tools (sdr_security_toolkit, radio_security, signal_analysis)',
      'Web tools (web_scraper, browser_control)',
      'Email tools (send_email, read_emails, parse_email, delete_emails, sort_emails, manage_email_accounts)',
      'Media tools (video_editing, ocr_tool, image_editing, audio_editing)',
      'Screenshot tools (screenshot)',
      'Mobile tools (mobile_device_info, mobile_file_ops, mobile_system_tools, mobile_hardware)',
      'Virtualization tools (vm_management, docker_management)',
      'Utility tools (calculator, dice_rolling, math_calculate, data_analysis, machine_learning)',
      'Cloud tools (cloud_security)',
      'Forensics tools (forensics_analysis)',
      'Modular architecture for easy customization and maintenance',
      'Comprehensive security testing and media processing capabilities'
    ],
    useCase: 'Professional security testing, comprehensive system administration, media creation, development testing, enterprise deployments',
    size: 'Large, comprehensive with modular architecture'
  },
  'custom': {
    name: 'Custom Server',
    description: 'Build your own server with only the tools you need',
    tools: 'Variable',
    features: [
      'Choose from available tool modules',
      'Mix and match functionality',
      'Optimize for specific use cases',
      'Reduce resource usage',
      'Customize for deployment needs',
      'Include dice tool and other utilities as needed'
    ],
    useCase: 'Specific requirements, specialized deployments',
    size: 'Variable, tailored'
  }
};

function displayBanner() {
  console.log('\n🤖 MCP God Mode - Interactive Installer');
  console.log('=========================================\n');
}

function displayServerOptions() {
  console.log('Available Server Versions:\n');
  
  Object.entries(SERVER_CONFIGS).forEach(([key, config]) => {
    console.log(`🔹 ${config.name.toUpperCase()}`);
    console.log(`   Tools: ${config.tools}`);
    console.log(`   Size: ${config.size}`);
    console.log(`   Use Case: ${config.useCase}`);
    console.log(`   Description: ${config.description}`);
    console.log('');
  });
}

function getServerChoice() {
  const readline = require('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    rl.question('Which server version would you like to install? (ultra-minimal/minimal/full/modular/custom): ', (answer) => {
      rl.close();
      resolve(answer.toLowerCase().trim());
    });
  });
}

function displayServerDetails(choice) {
  const config = SERVER_CONFIGS[choice];
  if (!config) return;

  console.log(`\n📋 ${config.name.toUpperCase()} - DETAILED INFORMATION`);
  console.log('='.repeat(50));
  console.log(`🛠️  Total Tools: ${config.tools}`);
  console.log(`📦 Size: ${config.size}`);
  console.log(`🎯 Use Case: ${config.useCase}`);
  console.log(`📝 Description: ${config.description}`);
  console.log('\n🚀 Key Features:');
  config.features.forEach((feature, index) => {
    console.log(`   ${index + 1}. ${feature}`);
  });
  console.log('');
}

function confirmInstallation(choice) {
  const readline = require('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    rl.question(`Are you sure you want to install the ${SERVER_CONFIGS[choice].name}? (yes/no): `, (answer) => {
      rl.close();
      resolve(answer.toLowerCase().trim() === 'yes' || answer.toLowerCase().trim() === 'y');
    });
  });
}

function installServer(choice) {
  console.log(`\n🚀 Installing ${SERVER_CONFIGS[choice].name}...\n`);
  
  try {
    if (choice === 'custom') {
      console.log('For custom server installation, please use:');
      console.log('  node build-server.js <tool1> <tool2> ...');
      console.log('\nExample:');
      console.log('  node build-server.js health system_info send_email parse_email');
      return;
    }
    
    if (choice === 'modular') {
      console.log('For modular server installation, please use:');
      console.log('  npm run build:modular');
      console.log('\nOr manually:');
      console.log('  cd dev && npm run build:modular');
      console.log('\nThe modular server includes all 67 tools:');
      console.log('  - Core system tools (health, system_info)');
      console.log('  - File system operations (fs_list, fs_read_text, fs_write_text, fs_search, file_ops)');
      console.log('  - Security tools (vulnerability_scanner, password_cracker, exploit_framework, etc.)');
      console.log('  - Media tools (video_editing, image_editing, audio_editing, ocr_tool)');
      console.log('  - Network tools (packet_sniffer, port_scanner, network_diagnostics)');
      console.log('  - And many more specialized tools...');
      return;
    }
    
    // Install dependencies
    console.log('📦 Installing dependencies...');
    execSync('npm install', { stdio: 'inherit' });
    
    // Build the server
    console.log('🔨 Building server...');
    execSync('npm run build', { stdio: 'inherit' });
    
    console.log(`\n✅ ${SERVER_CONFIGS[choice].name} installed successfully!`);
    console.log('\nTo start the server, run:');
    console.log('  npm start');
    
  } catch (error) {
    console.error('\n❌ Installation failed:', error.message);
    console.log('\nPlease check the error and try again.');
  }
}

async function main() {
  try {
    displayBanner();
    displayServerOptions();
    
    const choice = await getServerChoice();
    
    if (!SERVER_CONFIGS[choice]) {
      console.log('❌ Invalid choice. Please select a valid server version.');
      return;
    }
    
    displayServerDetails(choice);
    
    const confirmed = await confirmInstallation(choice);
    if (!confirmed) {
      console.log('❌ Installation cancelled.');
      return;
    }
    
    installServer(choice);
    
  } catch (error) {
    console.error('❌ An error occurred:', error.message);
  }
}

// Handle command line arguments
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log('\nMCP God Mode Installer - Help');
  console.log('==============================');
  console.log('\nUsage:');
  console.log('  node install.js                    # Interactive installer');
  console.log('  node install.js --help             # Show this help');
  console.log('  node install.js --version          # Show version info');
  console.log('\nAvailable server versions:');
  Object.keys(SERVER_CONFIGS).forEach(key => {
    console.log(`  - ${key}`);
  });
  process.exit(0);
}

if (process.argv.includes('--version') || process.argv.includes('-v')) {
  console.log('MCP God Mode Installer v1.4a');
  process.exit(0);
}

// Run the installer
main();
