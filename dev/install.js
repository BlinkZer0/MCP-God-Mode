#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

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
    name: 'Full-Featured Server (Refactored)',
    description: 'Complete MCP God Mode with all 99 tools including comprehensive penetration testing, audio editing, video editing with recording, and screenshot capabilities',
    tools: 99,
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
      'Dice rolling utility (because even gods need to roll dice 🎲)',
      'Port scanner tool for network reconnaissance',
      'Vulnerability scanner for security assessment',
      'Password cracker for authentication testing',
      'Exploit framework for vulnerability testing',
      'Packet sniffer for network analysis',
      'Audio editing tool with recording capabilities (25+ actions)',
      'Video editing tool with recording capabilities (16+ actions)',
      'Screenshot tool for window and screen capture (9+ actions)',
      'Image editing tool with comprehensive manipulation capabilities (30+ actions)',
      'Enhanced mobile app toolkits (analytics, deployment, optimization, security, monitoring, performance, testing)',
      'Advanced utility tools (chart generation, text processing, password generation)',
      'Cloud infrastructure management',
      'Enhanced penetration testing toolkits',
      'Advanced wireless network scanning capabilities'
    ],
    useCase: 'Power users, security professionals, developers, penetration testers, media creators, and anyone who wants to feel like a cybersecurity deity',
    size: 'Massive, comprehensive with media capabilities and enough tools to make any sysadmin weep tears of joy'
  },
  'modular': {
    name: 'Modular Server',
    description: 'Complete modular server with all 96 tools including comprehensive penetration testing, media processing, cloud security, and forensics capabilities',
    tools: 96,
    features: [
      'Core system tools (health, system_info)',
      'File system operations (fs_list, fs_read_text, fs_write_text, fs_search, file_ops)',
      'Process management (proc_run, proc_run_elevated)',
      'System tools (system_restore, elevated_permissions_manager, cron_job_manager, system_monitor)',
      'Git integration (git_status)',
      'Windows tools (win_services, win_processes)',
      'Network tools (packet_sniffer, port_scanner, network_diagnostics, download_file, network_traffic_analyzer)',
      'Security tools (vulnerability_scanner, password_cracker, exploit_framework, network_security, blockchain_security, quantum_security, iot_security, social_engineering, threat_intelligence, compliance_assessment, malware_analysis)',
      'Penetration tools (hack_network, security_testing, network_penetration, penetration_testing_toolkit, social_engineering_toolkit)',
      'Wireless tools (wifi_security_toolkit, wifi_hacking, wireless_security, wireless_network_scanner)',
      'Bluetooth tools (bluetooth_security_toolkit, bluetooth_hacking, bluetooth_device_manager)',
      'Radio tools (sdr_security_toolkit, radio_security, signal_analysis)',
      'Web tools (web_scraper, browser_control, web_automation, webhook_manager)',
      'Email tools (send_email, read_emails, parse_email, delete_emails, sort_emails, manage_email_accounts)',
      'Media tools (video_editing, ocr_tool, image_editing, audio_editing)',
      'Screenshot tools (screenshot)',
      'Mobile tools (mobile_device_info, mobile_file_ops, mobile_system_tools, mobile_hardware, mobile_device_management, mobile_app_analytics_toolkit, mobile_app_deployment_toolkit, mobile_app_optimization_toolkit, mobile_app_security_toolkit, mobile_app_monitoring_toolkit, mobile_app_performance_toolkit, mobile_app_testing_toolkit, mobile_network_analyzer)',
      'Virtualization tools (vm_management, docker_management)',
      'Utility tools (calculator, dice_rolling, math_calculate, data_analysis, machine_learning, encryption_tool, chart_generator, text_processor, password_generator, data_analyzer, download_file)',
      'Cloud tools (cloud_security, cloud_infrastructure_manager, cloud_security_toolkit)',
      'Forensics tools (forensics_analysis, forensics_toolkit, malware_analysis_toolkit)',
      'Modular architecture for easy customization and maintenance',
      'Comprehensive security testing and media processing capabilities',
      'File watcher and monitoring capabilities',
      'Advanced chart generation and text processing',
      'Professional password generation (because "password123" is not secure, even for gods)'
    ],
    useCase: 'Professional security testing, comprehensive system administration, media creation, development testing, enterprise deployments, and anyone who appreciates a well-organized toolkit',
    size: 'Large, comprehensive with modular architecture and enough tools to make any penetration tester smile'
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
      'Include dice tool and other utilities as needed (dice rolling is mandatory - it\'s the law around here! 🎲)'
    ],
    useCase: 'Specific requirements, specialized deployments, and control freaks who want everything their way',
    size: 'Variable, tailored to your specific needs (or whims)'
  }
};

function displayBanner() {
  console.log('\n🤖 MCP God Mode - Interactive Installer');
  console.log('=========================================\n');
  console.log('🎲 "With great power comes great responsibility... and the ability to roll dice!" 🎲\n');
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
  
  if (choice === 'full') {
    console.log('🎭 Fun Fact: This server has so many tools, even the tools have tools!');
    console.log('   It\'s like having a Swiss Army knife, but the knife has its own Swiss Army knife! 🪛🔪\n');
  } else if (choice === 'modular') {
    console.log('🎭 Fun Fact: This modular server is so organized, Marie Kondo would be proud!');
    console.log('   Every tool sparks joy and has its proper place! ✨📦\n');
  }
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
      console.log('  node build-server.js health system_info send_email parse_email dice_rolling');
      console.log('  (Note: dice_rolling is mandatory - it\'s the law around here! 🎲)');
      return;
    }
    
    if (choice === 'modular') {
      console.log('For modular server installation, please use:');
      console.log('  npm run build:modular');
      console.log('\nOr manually:');
      console.log('  cd dev && npm run build:modular');
      console.log('\nThe modular server includes all 96 tools:');
      console.log('  - Core system tools (health, system_info)');
      console.log('  - File system operations (fs_list, fs_read_text, fs_write_text, fs_search, file_ops)');
      console.log('  - Security tools (vulnerability_scanner, password_cracker, exploit_framework, etc.)');
      console.log('  - Media tools (video_editing, image_editing, audio_editing, ocr_tool)');
      console.log('  - Network tools (packet_sniffer, port_scanner, network_diagnostics)');
      console.log('  - Enhanced mobile toolkits (analytics, deployment, optimization, security, monitoring, performance, testing)');
      console.log('  - Advanced utility tools (chart generation, text processing, password generation, data analyzer)');
      console.log('  - Cloud security toolkits (cloud_security_toolkit, cloud_infrastructure_manager)');
      console.log('  - Forensics toolkits (forensics_toolkit, malware_analysis_toolkit)');
      console.log('  - Penetration testing toolkits (penetration_testing_toolkit, social_engineering_toolkit)');
      console.log('  - Wireless network scanning capabilities');
      console.log('  - And many more specialized tools...');
      console.log('\n🎭 Fun Fact: This modular server is so comprehensive, it\'s like having a cybersecurity buffet!');
      console.log('   You can pick and choose what you want, but why not take it all? 🍽️✨');
      return;
    }
    
    if (choice === 'full') {
      console.log('For full server installation, please use:');
      console.log('  cd dev && npm run build');
      console.log('\nThe full server includes all 99 tools:');
      console.log('  - Everything from the modular server (96 tools)');
      console.log('  - Plus 3 additional enhanced tools');
      console.log('  - Including advanced mobile app toolkits');
      console.log('  - Enhanced utility and cloud tools');
      console.log('  - Advanced penetration testing toolkits');
      console.log('\n🎭 Fun Fact: This server is so powerful, it could probably hack the Matrix!');
      console.log('   Neo would be proud (and maybe a little intimidated) 🕶️💻');
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
    console.log('🎭 Remember: Even the best tools need proper setup - just like a good joke needs proper timing! 😄');
  }
}

async function main() {
  try {
    displayBanner();
    displayServerOptions();
    
    const choice = await getServerChoice();
    
    if (!SERVER_CONFIGS[choice]) {
      console.log('❌ Invalid choice. Please select a valid server version.');
      console.log('🎭 Pro tip: When in doubt, choose "full" - it\'s like ordering the deluxe combo at a restaurant! 🍔');
      return;
    }
    
    displayServerDetails(choice);
    
    const confirmed = await confirmInstallation(choice);
    if (!confirmed) {
      console.log('❌ Installation cancelled.');
      console.log('🎭 No worries! Sometimes the best tools are the ones you don\'t install... said no one ever! 😄');
      return;
    }
    
    installServer(choice);
    
  } catch (error) {
    console.error('❌ An error occurred:', error.message);
    console.log('🎭 Remember: Even the most powerful tools can have hiccups - it\'s what makes them human! 🤖💙');
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
  console.log('\n🎭 Fun Fact: This installer is so user-friendly, even your grandma could use it!');
  console.log('   (Though we don\'t recommend giving your grandma penetration testing tools) 👵🔒');
  process.exit(0);
}

if (process.argv.includes('--version') || process.argv.includes('-v')) {
  console.log('MCP God Mode Installer v1.5');
  console.log('🎭 "Version numbers are like jokes - they\'re better when they\'re current!" 🎲');
  process.exit(0);
}

// Run the installer
main();
