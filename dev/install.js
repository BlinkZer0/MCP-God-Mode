#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// Tool categories with accurate counts and descriptions
const TOOL_CATEGORIES = {
  'core': {
    name: 'Core System Tools',
    description: 'Essential system monitoring and health check tools',
    tools: 2,
    toolList: ['health', 'system_info'],
    features: [
      'System health monitoring',
      'Basic system information retrieval',
      'Essential for all server operations'
    ]
  },
  'filesystem': {
    name: 'File System Tools',
    description: 'Complete file and directory management capabilities',
    tools: 6,
    toolList: ['fs_list', 'fs_read_text', 'fs_write_text', 'fs_search', 'file_ops', 'file_watcher'],
    features: [
      'Directory listing and navigation',
      'Text file reading and writing',
      'File search and discovery',
      'Advanced file operations',
      'Real-time file system monitoring'
    ]
  },
  'process': {
    name: 'Process Management',
    description: 'Process execution and management tools',
    tools: 2,
    toolList: ['proc_run', 'proc_run_elevated'],
    features: [
      'Execute system commands',
      'Run processes with elevated privileges',
      'Cross-platform process management'
    ]
  },
  'system': {
    name: 'System Administration',
    description: 'Advanced system management and monitoring',
    tools: 4,
    toolList: ['system_restore', 'elevated_permissions_manager', 'cron_job_manager', 'system_monitor'],
    features: [
      'System restore point management',
      'Elevated permissions handling',
      'Scheduled task management',
      'System performance monitoring'
    ]
  },
  'git': {
    name: 'Git Integration',
    description: 'Version control and repository management',
    tools: 1,
    toolList: ['git_status'],
    features: [
      'Git repository status checking',
      'Version control integration'
    ]
  },
  'windows': {
    name: 'Windows Tools',
    description: 'Windows-specific system management',
    tools: 2,
    toolList: ['win_services', 'win_processes'],
    features: [
      'Windows service management',
      'Windows process control',
      'Windows-specific operations'
    ]
  },
  'network': {
    name: 'Network Tools',
    description: 'Comprehensive network analysis and reconnaissance',
    tools: 14,
    toolList: ['packet_sniffer', 'port_scanner', 'network_diagnostics', 'download_file', 'network_traffic_analyzer', 'ip_geolocation', 'network_triangulation', 'osint_reconnaissance', 'latency_geolocation', 'network_discovery', 'vulnerability_assessment', 'traffic_analysis', 'network_utilities', 'social_account_ripper', 'social_account_ripper_modular'],
    features: [
      'Network packet analysis',
      'Port scanning and discovery',
      'IP geolocation and triangulation',
      'OSINT reconnaissance',
      'Network vulnerability assessment',
      'Traffic analysis and monitoring',
      'Social media account discovery',
      'Modular social account ripper'
    ]
  },
  'security': {
    name: 'Security Tools',
    description: 'Advanced security testing and assessment',
    tools: 12,
    toolList: ['vulnerability_scanner', 'password_cracker', 'exploit_framework', 'network_security', 'blockchain_security', 'quantum_security', 'iot_security', 'social_engineering', 'threat_intelligence', 'compliance_assessment', 'social_network_ripper', 'metadata_extractor', 'encryption_tool', 'malware_analysis', 'social_network_ripper'],
    features: [
      'Vulnerability scanning and assessment',
      'Password cracking and analysis',
      'Exploit development framework',
      'Blockchain and quantum security',
      'IoT device security testing',
      'Social engineering assessment',
      'Threat intelligence gathering',
      'Compliance framework assessment',
      'Metadata extraction and analysis',
      'Encryption and cryptographic operations',
      'Malware analysis and detection',
      'Social network ripper (duplicate entry)'
    ]
  },
  'penetration': {
    name: 'Penetration Testing',
    description: 'Comprehensive penetration testing framework',
    tools: 5,
    toolList: ['hack_network', 'security_testing', 'network_penetration', 'penetration_testing_toolkit', 'social_engineering_toolkit'],
    features: [
      'Network penetration testing',
      'Comprehensive security testing',
      'Advanced attack simulation',
      'Penetration testing toolkit',
      'Social engineering toolkit'
    ]
  },
  'wireless': {
    name: 'Wireless Security',
    description: 'Wi-Fi and wireless network security tools',
    tools: 4,
    toolList: ['wifi_security_toolkit', 'wifi_hacking', 'wireless_security', 'wireless_network_scanner'],
    features: [
      'Wi-Fi security assessment',
      'Wireless network penetration testing',
      'Wireless network scanning',
      'Wireless security analysis'
    ]
  },
  'bluetooth': {
    name: 'Bluetooth Security',
    description: 'Bluetooth device security and management',
    tools: 3,
    toolList: ['bluetooth_security_toolkit', 'bluetooth_hacking', 'bluetooth_device_manager'],
    features: [
      'Bluetooth security assessment',
      'Bluetooth device penetration testing',
      'Bluetooth device management'
    ]
  },
  'radio': {
    name: 'Radio & SDR',
    description: 'Software Defined Radio and signal analysis',
    tools: 3,
    toolList: ['sdr_security_toolkit', 'radio_security', 'signal_analysis'],
    features: [
      'Software Defined Radio security',
      'Radio frequency analysis',
      'Signal processing and analysis'
    ]
  },
  'web': {
    name: 'Web Tools',
    description: 'Web automation, scraping, and browser control',
    tools: 7,
    toolList: ['web_scraper', 'browser_control', 'web_automation', 'webhook_manager'],
    features: [
      'Web page scraping and data extraction',
      'Browser automation and control',
      'Webhook management and testing',
      'Web application testing'
    ]
  },
  'email': {
    name: 'Email Management',
    description: 'Complete email handling and management',
    tools: 6,
    toolList: ['send_email', 'read_emails', 'parse_email', 'delete_emails', 'sort_emails', 'manage_email_accounts'],
    features: [
      'Email sending and receiving',
      'Email parsing and analysis',
      'Email account management',
      'Email organization and sorting'
    ]
  },
  'media': {
    name: 'Media Processing',
    description: 'Video, image, and audio editing capabilities',
    tools: 4,
    toolList: ['video_editing', 'ocr_tool', 'image_editing', 'audio_editing'],
    features: [
      'Video editing and processing',
      'Optical Character Recognition (OCR)',
      'Image editing and manipulation',
      'Audio editing and processing'
    ]
  },
  'screenshot': {
    name: 'Screenshot Tools',
    description: 'Screen capture and screenshot capabilities',
    tools: 1,
    toolList: ['screenshot'],
    features: [
      'Screen capture functionality',
      'Window and region screenshot',
      'Cross-platform screenshot support'
    ]
  },
  'mobile': {
    name: 'Mobile Tools',
    description: 'Comprehensive mobile device management and app development',
    tools: 12,
    toolList: ['mobile_device_info', 'mobile_file_ops', 'mobile_system_tools', 'mobile_hardware', 'mobile_device_management', 'mobile_app_analytics_toolkit', 'mobile_app_deployment_toolkit', 'mobile_app_optimization_toolkit', 'mobile_app_security_toolkit', 'mobile_app_monitoring_toolkit', 'mobile_app_performance_toolkit', 'mobile_app_testing_toolkit', 'mobile_network_analyzer'],
    features: [
      'Mobile device information and management',
      'Mobile file operations',
      'Mobile app analytics and monitoring',
      'Mobile app deployment and optimization',
      'Mobile app security testing',
      'Mobile app performance analysis',
      'Mobile network analysis'
    ]
  },
  'virtualization': {
    name: 'Virtualization',
    description: 'Virtual machine and container management',
    tools: 2,
    toolList: ['vm_management', 'docker_management'],
    features: [
      'Virtual machine management',
      'Docker container management',
      'Virtualization platform support'
    ]
  },
  'utilities': {
    name: 'Utility Tools',
    description: 'Mathematical, data analysis, and utility functions',
    tools: 10,
    toolList: ['calculator', 'dice_rolling', 'math_calculate', 'data_analysis', 'machine_learning', 'chart_generator', 'text_processor', 'password_generator', 'data_analyzer'],
    features: [
      'Mathematical calculations',
      'Data analysis and processing',
      'Machine learning capabilities',
      'Chart and visualization generation',
      'Text processing and analysis',
      'Password generation',
      'Dice rolling (essential for any toolkit! 🎲)'
    ]
  },
  'cloud': {
    name: 'Cloud Security',
    description: 'Cloud infrastructure security and management',
    tools: 3,
    toolList: ['cloud_security', 'cloud_infrastructure_manager', 'cloud_security_toolkit'],
    features: [
      'Cloud security assessment',
      'Cloud infrastructure management',
      'Multi-cloud platform support',
      'Cloud security toolkit'
    ]
  },
  'forensics': {
    name: 'Digital Forensics',
    description: 'Digital forensics and malware analysis',
    tools: 3,
    toolList: ['forensics_analysis', 'forensics_toolkit', 'malware_analysis_toolkit'],
    features: [
      'Digital forensics analysis',
      'Malware analysis and detection',
      'Evidence collection and analysis'
    ]
  },
  'discovery': {
    name: 'Tool Discovery',
    description: 'Tool discovery and category exploration',
    tools: 2,
    toolList: ['tool_discovery', 'explore_categories'],
    features: [
      'Tool discovery and listing',
      'Category exploration',
      'Tool information retrieval'
    ]
  },
  'social': {
    name: 'Social Tools',
    description: 'Social media and social network tools',
    tools: 1,
    toolList: ['social_network_ripper'],
    features: [
      'Social network account discovery',
      'Social media OSINT operations',
      'Social network analysis'
    ]
  }
};

// Server configurations with accurate tool counts and descriptions
const SERVER_CONFIGS = {
  'ultra-minimal': {
    name: 'Ultra-Minimal Server',
    description: 'Essential tools only - perfect for embedded systems and resource-constrained environments',
    tools: 20,
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
    tools: 40,
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
    name: 'Full-Featured Server (Monolithic)',
    description: 'Complete MCP God Mode with all 113 tools including comprehensive penetration testing, network reconnaissance, metadata extraction, and security testing capabilities',
    tools: 113,
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
    description: 'Complete modular server with all 119 tools including comprehensive penetration testing, network reconnaissance, metadata extraction, and security testing capabilities',
    tools: 119,
    features: [
      'Core system tools (health, system_info)',
      'File system operations (fs_list, fs_read_text, fs_write_text, fs_search, file_ops)',
      'Process management (proc_run, proc_run_elevated)',
      'System tools (system_restore, elevated_permissions_manager, cron_job_manager, system_monitor)',
      'Git integration (git_status)',
      'Windows tools (win_services, win_processes)',
      'Network tools (packet_sniffer, port_scanner, network_diagnostics, download_file, network_traffic_analyzer, ip_geolocation, network_triangulation, osint_reconnaissance, latency_geolocation, network_discovery, vulnerability_assessment, traffic_analysis, network_utilities)',
      'Security tools (vulnerability_scanner, password_cracker, exploit_framework, network_security, blockchain_security, quantum_security, iot_security, social_engineering, threat_intelligence, compliance_assessment, social_network_ripper, metadata_extractor, malware_analysis)',
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
  console.log('📊 Server Architecture Information:');
  console.log('   • Server-Refactored: 113 tools (unified, production-ready)');
  console.log('   • Modular Server: 119 tools (granular, development-friendly)');
  console.log('   • Tool count difference: Modular breaks complex tools into specialized functions');
  console.log('   • Legal Compliance: Built-in audit logging, evidence preservation, and forensic readiness\n');
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

function displayToolCategories() {
  console.log('\n📋 Available Tool Categories:\n');
  
  Object.entries(TOOL_CATEGORIES).forEach(([key, category]) => {
    console.log(`🔹 ${category.name.toUpperCase()}`);
    console.log(`   Tools: ${category.tools}`);
    console.log(`   Description: ${category.description}`);
    console.log(`   Key Features:`);
    category.features.forEach((feature, index) => {
      console.log(`     ${index + 1}. ${feature}`);
    });
    console.log('');
  });
}

function getToolSelection() {
  const readline = require('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    displayToolCategories();
    
    console.log('🎯 Tool Selection Options:');
    console.log('  - Type "all" to select all categories');
    console.log('  - Type category names separated by commas (e.g., "core,filesystem,network")');
    console.log('  - Type "essential" for core system tools only');
    console.log('  - Type "security" for security-focused tools');
    console.log('  - Type "media" for media processing tools');
    console.log('  - Type "mobile" for mobile development tools');
    console.log('');
    
    rl.question('Which tool categories would you like to include? ', (answer) => {
      rl.close();
      resolve(answer.toLowerCase().trim());
    });
  });
}

function parseToolSelection(selection) {
  const selectedCategories = new Set();
  const allCategories = Object.keys(TOOL_CATEGORIES);
  
  if (selection === 'all') {
    allCategories.forEach(cat => selectedCategories.add(cat));
  } else if (selection === 'essential') {
    ['core', 'filesystem', 'process', 'system'].forEach(cat => selectedCategories.add(cat));
  } else if (selection === 'security') {
    ['core', 'filesystem', 'process', 'network', 'security', 'penetration', 'wireless', 'bluetooth', 'radio'].forEach(cat => selectedCategories.add(cat));
  } else if (selection === 'media') {
    ['core', 'filesystem', 'process', 'media', 'web', 'utilities'].forEach(cat => selectedCategories.add(cat));
  } else if (selection === 'mobile') {
    ['core', 'filesystem', 'process', 'mobile', 'web', 'utilities'].forEach(cat => selectedCategories.add(cat));
  } else {
    // Parse comma-separated categories
    const categories = selection.split(',').map(cat => cat.trim());
    categories.forEach(cat => {
      if (allCategories.includes(cat)) {
        selectedCategories.add(cat);
      } else {
        console.log(`⚠️  Warning: Unknown category "${cat}" - skipping`);
      }
    });
  }
  
  return Array.from(selectedCategories);
}

function displaySelectedTools(selectedCategories) {
  console.log('\n📊 Selected Tool Configuration:');
  console.log('='.repeat(50));
  
  let totalTools = 0;
  const selectedTools = [];
  
  selectedCategories.forEach(categoryKey => {
    const category = TOOL_CATEGORIES[categoryKey];
    console.log(`\n🔹 ${category.name}`);
    console.log(`   Tools: ${category.tools}`);
    console.log(`   Description: ${category.description}`);
    totalTools += category.tools;
    selectedTools.push(...category.toolList);
  });
  
  console.log(`\n📈 Summary:`);
  console.log(`   Total Categories: ${selectedCategories.length}`);
  console.log(`   Total Tools: ${totalTools}`);
  console.log(`   Selected Categories: ${selectedCategories.join(', ')}`);
  
  return { totalTools, selectedTools };
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

async function installServer(choice) {
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
      console.log('🔧 Modular Server - Custom Tool Selection');
      console.log('==========================================');
      
      try {
        // Get tool selection from user
        const toolSelection = await getToolSelection();
        const selectedCategories = parseToolSelection(toolSelection);
        
        if (selectedCategories.length === 0) {
          console.log('❌ No valid categories selected. Please try again.');
          return;
        }
        
        // Display selected configuration
        const { totalTools, selectedTools } = displaySelectedTools(selectedCategories);
        
        // Confirm installation
        const readline = require('readline');
        const rl = readline.createInterface({
          input: process.stdin,
          output: process.stdout
        });
        
        const confirmed = await new Promise((resolve) => {
          rl.question(`\nDo you want to proceed with this configuration? (yes/no): `, (answer) => {
            rl.close();
            resolve(answer.toLowerCase().trim() === 'yes' || answer.toLowerCase().trim() === 'y');
          });
        });
        
        if (!confirmed) {
          console.log('❌ Installation cancelled.');
          return;
        }
        
        // Generate build command
        console.log('\n🚀 Building Modular Server with Selected Tools...');
        console.log(`📊 Configuration: ${totalTools} tools across ${selectedCategories.length} categories`);
        
        // Create build command
        const buildCommand = `node build-server.js ${selectedTools.join(' ')}`;
        console.log(`\n🔨 Build Command: ${buildCommand}`);
        
        // Execute build
        console.log('\n📦 Building server...');
        execSync(buildCommand, { stdio: 'inherit', cwd: 'dev' });
        
        console.log(`\n✅ Modular server built successfully with ${totalTools} tools!`);
        console.log('\nTo start the server, run:');
        console.log('  cd dev && npm start');
        
        console.log('\n🎭 Fun Fact: Your custom modular server is like a perfectly tailored suit!');
        console.log('   It fits your needs exactly - no more, no less! 👔✨');
        
      } catch (error) {
        console.error('\n❌ Modular server build failed:', error.message);
        console.log('\nPlease check the error and try again.');
        console.log('🎭 Remember: Even the best tools need proper configuration! 🔧');
      }
      return;
    }
    
    if (choice === 'full') {
      console.log('For full server installation, please use:');
      console.log('  cd dev && npm run build');
      console.log('\nThe full server includes all 113 tools:');
      console.log('  - Core functionality with 113 tools (6 fewer than modular)');
      console.log('  - Including comprehensive network reconnaissance tools');
      console.log('  - Advanced metadata extraction capabilities');
      console.log('  - Social network ripper for OSINT operations');
      console.log('  - Enhanced security testing and penetration tools');
      console.log('  - Legal compliance and forensic readiness capabilities');
      console.log('\n🎭 Fun Fact: This server is so powerful, it could probably hack the Matrix!');
      console.log('   Neo would be proud (and maybe a little intimidated) 🕶️💻');
      console.log('\n⚖️ Legal Compliance Setup:');
      console.log('   To enable legal compliance features, copy and configure:');
      console.log('   cp dev/legal-compliance.env.template .env');
      console.log('   See docs/LEGAL_COMPLIANCE.md for detailed configuration');
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
    
    await installServer(choice);
    
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
  console.log('MCP God Mode Installer v1.6');
  console.log('🎭 "Version numbers are like jokes - they\'re better when they\'re current!" 🎲');
  process.exit(0);
}

// Run the installer
main();
