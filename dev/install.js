#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// Import tool configuration system
import { 
  createMinimalConfig, 
  createFullConfig, 
  createConfigFromCategories, 
  saveToolConfig,
  TOOL_CATEGORIES as CONFIG_TOOL_CATEGORIES 
} from './dist/config/tool-config.js';

// Auto-generated tool categories based on actual tools in src/tools/
// Generated on: 2025-09-07T08:28:51.173Z
// Total tools discovered: 117

const TOOL_CATEGORIES = {
  "bluetooth": {
    "name": "Bluetooth Security",
    "description": "Bluetooth device security and management",
    "features": [
      "Bluetooth security testing",
      "Bluetooth penetration testing",
      "Bluetooth device management",
      "Bluetooth vulnerability assessment"
    ],
    "tools": 3,
    "toolList": [
      "bluetooth_device_manager",
      "bluetooth_hacking",
      "bluetooth_security_toolkit"
    ]
  },
  "cloud": {
    "name": "Cloud Security",
    "description": "Cloud infrastructure security and management",
    "features": [
      "Cloud security assessment",
      "Cloud infrastructure management",
      "Multi-cloud security toolkit",
      "Cloud compliance validation"
    ],
    "tools": 3,
    "toolList": [
      "cloud_infrastructure_manager",
      "cloud_security",
      "cloud_security_toolkit"
    ]
  },
  "core": {
    "name": "Core System Tools",
    "description": "Essential system monitoring and health check tools",
    "features": [
      "System health monitoring",
      "Basic system information retrieval",
      "Essential for all server operations"
    ],
    "tools": 2,
    "toolList": [
      "health",
      "system_info"
    ]
  },
  "discovery": {
    "name": "Tool Discovery",
    "description": "Tool discovery and exploration capabilities",
    "features": [
      "Tool discovery and exploration",
      "Category exploration",
      "Tool capability analysis"
    ],
    "tools": 2,
    "toolList": [
      "explore_categories",
      "tool_discovery"
    ]
  },
  "email": {
    "name": "Email Management",
    "description": "Comprehensive email processing and management",
    "features": [
      "Email sending and receiving",
      "Email parsing and analysis",
      "Email account management",
      "Email organization and sorting",
      "Email deletion and cleanup"
    ],
    "tools": 7,
    "toolList": [
      "delete_emails",
      "email_utils",
      "manage_email_accounts",
      "parse_email",
      "read_emails",
      "send_email",
      "sort_emails"
    ]
  },
  "file_system": {
    "name": "File System Tools",
    "description": "Complete file and directory management capabilities",
    "features": [
      "Directory listing and navigation",
      "Text file reading and writing",
      "File search and discovery",
      "Advanced file operations",
      "Real-time file system monitoring"
    ],
    "tools": 6,
    "toolList": [
      "file_ops",
      "file_watcher",
      "fs_list",
      "fs_read_text",
      "fs_search",
      "fs_write_text"
    ]
  },
  "forensics": {
    "name": "Digital Forensics",
    "description": "Digital forensics and incident response",
    "features": [
      "Digital forensics analysis",
      "Evidence collection and preservation",
      "Malware analysis and reverse engineering",
      "Incident response capabilities"
    ],
    "tools": 3,
    "toolList": [
      "forensics_analysis",
      "forensics_toolkit",
      "malware_analysis_toolkit"
    ]
  },
  "git": {
    "name": "Git Integration",
    "description": "Version control and repository management",
    "features": [
      "Git repository status checking",
      "Version control integration"
    ],
    "tools": 1,
    "toolList": [
      "git_status"
    ]
  },
  "legal": {
    "name": "Legal Compliance",
    "description": "Legal compliance and audit management",
    "features": [
      "Legal compliance management",
      "Audit logging and evidence preservation",
      "Chain of custody tracking",
      "Regulatory compliance support"
    ],
    "tools": 1,
    "toolList": [
      "legal_compliance_manager"
    ]
  },
  "media": {
    "name": "Media Processing",
    "description": "Video, image, and audio editing capabilities",
    "features": [
      "Video editing and processing",
      "Optical Character Recognition (OCR)",
      "Image editing and manipulation",
      "Audio editing and processing"
    ],
    "tools": 3,
    "toolList": [
      "image_editing",
      "ocr_tool",
      "video_editing"
    ]
  },
  "mobile": {
    "name": "Mobile Tools",
    "description": "Comprehensive mobile device management and app development",
    "features": [
      "Mobile device information and management",
      "Mobile file operations",
      "Mobile app analytics and monitoring",
      "Mobile app deployment and optimization",
      "Mobile app security testing",
      "Mobile app performance analysis",
      "Mobile network analysis"
    ],
    "tools": 13,
    "toolList": [
      "mobile_app_analytics_toolkit",
      "mobile_app_deployment_toolkit",
      "mobile_app_monitoring_toolkit",
      "mobile_app_optimization_toolkit",
      "mobile_app_performance_toolkit",
      "mobile_app_security_toolkit",
      "mobile_app_testing_toolkit",
      "mobile_device_info",
      "mobile_device_management",
      "mobile_file_ops",
      "mobile_hardware",
      "mobile_network_analyzer",
      "mobile_system_tools"
    ]
  },
  "network": {
    "name": "Network Tools",
    "description": "Comprehensive network analysis and reconnaissance",
    "features": [
      "Network packet analysis",
      "Port scanning and discovery",
      "IP geolocation and triangulation",
      "OSINT reconnaissance",
      "Network vulnerability assessment",
      "Traffic analysis and monitoring",
      "Social media account discovery",
      "Modular social account ripper"
    ],
    "tools": 16,
    "toolList": [
      "download_file",
      "ip_geolocation",
      "latency_geolocation",
      "network_diagnostics",
      "network_discovery",
      "network_penetration",
      "network_traffic_analyzer",
      "network_triangulation",
      "network_utilities",
      "osint_reconnaissance",
      "packet_sniffer",
      "port_scanner",
      "social_account_ripper",
      "social_account_ripper_modular",
      "traffic_analysis",
      "vulnerability_assessment"
    ]
  },
  "penetration": {
    "name": "Penetration Testing",
    "description": "Comprehensive penetration testing and ethical hacking",
    "features": [
      "Network penetration testing",
      "Security assessment tools",
      "Network exploitation",
      "Penetration testing toolkit",
      "Social engineering toolkit"
    ],
    "tools": 5,
    "toolList": [
      "hack_network",
      "network_penetration",
      "penetration_testing_toolkit",
      "security_testing",
      "social_engineering_toolkit"
    ]
  },
  "process": {
    "name": "Process Management",
    "description": "Process execution and management tools",
    "features": [
      "Execute system commands",
      "Run processes with elevated privileges",
      "Cross-platform process management"
    ],
    "tools": 2,
    "toolList": [
      "proc_run",
      "proc_run_elevated"
    ]
  },
  "radio": {
    "name": "Radio & SDR Security",
    "description": "Software Defined Radio and signal analysis",
    "features": [
      "SDR security testing",
      "Radio signal analysis",
      "Signal decoding and analysis",
      "Radio frequency security"
    ],
    "tools": 3,
    "toolList": [
      "radio_security",
      "sdr_security_toolkit",
      "signal_analysis"
    ]
  },
  "security": {
    "name": "Security Tools",
    "description": "Advanced security testing and assessment",
    "features": [
      "Vulnerability scanning and assessment",
      "Password cracking and analysis",
      "Exploit development framework",
      "Network security testing",
      "Blockchain security analysis",
      "Quantum-resistant cryptography",
      "IoT security assessment",
      "Social engineering testing",
      "Threat intelligence gathering",
      "Compliance assessment",
      "Social network reconnaissance",
      "Metadata extraction and analysis",
      "Encryption and cryptographic operations",
      "Malware analysis and reverse engineering"
    ],
    "tools": 16,
    "toolList": [
      "blockchain_security",
      "compliance_assessment",
      "exploit_framework",
      "iot_security",
      "malware_analysis",
      "metadata_extractor",
      "network_security",
      "packet_sniffer",
      "password_cracker",
      "port_scanner",
      "quantum_security",
      "security_testing",
      "social_engineering",
      "social_network_ripper",
      "threat_intelligence",
      "vulnerability_scanner"
    ]
  },
  "social": {
    "tools": 1,
    "toolList": [
      "social_network_ripper"
    ]
  },
  "system": {
    "name": "System Administration",
    "description": "Advanced system management and monitoring",
    "features": [
      "System restore point management",
      "Elevated permissions handling",
      "Scheduled task management",
      "System performance monitoring"
    ],
    "tools": 4,
    "toolList": [
      "cron_job_manager",
      "elevated_permissions_manager",
      "system_monitor",
      "system_restore"
    ]
  },
  "utilities": {
    "name": "Utility Tools",
    "description": "Mathematical, data processing, and utility functions",
    "features": [
      "Mathematical calculations",
      "Data analysis and processing",
      "Chart and graph generation",
      "Text processing utilities",
      "Password generation",
      "Machine learning capabilities",
      "Dice rolling and gaming utilities"
    ],
    "tools": 11,
    "toolList": [
      "calculator",
      "chart_generator",
      "data_analysis",
      "data_analyzer",
      "dice_rolling",
      "download_file",
      "encryption_tool",
      "machine_learning",
      "math_calculate",
      "password_generator",
      "text_processor"
    ]
  },
  "virtualization": {
    "name": "Virtualization",
    "description": "Virtual machine and container management",
    "features": [
      "Virtual machine management",
      "Docker container management",
      "Container orchestration",
      "VM security and monitoring"
    ],
    "tools": 2,
    "toolList": [
      "docker_management",
      "vm_management"
    ]
  },
  "web": {
    "name": "Web Automation",
    "description": "Browser automation and web interaction tools",
    "features": [
      "Web scraping and data extraction",
      "Browser automation and control",
      "Web automation toolkit",
      "Webhook management",
      "Universal browser operations",
      "Web search capabilities",
      "Form completion and validation"
    ],
    "tools": 7,
    "toolList": [
      "browser_control",
      "form_completion",
      "universal_browser_operator",
      "webhook_manager",
      "web_automation",
      "web_scraper",
      "web_search"
    ]
  },
  "windows": {
    "name": "Windows Tools",
    "description": "Windows-specific system management",
    "features": [
      "Windows service management",
      "Windows process control",
      "Windows-specific operations"
    ],
    "tools": 2,
    "toolList": [
      "win_processes",
      "win_services"
    ]
  },
  "wireless": {
    "name": "Wireless Security",
    "description": "Wi-Fi and wireless network security testing",
    "features": [
      "Wi-Fi security assessment",
      "Wi-Fi penetration testing",
      "Wireless security testing",
      "Wireless network scanning",
      "Wireless network analysis"
    ],
    "tools": 4,
    "toolList": [
      "wifi_hacking",
      "wifi_security_toolkit",
      "wireless_network_scanner",
      "wireless_security"
    ]
  }
};

// Server configurations
const SERVER_CONFIGS = {
  'minimal': {
    name: 'Minimal Server',
    description: 'Essential tools for basic functionality',
    tools: 15,
    categories: ['core', 'file_system', 'process'],
    features: [
      'System health monitoring',
      'Basic file operations',
      'Process execution',
      'Essential for all operations'
    ]
  },
  'modular': {
    name: 'Modular Server',
    description: 'All available tools in modular architecture',
    tools: 117,
    categories: Object.keys(TOOL_CATEGORIES),
    features: [
      'Complete tool coverage',
      'Modular architecture',
      'All 117 tools available',
      'Professional security platform'
    ]
  },
  'full': {
    name: 'Full Server',
    description: 'Complete server with all tools',
    tools: 122, // +5 for additional tools in server-refactored
    categories: Object.keys(TOOL_CATEGORIES),
    features: [
      'Complete tool coverage',
      'Enhanced security tools',
      'Legal compliance features',
      'Professional-grade platform'
    ]
  }
};

// Interactive installer
async function runInstaller() {
  console.log('🚀 MCP God Mode - Dynamic Modular Installer');
  console.log('==========================================');
  console.log('');
  console.log('📊 Available Server Configurations:');
  console.log('');

  Object.entries(SERVER_CONFIGS).forEach(([key, config], index) => {
    console.log(`${index + 1}. ${config.name}`);
    console.log(`   Description: ${config.description}`);
    console.log(`   Tools: ${config.tools}`);
    console.log(`   Categories: ${config.categories.length}`);
    console.log('');
  });

  console.log('🔧 Available Tool Categories:');
  console.log('');
  
  Object.entries(TOOL_CATEGORIES).forEach(([key, category], index) => {
    console.log(`${index + 1}. ${category.name} (${category.tools} tools)`);
    console.log(`   ${category.description}`);
    console.log('');
  });

  console.log('📋 Tool Details:');
  console.log('');
  
  Object.entries(TOOL_CATEGORIES).forEach(([key, category]) => {
    console.log(`🔹 ${category.name}:`);
    category.toolList.forEach(tool => {
      console.log(`   - ${tool}`);
    });
    console.log('');
  });

  console.log('✅ Installation Options:');
  console.log('');
  console.log('1. Install Minimal Server (15 tools)');
  console.log('2. Install Modular Server (117 tools)');
  console.log('3. Install Full Server (122 tools)');
  console.log('4. Build Custom Server');
  console.log('5. Show Tool Information');
  console.log('6. Exit');
  console.log('');

  console.log('💡 To install, run one of these commands:');
  console.log('');
  console.log('npm run install:minimal    # Install minimal server');
  console.log('npm run install:modular    # Install modular server');
  console.log('npm run install:full       # Install full server');
  console.log('node build-server.js       # Build custom server');
  console.log('');
}

// Install minimal server
async function installMinimalServer() {
  console.log('🔧 Installing Minimal Server...');
  console.log('================================');
  
  try {
    const config = createMinimalConfig();
    await saveToolConfig(config);
    
    console.log('✅ Minimal server configuration created');
    console.log('📋 Enabled categories: Core, File System, Discovery');
    console.log('🔧 Total tools: ~15 essential tools');
    console.log('');
    console.log('💡 Run: npm run build && node dist/server-modular.js');
  } catch (error) {
    console.error('❌ Failed to create minimal server configuration:', error);
    console.error('Error details:', error.message);
    console.error('Stack:', error.stack);
  }
}

// Install modular server with user choice
async function installModularServer() {
  console.log('🔧 Installing Modular Server...');
  console.log('================================');
  console.log('');
  console.log('Available tool categories:');
  console.log('');
  
  Object.entries(CONFIG_TOOL_CATEGORIES).forEach(([key, category], index) => {
    console.log(`${index + 1}. ${category.name} (${category.tools.length} tools)`);
    console.log(`   ${category.description}`);
    console.log('');
  });
  
  console.log('💡 To install with specific categories, run:');
  console.log('node install.js --modular --categories core,file_system,network');
  console.log('');
  console.log('💡 To install with all tools, run:');
  console.log('node install.js --modular --all');
  console.log('');
}

// Install full server
async function installFullServer() {
  console.log('🔧 Installing Full Server...');
  console.log('=============================');
  
  try {
    const config = createFullConfig();
    await saveToolConfig(config);
    
    console.log('✅ Full server configuration created');
    console.log('📋 All categories enabled (including enhanced tools)');
    console.log('🔧 Total tools: ~124 tools (119 standard + 5 enhanced)');
    console.log('');
    console.log('💡 Run: npm run build && node dist/server-modular.js');
  } catch (error) {
    console.error('❌ Failed to create full server configuration:', error);
  }
}

// Build custom server
async function buildCustomServer() {
  console.log('🔧 Custom Server Builder');
  console.log('========================');
  console.log('');
  console.log('Available tools by category:');
  console.log('');
  
  Object.entries(TOOL_CATEGORIES).forEach(([key, category]) => {
    console.log(`📁 ${category.name}:`);
    category.toolList.forEach(tool => {
      console.log(`   ${tool}`);
    });
    console.log('');
  });
  
  console.log('💡 Usage: node build-server.js <tool1> <tool2> ... <toolN>');
  console.log('Example: node build-server.js health system_info fs_list');
  console.log('');
}

// Install modular server with specific categories
async function installModularWithCategories(categories) {
  console.log('🔧 Installing Modular Server with Selected Categories...');
  console.log('=======================================================');
  
  try {
    const config = createConfigFromCategories(categories);
    await saveToolConfig(config);
    
    console.log('✅ Modular server configuration created');
    console.log(`📋 Enabled categories: ${categories.join(', ')}`);
    
    // Count total tools
    const totalTools = categories.reduce((count, category) => {
      return count + (CONFIG_TOOL_CATEGORIES[category]?.tools.length || 0);
    }, 0);
    
    console.log(`🔧 Total tools: ~${totalTools} tools`);
    console.log('');
    console.log('💡 Run: npm run build && node dist/server-modular.js');
  } catch (error) {
    console.error('❌ Failed to create modular server configuration:', error);
  }
}

// Main execution
if (import.meta.url === `file://${process.argv[1]}` || import.meta.url.endsWith('install.js')) {
  const args = process.argv.slice(2);
  
  async function main() {
    if (args.includes('--minimal')) {
      await installMinimalServer();
    } else if (args.includes('--modular')) {
      if (args.includes('--all')) {
        await installFullServer();
      } else if (args.includes('--categories')) {
        const categoriesIndex = args.indexOf('--categories');
        const categoriesArg = args[categoriesIndex + 1];
        if (categoriesArg) {
          const categories = categoriesArg.split(',').map(c => c.trim());
          await installModularWithCategories(categories);
        } else {
          console.error('❌ Please specify categories after --categories');
          console.log('Example: --categories core,file_system,network');
        }
      } else {
        await installModularServer();
      }
    } else if (args.includes('--full')) {
      await installFullServer();
    } else if (args.includes('--custom') || args.includes('-c')) {
      await buildCustomServer();
    } else {
      runInstaller();
    }
  }
  
  main().catch(console.error);
}

export { TOOL_CATEGORIES, SERVER_CONFIGS };
