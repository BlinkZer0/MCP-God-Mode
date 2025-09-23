#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// Import tool configuration system
import {
  createMinimalConfig,
  createFullConfig,
  createConfigFromCategories,
  createConfigFromTools,
  createConfigFromMixed,
  validateToolNames,
  validateToolDependencies,
  includeToolDependencies,
  getAllAvailableTools,
  saveToolConfig,
  getAllToolsFromManifest,
  TOOL_CATEGORIES as CONFIG_TOOL_CATEGORIES
} from './dist/config/tool-config.js';

// Enhanced tool categories with drone tools
const ENHANCED_TOOL_CATEGORIES = {
  ...CONFIG_TOOL_CATEGORIES,
  "drone": {
    name: "Drone Management",
    description: "Advanced drone deployment for cybersecurity threat response",
    tools: ["drone_defense", "drone_offense"]
  }
};

// Load tools from manifest
function getAllToolsFromManifest() {
  try {
    // Try to load from manifest first (for latest tools)
    const manifestPath = path.join(process.cwd(), 'tools.manifest.json');
    if (fs.existsSync(manifestPath)) {
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
      return manifest.tools.map(tool => tool.name);
    }
  } catch (error) {
    console.log('⚠️  Could not load tools from manifest, using config categories');
  }

  // Fallback to config categories
  const allTools = [];
  Object.values(ENHANCED_TOOL_CATEGORIES).forEach(category => {
    allTools.push(...category.tools);
  });
  return [...new Set(allTools)]; // Remove duplicates
}

// Get all available tools
function getAllTools() {
  const allTools = [];
  Object.values(ENHANCED_TOOL_CATEGORIES).forEach(category => {
    allTools.push(...category.tools);
  });
  return [...new Set(allTools)]; // Remove duplicates
}

// Interactive installer with comprehensive tool selection
async function runInteractiveInstaller() {
  console.log('🚀 MCP God Mode v2.1b - Interactive Installer');
  console.log('=============================================');
  console.log('');
  console.log('🎯 Enhanced Features in v2.1b:');
  console.log('   • 190+ Comprehensive Tools Available');
  console.log('   • Advanced Security & Penetration Testing');
  console.log('   • AI-Powered Tools & Autonomous Cascade');
  console.log('   • Cross-Platform Support (Windows, macOS, Linux, Mobile)');
  console.log('   • Interactive Category & Individual Tool Selection');
  console.log('');

  // Try to load tools from manifest first
  const allTools = getAllToolsFromManifest();
  console.log(`📊 Total Available Tools: ${allTools.length}`);
  console.log(`📁 Total Categories: ${Object.keys(ENHANCED_TOOL_CATEGORIES).length}`);
  console.log('');

  // Installation mode selection
  console.log('🔧 Installation Modes:');
  console.log('');
  console.log('1. 🎯 Quick Install (Recommended Configurations)');
  console.log('2. 🛠️  Custom Install (Category Selection)');
  console.log('3. 🔍 Individual Tool Selection');
  console.log('4. 📋 Browse All Tools');
  console.log('5. ❌ Exit');
  console.log('');

  const readline = require('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  const question = (prompt) => new Promise(resolve => rl.question(prompt, resolve));

  try {
    const mode = await question('Select installation mode (1-5): ');
    
    switch (mode.trim()) {
      case '1':
        await quickInstall(rl, question);
        break;
      case '2':
        await customCategoryInstall(rl, question);
        break;
      case '3':
        await individualToolInstall(rl, question);
        break;
      case '4':
        await browseAllTools();
        break;
      case '5':
        console.log('👋 Goodbye!');
        break;
      default:
        console.log('❌ Invalid selection. Please run the installer again.');
    }
  } catch (error) {
    console.error('❌ Installer error:', error.message);
  } finally {
    rl.close();
  }
}

// Quick install with recommended configurations
async function quickInstall(rl, question) {
  console.log('');
  console.log('🎯 Quick Install Options:');
  console.log('');
  console.log('1. 🏃 Minimal Server (15 essential tools)');
  console.log('2. 🔒 Security Focused (Core + Security + Network tools)');
  console.log('3. 🛸 Drone Operations (Core + Drone + Security tools)');
  console.log('4. 🌐 Full Network Suite (All network and security tools)');
  console.log('5. 🚀 Complete Platform (All 190+ tools)');
  console.log('');

  const choice = await question('Select configuration (1-5): ');
  
  switch (choice.trim()) {
    case '1':
      await installMinimal();
      break;
    case '2':
      await installSecurityFocused();
      break;
    case '3':
      await installDroneOperations();
      break;
    case '4':
      await installNetworkSuite();
      break;
    case '5':
      await installComplete();
      break;
    default:
      console.log('❌ Invalid selection.');
  }
}

// Custom category installation
async function customCategoryInstall(rl, question) {
  console.log('');
  console.log('🛠️  Custom Category Selection:');
  console.log('');
  
  const categories = Object.entries(ENHANCED_TOOL_CATEGORIES);
  categories.forEach(([key, category], index) => {
    console.log(`${index + 1}. ${category.name} (${category.tools.length} tools)`);
    console.log(`   ${category.description}`);
    console.log('');
  });

  const selectedCategories = [];
  let continueSelection = true;

  while (continueSelection) {
    const categoryChoice = await question(`Select category (1-${categories.length}) or 'done' to finish: `);
    
    if (categoryChoice.toLowerCase() === 'done') {
      continueSelection = false;
    } else {
      const categoryIndex = parseInt(categoryChoice) - 1;
      if (categoryIndex >= 0 && categoryIndex < categories.length) {
        const [key, category] = categories[categoryIndex];
        if (!selectedCategories.includes(key)) {
          selectedCategories.push(key);
          console.log(`✅ Added: ${category.name}`);
        } else {
          console.log(`⚠️  Already selected: ${category.name}`);
        }
      } else {
        console.log('❌ Invalid category selection.');
      }
    }
  }

  if (selectedCategories.length > 0) {
    await installWithCategories(selectedCategories);
  } else {
    console.log('❌ No categories selected.');
  }
}

// Individual tool selection
async function individualToolInstall(rl, question) {
  console.log('');
  console.log('🔍 Individual Tool Selection:');
  console.log('');
  console.log('Available tools by category:');
  console.log('');

  const allTools = getAllToolsFromManifest();
  const categories = Object.entries(ENHANCED_TOOL_CATEGORIES);
  
  categories.forEach(([key, category]) => {
    console.log(`📁 ${category.name}:`);
    category.tools.forEach(tool => {
      console.log(`   • ${tool}`);
    });
    console.log('');
  });

  const selectedTools = [];
  let continueSelection = true;

  while (continueSelection) {
    const toolChoice = await question(`Enter tool name or 'done' to finish: `);
    
    if (toolChoice.toLowerCase() === 'done') {
      continueSelection = false;
    } else {
      if (allTools.includes(toolChoice)) {
        if (!selectedTools.includes(toolChoice)) {
          selectedTools.push(toolChoice);
          console.log(`✅ Added: ${toolChoice}`);
        } else {
          console.log(`⚠️  Already selected: ${toolChoice}`);
        }
      } else {
        console.log(`❌ Tool not found: ${toolChoice}`);
        console.log('💡 Use the browse option to see all available tools.');
      }
    }
  }

  if (selectedTools.length > 0) {
    await installWithTools(selectedTools);
  } else {
    console.log('❌ No tools selected.');
  }
}

// Browse all tools
async function browseAllTools() {
  console.log('');
  console.log('📋 All Available Tools:');
  console.log('========================');
  console.log('');

  const categories = Object.entries(ENHANCED_TOOL_CATEGORIES);
  categories.forEach(([key, category]) => {
    console.log(`🔹 ${category.name} (${category.tools.length} tools):`);
    console.log(`   ${category.description}`);
    category.tools.forEach(tool => {
      console.log(`   • ${tool}`);
    });
    console.log('');
  });

  const allTools = getAllTools();
  console.log(`📊 Total: ${allTools.length} tools across ${categories.length} categories`);
  console.log('');
}

// Installation functions
async function installMinimal() {
  console.log('🔧 Installing Minimal Server...');
  try {
    const config = createMinimalConfig();
    await saveToolConfig(config);
    console.log('✅ Minimal server configuration created');
    console.log('📋 Core system tools enabled');
    console.log('🔧 Total tools: ~15 essential tools');
    console.log('');
    console.log('💡 Run: npm run build && node dist/server-modular.js');
  } catch (error) {
    console.error('❌ Failed to create minimal server configuration:', error);
  }
}

async function installSecurityFocused() {
  console.log('🔧 Installing Security Focused Configuration...');
  try {
    const categories = ['core', 'security', 'network', 'penetration', 'forensics'];
    const config = createConfigFromCategories(categories);
    await saveToolConfig(config);
    
    const totalTools = categories.reduce((count, category) => {
      return count + (ENHANCED_TOOL_CATEGORIES[category]?.tools.length || 0);
    }, 0);
    
    console.log('✅ Security focused configuration created');
    console.log(`📋 Categories: ${categories.join(', ')}`);
    console.log(`🔧 Total tools: ~${totalTools} security-focused tools`);
    console.log('');
    console.log('💡 Run: npm run build && node dist/server-modular.js');
  } catch (error) {
    console.error('❌ Failed to create security configuration:', error);
  }
}

async function installDroneOperations() {
  console.log('🔧 Installing Drone Operations Configuration...');
  try {
    const categories = ['core', 'drone', 'security', 'network', 'penetration'];
    const config = createConfigFromCategories(categories);
    await saveToolConfig(config);
    
    const totalTools = categories.reduce((count, category) => {
      return count + (ENHANCED_TOOL_CATEGORIES[category]?.tools.length || 0);
    }, 0);
    
    console.log('✅ Drone operations configuration created');
    console.log(`📋 Categories: ${categories.join(', ')}`);
    console.log(`🔧 Total tools: ~${totalTools} tools (including drone management)`);
    console.log('');
    console.log('💡 Run: npm run build && node dist/server-modular.js');
  } catch (error) {
    console.error('❌ Failed to create drone operations configuration:', error);
  }
}

async function installNetworkSuite() {
  console.log('🔧 Installing Full Network Suite...');
  try {
    const categories = ['core', 'network', 'security', 'penetration', 'wireless', 'bluetooth', 'radio'];
    const config = createConfigFromCategories(categories);
    await saveToolConfig(config);
    
    const totalTools = categories.reduce((count, category) => {
      return count + (ENHANCED_TOOL_CATEGORIES[category]?.tools.length || 0);
    }, 0);
    
    console.log('✅ Full network suite configuration created');
    console.log(`📋 Categories: ${categories.join(', ')}`);
    console.log(`🔧 Total tools: ~${totalTools} network and security tools`);
    console.log('');
    console.log('💡 Run: npm run build && node dist/server-modular.js');
  } catch (error) {
    console.error('❌ Failed to create network suite configuration:', error);
  }
}

async function installComplete() {
  console.log('🔧 Installing Complete Platform...');
  try {
    const config = createFullConfig();
    await saveToolConfig(config);
    console.log('✅ Complete platform configuration created');
    console.log('📋 All categories enabled');
    console.log('🔧 Total tools: 190+ tools (all available tools)');
    console.log('');
    console.log('💡 Run: npm run build && node dist/server-modular.js');
  } catch (error) {
    console.error('❌ Failed to create complete configuration:', error);
  }
}

async function installWithCategories(categories) {
  console.log('🔧 Installing with Selected Categories...');
  try {
    const config = createConfigFromCategories(categories);
    await saveToolConfig(config);
    
    const totalTools = categories.reduce((count, category) => {
      return count + (ENHANCED_TOOL_CATEGORIES[category]?.tools.length || 0);
    }, 0);
    
    console.log('✅ Custom configuration created');
    console.log(`📋 Categories: ${categories.join(', ')}`);
    console.log(`🔧 Total tools: ~${totalTools} tools`);
    console.log('');
    console.log('💡 Run: npm run build && node dist/server-modular.js');
  } catch (error) {
    console.error('❌ Failed to create custom configuration:', error);
  }
}

async function installWithTools(tools) {
  console.log('🔧 Installing with Selected Tools...');
  try {
    const validation = validateToolDependencies(tools);
    
    if (validation.missing.length > 0) {
      console.log('❌ Invalid tools found:');
      validation.missing.forEach(tool => console.log(`   - ${tool}`));
      return;
    }
    
    let finalTools = validation.valid;
    
    if (validation.warnings.length > 0) {
      console.log('⚠️  Auto-including missing dependencies...');
      finalTools = includeToolDependencies(validation.valid);
      const addedDependencies = finalTools.filter(tool => !validation.valid.includes(tool));
      
      if (addedDependencies.length > 0) {
        console.log('📦 Added dependencies:');
        addedDependencies.forEach(tool => console.log(`   - ${tool}`));
      }
    }
    
    const config = createConfigFromTools(finalTools);
    await saveToolConfig(config);
    
    console.log('✅ Custom tool configuration created');
    console.log(`📋 Tools: ${finalTools.length} tools (${validation.valid.length} requested + ${finalTools.length - validation.valid.length} dependencies)`);
    console.log('');
    console.log('💡 Run: npm run build && node dist/server-modular.js');
  } catch (error) {
    console.error('❌ Failed to create tool configuration:', error);
  }
}

// Main execution
if (import.meta.url === `file://${process.argv[1]}` || import.meta.url.endsWith('interactive-installer.js')) {
  runInteractiveInstaller().catch(console.error);
}

export { ENHANCED_TOOL_CATEGORIES, getAllTools };
