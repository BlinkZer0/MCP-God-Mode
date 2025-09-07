#!/usr/bin/env node

import { discoverTools, generateInstallJS, generateBuildServerJS, updatePackageScripts } from './update-modular-installer.js';
import fs from 'fs';

async function main() {
  console.log('🔍 Discovering tools in src/tools/...');
  console.log('');
  
  const tools = discoverTools();
  const totalTools = Object.values(tools).reduce((sum, cat) => sum + cat.tools, 0);
  
  if (totalTools === 0) {
    console.log('❌ No tools discovered!');
    return;
  }
  
  console.log(`✅ Discovered ${totalTools} tools in ${Object.keys(tools).length} categories`);
  console.log('');
  
  // Show discovered tools
  console.log('📋 Discovered Tools:');
  Object.entries(tools).forEach(([category, data]) => {
    console.log(`🔹 ${data.name}: ${data.tools} tools`);
  });
  console.log('');
  
  // Generate updated files
  console.log('📝 Generating updated installer files...');
  
  // Update install.js
  const installJSContent = generateInstallJS(tools);
  fs.writeFileSync('install.js', installJSContent);
  console.log('✅ Updated install.js');
  
  // Update build-server.js
  const buildServerJSContent = generateBuildServerJS(tools);
  fs.writeFileSync('build-server.js', buildServerJSContent);
  console.log('✅ Updated build-server.js');
  
  // Update package.json
  updatePackageScripts(tools);
  
  console.log('');
  console.log('🎉 Modular installer successfully updated!');
  console.log('');
  console.log('📊 Summary:');
  console.log(`   - Total tools: ${totalTools}`);
  console.log(`   - Categories: ${Object.keys(tools).length}`);
  console.log(`   - Files updated: install.js, build-server.js, package.json`);
  console.log('');
  console.log('🚀 Usage:');
  console.log('   node install.js              # Interactive installer');
  console.log('   node build-server.js         # Custom server builder');
  console.log('   npm run install:modular      # Install modular server');
  console.log('   npm run build:custom         # Build custom server');
  console.log('');
}

main().catch(console.error);
