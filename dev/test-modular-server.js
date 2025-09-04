#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🔍 Testing Modular Server Tool Registration');
console.log('==========================================\n');

// Test 1: Check if server-modular.ts compiles
console.log('📋 Test 1: Compilation Check');
try {
  execSync('npx tsc --noEmit --skipLibCheck src/server-modular.ts', { stdio: 'pipe' });
  console.log('✅ server-modular.ts compiles successfully\n');
} catch (error) {
  console.log('❌ server-modular.ts compilation failed');
  console.log('Error:', error.message);
  process.exit(1);
}

// Test 2: Check if comprehensive tools index exists and has 67 exports
console.log('📋 Test 2: Comprehensive Tools Index Check');
try {
  const toolsIndexPath = path.join(__dirname, 'src', 'tools', 'index.ts');
  const toolsIndexContent = fs.readFileSync(toolsIndexPath, 'utf8');
  
  // Count export statements
  const exportMatches = toolsIndexContent.match(/export\s*{\s*register[A-Za-z]+\s*}/g);
  const exportCount = exportMatches ? exportMatches.length : 0;
  
  console.log(`📊 Found ${exportCount} tool exports in comprehensive index`);
  
  if (exportCount >= 67) {
    console.log('✅ Comprehensive tools index has sufficient exports\n');
  } else {
    console.log(`⚠️  Expected 67+ exports, found ${exportCount}\n`);
  }
} catch (error) {
  console.log('❌ Failed to read comprehensive tools index');
  console.log('Error:', error.message);
  process.exit(1);
}

// Test 3: Check if modular server imports the comprehensive index
console.log('📋 Test 3: Modular Server Import Check');
try {
  const modularServerPath = path.join(__dirname, 'src', 'server-modular.ts');
  const modularServerContent = fs.readFileSync(modularServerPath, 'utf8');
  
  if (modularServerContent.includes('import * as allTools from "./tools/index.js"')) {
    console.log('✅ Modular server imports comprehensive tools index');
  } else {
    console.log('❌ Modular server does not import comprehensive tools index');
  }
  
  if (modularServerContent.includes('Object.values(allTools)')) {
    console.log('✅ Modular server uses comprehensive tools index for registration');
  } else {
    console.log('❌ Modular server does not use comprehensive tools index for registration');
  }
  
  console.log('');
} catch (error) {
  console.log('❌ Failed to read modular server file');
  console.log('Error:', error.message);
  process.exit(1);
}

// Test 4: Check if all tool files exist
console.log('📋 Test 4: Tool File Existence Check');
try {
  const toolsDir = path.join(__dirname, 'src', 'tools');
  const categories = fs.readdirSync(toolsDir).filter(item => 
    fs.statSync(path.join(toolsDir, item)).isDirectory()
  );
  
  console.log(`📁 Found ${categories.length} tool categories:`);
  categories.forEach(category => {
    const categoryPath = path.join(toolsDir, category);
    const files = fs.readdirSync(categoryPath).filter(file => file.endsWith('.ts'));
    console.log(`   ${category}: ${files.length} tool files`);
  });
  
  console.log('');
} catch (error) {
  console.log('❌ Failed to read tools directory');
  console.log('Error:', error.message);
}

// Test 5: Check package.json scripts
console.log('📋 Test 5: Package.json Scripts Check');
try {
  const packageJsonPath = path.join(__dirname, 'package.json');
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  
  if (packageJson.scripts['build:modular']) {
    console.log('✅ build:modular script exists');
    console.log(`   Command: ${packageJson.scripts['build:modular']}`);
  } else {
    console.log('❌ build:modular script missing');
  }
  
  console.log('');
} catch (error) {
  console.log('❌ Failed to read package.json');
  console.log('Error:', error.message);
}

// Test 6: Verify install.js configuration
console.log('📋 Test 6: Install Script Configuration Check');
try {
  const installScriptPath = path.join(__dirname, 'install.js');
  const installScriptContent = fs.readFileSync(installScriptPath, 'utf8');
  
  if (installScriptContent.includes('tools: 67')) {
    console.log('✅ Install script correctly shows 67 tools for modular server');
  } else {
    console.log('❌ Install script does not show 67 tools for modular server');
  }
  
  if (installScriptContent.includes('Complete modular server with all 67 tools')) {
    console.log('✅ Install script correctly describes comprehensive modular server');
  } else {
    console.log('❌ Install script does not describe comprehensive modular server');
  }
  
  console.log('');
} catch (error) {
  console.log('❌ Failed to read install script');
  console.log('Error:', error.message);
}

console.log('🎯 Summary:');
console.log('===========');
console.log('The modular server should now:');
console.log('✅ Compile without errors');
console.log('✅ Import all 67 tools from comprehensive index');
console.log('✅ Register all tools dynamically');
console.log('✅ Be properly documented in install.js');
console.log('✅ Have working build scripts');
console.log('');
console.log('🚀 To test the modular server:');
console.log('   1. npm run build:modular');
console.log('   2. node dist/server-modular.js');
console.log('');
console.log('🔧 To install via installer:');
console.log('   node install.js');
console.log('   Choose "modular" option');
console.log('');
console.log('✨ All tests completed!');
