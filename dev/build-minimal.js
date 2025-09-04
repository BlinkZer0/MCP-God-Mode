#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🔧 Building minimal MCP server...');

// Step 1: Install minimal dependencies
console.log('📦 Installing minimal dependencies...');
const minimalPackageJson = {
  "name": "mcp-god-mode-minimal",
  "version": "1.4",
  "private": true,
  "main": "dist/server-minimal.js",
  "scripts": {
    "build": "tsc -p .",
    "start": "node dist/server-minimal.js",
    "dev": "tsc -p . && node dist/server-minimal.js"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.2.0",
    "zod": "^3.23.8",
    "simple-git": "^3.24.0",
    "mathjs": "^14.6.0",
    "nanoid": "^5.0.6"
  },
  "devDependencies": {
    "@types/node": "^22.5.4",
    "typescript": "^5.6.2",
    "esbuild": "^0.19.0"
  }
};

// Backup original package.json
if (fs.existsSync('package.json')) {
  fs.copyFileSync('package.json', 'package.json.backup');
}

// Write minimal package.json
fs.writeFileSync('package-minimal.json', JSON.stringify(minimalPackageJson, null, 2));

// Step 2: Install only minimal dependencies
try {
  execSync('npm install --package-lock-only --no-save', { stdio: 'inherit' });
  console.log('✅ Minimal dependencies installed');
} catch (error) {
  console.error('❌ Failed to install minimal dependencies:', error.message);
  process.exit(1);
}

// Step 3: Build TypeScript
console.log('🔨 Building TypeScript...');
try {
  execSync('npx tsc -p .', { stdio: 'inherit' });
  console.log('✅ TypeScript build completed');
} catch (error) {
  console.error('❌ TypeScript build failed:', error.message);
  process.exit(1);
}

// Step 4: Bundle with esbuild for smaller size
console.log('📦 Bundling with esbuild...');
try {
  execSync('npx esbuild dist/server-minimal.js --bundle --platform=node --target=node18 --outfile=dist/server-bundled.js --external:@modelcontextprotocol/sdk --external:simple-git --external:mathjs --external:nanoid --external:zod', { stdio: 'inherit' });
  console.log('✅ Bundling completed');
} catch (error) {
  console.error('❌ Bundling failed:', error.message);
  process.exit(1);
}

// Step 5: Create executable with pkg (if available)
console.log('🚀 Creating executable...');
try {
  execSync('npx pkg dist/server-bundled.js --targets node18-win-x64 --output mcp-server-minimal.exe', { stdio: 'inherit' });
  console.log('✅ Executable created: mcp-server-minimal.exe');
} catch (error) {
  console.log('⚠️  pkg not available, skipping executable creation');
  console.log('💡 You can run: node dist/server-bundled.js');
}

// Step 6: Show size comparison
try {
  const stats = fs.statSync('dist/server-bundled.js');
  const sizeKB = Math.round(stats.size / 1024);
  console.log(`📊 Bundled size: ${sizeKB} KB`);
  
  if (fs.existsSync('mcp-server-minimal.exe')) {
    const exeStats = fs.statSync('mcp-server-minimal.exe');
    const exeSizeMB = Math.round(exeStats.size / (1024 * 1024) * 100) / 100;
    console.log(`📊 Executable size: ${exeSizeMB} MB`);
  }
} catch (error) {
  console.log('⚠️  Could not calculate file sizes');
}

console.log('🎉 Minimal build completed!');
console.log('📝 To restore original dependencies: mv package.json.backup package.json && npm install');
