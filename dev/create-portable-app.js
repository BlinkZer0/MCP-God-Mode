#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🚀 Creating Portable MCP Application');
console.log('===================================');

// Strategy: Create a portable app that doesn't need pkg
// This will be much smaller because it doesn't bundle Node.js

// Step 1: Create a minimal launcher script
const launcherScript = `#!/usr/bin/env node
// Ultra-minimal MCP server launcher
const { spawn } = require('child_process');
const path = require('path');

// Find the bundled server
const serverPath = path.join(__dirname, 'server-bundled.js');

// Start the server
const server = spawn('node', [serverPath], {
  stdio: 'inherit',
  cwd: __dirname
});

server.on('error', (err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

server.on('exit', (code) => {
  process.exit(code);
});
`;

fs.writeFileSync('dist/launcher.js', launcherScript);

// Step 2: Create a batch file for Windows
const batchFile = `@echo off
cd /d "%~dp0"
node launcher.js
pause
`;

fs.writeFileSync('dist/mcp-server.bat', batchFile);

// Step 3: Create a shell script for Unix
const shellScript = `#!/bin/bash
cd "$(dirname "$0")"
node launcher.js
`;

fs.writeFileSync('dist/mcp-server.sh', shellScript);

// Step 4: Make shell script executable
try {
  execSync('chmod +x dist/mcp-server.sh');
} catch (error) {
  // Ignore on Windows
}

// Step 5: Create a portable package
console.log('\n📦 Creating portable package...');

const packageDir = 'mcp-portable';
if (fs.existsSync(packageDir)) {
  fs.rmSync(packageDir, { recursive: true });
}
fs.mkdirSync(packageDir);

// Copy essential files
const filesToCopy = [
  'dist/server-ultra-bundled.js',
  'dist/launcher.js',
  'dist/mcp-server.bat',
  'dist/mcp-server.sh'
];

filesToCopy.forEach(file => {
  if (fs.existsSync(file)) {
    const fileName = path.basename(file);
    fs.copyFileSync(file, path.join(packageDir, fileName));
  }
});

// Create README
const readme = `# MCP Server Portable

## Usage

### Windows:
Double-click mcp-server.bat or run:
\`\`\`
mcp-server.bat
\`\`\`

### Linux/Mac:
\`\`\`
./mcp-server.sh
\`\`\`

### Manual:
\`\`\`
node launcher.js
\`\`\`

## Requirements
- Node.js 18+ installed on the system
- No additional dependencies needed

## Size
This portable version is much smaller than a standalone executable because it uses the system's Node.js instead of bundling it.
`;

fs.writeFileSync(path.join(packageDir, 'README.md'), readme);

// Step 6: Create a zip file
console.log('\n🗜️  Creating portable package...');
try {
  if (fs.existsSync('mcp-portable.zip')) {
    fs.unlinkSync('mcp-portable.zip');
  }
  
  // Use PowerShell to create zip on Windows
  execSync(`powershell Compress-Archive -Path "${packageDir}" -DestinationPath "mcp-portable.zip" -Force`, { stdio: 'inherit' });
  
  if (fs.existsSync('mcp-portable.zip')) {
    const stats = fs.statSync('mcp-portable.zip');
    const sizeKB = Math.round(stats.size / 1024);
    const sizeMB = Math.round(stats.size / (1024 * 1024) * 100) / 100;
    
    console.log(`✅ Portable package created: mcp-portable.zip (${sizeMB} MB)`);
    console.log('🎯 This is much smaller than a standalone executable!');
  }
} catch (error) {
  console.log('⚠️  Could not create zip file:', error.message);
}

// Step 7: Show size comparison
console.log('\n📊 Size Comparison:');
console.log('==================');

const files = [
  { name: 'Portable package', path: 'mcp-portable.zip' },
  { name: 'Bundled server', path: 'dist/server-ultra-bundled.js' },
  { name: 'Launcher script', path: 'dist/launcher.js' }
];

files.forEach(file => {
  if (fs.existsSync(file.path)) {
    const stats = fs.statSync(file.path);
    const sizeKB = Math.round(stats.size / 1024);
    const sizeMB = Math.round(stats.size / (1024 * 1024) * 100) / 100;
    
    if (sizeKB < 1024) {
      console.log(`  ${file.name}: ${sizeKB} KB`);
    } else {
      console.log(`  ${file.name}: ${sizeMB} MB`);
    }
  }
});

console.log('\n💡 Benefits of portable version:');
console.log('  ✅ Much smaller download size');
console.log('  ✅ Uses system Node.js (no bundling)');
console.log('  ✅ Easy to distribute');
console.log('  ✅ Works on any system with Node.js');
console.log('  ✅ Perfect for GitHub releases!');

console.log('\n🚀 Usage:');
console.log('  1. Extract mcp-portable.zip');
console.log('  2. Run mcp-server.bat (Windows) or ./mcp-server.sh (Unix)');
console.log('  3. Or manually: node launcher.js');
