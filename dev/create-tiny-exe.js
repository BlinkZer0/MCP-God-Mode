#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🚀 Creating Ultra-Tiny MCP Executable');
console.log('=====================================');

// Step 1: Build TypeScript
console.log('\n🔨 Building TypeScript...');
try {
  execSync('npx tsc -p .', { stdio: 'inherit' });
  console.log('✅ TypeScript build completed');
} catch (error) {
  console.error('❌ TypeScript build failed:', error.message);
  process.exit(1);
}

// Step 2: Bundle with ultra-aggressive esbuild
console.log('\n📦 Bundling with ultra-aggressive esbuild...');
try {
  execSync('node esbuild-ultra.config.js', { stdio: 'inherit' });
  console.log('✅ Ultra-aggressive bundling completed');
} catch (error) {
  console.error('❌ Bundling failed:', error.message);
}

// Step 3: Try multiple executable creation methods
console.log('\n🚀 Creating executable with multiple methods...');

const methods = [
  {
    name: 'pkg (Node 18)',
    command: 'npx pkg dist/server-ultra-bundled.js --targets node18-win-x64 --output mcp-tiny-pkg.exe'
  },
  {
    name: 'pkg (Node 16)',
    command: 'npx pkg dist/server-ultra-bundled.js --targets node16-win-x64 --output mcp-tiny-pkg16.exe'
  },
  {
    name: 'nexe',
    command: 'npx nexe dist/server-ultra-bundled.js --target windows-x64-18.0.0 --output mcp-tiny-nexe.exe'
  }
];

let smallestExe = null;
let smallestSize = Infinity;

for (const method of methods) {
  try {
    console.log(`\n🔧 Trying ${method.name}...`);
    execSync(method.command, { stdio: 'inherit' });
    
    const outputFile = method.command.split('--output ')[1];
    if (fs.existsSync(outputFile)) {
      const stats = fs.statSync(outputFile);
      const sizeMB = Math.round(stats.size / (1024 * 1024) * 100) / 100;
      console.log(`✅ ${method.name} created: ${sizeMB} MB`);
      
      if (stats.size < smallestSize) {
        smallestSize = stats.size;
        smallestExe = outputFile;
      }
    }
  } catch (error) {
    console.log(`⚠️  ${method.name} failed: ${error.message}`);
  }
}

// Step 4: Try UPX compression if available
if (smallestExe) {
  console.log(`\n🗜️  Trying UPX compression on ${smallestExe}...`);
  try {
    const originalSize = fs.statSync(smallestExe).size;
    execSync(`upx --best --lzma ${smallestExe}`, { stdio: 'inherit' });
    
    const compressedSize = fs.statSync(smallestExe).size;
    const originalMB = Math.round(originalSize / (1024 * 1024) * 100) / 100;
    const compressedMB = Math.round(compressedSize / (1024 * 1024) * 100) / 100;
    const savings = Math.round((1 - compressedSize / originalSize) * 100);
    
    console.log(`✅ UPX compression: ${originalMB} MB → ${compressedMB} MB (${savings}% smaller)`);
  } catch (error) {
    console.log('⚠️  UPX not available or failed');
  }
}

// Step 5: Show final results
console.log('\n📊 Final Results:');
console.log('================');

try {
  const files = [
    { name: 'Original server', path: 'dist/server-refactored.js' },
    { name: 'Minimal server', path: 'dist/server-minimal.js' },
    { name: 'Ultra-minimal server', path: 'dist/server-ultra-minimal.js' },
    { name: 'Ultra-bundled server', path: 'dist/server-ultra-bundled.js' }
  ];
  
  files.forEach(file => {
    if (fs.existsSync(file.path)) {
      const stats = fs.statSync(file.path);
      const sizeKB = Math.round(stats.size / 1024);
      console.log(`  ${file.name}: ${sizeKB} KB`);
    }
  });
  
  // Show executable sizes
  const exeFiles = fs.readdirSync('.').filter(f => f.endsWith('.exe'));
  exeFiles.forEach(exe => {
    const stats = fs.statSync(exe);
    const sizeMB = Math.round(stats.size / (1024 * 1024) * 100) / 100;
    console.log(`  ${exe}: ${sizeMB} MB`);
  });
  
  if (smallestExe) {
    const finalSize = fs.statSync(smallestExe).size;
    const finalSizeMB = Math.round(finalSize / (1024 * 1024) * 100) / 100;
    console.log(`\n🎉 Smallest executable: ${smallestExe} (${finalSizeMB} MB)`);
    
    if (finalSizeMB < 10) {
      console.log('🎯 SUCCESS: Under 10MB - Perfect for GitHub!');
    } else if (finalSizeMB < 25) {
      console.log('✅ GOOD: Under 25MB - Should work for GitHub');
    } else {
      console.log('⚠️  Still large - may need more optimization');
    }
  }
  
} catch (error) {
  console.log('⚠️  Could not calculate final sizes');
}

console.log('\n💡 Usage:');
console.log(`  node dist/server-ultra-bundled.js`);
if (smallestExe) {
  console.log(`  ./${smallestExe}`);
}

console.log('\n🔧 To restore original:');
console.log('  mv package.json.backup package.json && npm install');
