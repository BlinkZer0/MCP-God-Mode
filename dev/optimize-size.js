#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🚀 MCP Server Size Optimization');
console.log('================================');

// Step 1: Analyze current dependencies
console.log('\n📊 Analyzing current dependencies...');
try {
  const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const depCount = Object.keys(packageJson.dependencies || {}).length;
  const devDepCount = Object.keys(packageJson.devDependencies || {}).length;
  
  console.log(`📦 Current dependencies: ${depCount} production, ${devDepCount} development`);
  
  // Show largest dependencies
  const largeDeps = [
    'electron', 'app-builder-bin', 'ffmpeg-static', 'better-sqlite3',
    'pdf-parse', 'canvas', 'tesseract.js-core', '@mui', 'typescript',
    'date-fns', 'fluent-ffmpeg', 'plotly.js-dist', 'puppeteer'
  ];
  
  const foundLargeDeps = largeDeps.filter(dep => 
    packageJson.dependencies?.[dep] || packageJson.devDependencies?.[dep]
  );
  
  console.log(`🔍 Large dependencies found: ${foundLargeDeps.join(', ')}`);
  
} catch (error) {
  console.error('❌ Failed to analyze dependencies:', error.message);
}

// Step 2: Create minimal package.json
console.log('\n📝 Creating minimal package.json...');
const minimalPackage = {
  "name": "mcp-god-mode-minimal",
  "version": "1.3",
  "private": true,
  "main": "dist/server-minimal.js",
  "scripts": {
    "build": "tsc -p .",
    "start": "node dist/server-minimal.js",
    "dev": "tsc -p . && node dist/server-minimal.js",
    "bundle": "node esbuild.config.js",
    "optimize": "node optimize-size.js"
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
    "esbuild": "^0.19.0",
    "terser": "^5.24.0"
  }
};

fs.writeFileSync('package-minimal.json', JSON.stringify(minimalPackage, null, 2));
console.log('✅ Minimal package.json created');

// Step 3: Build TypeScript
console.log('\n🔨 Building TypeScript...');
try {
  execSync('npx tsc -p .', { stdio: 'inherit' });
  console.log('✅ TypeScript build completed');
} catch (error) {
  console.error('❌ TypeScript build failed:', error.message);
  process.exit(1);
}

// Step 4: Bundle with esbuild
console.log('\n📦 Bundling with esbuild...');
try {
  execSync('node esbuild.config.js', { stdio: 'inherit' });
  console.log('✅ esbuild bundling completed');
} catch (error) {
  console.error('❌ esbuild bundling failed:', error.message);
}

// Step 5: Show size comparison
console.log('\n📊 Size Analysis:');
try {
  const files = [
    { name: 'Original server', path: 'dist/server-refactored.js' },
    { name: 'Minimal server', path: 'dist/server-minimal.js' },
    { name: 'Bundled server', path: 'dist/server-bundled.js' }
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
  
  // Calculate savings
  const originalPath = 'dist/server-refactored.js';
  const bundledPath = 'dist/server-bundled.js';
  
  if (fs.existsSync(originalPath) && fs.existsSync(bundledPath)) {
    const originalSize = fs.statSync(originalPath).size;
    const bundledSize = fs.statSync(bundledPath).size;
    const savings = Math.round((1 - bundledSize / originalSize) * 100);
    
    console.log(`\n🎉 Size reduction: ${savings}% smaller!`);
  }
  
} catch (error) {
  console.log('⚠️  Could not calculate size comparison');
}

// Step 6: Create executable (optional)
console.log('\n🚀 Creating executable...');
try {
  // Try pkg first
  execSync('npx pkg dist/server-bundled.js --targets node18-win-x64 --output mcp-server-minimal.exe', { stdio: 'inherit' });
  console.log('✅ Executable created with pkg');
} catch (error) {
  try {
    // Try nexe as fallback
    execSync('npx nexe dist/server-bundled.js --target windows-x64-18.0.0 --output mcp-server-minimal.exe', { stdio: 'inherit' });
    console.log('✅ Executable created with nexe');
  } catch (error2) {
    console.log('⚠️  Could not create executable (pkg/nexe not available)');
    console.log('💡 You can run: node dist/server-bundled.js');
  }
}

// Step 7: Show final results
console.log('\n🎯 Optimization Complete!');
console.log('========================');
console.log('📁 Files created:');
console.log('  - package-minimal.json (minimal dependencies)');
console.log('  - dist/server-minimal.js (minimal server)');
console.log('  - dist/server-bundled.js (bundled & optimized)');
console.log('  - mcp-server-minimal.exe (executable, if available)');

console.log('\n💡 Next steps:');
console.log('  1. Test the minimal server: node dist/server-bundled.js');
console.log('  2. If working, replace package.json with package-minimal.json');
console.log('  3. Run npm install to get only minimal dependencies');
console.log('  4. The executable should now be much smaller for GitHub!');

console.log('\n🔧 To restore original:');
console.log('  mv package.json.backup package.json && npm install');
