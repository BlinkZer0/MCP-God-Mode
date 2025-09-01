#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');

console.log('🚀 Creating Single-File MCP Executable');
console.log('=====================================');

// This approach bundles EVERYTHING into a single file
// No external dependencies at all

const singleFileConfig = {
  entryPoints: ['dist/server-ultra-minimal.js'],
  bundle: true,
  platform: 'node',
  target: 'node18',
  outfile: 'dist/server-single-file.js',
  external: [], // Bundle EVERYTHING - no external deps
  minify: true,
  sourcemap: false,
  treeShaking: true,
  drop: ['console', 'debugger'],
  define: {
    'process.env.NODE_ENV': '"production"',
    'process.env.DEBUG': 'false'
  },
  format: 'cjs',
  mainFields: ['main'],
  conditions: ['node'],
  pure: ['console.log', 'console.info', 'console.debug', 'console.warn'],
  minifyIdentifiers: true,
  minifySyntax: true,
  minifyWhitespace: true
};

async function createSingleFile() {
  try {
    console.log('🔨 Building single-file version...');
    
    const esbuild = require('esbuild');
    const result = await esbuild.build(singleFileConfig);
    
    console.log('✅ Single-file build completed');
    
    if (result.outputFiles?.[0]) {
      const sizeKB = Math.round(result.outputFiles[0].contents.length / 1024);
      console.log(`📊 Single-file size: ${sizeKB} KB`);
    }
    
    // Create executable
    console.log('\n🚀 Creating single-file executable...');
    try {
      execSync('npx pkg dist/server-single-file.js --targets node18-win-x64 --output mcp-single-file.exe', { stdio: 'inherit' });
      
      if (fs.existsSync('mcp-single-file.exe')) {
        const stats = fs.statSync('mcp-single-file.exe');
        const sizeMB = Math.round(stats.size / (1024 * 1024) * 100) / 100;
        console.log(`✅ Single-file executable: ${sizeMB} MB`);
        
        // Try UPX compression
        try {
          console.log('🗜️  Compressing with UPX...');
          execSync('upx --best --lzma mcp-single-file.exe', { stdio: 'inherit' });
          
          const compressedStats = fs.statSync('mcp-single-file.exe');
          const compressedMB = Math.round(compressedStats.size / (1024 * 1024) * 100) / 100;
          const savings = Math.round((1 - compressedStats.size / stats.size) * 100);
          
          console.log(`✅ Compressed: ${sizeMB} MB → ${compressedMB} MB (${savings}% smaller)`);
        } catch (error) {
          console.log('⚠️  UPX compression failed');
        }
      }
    } catch (error) {
      console.log('⚠️  Executable creation failed:', error.message);
    }
    
  } catch (error) {
    console.error('❌ Single-file build failed:', error);
  }
}

createSingleFile();
