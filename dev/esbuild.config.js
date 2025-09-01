const esbuild = require('esbuild');
const path = require('path');

const buildConfig = {
  entryPoints: ['dist/server-minimal.js'],
  bundle: true,
  platform: 'node',
  target: 'node18',
  outfile: 'dist/server-bundled.js',
  external: [
    // Keep these as external dependencies
    '@modelcontextprotocol/sdk',
    'simple-git',
    'mathjs',
    'nanoid',
    'zod'
  ],
  minify: true,
  sourcemap: false,
  treeShaking: true,
  drop: ['console', 'debugger'],
  define: {
    'process.env.NODE_ENV': '"production"'
  },
  // Remove shebang for now
  // banner: {
  //   js: '#!/usr/bin/env node'
  // }
};

async function build() {
  try {
    console.log('🔨 Building with esbuild...');
    
    const result = await esbuild.build(buildConfig);
    
    console.log('✅ Build completed successfully');
    console.log(`📊 Output: ${result.outputFiles?.[0]?.path}`);
    
    // Show size
    if (result.outputFiles?.[0]) {
      const sizeKB = Math.round(result.outputFiles[0].contents.length / 1024);
      console.log(`📊 Bundle size: ${sizeKB} KB`);
    }
    
  } catch (error) {
    console.error('❌ Build failed:', error);
    process.exit(1);
  }
}

build();
