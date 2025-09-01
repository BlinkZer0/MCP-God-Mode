const esbuild = require('esbuild');

const buildConfig = {
  entryPoints: ['dist/server-ultra-minimal.js'],
  bundle: true,
  platform: 'node',
  target: 'node18',
  outfile: 'dist/server-ultra-bundled.js',
  external: [
    // Only keep MCP SDK as external - bundle everything else
    '@modelcontextprotocol/sdk'
  ],
  minify: true,
  sourcemap: false,
  treeShaking: true,
  drop: ['console', 'debugger'],
  define: {
    'process.env.NODE_ENV': '"production"',
    'process.env.DEBUG': 'false'
  },
  // Aggressive optimization
  format: 'cjs',
  mainFields: ['main'],
  conditions: ['node'],
  // Remove unused code
  pure: ['console.log', 'console.info', 'console.debug', 'console.warn'],
  // Compress more aggressively
  minifyIdentifiers: true,
  minifySyntax: true,
  minifyWhitespace: true
};

async function build() {
  try {
    console.log('🔨 Building ultra-minimal version with esbuild...');
    
    const result = await esbuild.build(buildConfig);
    
    console.log('✅ Ultra-minimal build completed successfully');
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
