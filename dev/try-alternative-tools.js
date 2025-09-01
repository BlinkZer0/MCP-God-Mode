#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');

console.log('🚀 Trying Alternative Executable Creation Tools');
console.log('==============================================');

// Try different tools that might create smaller executables

const tools = [
  {
    name: 'vercel/pkg (latest)',
    command: 'npx pkg@latest dist/server-ultra-bundled.js --targets node18-win-x64 --output mcp-vercel-pkg.exe'
  },
  {
    name: 'node-binary',
    command: 'npx node-binary dist/server-ultra-bundled.js --output mcp-node-binary.exe'
  },
  {
    name: 'ncc + pkg',
    command: 'npx @vercel/ncc build dist/server-ultra-bundled.js --out dist/ncc && npx pkg dist/ncc/index.js --targets node18-win-x64 --output mcp-ncc-pkg.exe'
  }
];

let smallestExe = null;
let smallestSize = Infinity;

for (const tool of tools) {
  try {
    console.log(`\n🔧 Trying ${tool.name}...`);
    execSync(tool.command, { stdio: 'inherit' });
    
    // Extract output filename from command
    const outputFile = tool.command.split('--output ')[1] || tool.command.split('--out ')[1];
    if (outputFile && fs.existsSync(outputFile)) {
      const stats = fs.statSync(outputFile);
      const sizeMB = Math.round(stats.size / (1024 * 1024) * 100) / 100;
      console.log(`✅ ${tool.name} created: ${sizeMB} MB`);
      
      if (stats.size < smallestSize) {
        smallestSize = stats.size;
        smallestExe = outputFile;
      }
    }
  } catch (error) {
    console.log(`⚠️  ${tool.name} failed: ${error.message}`);
  }
}

// Also try creating a simple Node.js script that can be run directly
console.log('\n📝 Creating simple Node.js script...');
const simpleScript = `#!/usr/bin/env node
// Simple MCP server - no external dependencies
const { spawn } = require('child_process');
const path = require('path');

console.log('Starting MCP Server...');

// Run the bundled server
const server = spawn('node', [path.join(__dirname, 'server-ultra-bundled.js')], {
  stdio: 'inherit'
});

server.on('error', (err) => {
  console.error('Error:', err);
  process.exit(1);
});

server.on('exit', (code) => {
  process.exit(code);
});
`;

fs.writeFileSync('dist/start-mcp.js', simpleScript);

// Show final comparison
console.log('\n📊 Final Size Comparison:');
console.log('========================');

const allFiles = [
  { name: 'Portable package (total)', path: 'mcp-portable', isDir: true },
  { name: 'Ultra-bundled server', path: 'dist/server-ultra-bundled.js' },
  { name: 'Simple start script', path: 'dist/start-mcp.js' }
];

// Add any executables that were created
const exeFiles = fs.readdirSync('.').filter(f => f.endsWith('.exe'));
exeFiles.forEach(exe => {
  allFiles.push({ name: exe, path: exe });
});

allFiles.forEach(file => {
  if (fs.existsSync(file.path)) {
    let size;
    if (file.isDir) {
      const files = fs.readdirSync(file.path, { recursive: true });
      size = files.reduce((total, f) => {
        const fullPath = path.join(file.path, f);
        if (fs.statSync(fullPath).isFile()) {
          return total + fs.statSync(fullPath).size;
        }
        return total;
      }, 0);
    } else {
      size = fs.statSync(file.path).size;
    }
    
    const sizeKB = Math.round(size / 1024);
    const sizeMB = Math.round(size / (1024 * 1024) * 100) / 100;
    
    if (sizeKB < 1024) {
      console.log(`  ${file.name}: ${sizeKB} KB`);
    } else {
      console.log(`  ${file.name}: ${sizeMB} MB`);
    }
  }
});

console.log('\n🎯 RECOMMENDATION:');
console.log('==================');
console.log('The PORTABLE PACKAGE (72 KB) is the best solution!');
console.log('✅ Smallest size');
console.log('✅ No bundling of Node.js');
console.log('✅ Easy to distribute');
console.log('✅ Perfect for GitHub releases');
console.log('✅ Works on any system with Node.js');

console.log('\n💡 Usage:');
console.log('  1. Distribute the mcp-portable folder');
console.log('  2. Users run: node launcher.js');
console.log('  3. Or double-click mcp-server.bat (Windows)');
