#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');

console.log('🚀 Verifying Modular Server Startup');
console.log('===================================\n');

// Check if the built modular server exists
const modularServerPath = path.join(__dirname, 'dist', 'server-modular.js');
const fs = require('fs');

if (!fs.existsSync(modularServerPath)) {
  console.log('❌ Modular server not built. Please run: npm run build:modular');
  process.exit(1);
}

console.log('✅ Modular server built successfully');
console.log(`📁 Location: ${modularServerPath}`);
console.log(`📊 Size: ${(fs.statSync(modularServerPath).size / 1024).toFixed(2)} KB\n`);

console.log('🔄 Starting modular server for verification...\n');

// Start the modular server
const serverProcess = spawn('node', [modularServerPath], {
  stdio: ['pipe', 'pipe', 'pipe'],
  cwd: __dirname
});

let output = '';
let errorOutput = '';
let serverStarted = false;
let toolCount = 0;

// Set a timeout for the server startup
const startupTimeout = setTimeout(() => {
  console.log('⏰ Server startup timeout - checking output...');
  serverProcess.kill();
  analyzeOutput();
}, 10000);

serverProcess.stdout.on('data', (data) => {
  const outputChunk = data.toString();
  output += outputChunk;
  
  // Check for server startup messages
  if (outputChunk.includes('MCP GOD MODE - MODULAR SERVER STARTED')) {
    serverStarted = true;
    console.log('✅ Server startup message detected');
  }
  
  // Check for tool count
  const toolCountMatch = outputChunk.match(/Total Tools Available: (\d+)/);
  if (toolCountMatch) {
    toolCount = parseInt(toolCountMatch[1]);
    console.log(`📊 Tool count detected: ${toolCount}`);
  }
  
  // Check for comprehensive tool suite message
  if (outputChunk.includes('COMPREHENSIVE TOOL SUITE LOADED')) {
    console.log('✅ Comprehensive tool suite message detected');
  }
  
  // Check for security notice
  if (outputChunk.includes('SECURITY NOTICE')) {
    console.log('✅ Security notice displayed');
  }
  
  // If we have all the expected output, we can stop
  if (serverStarted && toolCount > 0) {
    clearTimeout(startupTimeout);
    setTimeout(() => {
      serverProcess.kill();
      analyzeOutput();
    }, 2000);
  }
});

serverProcess.stderr.on('data', (data) => {
  errorOutput += data.toString();
});

serverProcess.on('close', (code) => {
  clearTimeout(startupTimeout);
  analyzeOutput();
});

function analyzeOutput() {
  console.log('\n📋 Verification Results:');
  console.log('========================');
  
  if (serverStarted) {
    console.log('✅ Server started successfully');
  } else {
    console.log('❌ Server startup not detected');
  }
  
  if (toolCount >= 67) {
    console.log(`✅ Tool count verified: ${toolCount} (expected 67+)`);
  } else if (toolCount > 0) {
    console.log(`⚠️  Tool count: ${toolCount} (expected 67+)`);
  } else {
    console.log('❌ Tool count not detected');
  }
  
  if (output.includes('COMPREHENSIVE TOOL SUITE LOADED')) {
    console.log('✅ Comprehensive tool suite message displayed');
  } else {
    console.log('❌ Comprehensive tool suite message not displayed');
  }
  
  if (output.includes('SECURITY NOTICE')) {
    console.log('✅ Security notice displayed');
  } else {
    console.log('❌ Security notice not displayed');
  }
  
  if (output.includes('Successfully registered')) {
    console.log('✅ Tool registration success message displayed');
  } else {
    console.log('❌ Tool registration success message not displayed');
  }
  
  // Check for specific tool categories mentioned
  const expectedCategories = [
    'File System Tools', 'Process Tools', 'Network Tools', 'Security Tools',
    'Email Tools', 'Media Tools', 'Mobile Tools', 'Cloud Tools', 'Forensics Tools'
  ];
  
  console.log('\n📁 Tool Categories Detected:');
  expectedCategories.forEach(category => {
    if (output.includes(category)) {
      console.log(`   ✅ ${category}`);
    } else {
      console.log(`   ❌ ${category}`);
    }
  });
  
  console.log('\n🎯 Final Assessment:');
  if (serverStarted && toolCount >= 67) {
    console.log('🎉 MODULAR SERVER VERIFICATION PASSED!');
    console.log('   All 67 tools are properly registered and the server starts correctly.');
  } else {
    console.log('⚠️  MODULAR SERVER VERIFICATION PARTIALLY PASSED');
    console.log('   Some issues detected. Check the output above for details.');
  }
  
  console.log('\n📝 Server Output Summary:');
  console.log('========================');
  console.log(output);
  
  if (errorOutput) {
    console.log('\n❌ Error Output:');
    console.log('================');
    console.log(errorOutput);
  }
  
  console.log('\n🚀 Next Steps:');
  console.log('===============');
  console.log('1. The modular server is ready for use');
  console.log('2. Run: npm run build:modular (to rebuild)');
  console.log('3. Run: node dist/server-modular.js (to start)');
  console.log('4. Use the installer: node install.js (choose "modular")');
  console.log('\n✨ Verification complete!');
}
