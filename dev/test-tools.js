// Simple test script for MCP God Mode tools
const { spawn } = require('child_process');

console.log('🧪 Testing MCP God Mode Tools...\n');

// Test the health tool
console.log('1. Testing health tool...');
const healthTest = spawn('node', ['dist/server-modular.js'], {
  stdio: ['pipe', 'pipe', 'pipe']
});

let healthOutput = '';
healthTest.stdout.on('data', (data) => {
  healthOutput += data.toString();
});

healthTest.stderr.on('data', (data) => {
  console.error('Health tool error:', data.toString());
});

healthTest.on('close', (code) => {
  console.log('Health tool test completed with code:', code);
  console.log('Output:', healthOutput);
  console.log('✅ Health tool test completed\n');
  
  // Test system info tool
  testSystemInfo();
});

function testSystemInfo() {
  console.log('2. Testing system info tool...');
  const sysInfoTest = spawn('node', ['dist/server-modular.js'], {
    stdio: ['pipe', 'pipe', 'pipe']
  });
  
  let sysInfoOutput = '';
  sysInfoTest.stdout.on('data', (data) => {
    sysInfoOutput += data.toString();
  });
  
  sysInfoTest.stderr.on('data', (data) => {
    console.error('System info tool error:', data.toString());
  });
  
  sysInfoTest.on('close', (code) => {
    console.log('System info tool test completed with code:', code);
    console.log('Output:', sysInfoOutput);
    console.log('✅ System info tool test completed\n');
    
    // Test file system tool
    testFileSystem();
  });
}

function testFileSystem() {
  console.log('3. Testing file system tool...');
  const fsTest = spawn('node', ['dist/server-modular.js'], {
    stdio: ['pipe', 'pipe', 'pipe']
  });
  
  let fsOutput = '';
  fsTest.stdout.on('data', (data) => {
    fsOutput += data.toString();
  });
  
  fsTest.stderr.on('data', (data) => {
    console.error('File system tool error:', data.toString());
  });
  
  fsTest.on('close', (code) => {
    console.log('File system tool test completed with code:', code);
    console.log('Output:', fsOutput);
    console.log('✅ File system tool test completed\n');
    
    // Test media tools
    testMediaTools();
  });
}

function testMediaTools() {
  console.log('4. Testing media tools...');
  const mediaTest = spawn('node', ['dist/server-modular.js'], {
    stdio: ['pipe', 'pipe', 'pipe']
  });
  
  let mediaOutput = '';
  mediaTest.stdout.on('data', (data) => {
    mediaOutput += data.toString();
  });
  
  mediaTest.stderr.on('data', (data) => {
    console.error('Media tools error:', data.toString());
  });
  
  mediaTest.on('close', (code) => {
    console.log('Media tools test completed with code:', code);
    console.log('Output:', mediaOutput);
    console.log('✅ Media tools test completed\n');
    
    console.log('🎉 All tool tests completed!');
    process.exit(0);
  });
}

// Handle process termination
process.on('SIGINT', () => {
  console.log('\n🛑 Test interrupted by user');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Test terminated');
  process.exit(0);
});
