// Simple test to verify server functionality
const { spawn } = require('child_process');

console.log('🧪 Testing MCP Server Parameter Descriptions...\n');

// Start the server
const server = spawn('node', ['dist/server-minimal.js'], {
  stdio: ['pipe', 'pipe', 'pipe']
});

console.log('📋 Server started. Testing tools...\n');

// Test the tools/list method
const listToolsMessage = {
  jsonrpc: "2.0",
  id: 1,
  method: "tools/list"
};

console.log('📤 Requesting tools list...');
server.stdin.write(JSON.stringify(listToolsMessage) + '\n');

// Handle server responses
server.stdout.on('data', (data) => {
  const output = data.toString().trim();
  if (output) {
    try {
      const response = JSON.parse(output);
      console.log('📥 Response received:');
      console.log(JSON.stringify(response, null, 2));
      
      if (response.result && response.result.tools) {
        console.log('\n🔧 Available Tools:');
        response.result.tools.forEach(tool => {
          console.log(`  - ${tool.name}: ${tool.description}`);
          if (tool.inputSchema && tool.inputSchema.properties) {
            console.log('    Parameters:');
            Object.entries(tool.inputSchema.properties).forEach(([paramName, paramSchema]) => {
              const description = paramSchema.description || 'No description';
              console.log(`      ${paramName}: ${description}`);
            });
          }
          console.log('');
        });
      }
      
      // Close server after response
      setTimeout(() => {
        console.log('✅ Test complete. Closing server...');
        server.kill();
        process.exit(0);
      }, 1000);
      
    } catch (e) {
      console.log('📥 Raw output:', output);
    }
  }
});

// Handle errors
server.stderr.on('data', (data) => {
  console.log('❌ Server error:', data.toString());
});

server.on('close', (code) => {
  console.log(`🔒 Server closed with code ${code}`);
});

// Timeout fallback
setTimeout(() => {
  console.log('⏰ Timeout reached. Closing server...');
  server.kill();
  process.exit(1);
}, 10000);
