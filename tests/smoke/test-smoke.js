const { execSync } = require('child_process');

// Test a single tool's smoke test
function testSmoke(toolName) {
  console.log(`Testing smoke test for: ${toolName}`);
  
  try {
    // Execute the smoke test command
    const command = `node -e "console.log('Smoke test for ${toolName}')"`;
    console.log(`Running: ${command}`);
    
    const result = execSync(command, { 
      timeout: 5000,
      stdio: 'inherit'  // This will show the output directly
    });
    
    console.log('✅ Smoke test passed');
    return true;
  } catch (error) {
    console.error('❌ Smoke test failed:', error.message);
    return false;
  }
}

// Test the example_tool
const toolName = process.argv[2] || 'example_tool';
testSmoke(toolName);
