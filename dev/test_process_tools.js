// Test script to verify process tools are loaded
const { registerProcRun, registerProcRunElevated, registerProcRunRemote } = require('./dist/tools/process/proc_run.js');

console.log('Testing process tools...');

// Mock server object
const mockServer = {
  registerTool: (name, config, handler) => {
    console.log(`✅ Tool registered: ${name}`);
    console.log(`   Description: ${config.description}`);
    return true;
  }
};

try {
  console.log('\n1. Testing registerProcRun...');
  registerProcRun(mockServer);
  
  console.log('\n2. Testing registerProcRunElevated...');
  registerProcRunElevated(mockServer);
  
  console.log('\n3. Testing registerProcRunRemote...');
  registerProcRunRemote(mockServer);
  
  console.log('\n✅ All process tools registered successfully!');
} catch (error) {
  console.error('❌ Error testing process tools:', error.message);
}
