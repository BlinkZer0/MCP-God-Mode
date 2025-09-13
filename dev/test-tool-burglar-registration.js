#!/usr/bin/env node

/**
 * Test tool_burglar registration specifically
 */

import * as allTools from './dist/tools/index.js';

console.log('🧪 Testing tool_burglar registration...');

// Get all tool registration functions
const toolFunctions = Object.values(allTools).filter(fn => typeof fn === 'function' && fn.name.startsWith('register'));

console.log(`📊 Found ${toolFunctions.length} tool functions`);
console.log('🔍 Looking for registerToolBurglar...');

const burglarFunction = toolFunctions.find(fn => fn.name === 'registerToolBurglar');

if (burglarFunction) {
  console.log('✅ Found registerToolBurglar function');
  
  // Create a mock server to test registration
  const mockServer = {
    registerTool: (name, config, handler) => {
      console.log(`🔧 Mock server: Registering tool "${name}"`);
      console.log(`   Description: ${config.description}`);
      console.log(`   Input schema keys: ${Object.keys(config.inputSchema || {}).join(', ')}`);
      return true;
    }
  };
  
  try {
    console.log('🎯 Attempting to register tool_burglar...');
    burglarFunction(mockServer);
    console.log('✅ tool_burglar registration successful!');
  } catch (error) {
    console.error('❌ tool_burglar registration failed:', error);
    console.error('Stack trace:', error.stack);
  }
} else {
  console.log('❌ registerToolBurglar function not found');
  console.log('Available functions:', toolFunctions.map(fn => fn.name));
}

console.log('\n🔍 Checking dependencies...');

// Check if required dependencies exist
try {
  const { fetchSourceRepos, scanForMcpTools } = await import('./dist/utils/repoFetcher.js');
  console.log('✅ repoFetcher.js available');
} catch (error) {
  console.error('❌ repoFetcher.js missing:', error.message);
}

try {
  const { planConflicts, applyWritePlan, writeDocs, buildRollbackPlan, moveLocalTool, exportLocalTool } = await import('./dist/utils/burglarOps.js');
  console.log('✅ burglarOps.js available');
} catch (error) {
  console.error('❌ burglarOps.js missing:', error.message);
}

try {
  const { runLicenseCheck } = await import('./dist/utils/license.js');
  console.log('✅ license.js available');
} catch (error) {
  console.error('❌ license.js missing:', error.message);
}

try {
  const { parseNL } = await import('./dist/utils/nl_router.js');
  console.log('✅ nl_router.js available');
} catch (error) {
  console.error('❌ nl_router.js missing:', error.message);
}

try {
  const { listVendoredSources, listLocalTools, enableTool, disableTool, renameTool, ensureRegisteredParity } = await import('./dist/utils/registry.js');
  console.log('✅ registry.js available');
} catch (error) {
  console.error('❌ registry.js missing:', error.message);
}
