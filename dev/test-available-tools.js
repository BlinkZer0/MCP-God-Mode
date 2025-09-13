#!/usr/bin/env node

/**
 * Test to see what tools are actually available in the MCP server
 */

import * as allTools from './dist/tools/index.js';

console.log('🔍 Checking available tool registration functions...');

const toolFunctions = Object.values(allTools).filter(fn => typeof fn === 'function' && fn.name.startsWith('register'));

console.log(`📊 Found ${toolFunctions.length} tool registration functions:`);

toolFunctions.forEach(fn => {
  console.log(`  - ${fn.name}`);
});

// Check specifically for tool_burglar
const toolBurglarFn = toolFunctions.find(fn => fn.name === 'registerToolBurglar');

if (toolBurglarFn) {
  console.log('\n✅ registerToolBurglar found in tool functions!');
} else {
  console.log('\n❌ registerToolBurglar NOT found in tool functions!');
}

// Check the export
if (allTools.registerToolBurglar) {
  console.log('✅ registerToolBurglar found in exports!');
} else {
  console.log('❌ registerToolBurglar NOT found in exports!');
}
