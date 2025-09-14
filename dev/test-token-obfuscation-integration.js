#!/usr/bin/env node

/**
 * Token Obfuscation Integration Test
 * Test if the token obfuscation tool is properly integrated into the MCP server
 */

import { registerTokenObfuscation } from './dist/tools/security/token_obfuscation.js';
import { registerTokenObfuscationNL } from './dist/tools/security/token_obfuscation_nl.js';

console.log('🧪 Testing Token Obfuscation Integration');
console.log('=======================================\n');

// Create a mock server to test registration
const mockServer = {
  registerTool: (name, toolDef, handler) => {
    console.log(`✅ Tool registered: ${name}`);
    console.log(`   Description: ${toolDef.description.substring(0, 100)}...`);
    console.log(`   Handler: ${typeof handler}`);
    return true;
  }
};

try {
  console.log('🔧 Testing registerTokenObfuscation...');
  registerTokenObfuscation(mockServer);
  console.log('✅ registerTokenObfuscation: SUCCESS\n');
  
  console.log('🔧 Testing registerTokenObfuscationNL...');
  registerTokenObfuscationNL(mockServer);
  console.log('✅ registerTokenObfuscationNL: SUCCESS\n');
  
  console.log('🎉 All token obfuscation tools integrated successfully!');
  console.log('✅ Integration test: PASSED');
  
} catch (error) {
  console.error('❌ Integration test failed:', error.message);
  console.error('❌ Integration test: FAILED');
  process.exit(1);
}
