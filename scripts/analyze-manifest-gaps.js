#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Load the manifest
const manifestPath = path.join(__dirname, '..', 'tools.manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

// Load the tools index to get all available tools
const toolsIndexPath = path.join(__dirname, '..', 'dev', 'dist', 'tools', 'index.js');
const toolsIndexContent = fs.readFileSync(toolsIndexPath, 'utf8');

// Extract all export statements from tools index
const exportRegex = /export \{ (register\w+) \}/g;
const availableTools = [];
let match;
while ((match = exportRegex.exec(toolsIndexContent)) !== null) {
  const registerFunctionName = match[1];
  // Convert registerFunctionName to tool name (remove 'register' prefix and convert to snake_case)
  const toolName = registerFunctionName
    .replace(/^register/, '')
    .replace(/([A-Z])/g, '_$1')
    .toLowerCase()
    .replace(/^_/, '');
  availableTools.push({
    registerFunction: registerFunctionName,
    toolName: toolName
  });
}

// Get tools from manifest
const manifestTools = manifest.tools.map(tool => tool.name);

console.log('🔍 MCP God Mode Tools Manifest Analysis');
console.log('=====================================\n');

console.log(`📊 Available Tools: ${availableTools.length}`);
console.log(`📋 Manifest Tools: ${manifestTools.length}\n`);

// Find tools with empty args
const emptyArgsTools = manifest.tools.filter(tool => 
  Array.isArray(tool.args) && tool.args.length === 0
);

console.log(`⚠️  Tools with Empty Args: ${emptyArgsTools.length}`);
emptyArgsTools.forEach(tool => {
  console.log(`   - ${tool.name} (${tool.category})`);
});

// Find potential missing tools by comparing naming patterns
console.log('\n🔍 Potential Missing Tools from Manifest:');
const potentialMissing = [];

availableTools.forEach(({ registerFunction, toolName }) => {
  // Check various naming patterns
  const possibleNames = [
    toolName,
    toolName.replace(/_/g, ''),
    registerFunction.replace(/^register/, '').toLowerCase(),
    registerFunction.replace(/^register/, '').replace(/([A-Z])/g, '_$1').toLowerCase().replace(/^_/, '')
  ];
  
  const found = possibleNames.some(name => 
    manifestTools.some(manifestTool => 
      manifestTool.toLowerCase() === name.toLowerCase() ||
      manifestTool.replace(/_/g, '').toLowerCase() === name.replace(/_/g, '').toLowerCase()
    )
  );
  
  if (!found) {
    potentialMissing.push({ registerFunction, toolName, possibleNames });
  }
});

potentialMissing.forEach(({ registerFunction, toolName, possibleNames }) => {
  console.log(`   - ${registerFunction} -> ${toolName} (possible names: ${possibleNames.join(', ')})`);
});

console.log(`\n📈 Summary:`);
console.log(`   - Tools needing args schemas: ${emptyArgsTools.length}`);
console.log(`   - Potentially missing tools: ${potentialMissing.length}`);
console.log(`   - Total tools to review: ${emptyArgsTools.length + potentialMissing.length}`);

// Output detailed analysis for tools with empty args
console.log('\n📝 First 10 Tools Needing Schema Updates:');
console.log('=========================================');

emptyArgsTools.slice(0, 10).forEach(tool => {
  console.log(`\n${tool.name}:`);
  console.log(`  Category: ${tool.category}`);
  console.log(`  Invoke: ${tool.invoke}`);
  console.log(`  Privileges: ${tool.requires_privilege}`);
});
