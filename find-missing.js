const fs = require('fs');
const path = require('path');

// Load the manifest
const manifest = require('./tools.manifest.json');
const manifestTools = new Set(manifest.tools.map(t => t.name));

// Load the canonical list from add-missing-tools.js
const addMissingToolsPath = path.join(__dirname, 'scripts', 'add-missing-tools.js');
const addMissingToolsContent = fs.readFileSync(addMissingToolsPath, 'utf8');
const allToolsMatch = addMissingToolsContent.match(/const ALL_TOOL_NAMES = \[([\s\S]*?)\]/);
if (!allToolsMatch) {
  console.error('Could not find ALL_TOOL_NAMES in add-missing-tools.js');
  process.exit(1);
}

// Extract tool names from the array
const allTools = allToolsMatch[1]
  .split('\n')
  .map(line => line.trim())
  .filter(line => line && line !== ']' && line !== '[')
  .map(line => line.replace(/[",]/g, '').trim())
  .filter(Boolean);

console.log(`Manifest tools: ${manifestTools.size}`);
console.log(`Canonical tools: ${allTools.length}`);

// Find missing tools
const missing = allTools.filter(tool => !manifestTools.has(tool));

if (missing.length > 0) {
  console.log('\nMissing tools:');
  console.log(missing.map(t => `- ${t}`).join('\n'));
} else {
  console.log('\nNo tools are missing from the manifest.');
  
  // Check for duplicates in the manifest
  const toolCounts = {};
  manifest.tools.forEach(tool => {
    toolCounts[tool.name] = (toolCounts[tool.name] || 0) + 1;
  });
  
  const duplicates = Object.entries(toolCounts).filter(([_, count]) => count > 1);
  if (duplicates.length > 0) {
    console.log('\nDuplicate tools in manifest:');
    console.log(duplicates.map(([name, count]) => `- ${name} (${count} entries)`).join('\n'));
  }
}
