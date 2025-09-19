const fs = require('fs');
const path = require('path');

// Load the manifest
const manifestPath = path.join(__dirname, 'tools.manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

console.log('Checking smoke tests for all tools...\n');

// Check each tool's smoke test configuration
manifest.tools.forEach((tool, index) => {
  console.log(`[${index + 1}/${manifest.tools.length}] ${tool.name}`);
  
  if (!tool.smoke_test) {
    console.log('   ❌ No smoke test configuration');
    return;
  }
  
  console.log('   ✅ Has smoke test');
  console.log(`   Command: ${tool.smoke_test.cmd} ${(tool.smoke_test.args || []).join(' ')}`);
  console.log(`   Timeout: ${tool.smoke_test.timeout_ms || 5000}ms\n`);
});

console.log(`\nChecked ${manifest.tools.length} tools.`);
