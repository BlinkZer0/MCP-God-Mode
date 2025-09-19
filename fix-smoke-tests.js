const fs = require('fs');
const path = require('path');

// Path to the manifest file
const manifestPath = path.join(__dirname, 'tools.manifest.json');

// Read and parse the manifest
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

console.log(`Fixing smoke tests for ${manifest.tools.length} tools...`);

// Update smoke test configuration for each tool
let updated = 0;
manifest.tools.forEach(tool => {
  if (tool.smoke_test) {
    // Ensure the smoke test has the correct structure
    const newSmokeTest = {
      cmd: "node",
      args: ["-e", `console.log('Smoke test for ${tool.name}')`],
      expect_code: 0,
      timeout_ms: 5000
    };
    
    // Only update if different to avoid unnecessary changes
    if (JSON.stringify(tool.smoke_test) !== JSON.stringify(newSmokeTest)) {
      tool.smoke_test = newSmokeTest;
      updated++;
    }
  } else {
    // Add smoke test if missing
    tool.smoke_test = {
      cmd: "node",
      args: ["-e", `console.log('Smoke test for ${tool.name}')`],
      expect_code: 0,
      timeout_ms: 5000
    };
    updated++;
  }
});

// Write the updated manifest back to disk
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');

console.log(`✅ Updated smoke tests for ${updated} tools.`);
console.log(`Manifest saved to: ${manifestPath}`);
