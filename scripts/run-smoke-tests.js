#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');

const execPromise = util.promisify(exec);

// Load the manifest
const manifestPath = path.join(__dirname, '..', 'tools.manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

async function runSmokeTest(tool) {
  const { name, smoke_test } = tool;
  const testCmd = smoke_test.cmd;
  const testArgs = smoke_test.args || [];
  const timeout = smoke_test.timeout_ms || 10000;
  const expectCode = smoke_test.expect_code || 0;

  console.log(`\n🚀 Running smoke test for ${name}...`);
  
  try {
    const { stdout, stderr } = await execPromise(
      [testCmd, ...testArgs].join(' '),
      { 
        timeout,
        shell: true,
        env: { ...process.env, ...process.env }
      }
    );

    if (stderr) {
      console.log(`⚠️  ${name} stderr:`, stderr);
    }
    
    console.log(`✅ ${name} smoke test passed`);
    return { success: true, name };
  } catch (error) {
    console.error(`❌ ${name} smoke test failed:`, error.message);
    return { success: false, name, error };
  }
}

async function runAllSmokeTests() {
  console.log('🚀 Starting smoke tests...');
  
  const results = [];
  let successCount = 0;
  let failureCount = 0;

  // Run tests sequentially to avoid conflicts
  for (const tool of manifest.tools) {
    const result = await runSmokeTest(tool);
    results.push(result);
    
    if (result.success) {
      successCount++;
    } else {
      failureCount++;
    }
  }

  // Print summary
  console.log('\n📊 Test Summary:');
  console.log(`✅ ${successCount} passed`);
  console.log(`❌ ${failureCount} failed`);
  
  if (failureCount > 0) {
    console.log('\nFailed tests:');
    results
      .filter(r => !r.success)
      .forEach(r => console.log(`- ${r.name}: ${r.error.message}`));
    
    process.exit(1);
  }
  
  console.log('\n🎉 All smoke tests passed!');
}

// Run the tests
runAllSmokeTests().catch(error => {
  console.error('Fatal error running smoke tests:', error);
  process.exit(1);
});
