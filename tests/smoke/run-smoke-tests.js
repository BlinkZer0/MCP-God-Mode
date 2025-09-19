const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');

// Load the manifest
const manifestPath = path.join(__dirname, '..', 'tools.manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

// Track test results
const results = {
  total: 0,
  passed: 0,
  failed: 0,
  errors: []
};

// Function to run a single smoke test
async function runSmokeTest(tool, index, total) {
  return new Promise((resolve) => {
    results.total++;
    const testNum = `${index + 1}`.padStart(3, '0');
    
    try {
      if (!tool.smoke_test) {
        throw new Error('No smoke test defined');
      }
      
      const { cmd, args = [], timeout_ms = 5000 } = tool.smoke_test;
      
      // Create a child process for the smoke test
      const child = spawn(cmd, args, {
        timeout: timeout_ms,
        stdio: ['ignore', 'pipe', 'pipe']
      });
      
      let output = '';
      let errorOutput = '';
      
      child.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      child.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });
      
      child.on('close', (code) => {
        process.stdout.write(`[${testNum}/${total}] ${tool.name}... `);
        
        if (code === 0) {
          console.log('✅');
          results.passed++;
          resolve(true);
        } else {
          console.log('❌');
          results.failed++;
          results.errors.push({
            tool: tool.name,
            error: `Process exited with code ${code}`,
            command: `${cmd} ${args.join(' ')}`,
            output: output,
            error: errorOutput
          });
          resolve(false);
        }
      });
      
      child.on('error', (error) => {
        process.stdout.write(`[${testNum}/${total}] ${tool.name}... `);
        console.log('❌');
        results.failed++;
        results.errors.push({
          tool: tool.name,
          error: error.message,
          command: `${cmd} ${args.join(' ')}`
        });
        resolve(false);
      });
      
    } catch (error) {
      process.stdout.write(`[${testNum}/${total}] ${tool.name}... `);
      console.log('❌ (Invalid smoke test configuration)');
      results.failed++;
      results.errors.push({
        tool: tool.name,
        error: 'Invalid smoke test configuration',
        details: error.message
      });
      resolve(false);
    }
  });
}

// Run smoke tests
async function runAllTests() {
  console.log(`🚀 Running smoke tests for ${manifest.tools.length} tools...\n`);
  
  // Run tests in sequence to avoid overwhelming the system
  for (let i = 0; i < manifest.tools.length; i++) {
    await runSmokeTest(manifest.tools[i], i, manifest.tools.length);
  }
  
  // Print summary
  console.log('\n📊 Test Summary:');
  console.log(`✅ ${results.passed} passed`);
  console.log(`❌ ${results.failed} failed`);
  console.log(`📊 ${results.total} total`);
  
  // Print detailed errors if any
  if (results.errors.length > 0) {
    console.log('\n🔍 Error Details:');
    results.errors.forEach((err, idx) => {
      console.log(`\n${idx + 1}. ${err.tool}:`);
      console.log(`   Error: ${err.error}`);
      if (err.command) {
        console.log(`   Command: ${err.command}`);
      }
      if (err.details) {
        console.log(`   Details: ${err.details}`);
      }
      if (err.output) {
        console.log(`   Output: ${err.output.trim()}`);
      }
      if (err.error) {
        console.log(`   Error Output: ${err.error.trim()}`);
      }
    });
  }
  
  process.exit(results.failed > 0 ? 1 : 0);
}

// Start the tests
runAllTests().catch(console.error);
