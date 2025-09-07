#!/usr/bin/env node

// Simple test to check if server starts without duplicate registration errors
const { spawn } = require('child_process');

console.log('Testing server startup...');

const server = spawn('node', ['dist/server-refactored.js'], {
  stdio: ['pipe', 'pipe', 'pipe']
});

let output = '';
let errorOutput = '';

server.stdout.on('data', (data) => {
  output += data.toString();
});

server.stderr.on('data', (data) => {
  errorOutput += data.toString();
});

server.on('close', (code) => {
  console.log('Server process closed with code:', code);
  console.log('STDOUT:', output);
  console.log('STDERR:', errorOutput);
  
  // Check for duplicate registration errors
  if (errorOutput.includes('already registered')) {
    console.log('❌ DUPLICATE REGISTRATION ERRORS FOUND');
    process.exit(1);
  } else {
    console.log('✅ No duplicate registration errors found');
    process.exit(0);
  }
});

// Kill the server after 3 seconds
setTimeout(() => {
  server.kill();
}, 3000);
