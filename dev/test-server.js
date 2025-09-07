// Simple test script to check server-refactored.js
console.log('Testing server-refactored.js...');

try {
  // Import the server
  const server = await import('./dist/server-refactored.js');
  console.log('✅ Server imported successfully');
} catch (error) {
  console.error('❌ Error importing server:', error.message);
  console.error('Stack:', error.stack);
}
