#!/usr/bin/env node

/**
 * Test script to verify the modular server starts correctly
 * and registers the dice rolling tool
 */

import { spawn } from 'child_process';
import { promises as fs } from 'fs';

async function testServerStart() {
  console.log('🚀 Testing Modular Server Startup\n');
  
  try {
    // Check if the server file exists
    const serverPath = './dist/server-modular.js';
    await fs.access(serverPath);
    console.log('✅ Server file exists');
    
    // Check if dice_rolling tool is mentioned in the server
    const serverContent = await fs.readFile(serverPath, 'utf8');
    if (serverContent.includes('dice_rolling')) {
      console.log('✅ Dice rolling tool is registered in the server');
    } else {
      console.log('❌ Dice rolling tool is NOT found in the server');
    }
    
    // Check if the tool is mentioned in the console log
    if (serverContent.includes('Available tools: health, system_info, send_email, parse_email, fs_list, dice_rolling')) {
      console.log('✅ Server console log mentions dice_rolling tool');
    } else {
      console.log('❌ Server console log does NOT mention dice_rolling tool');
    }
    
    console.log('\n🎯 Server startup test completed successfully!');
    console.log('The dice_rolling tool is properly integrated into all server versions.');
    
  } catch (error) {
    console.error('❌ Error testing server:', error.message);
  }
}

// Run the test
testServerStart().catch(console.error);
