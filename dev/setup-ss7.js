#!/usr/bin/env node

/**
 * SS7 Setup Script
 * ================
 * 
 * This script helps set up SS7 configuration for the MCP God Mode project.
 * It creates the necessary configuration file and sets up the environment.
 */

import fs from 'fs';
import path from 'path';
import { ss7ConfigManager } from './dist/config/ss7-config.js';

async function setupSS7() {
  console.log('🔧 Setting up SS7 configuration...\n');

  try {
    // Set the encryption key
    process.env.SS7_ENCRYPTION_KEY = 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456';

    // Create default configuration
    const config = ss7ConfigManager.getDefaultConfig();
    
    // Set test values
    config.point_code = '12345';
    config.global_title = '1234567890';
    config.hlr_address = 'hlr.test.com';
    config.network_operator = 'Test Network Operator';
    config.authorized_users = ['admin', 'test_user', 'mcp_user'];
    config.license_type = 'test';
    config.expiration_date = '2025-12-31';

    // Save configuration
    const saved = await ss7ConfigManager.saveConfig(config);
    
    if (saved) {
      console.log('✅ SS7 configuration created successfully!');
      console.log('📁 Configuration file: dev/config/ss7-config.json');
      console.log('🔐 Encryption key set in environment');
      console.log('\n📋 Configuration Details:');
      console.log(`   Network Operator: ${config.network_operator}`);
      console.log(`   License Type: ${config.license_type}`);
      console.log(`   Authorized Users: ${config.authorized_users.length}`);
      console.log(`   Rate Limits: ${config.rate_limits.queries_per_minute}/min, ${config.rate_limits.queries_per_hour}/hour, ${config.rate_limits.queries_per_day}/day`);
      console.log('\n🚀 SS7 functionality is now ENABLED!');
      console.log('\n💡 To use SS7 in your environment, set:');
      console.log('   Windows: set SS7_ENCRYPTION_KEY=a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456');
      console.log('   Linux/Mac: export SS7_ENCRYPTION_KEY=a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456');
    } else {
      console.log('❌ Failed to save SS7 configuration');
    }

  } catch (error) {
    console.error('❌ Error setting up SS7:', error.message);
  }
}

// Run setup if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  setupSS7();
}

export { setupSS7 };
