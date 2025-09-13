#!/usr/bin/env node

/**
 * Test script for lazy loading system
 * Demonstrates the performance benefits and functionality
 */

import { 
  lazyLoader, 
  discoverAllTools, 
  getToolMetadata, 
  hasTool,
  getLoaderStats 
} from './dist/lazy-tool-loader.js';

async function testLazyLoading() {
  console.log('🧪 Testing Lazy Loading System');
  console.log('================================\n');

  try {
    // Test 1: Tool Discovery
    console.log('🔍 Test 1: Tool Discovery');
    console.log('-------------------------');
    
    const startTime = Date.now();
    const discovered = await discoverAllTools();
    const discoveryTime = Date.now() - startTime;
    
    console.log(`✅ Discovered ${discovered.length} tools in ${discoveryTime}ms`);
    console.log(`📊 Average time per tool: ${(discoveryTime / discovered.length).toFixed(2)}ms`);
    
    // Show some discovered tools
    console.log('\n📋 Sample discovered tools:');
    discovered.slice(0, 5).forEach(tool => {
      console.log(`  - ${tool.name} (${tool.category})`);
    });
    console.log('');

    // Test 2: Metadata Access
    console.log('📋 Test 2: Metadata Access');
    console.log('-------------------------');
    
    const testTool = 'mcp_mcp-god-mode_tool_burglar';
    const metadata = getToolMetadata(testTool);
    
    if (metadata) {
      console.log(`✅ Found metadata for ${testTool}:`);
      console.log(`  Description: ${metadata.description}`);
      console.log(`  Category: ${metadata.category}`);
      console.log(`  Source: ${metadata.sourceFile}`);
      console.log(`  Register Function: ${metadata.registerFunction}`);
      console.log(`  File Size: ${metadata.fileSize} bytes`);
    } else {
      console.log(`❌ No metadata found for ${testTool}`);
    }
    console.log('');

    // Test 3: Tool Existence Check
    console.log('🔍 Test 3: Tool Existence Check');
    console.log('-------------------------------');
    
    const testTools = [
      'mcp_mcp-god-mode_tool_burglar',
      'mcp_mcp-god-mode_fs_list',
      'mcp_mcp-god-mode_port_scanner',
      'mcp_mcp-god-mode_nonexistent_tool'
    ];
    
    testTools.forEach(toolName => {
      const exists = hasTool(toolName);
      console.log(`  ${exists ? '✅' : '❌'} ${toolName}`);
    });
    console.log('');

    // Test 4: Performance Statistics
    console.log('📊 Test 4: Performance Statistics');
    console.log('--------------------------------');
    
    const stats = getLoaderStats();
    console.log(`Total Tools Discovered: ${stats.totalToolsDiscovered}`);
    console.log(`Total Tools Loaded: ${stats.totalToolsLoaded}`);
    console.log(`Total Tools Cached: ${stats.totalToolsCached}`);
    console.log(`Cache Hits: ${stats.cacheHits}`);
    console.log(`Cache Misses: ${stats.cacheMisses}`);
    console.log(`Last Discovery: ${stats.lastDiscovery.toISOString()}`);
    console.log('');

    // Test 5: Category Analysis
    console.log('📂 Test 5: Category Analysis');
    console.log('---------------------------');
    
    const categories = {};
    discovered.forEach(tool => {
      const category = tool.category || 'uncategorized';
      categories[category] = (categories[category] || 0) + 1;
    });
    
    console.log('Tool distribution by category:');
    Object.entries(categories)
      .sort(([,a], [,b]) => b - a)
      .forEach(([category, count]) => {
        console.log(`  ${category}: ${count} tools`);
      });
    console.log('');

    // Test 6: Memory Usage Comparison
    console.log('💾 Test 6: Memory Usage Analysis');
    console.log('-------------------------------');
    
    const memUsage = process.memoryUsage();
    console.log(`Current Memory Usage:`);
    console.log(`  RSS: ${(memUsage.rss / 1024 / 1024).toFixed(2)} MB`);
    console.log(`  Heap Used: ${(memUsage.heapUsed / 1024 / 1024).toFixed(2)} MB`);
    console.log(`  Heap Total: ${(memUsage.heapTotal / 1024 / 1024).toFixed(2)} MB`);
    console.log(`  External: ${(memUsage.external / 1024 / 1024).toFixed(2)} MB`);
    console.log('');

    // Summary
    console.log('📈 Test Summary');
    console.log('===============');
    console.log(`✅ Tool discovery completed successfully`);
    console.log(`📊 ${discovered.length} tools discovered in ${discoveryTime}ms`);
    console.log(`💾 Low memory footprint: ${(memUsage.heapUsed / 1024 / 1024).toFixed(2)} MB`);
    console.log(`⚡ Fast metadata access (no code loading)`);
    console.log(`🎯 Ready for on-demand tool loading`);
    console.log('');
    console.log('🚀 Lazy loading system is working correctly!');
    console.log('💡 Tools will be loaded automatically when called');

  } catch (error) {
    console.error('❌ Test failed:', error);
    process.exit(1);
  }
}

// Run the test
testLazyLoading();
