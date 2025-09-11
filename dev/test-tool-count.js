#!/usr/bin/env node

// Test script to count tools in server-refactored.js
import * as allTools from "./dist/tools/index.js";

console.log("🔧 Tool Count Analysis for server-refactored.js");
console.log("=" .repeat(50));

const toolFunctions = Object.values(allTools);
console.log(`📊 Total tool functions imported: ${toolFunctions.length}`);

// Count by category
const categories = {};
Object.keys(allTools).forEach(key => {
  const category = key.replace(/^register/, '').replace(/([A-Z])/g, ' $1').trim();
  const baseCategory = category.split(' ')[0].toLowerCase();
  categories[baseCategory] = (categories[baseCategory] || 0) + 1;
});

console.log("\n📋 Tools by category:");
Object.entries(categories)
  .sort(([,a], [,b]) => b - a)
  .forEach(([category, count]) => {
    console.log(`   ${category}: ${count} tools`);
  });

console.log(`\n✅ Total tools available: ${toolFunctions.length}`);
console.log("🎯 server-refactored.js should now be populating with all tools!");
