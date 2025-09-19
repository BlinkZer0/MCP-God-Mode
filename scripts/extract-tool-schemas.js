#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Function to extract schema information from a tool file
function extractSchemaFromTool(toolPath) {
  try {
    const content = fs.readFileSync(toolPath, 'utf8');
    
    // Look for registerTool calls and extract inputSchema
    const registerToolMatch = content.match(/server\.registerTool\(\s*["']([^"']+)["']\s*,\s*\{[\s\S]*?inputSchema:\s*\{([\s\S]*?)\}/);
    
    if (!registerToolMatch) {
      return null;
    }
    
    const toolName = registerToolMatch[1];
    const inputSchemaContent = registerToolMatch[2];
    
    // Extract individual parameters
    const params = [];
    
    // Look for z.enum patterns
    const enumMatches = [...inputSchemaContent.matchAll(/(\w+):\s*z\.enum\(\[(.*?)\]\)\.describe\(["'](.*?)["']\)/g)];
    enumMatches.forEach(match => {
      const [, paramName, enumValues, description] = match;
      const values = enumValues.split(',').map(v => v.trim().replace(/['"]/g, ''));
      params.push({
        name: paramName,
        type: `enum[${values.join(',')}]`,
        required: !inputSchemaContent.includes(`${paramName}:`) || inputSchemaContent.includes(`${paramName}:`) && !inputSchemaContent.includes('.optional()'),
        description: description
      });
    });
    
    // Look for z.string patterns
    const stringMatches = [...inputSchemaContent.matchAll(/(\w+):\s*z\.string\(\)(?:\.optional\(\))?\s*\.describe\(["'](.*?)["']\)/g)];
    stringMatches.forEach(match => {
      const [, paramName, description] = match;
      const isOptional = inputSchemaContent.includes(`${paramName}:`) && inputSchemaContent.includes('.optional()');
      params.push({
        name: paramName,
        type: "string",
        required: !isOptional,
        description: description
      });
    });
    
    // Look for z.number patterns
    const numberMatches = [...inputSchemaContent.matchAll(/(\w+):\s*z\.number\(\)(?:\.optional\(\))?\s*\.describe\(["'](.*?)["']\)/g)];
    numberMatches.forEach(match => {
      const [, paramName, description] = match;
      const isOptional = inputSchemaContent.includes(`${paramName}:`) && inputSchemaContent.includes('.optional()');
      params.push({
        name: paramName,
        type: "number",
        required: !isOptional,
        description: description
      });
    });
    
    // Look for z.boolean patterns
    const booleanMatches = [...inputSchemaContent.matchAll(/(\w+):\s*z\.boolean\(\)(?:\.optional\(\))?\s*\.describe\(["'](.*?)["']\)/g)];
    booleanMatches.forEach(match => {
      const [, paramName, description] = match;
      const isOptional = inputSchemaContent.includes(`${paramName}:`) && inputSchemaContent.includes('.optional()');
      params.push({
        name: paramName,
        type: "boolean",
        required: !isOptional,
        description: description
      });
    });
    
    // Look for z.array patterns
    const arrayMatches = [...inputSchemaContent.matchAll(/(\w+):\s*z\.array\(z\.string\(\)\)(?:\.optional\(\))?\s*\.describe\(["'](.*?)["']\)/g)];
    arrayMatches.forEach(match => {
      const [, paramName, description] = match;
      const isOptional = inputSchemaContent.includes(`${paramName}:`) && inputSchemaContent.includes('.optional()');
      params.push({
        name: paramName,
        type: "array[string]",
        required: !isOptional,
        description: description
      });
    });
    
    return {
      toolName,
      params: params.filter((param, index, self) => 
        index === self.findIndex(p => p.name === param.name)
      )
    };
    
  } catch (error) {
    console.error(`Error extracting schema from ${toolPath}:`, error.message);
    return null;
  }
}

// Main function
function main() {
  const toolsDir = path.join(__dirname, '..', 'dev', 'dist', 'tools');
  const manifestPath = path.join(__dirname, '..', 'tools.manifest.json');
  
  // Load current manifest
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  
  console.log('🔍 Extracting schemas from tool implementations...\n');
  
  // Find tools with empty args
  const emptyArgsTools = manifest.tools.filter(tool => 
    Array.isArray(tool.args) && tool.args.length === 0
  );
  
  console.log(`Found ${emptyArgsTools.length} tools with empty args arrays\n`);
  
  let updatedCount = 0;
  
  // Process each tool with empty args
  emptyArgsTools.forEach(tool => {
    const toolName = tool.name;
    
    // Try to find the corresponding implementation file
    const possiblePaths = [
      path.join(toolsDir, 'wireless', `${toolName}.js`),
      path.join(toolsDir, 'network', `${toolName}.js`),
      path.join(toolsDir, 'security', `${toolName}.js`),
      path.join(toolsDir, 'web', `${toolName}.js`),
      path.join(toolsDir, 'media', `${toolName}.js`),
      path.join(toolsDir, 'system', `${toolName}.js`),
      path.join(toolsDir, 'forensics', `${toolName}.js`),
      path.join(toolsDir, 'penetration', `${toolName}.js`),
      path.join(toolsDir, 'utilities', `${toolName}.js`),
      path.join(toolsDir, 'mobile', `${toolName}.js`),
      path.join(toolsDir, 'email', `${toolName}.js`),
      path.join(toolsDir, 'file_system', `${toolName}.js`),
      path.join(toolsDir, 'process', `${toolName}.js`),
      path.join(toolsDir, 'radio', `${toolName}.js`),
      path.join(toolsDir, 'bluetooth', `${toolName}.js`),
      path.join(toolsDir, 'cloud', `${toolName}.js`),
      path.join(toolsDir, 'ai', `${toolName}.js`),
      path.join(toolsDir, 'legal', `${toolName}.js`),
      path.join(toolsDir, 'virtualization', `${toolName}.js`),
      path.join(toolsDir, 'windows', `${toolName}.js`),
      path.join(toolsDir, 'git', `${toolName}.js`),
      path.join(toolsDir, 'core', `${toolName}.js`),
      path.join(toolsDir, `${toolName}.js`)
    ];
    
    let foundPath = null;
    for (const possiblePath of possiblePaths) {
      if (fs.existsSync(possiblePath)) {
        foundPath = possiblePath;
        break;
      }
    }
    
    if (foundPath) {
      const schema = extractSchemaFromTool(foundPath);
      if (schema && schema.params.length > 0) {
        console.log(`✅ Found schema for ${toolName}: ${schema.params.length} parameters`);
        
        // Update the tool in manifest
        const toolIndex = manifest.tools.findIndex(t => t.name === toolName);
        if (toolIndex !== -1) {
          manifest.tools[toolIndex].args = schema.params;
          updatedCount++;
        }
      } else {
        console.log(`⚠️  No schema extracted for ${toolName}`);
      }
    } else {
      console.log(`❌ No implementation file found for ${toolName}`);
    }
  });
  
  console.log(`\n📊 Summary: Updated ${updatedCount} tools with proper schemas`);
  
  if (updatedCount > 0) {
    // Write updated manifest
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
    console.log(`✅ Updated manifest saved to ${manifestPath}`);
  }
}

if (require.main === module) {
  main();
}
