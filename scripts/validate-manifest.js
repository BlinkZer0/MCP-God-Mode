#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const Ajv = require('ajv').default;
const addFormats = require('ajv-formats');

// Load the manifest
const manifestPath = path.join(__dirname, '..', 'tools.manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

// Define the schema for validation
const schema = {
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "MCP God Mode Tools Manifest",
  "type": "object",
  "properties": {
    "tools": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name", "category", "entry_file", "invoke", "args", "smoke_test"],
        "properties": {
          "name": {"type": "string"},
          "category": {"type": "string"},
          "entry_file": {"type": "string"},
          "invoke": {"type": "string"},
          "args": {
            "type": "array",
            "items": {
              "type": "object",
              "required": ["name", "type", "required", "description"],
              "properties": {
                "name": {"type": "string"},
                "type": {"type": "string"},
                "required": {"type": "boolean"},
                "description": {"type": "string"},
                "default": {}
              }
            }
          },
          "env_vars": {"type": "array", "items": {"type": "string"}},
          "requires_privilege": {"type": "boolean"},
          "side_effects": {"type": "string"},
          "safe_mode": {"type": "boolean"},
          "tags": {"type": "array", "items": {"type": "string"}},
          "smoke_test": {
            "type": "object",
            "required": ["cmd", "args", "expect_code", "timeout_ms"],
            "properties": {
              "cmd": {"type": "string"},
              "args": {"type": "array"},
              "expect_code": {"type": "integer"},
              "timeout_ms": {"type": "integer"}
            }
          }
        }
      }
    }
  },
  "required": ["tools"]
};

// Validate the manifest
const ajv = new Ajv({
  allErrors: true,
  strict: true
});
addFormats(ajv);

const validate = ajv.compile(schema);
const valid = validate(manifest);

if (!valid) {
  console.error('❌ Validation failed:');
  console.error(JSON.stringify(validate.errors, null, 2));
  process.exit(1);
}

console.log('✅ Manifest is valid!');

// Check for duplicate tool names
const toolNames = manifest.tools.map(tool => tool.name);
const duplicateTools = toolNames.filter((name, index) => toolNames.indexOf(name) !== index);

if (duplicateTools.length > 0) {
  console.error('❌ Duplicate tool names found:', duplicateTools);
  process.exit(1);
}

// Check that all entry files exist
let allFilesExist = true;
for (const tool of manifest.tools) {
  const filePath = path.join(process.cwd(), tool.entry_file);
  if (!fs.existsSync(filePath)) {
    console.error(`❌ Entry file not found for ${tool.name}: ${filePath}`);
    allFilesExist = false;
  }
}

if (!allFilesExist) {
  process.exit(1);
}

console.log('✅ All entry files exist');
console.log(`\nFound ${manifest.tools.length} tools in the manifest.`);
