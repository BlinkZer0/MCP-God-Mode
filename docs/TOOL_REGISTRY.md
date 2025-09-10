# Tool Registry System

## Overview

The Tool Registry is a unified system for managing tool registration across MCP God Mode servers. It eliminates duplicate tool registration issues by providing centralized tool management with signature-based conflict detection and automatic deduplication.

## Features

- **Unified Registration**: All tools flow through a single registry regardless of server type
- **Signature-Based Deduplication**: Identical tools are automatically deduplicated
- **Conflict Detection**: Hard errors on signature conflicts with detailed diagnostics
- **Source Tracking**: Track which module/file registered each tool
- **Comprehensive Diagnostics**: Detailed reporting and statistics
- **Cross-Platform Support**: Works across all MCP God Mode server variants

## Architecture

### Core Components

1. **ToolRegistry Class**: Singleton registry managing all tool registrations
2. **ToolDefinition Interface**: Standardized tool definition structure
3. **Signature Computation**: SHA-256 based tool signatures for comparison
4. **Conflict Detection**: Advanced conflict detection and reporting

### Integration Points

- **Refactored Server**: `dev/src/server-refactored.ts`
- **Modular Server**: `dev/src/server-modular.ts`
- **Tool Index**: `dev/src/tools/index.ts`

## Usage

### Basic Registration

```typescript
import { ToolRegistry, registerTool } from './core/tool-registry.js';

const tool: ToolDefinition = {
  name: 'my_tool',
  description: 'My custom tool',
  inputSchema: {
    type: 'object',
    properties: {
      param: { type: 'string' }
    }
  }
};

// Register with source tracking
const wasRegistered = registerTool(tool, 'my-module');
if (!wasRegistered) {
  console.log('Tool was deduplicated');
}
```

### Server Integration

Both refactored and modular servers automatically integrate with the ToolRegistry:

```typescript
// In server files - automatic integration
server.registerTool('tool_name', toolDef, handler);
// ↓ Automatically flows through ToolRegistry
// ↓ Duplicates are deduplicated
// ↓ Conflicts throw errors
```

### Diagnostics

Enable detailed diagnostics with environment variable:

```bash
LOG_TOOL_REGISTRY=1 npm run start:refactored
```

Output includes:
- Tool registration status
- Deduplication statistics
- Conflict detection
- Source tracking
- Comprehensive diagnostic report

## Configuration

### Environment Variables

- `LOG_TOOL_REGISTRY=1`: Enable detailed registry diagnostics
- `MCPGM_FLIPPER_ENABLED=true`: Enable Flipper Zero tools (affects tool count)

### Registry Statistics

The registry tracks:
- Total tools registered
- Duplicates deduplicated
- Conflicts detected
- Tools by source
- Last update timestamp

## Conflict Resolution

### Signature Conflicts

When tools have the same name but different signatures:

```
❌ [ToolRegistry] Duplicate tool 'conflict_tool' with different signatures detected!
Existing: source1 (a1b2c3d4e5f6g7h8)
New: source2 (x9y8z7w6v5u4t3s2)
Please rename one of the tools or merge their schemas.
```

**Resolution**: Rename one tool or merge their schemas to be identical.

### Signature Collisions

When different tools have identical signatures:

```
❌ [ToolRegistry] Tool signature collision detected!
Tool 'tool_one' and 'tool_two' have identical signatures.
This may indicate duplicate tool definitions.
```

**Resolution**: Ensure tools have unique schemas or combine them if they're truly identical.

## Troubleshooting

### Common Issues

1. **"Duplicate tool with different signatures"**
   - **Cause**: Two tools with same name but different schemas
   - **Fix**: Rename one tool or merge schemas

2. **"Tool signature collision"**
   - **Cause**: Different tools with identical schemas
   - **Fix**: Make schemas unique or combine tools

3. **Tools not appearing**
   - **Cause**: Tool was deduplicated
   - **Fix**: Check LOG_TOOL_REGISTRY output for deduplication messages

4. **Inconsistent tool counts**
   - **Cause**: Different servers loading different tool sets
   - **Fix**: Ensure both servers use same tool configuration

### Diagnostic Commands

```bash
# Enable detailed logging
LOG_TOOL_REGISTRY=1 npm run start:refactored

# Check tool counts
npm run smoke

# Compare server outputs
LOG_TOOL_REGISTRY=1 npm run start:refactored > refactored.log
LOG_TOOL_REGISTRY=1 npm run start:modular > modular.log
diff refactored.log modular.log
```

### Registry Report

Generate a comprehensive registry report:

```typescript
import { generateRegistryReport } from './core/tool-registry.js';

console.log(generateRegistryReport());
```

Sample output:
```
🔧 Tool Registry Diagnostic Report
==================================================
Total Tools Registered: 169
Duplicates Deduplicated: 12
Conflicts Detected: 0
Last Updated: 2024-01-15T10:30:45.123Z

📊 Tools by Source:
  server-refactored: 45 tools
  server-modular: 45 tools
  tools/index.js: 79 tools
```

## API Reference

### ToolRegistry Class

#### Methods

- `register(tool: ToolDefinition, source?: string): boolean`
  - Register a tool with the registry
  - Returns `true` if registered, `false` if deduplicated
  - Throws error on signature conflicts

- `get(name: string): ToolDefinition | undefined`
  - Get a tool by name (case-insensitive)

- `has(name: string): boolean`
  - Check if a tool is registered

- `list(): ToolDefinition[]`
  - Get all registered tools

- `getNames(): string[]`
  - Get all tool names

- `getStats(): ToolRegistryStats`
  - Get registry statistics

- `clear(): void`
  - Clear all tools (for testing)

- `getBySource(source: string): ToolDefinition[]`
  - Get tools by source

- `findConflicts(): Array<{ name: string; tools: ToolDefinition[] }>`
  - Find potential conflicts

- `generateReport(): string`
  - Generate diagnostic report

### ToolDefinition Interface

```typescript
interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: any;
  handler?: any;
  source?: string;
  signature?: string;
  registeredAt?: Date;
}
```

### Convenience Functions

- `registerTool(tool: ToolDefinition, source?: string): boolean`
- `getTool(name: string): ToolDefinition | undefined`
- `hasTool(name: string): boolean`
- `listTools(): ToolDefinition[]`
- `getToolNames(): string[]`
- `getRegistryStats(): ToolRegistryStats`
- `generateRegistryReport(): string`

## Testing

Run the comprehensive test suite:

```bash
npm test tool-registry.spec.ts
```

Tests cover:
- Basic registration and retrieval
- Duplicate detection and deduplication
- Signature conflict detection
- Case sensitivity handling
- Source tracking
- Performance with large tool sets
- Edge cases and error handling

## Migration Guide

### From Manual Duplicate Detection

**Before**:
```typescript
const registeredTools = new Set<string>();
if (registeredTools.has(name)) {
  console.warn(`Warning: Tool ${name} is already registered`);
  return;
}
registeredTools.add(name);
```

**After**:
```typescript
import { registerTool } from './core/tool-registry.js';

const wasRegistered = registerTool(toolDef, 'source');
if (!wasRegistered) {
  // Tool was deduplicated
  return;
}
```

### Benefits

1. **Centralized Management**: Single source of truth for all tools
2. **Automatic Deduplication**: No manual duplicate checking needed
3. **Conflict Detection**: Early detection of signature conflicts
4. **Better Diagnostics**: Comprehensive reporting and statistics
5. **Consistent Behavior**: Same logic across all server variants

## Performance

The ToolRegistry is optimized for:
- Fast tool registration (O(1) average case)
- Efficient duplicate detection
- Minimal memory overhead
- Scalable to thousands of tools

Benchmarks show:
- 1000 tool registrations: < 100ms
- 1000 duplicate registrations: < 50ms
- Memory usage: ~1KB per 100 tools

## Future Enhancements

Planned improvements:
- Tool versioning support
- Dynamic tool loading/unloading
- Tool dependency tracking
- Enhanced conflict resolution
- Tool metadata extensions
- Performance monitoring
