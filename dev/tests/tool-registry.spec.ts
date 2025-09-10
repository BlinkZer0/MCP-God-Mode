#!/usr/bin/env node

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ToolRegistry, ToolDefinition } from '../src/core/tool-registry.js';

describe('ToolRegistry', () => {
  let registry: ToolRegistry;

  beforeEach(() => {
    registry = ToolRegistry.getInstance();
    registry.clear(); // Start with clean state
  });

  afterEach(() => {
    registry.clear(); // Clean up after each test
  });

  describe('Basic Registration', () => {
    it('should register a new tool successfully', () => {
      const tool: ToolDefinition = {
        name: 'test_tool',
        description: 'A test tool',
        inputSchema: { type: 'object' }
      };

      const result = registry.register(tool, 'test-source');
      
      expect(result).toBe(true);
      expect(registry.has('test_tool')).toBe(true);
      expect(registry.get('test_tool')).toEqual(expect.objectContaining({
        name: 'test_tool',
        description: 'A test tool',
        source: 'test-source'
      }));
    });

    it('should normalize tool names consistently', () => {
      const tool1: ToolDefinition = {
        name: 'Test_Tool',
        description: 'A test tool',
        inputSchema: { type: 'object' }
      };

      const tool2: ToolDefinition = {
        name: 'test tool',
        description: 'A test tool',
        inputSchema: { type: 'object' }
      };

      registry.register(tool1, 'source1');
      const result = registry.register(tool2, 'source2');
      
      expect(result).toBe(false); // Should be deduplicated
      expect(registry.getNames()).toHaveLength(1);
    });

    it('should track registration statistics', () => {
      const tool: ToolDefinition = {
        name: 'test_tool',
        description: 'A test tool',
        inputSchema: { type: 'object' }
      };

      registry.register(tool, 'test-source');
      const stats = registry.getStats();
      
      expect(stats.totalRegistered).toBe(1);
      expect(stats.duplicatesDeduped).toBe(0);
      expect(stats.conflictsDetected).toBe(0);
      expect(stats.sources['test-source']).toBe(1);
    });
  });

  describe('Duplicate Detection', () => {
    it('should deduplicate identical tools', () => {
      const tool: ToolDefinition = {
        name: 'test_tool',
        description: 'A test tool',
        inputSchema: { type: 'object', properties: { param: { type: 'string' } } }
      };

      const result1 = registry.register(tool, 'source1');
      const result2 = registry.register(tool, 'source2');
      
      expect(result1).toBe(true);
      expect(result2).toBe(false); // Should be deduplicated
      
      const stats = registry.getStats();
      expect(stats.totalRegistered).toBe(1);
      expect(stats.duplicatesDeduped).toBe(1);
    });

    it('should detect signature conflicts', () => {
      const tool1: ToolDefinition = {
        name: 'test_tool',
        description: 'A test tool',
        inputSchema: { type: 'object', properties: { param1: { type: 'string' } } }
      };

      const tool2: ToolDefinition = {
        name: 'test_tool',
        description: 'A different test tool',
        inputSchema: { type: 'object', properties: { param2: { type: 'number' } } }
      };

      registry.register(tool1, 'source1');
      
      expect(() => {
        registry.register(tool2, 'source2');
      }).toThrow('Duplicate tool \'test_tool\' with different signatures detected');
      
      const stats = registry.getStats();
      expect(stats.conflictsDetected).toBe(1);
    });

    it('should detect signature collisions with different names', () => {
      const tool1: ToolDefinition = {
        name: 'tool_one',
        description: 'A test tool',
        inputSchema: { type: 'object', properties: { param: { type: 'string' } } }
      };

      const tool2: ToolDefinition = {
        name: 'tool_two',
        description: 'A test tool',
        inputSchema: { type: 'object', properties: { param: { type: 'string' } } }
      };

      registry.register(tool1, 'source1');
      
      expect(() => {
        registry.register(tool2, 'source2');
      }).toThrow('Tool signature collision detected');
      
      const stats = registry.getStats();
      expect(stats.conflictsDetected).toBe(1);
    });
  });

  describe('Case Sensitivity', () => {
    it('should handle case-insensitive tool names', () => {
      const tool1: ToolDefinition = {
        name: 'TestTool',
        description: 'A test tool',
        inputSchema: { type: 'object' }
      };

      const tool2: ToolDefinition = {
        name: 'testtool',
        description: 'A test tool',
        inputSchema: { type: 'object' }
      };

      registry.register(tool1, 'source1');
      const result = registry.register(tool2, 'source2');
      
      expect(result).toBe(false); // Should be deduplicated
      expect(registry.getNames()).toHaveLength(1);
    });

    it('should normalize whitespace in tool names', () => {
      const tool1: ToolDefinition = {
        name: '  test_tool  ',
        description: 'A test tool',
        inputSchema: { type: 'object' }
      };

      const tool2: ToolDefinition = {
        name: 'test_tool',
        description: 'A test tool',
        inputSchema: { type: 'object' }
      };

      registry.register(tool1, 'source1');
      const result = registry.register(tool2, 'source2');
      
      expect(result).toBe(false); // Should be deduplicated
    });
  });

  describe('Source Tracking', () => {
    it('should track tools by source', () => {
      const tool1: ToolDefinition = {
        name: 'tool1',
        description: 'Tool 1',
        inputSchema: { type: 'object' }
      };

      const tool2: ToolDefinition = {
        name: 'tool2',
        description: 'Tool 2',
        inputSchema: { type: 'object' }
      };

      registry.register(tool1, 'source1');
      registry.register(tool2, 'source1');
      registry.register(tool2, 'source2'); // Duplicate, should be deduplicated

      const source1Tools = registry.getBySource('source1');
      const source2Tools = registry.getBySource('source2');
      
      expect(source1Tools).toHaveLength(2);
      expect(source2Tools).toHaveLength(0); // tool2 was deduplicated
    });

    it('should handle unknown source gracefully', () => {
      const tools = registry.getBySource('nonexistent-source');
      expect(tools).toHaveLength(0);
    });
  });

  describe('Conflict Detection', () => {
    it('should find conflicts between tools with same name', () => {
      const tool1: ToolDefinition = {
        name: 'conflict_tool',
        description: 'Tool 1',
        inputSchema: { type: 'object', properties: { param1: { type: 'string' } } }
      };

      const tool2: ToolDefinition = {
        name: 'conflict_tool',
        description: 'Tool 2',
        inputSchema: { type: 'object', properties: { param2: { type: 'number' } } }
      };

      // Register first tool
      registry.register(tool1, 'source1');
      
      // Try to register conflicting tool (should throw)
      expect(() => {
        registry.register(tool2, 'source2');
      }).toThrow();

      const conflicts = registry.findConflicts();
      expect(conflicts).toHaveLength(0); // No conflicts remain after error
    });

    it('should not find conflicts for identical tools', () => {
      const tool: ToolDefinition = {
        name: 'identical_tool',
        description: 'Identical tool',
        inputSchema: { type: 'object' }
      };

      registry.register(tool, 'source1');
      registry.register(tool, 'source2'); // Should be deduplicated

      const conflicts = registry.findConflicts();
      expect(conflicts).toHaveLength(0);
    });
  });

  describe('Registry Management', () => {
    it('should list all registered tools', () => {
      const tool1: ToolDefinition = {
        name: 'tool1',
        description: 'Tool 1',
        inputSchema: { type: 'object' }
      };

      const tool2: ToolDefinition = {
        name: 'tool2',
        description: 'Tool 2',
        inputSchema: { type: 'object' }
      };

      registry.register(tool1, 'source1');
      registry.register(tool2, 'source2');

      const tools = registry.list();
      const names = registry.getNames();
      
      expect(tools).toHaveLength(2);
      expect(names).toHaveLength(2);
      expect(names).toContain('tool1');
      expect(names).toContain('tool2');
    });

    it('should clear all tools', () => {
      const tool: ToolDefinition = {
        name: 'test_tool',
        description: 'A test tool',
        inputSchema: { type: 'object' }
      };

      registry.register(tool, 'source1');
      expect(registry.getNames()).toHaveLength(1);

      registry.clear();
      expect(registry.getNames()).toHaveLength(0);
      expect(registry.getStats().totalRegistered).toBe(0);
    });

    it('should maintain singleton pattern', () => {
      const registry1 = ToolRegistry.getInstance();
      const registry2 = ToolRegistry.getInstance();
      
      expect(registry1).toBe(registry2);
    });
  });

  describe('Diagnostic Reporting', () => {
    it('should generate comprehensive diagnostic report', () => {
      const tool1: ToolDefinition = {
        name: 'tool1',
        description: 'Tool 1',
        inputSchema: { type: 'object' }
      };

      const tool2: ToolDefinition = {
        name: 'tool2',
        description: 'Tool 2',
        inputSchema: { type: 'object' }
      };

      registry.register(tool1, 'source1');
      registry.register(tool2, 'source2');
      registry.register(tool2, 'source3'); // Duplicate

      const report = registry.generateReport();
      
      expect(report).toContain('Tool Registry Diagnostic Report');
      expect(report).toContain('Total Tools Registered: 2');
      expect(report).toContain('Duplicates Deduplicated: 1');
      expect(report).toContain('source1: 1 tools');
      expect(report).toContain('source2: 1 tools');
    });

    it('should handle empty registry in report', () => {
      const report = registry.generateReport();
      
      expect(report).toContain('Total Tools Registered: 0');
      expect(report).toContain('Duplicates Deduplicated: 0');
      expect(report).toContain('Conflicts Detected: 0');
    });
  });

  describe('Edge Cases', () => {
    it('should handle tools with minimal definitions', () => {
      const tool: ToolDefinition = {
        name: 'minimal_tool',
        description: '',
        inputSchema: {}
      };

      const result = registry.register(tool, 'source');
      expect(result).toBe(true);
      expect(registry.has('minimal_tool')).toBe(true);
    });

    it('should handle tools with complex schemas', () => {
      const tool: ToolDefinition = {
        name: 'complex_tool',
        description: 'A complex tool',
        inputSchema: {
          type: 'object',
          properties: {
            nested: {
              type: 'object',
              properties: {
                array: {
                  type: 'array',
                  items: { type: 'string' }
                }
              }
            }
          },
          required: ['nested']
        }
      };

      const result = registry.register(tool, 'source');
      expect(result).toBe(true);
      
      const registered = registry.get('complex_tool');
      expect(registered?.signature).toBeDefined();
    });

    it('should handle undefined source gracefully', () => {
      const tool: ToolDefinition = {
        name: 'unsourced_tool',
        description: 'A tool without source',
        inputSchema: { type: 'object' }
      };

      const result = registry.register(tool);
      expect(result).toBe(true);
      
      const registered = registry.get('unsourced_tool');
      expect(registered?.source).toBe('unknown');
    });
  });

  describe('Performance', () => {
    it('should handle large numbers of tools efficiently', () => {
      const startTime = Date.now();
      
      // Register 1000 tools
      for (let i = 0; i < 1000; i++) {
        const tool: ToolDefinition = {
          name: `tool_${i}`,
          description: `Tool ${i}`,
          inputSchema: { type: 'object', properties: { param: { type: 'string' } } }
        };
        registry.register(tool, `source_${i % 10}`);
      }
      
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      expect(registry.getNames()).toHaveLength(1000);
      expect(duration).toBeLessThan(1000); // Should complete in under 1 second
    });

    it('should handle many duplicate registrations efficiently', () => {
      const tool: ToolDefinition = {
        name: 'duplicate_tool',
        description: 'A tool that will be registered many times',
        inputSchema: { type: 'object' }
      };

      const startTime = Date.now();
      
      // Try to register the same tool 1000 times
      for (let i = 0; i < 1000; i++) {
        registry.register(tool, `source_${i}`);
      }
      
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      expect(registry.getNames()).toHaveLength(1); // Only one unique tool
      expect(registry.getStats().duplicatesDeduped).toBe(999);
      expect(duration).toBeLessThan(500); // Should complete quickly
    });
  });
});
