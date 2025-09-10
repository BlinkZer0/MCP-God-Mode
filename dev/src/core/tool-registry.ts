#!/usr/bin/env node

import * as path from "node:path";
import * as fs from "node:fs";
import { createHash } from "node:crypto";

/**
 * Tool Registry - Unified tool registration system for MCP God Mode
 * 
 * This registry ensures:
 * - Unique tool names across all loaders
 * - Signature conflict detection
 * - Deduplication of identical tools
 * - Stable tool IDs for consistent registration
 * - Comprehensive diagnostics and logging
 */

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: any;
  handler?: any;
  source?: string; // Source file/module
  signature?: string; // Computed signature
  registeredAt?: Date;
}

export interface ToolRegistryStats {
  totalRegistered: number;
  duplicatesDeduped: number;
  conflictsDetected: number;
  sources: Record<string, number>;
  lastUpdated: Date;
}

export class ToolRegistry {
  private static instance: ToolRegistry;
  private tools: Map<string, ToolDefinition> = new Map();
  private signatures: Map<string, string> = new Map(); // signature -> tool name
  private stats: ToolRegistryStats = {
    totalRegistered: 0,
    duplicatesDeduped: 0,
    conflictsDetected: 0,
    sources: {},
    lastUpdated: new Date()
  };

  private constructor() {}

  public static getInstance(): ToolRegistry {
    if (!ToolRegistry.instance) {
      ToolRegistry.instance = new ToolRegistry();
    }
    return ToolRegistry.instance;
  }

  /**
   * Register a tool with the registry
   * @param tool Tool definition to register
   * @param source Source module/file (optional)
   * @returns true if registered, false if duplicate
   * @throws Error if signature conflict detected
   */
  public register(tool: ToolDefinition, source?: string): boolean {
    const normalizedName = this.normalizeName(tool.name);
    const signature = this.computeSignature(tool);
    const sourceInfo = source || tool.source || 'unknown';

    // Update stats
    this.stats.sources[sourceInfo] = (this.stats.sources[sourceInfo] || 0) + 1;
    this.stats.lastUpdated = new Date();

    // Check for existing tool with same name
    const existing = this.tools.get(normalizedName);
    if (existing) {
      const existingSignature = this.computeSignature(existing);
      
      if (signature === existingSignature) {
        // Identical tool - deduplicate
        this.stats.duplicatesDeduped++;
        if (process.env.LOG_TOOL_REGISTRY === "1") {
          console.log(`🔄 [ToolRegistry] Deduplicated identical tool: ${normalizedName} (from ${sourceInfo})`);
        }
        return false;
      } else {
        // Signature conflict - throw error
        this.stats.conflictsDetected++;
        const error = new Error(
          `Duplicate tool '${normalizedName}' with different signatures detected!\n` +
          `Existing: ${existing.source || 'unknown'} (${existingSignature})\n` +
          `New: ${sourceInfo} (${signature})\n` +
          `Please rename one of the tools or merge their schemas.`
        );
        console.error(`❌ [ToolRegistry] ${error.message}`);
        throw error;
      }
    }

    // Check for signature collision with different name
    const existingBySignature = this.signatures.get(signature);
    if (existingBySignature && existingBySignature !== normalizedName) {
      this.stats.conflictsDetected++;
      const error = new Error(
        `Tool signature collision detected!\n` +
        `Tool '${existingBySignature}' and '${normalizedName}' have identical signatures.\n` +
        `This may indicate duplicate tool definitions.`
      );
      console.error(`❌ [ToolRegistry] ${error.message}`);
      throw error;
    }

    // Register the tool
    const toolDef: ToolDefinition = {
      ...tool,
      name: normalizedName,
      source: sourceInfo,
      signature,
      registeredAt: new Date()
    };

    this.tools.set(normalizedName, toolDef);
    this.signatures.set(signature, normalizedName);
    this.stats.totalRegistered++;

    if (process.env.LOG_TOOL_REGISTRY === "1") {
      console.log(`✅ [ToolRegistry] Registered: ${normalizedName} (from ${sourceInfo})`);
    }

    return true;
  }

  /**
   * Get a tool by name
   */
  public get(name: string): ToolDefinition | undefined {
    return this.tools.get(this.normalizeName(name));
  }

  /**
   * Check if a tool is registered
   */
  public has(name: string): boolean {
    return this.tools.has(this.normalizeName(name));
  }

  /**
   * Get all registered tools
   */
  public list(): ToolDefinition[] {
    return Array.from(this.tools.values());
  }

  /**
   * Get tool names only
   */
  public getNames(): string[] {
    return Array.from(this.tools.keys());
  }

  /**
   * Get registry statistics
   */
  public getStats(): ToolRegistryStats {
    return { ...this.stats };
  }

  /**
   * Clear all tools (for testing)
   */
  public clear(): void {
    this.tools.clear();
    this.signatures.clear();
    this.stats = {
      totalRegistered: 0,
      duplicatesDeduped: 0,
      conflictsDetected: 0,
      sources: {},
      lastUpdated: new Date()
    };
  }

  /**
   * Get tools by source
   */
  public getBySource(source: string): ToolDefinition[] {
    return this.list().filter(tool => tool.source === source);
  }

  /**
   * Find potential duplicates (same name, different signatures)
   */
  public findConflicts(): Array<{ name: string; tools: ToolDefinition[] }> {
    const conflicts: Array<{ name: string; tools: ToolDefinition[] }> = [];
    const byName = new Map<string, ToolDefinition[]>();

    for (const tool of this.tools.values()) {
      const name = tool.name;
      if (!byName.has(name)) {
        byName.set(name, []);
      }
      byName.get(name)!.push(tool);
    }

    for (const [name, tools] of byName.entries()) {
      if (tools.length > 1) {
        conflicts.push({ name, tools });
      }
    }

    return conflicts;
  }

  /**
   * Generate a diagnostic report
   */
  public generateReport(): string {
    const stats = this.getStats();
    const conflicts = this.findConflicts();
    
    let report = "🔧 Tool Registry Diagnostic Report\n";
    report += "=" .repeat(50) + "\n";
    report += `Total Tools Registered: ${stats.totalRegistered}\n`;
    report += `Duplicates Deduplicated: ${stats.duplicatesDeduped}\n`;
    report += `Conflicts Detected: ${stats.conflictsDetected}\n`;
    report += `Last Updated: ${stats.lastUpdated.toISOString()}\n\n`;

    report += "📊 Tools by Source:\n";
    for (const [source, count] of Object.entries(stats.sources)) {
      report += `  ${source}: ${count} tools\n`;
    }

    if (conflicts.length > 0) {
      report += "\n⚠️ Conflicts Found:\n";
      for (const conflict of conflicts) {
        report += `  ${conflict.name}: ${conflict.tools.length} versions\n`;
        for (const tool of conflict.tools) {
          report += `    - ${tool.source} (${tool.signature})\n`;
        }
      }
    }

    return report;
  }

  /**
   * Normalize tool name for consistent comparison
   */
  private normalizeName(name: string): string {
    return name.toLowerCase().trim();
  }

  /**
   * Compute a stable signature for a tool definition
   */
  private computeSignature(tool: ToolDefinition): string {
    const signatureData = {
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema
    };

    const jsonString = JSON.stringify(signatureData, Object.keys(signatureData).sort());
    return createHash('sha256').update(jsonString).digest('hex').substring(0, 16);
  }

  /**
   * Resolve symlinks and normalize paths for consistent source tracking
   */
  private resolveSource(source: string): string {
    try {
      if (fs.existsSync(source)) {
        const resolved = fs.realpathSync(source);
        return path.relative(process.cwd(), resolved);
      }
    } catch (error) {
      // Ignore resolution errors
    }
    return source;
  }
}

// Export singleton instance
export const toolRegistry = ToolRegistry.getInstance();

// Export convenience functions
export function registerTool(tool: ToolDefinition, source?: string): boolean {
  return toolRegistry.register(tool, source);
}

export function getTool(name: string): ToolDefinition | undefined {
  return toolRegistry.get(name);
}

export function hasTool(name: string): boolean {
  return toolRegistry.has(name);
}

export function listTools(): ToolDefinition[] {
  return toolRegistry.list();
}

export function getToolNames(): string[] {
  return toolRegistry.getNames();
}

export function getRegistryStats(): ToolRegistryStats {
  return toolRegistry.getStats();
}

export function generateRegistryReport(): string {
  return toolRegistry.generateReport();
}
