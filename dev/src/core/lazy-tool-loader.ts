#!/usr/bin/env node

import * as path from "node:path";
import * as fs from "node:fs/promises";
import { createHash } from "node:crypto";

/**
 * Lazy Tool Loader - On-demand tool loading system for MCP God Mode
 * 
 * This system enables:
 * - Tools are only loaded when actually called
 * - Faster server startup times
 * - Reduced memory footprint
 * - Dynamic tool discovery and loading
 * - Tool metadata caching for quick lookups
 */

export interface LazyToolMetadata {
  name: string;
  description: string;
  inputSchema: any;
  sourceFile: string;
  registerFunction: string;
  category?: string;
  tags?: string[];
  lastModified?: Date;
  fileSize?: number;
  signature?: string;
}

export interface LazyLoaderStats {
  totalToolsDiscovered: number;
  totalToolsLoaded: number;
  totalToolsCached: number;
  cacheHits: number;
  cacheMisses: number;
  lastDiscovery: Date;
  lastLoad: Date;
}

export class LazyToolLoader {
  private static instance: LazyToolLoader;
  private metadataCache: Map<string, LazyToolMetadata> = new Map();
  private loadedModules: Map<string, any> = new Map();
  private stats: LazyLoaderStats = {
    totalToolsDiscovered: 0,
    totalToolsLoaded: 0,
    totalToolsCached: 0,
    cacheHits: 0,
    cacheMisses: 0,
    lastDiscovery: new Date(),
    lastLoad: new Date()
  };

  private constructor() {}

  public static getInstance(): LazyToolLoader {
    if (!LazyToolLoader.instance) {
      LazyToolLoader.instance = new LazyToolLoader();
    }
    return LazyToolLoader.instance;
  }

  /**
   * Discover all available tools without loading them
   */
  public async discoverTools(toolsDir: string = "dev/src/tools"): Promise<LazyToolMetadata[]> {
    const discovered: LazyToolMetadata[] = [];
    
    try {
      const fullPath = path.resolve(toolsDir);
      await this.scanDirectory(fullPath, discovered);
      
      this.stats.totalToolsDiscovered = discovered.length;
      this.stats.lastDiscovery = new Date();
      
      // Cache metadata
      for (const tool of discovered) {
        this.metadataCache.set(tool.name, tool);
      }
      
      this.stats.totalToolsCached = this.metadataCache.size;
      
      if (process.env.LOG_LAZY_LOADER === "1") {
        console.log(`🔍 [LazyLoader] Discovered ${discovered.length} tools`);
      }
      
    } catch (error) {
      console.error(`❌ [LazyLoader] Discovery failed:`, error);
    }
    
    return discovered;
  }

  /**
   * Get tool metadata without loading the actual tool
   */
  public getToolMetadata(name: string): LazyToolMetadata | undefined {
    return this.metadataCache.get(name);
  }

  /**
   * Check if a tool exists without loading it
   */
  public hasTool(name: string): boolean {
    return this.metadataCache.has(name);
  }

  /**
   * List all discovered tools (metadata only)
   */
  public listDiscoveredTools(): LazyToolMetadata[] {
    return Array.from(this.metadataCache.values());
  }

  /**
   * Load a specific tool on-demand
   */
  public async loadTool(name: string): Promise<any> {
    const metadata = this.metadataCache.get(name);
    if (!metadata) {
      throw new Error(`Tool '${name}' not found in metadata cache. Run discovery first.`);
    }

    // Check if already loaded
    if (this.loadedModules.has(name)) {
      this.stats.cacheHits++;
      if (process.env.LOG_LAZY_LOADER === "1") {
        console.log(`🎯 [LazyLoader] Cache hit for tool: ${name}`);
      }
      return this.loadedModules.get(name);
    }

    this.stats.cacheMisses++;
    
    try {
      // Dynamically import the tool module
      const modulePath = path.resolve(metadata.sourceFile);
      const module = await import(modulePath);
      
      // Get the register function
      const registerFunction = module[metadata.registerFunction];
      if (!registerFunction) {
        throw new Error(`Register function '${metadata.registerFunction}' not found in ${metadata.sourceFile}`);
      }
      
      // Cache the loaded module
      this.loadedModules.set(name, {
        module,
        registerFunction,
        metadata
      });
      
      this.stats.totalToolsLoaded++;
      this.stats.lastLoad = new Date();
      
      if (process.env.LOG_LAZY_LOADER === "1") {
        console.log(`⚡ [LazyLoader] Loaded tool: ${name} from ${metadata.sourceFile}`);
      }
      
      return this.loadedModules.get(name);
      
    } catch (error) {
      console.error(`❌ [LazyLoader] Failed to load tool '${name}':`, error);
      throw error;
    }
  }

  /**
   * Register a tool with the MCP server (loads if needed)
   */
  public async registerTool(server: any, name: string): Promise<boolean> {
    try {
      const toolData = await this.loadTool(name);
      const { registerFunction, metadata } = toolData;
      
      // Call the register function
      await registerFunction(server);
      
      if (process.env.LOG_LAZY_LOADER === "1") {
        console.log(`✅ [LazyLoader] Registered tool: ${name}`);
      }
      
      return true;
      
    } catch (error) {
      console.error(`❌ [LazyLoader] Failed to register tool '${name}':`, error);
      return false;
    }
  }

  /**
   * Preload commonly used tools
   */
  public async preloadTools(toolNames: string[]): Promise<void> {
    const loadPromises = toolNames.map(async (name) => {
      try {
        await this.loadTool(name);
      } catch (error) {
        console.warn(`⚠️ [LazyLoader] Failed to preload tool '${name}':`, error);
      }
    });
    
    await Promise.all(loadPromises);
    
    if (process.env.LOG_LAZY_LOADER === "1") {
      console.log(`🚀 [LazyLoader] Preloaded ${toolNames.length} tools`);
    }
  }

  /**
   * Get loader statistics
   */
  public getStats(): LazyLoaderStats {
    return { ...this.stats };
  }

  /**
   * Clear cache (for testing)
   */
  public clearCache(): void {
    this.metadataCache.clear();
    this.loadedModules.clear();
    this.stats = {
      totalToolsDiscovered: 0,
      totalToolsLoaded: 0,
      totalToolsCached: 0,
      cacheHits: 0,
      cacheMisses: 0,
      lastDiscovery: new Date(),
      lastLoad: new Date()
    };
  }

  /**
   * Recursively scan directory for tool files
   */
  private async scanDirectory(dirPath: string, discovered: LazyToolMetadata[]): Promise<void> {
    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        
        if (entry.isDirectory()) {
          // Recursively scan subdirectories
          await this.scanDirectory(fullPath, discovered);
        } else if (entry.isFile() && this.isToolFile(entry.name)) {
          // Analyze tool file
          const metadata = await this.analyzeToolFile(fullPath);
          if (metadata) {
            discovered.push(metadata);
          }
        }
      }
    } catch (error) {
      console.warn(`⚠️ [LazyLoader] Failed to scan directory '${dirPath}':`, error);
    }
  }

  /**
   * Check if file is a tool file
   */
  private isToolFile(filename: string): boolean {
    return filename.endsWith('.ts') || filename.endsWith('.js');
  }

  /**
   * Analyze a tool file to extract metadata
   */
  private async analyzeToolFile(filePath: string): Promise<LazyToolMetadata | null> {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const stats = await fs.stat(filePath);
      
      // Extract tool name from filename
      const fileName = path.basename(filePath, path.extname(filePath));
      
      // Look for register function pattern
      const registerMatch = content.match(/export\s+function\s+(register\w+)\s*\(/);
      if (!registerMatch) {
        return null; // Not a tool file
      }
      
      const registerFunction = registerMatch[1];
      
      // Extract description from registerTool call
      const descriptionMatch = content.match(/description:\s*["'`]([^"'`]+)["'`]/);
      const description = descriptionMatch ? descriptionMatch[1] : `Tool from ${fileName}`;
      
      // Extract input schema (simplified)
      const schemaMatch = content.match(/inputSchema:\s*(\{[^}]*\})/s);
      let inputSchema = {};
      if (schemaMatch) {
        try {
          // This is a simplified schema extraction - in reality you'd need a proper parser
          inputSchema = { extracted: true }; // Placeholder
        } catch (error) {
          inputSchema = {};
        }
      }
      
      // Generate signature
      const signature = createHash('sha256')
        .update(content)
        .digest('hex')
        .substring(0, 16);
      
      // Determine category from directory structure
      const category = this.determineCategory(filePath);
      
      const metadata: LazyToolMetadata = {
        name: `mcp_mcp-god-mode_${fileName}`,
        description,
        inputSchema,
        sourceFile: filePath,
        registerFunction,
        category,
        lastModified: stats.mtime,
        fileSize: stats.size,
        signature
      };
      
      return metadata;
      
    } catch (error) {
      console.warn(`⚠️ [LazyLoader] Failed to analyze file '${filePath}':`, error);
      return null;
    }
  }

  /**
   * Determine tool category from file path
   */
  private determineCategory(filePath: string): string {
    const pathParts = filePath.split(path.sep);
    const toolsIndex = pathParts.indexOf('tools');
    
    if (toolsIndex >= 0 && pathParts[toolsIndex + 1]) {
      return pathParts[toolsIndex + 1];
    }
    
    return 'unknown';
  }
}

// Export singleton instance
export const lazyLoader = LazyToolLoader.getInstance();

// Export convenience functions
export async function discoverAllTools(toolsDir?: string): Promise<LazyToolMetadata[]> {
  return lazyLoader.discoverTools(toolsDir);
}

export function getToolMetadata(name: string): LazyToolMetadata | undefined {
  return lazyLoader.getToolMetadata(name);
}

export function hasTool(name: string): boolean {
  return lazyLoader.hasTool(name);
}

export async function loadTool(name: string): Promise<any> {
  return lazyLoader.loadTool(name);
}

export async function registerTool(server: any, name: string): Promise<boolean> {
  return lazyLoader.registerTool(server, name);
}

export async function preloadTools(toolNames: string[]): Promise<void> {
  return lazyLoader.preloadTools(toolNames);
}

export function getLoaderStats(): LazyLoaderStats {
  return lazyLoader.getStats();
}
