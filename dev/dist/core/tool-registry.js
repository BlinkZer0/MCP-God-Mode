#!/usr/bin/env node
import * as path from "node:path";
import * as fs from "node:fs";
import { createHash } from "node:crypto";
export class ToolRegistry {
    static instance;
    tools = new Map();
    signatures = new Map(); // signature -> tool name
    stats = {
        totalRegistered: 0,
        duplicatesDeduped: 0,
        conflictsDetected: 0,
        sources: {},
        lastUpdated: new Date()
    };
    constructor() { }
    static getInstance() {
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
    register(tool, source) {
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
            }
            else {
                // Signature conflict - throw error
                this.stats.conflictsDetected++;
                const error = new Error(`Duplicate tool '${normalizedName}' with different signatures detected!\n` +
                    `Existing: ${existing.source || 'unknown'} (${existingSignature})\n` +
                    `New: ${sourceInfo} (${signature})\n` +
                    `Please rename one of the tools or merge their schemas.`);
                console.error(`❌ [ToolRegistry] ${error.message}`);
                throw error;
            }
        }
        // Check for signature collision with different name
        const existingBySignature = this.signatures.get(signature);
        if (existingBySignature && existingBySignature !== normalizedName) {
            this.stats.conflictsDetected++;
            const error = new Error(`Tool signature collision detected!\n` +
                `Tool '${existingBySignature}' and '${normalizedName}' have identical signatures.\n` +
                `This may indicate duplicate tool definitions.`);
            console.error(`❌ [ToolRegistry] ${error.message}`);
            throw error;
        }
        // Register the tool
        const toolDef = {
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
    get(name) {
        return this.tools.get(this.normalizeName(name));
    }
    /**
     * Check if a tool is registered
     */
    has(name) {
        return this.tools.has(this.normalizeName(name));
    }
    /**
     * Get all registered tools
     */
    list() {
        return Array.from(this.tools.values());
    }
    /**
     * Get tool names only
     */
    getNames() {
        return Array.from(this.tools.keys());
    }
    /**
     * Get registry statistics
     */
    getStats() {
        return { ...this.stats };
    }
    /**
     * Clear all tools (for testing)
     */
    clear() {
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
    getBySource(source) {
        return this.list().filter(tool => tool.source === source);
    }
    /**
     * Find potential duplicates (same name, different signatures)
     */
    findConflicts() {
        const conflicts = [];
        const byName = new Map();
        for (const tool of this.tools.values()) {
            const name = tool.name;
            if (!byName.has(name)) {
                byName.set(name, []);
            }
            byName.get(name).push(tool);
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
    generateReport() {
        const stats = this.getStats();
        const conflicts = this.findConflicts();
        let report = "🔧 Tool Registry Diagnostic Report\n";
        report += "=".repeat(50) + "\n";
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
    normalizeName(name) {
        return name.toLowerCase().trim();
    }
    /**
     * Compute a stable signature for a tool definition
     */
    computeSignature(tool) {
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
    resolveSource(source) {
        try {
            if (fs.existsSync(source)) {
                const resolved = fs.realpathSync(source);
                return path.relative(process.cwd(), resolved);
            }
        }
        catch (error) {
            // Ignore resolution errors
        }
        return source;
    }
}
// Export singleton instance
export const toolRegistry = ToolRegistry.getInstance();
// Export convenience functions
export function registerTool(tool, source) {
    return toolRegistry.register(tool, source);
}
export function getTool(name) {
    return toolRegistry.get(name);
}
export function hasTool(name) {
    return toolRegistry.has(name);
}
export function listTools() {
    return toolRegistry.list();
}
export function getToolNames() {
    return toolRegistry.getNames();
}
export function getRegistryStats() {
    return toolRegistry.getStats();
}
export function generateRegistryReport() {
    return toolRegistry.generateReport();
}
