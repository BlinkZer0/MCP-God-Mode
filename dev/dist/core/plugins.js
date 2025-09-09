"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.PluginManager = exports.PluginManifestSchema = exports.defaultPluginConfig = void 0;
const events_1 = require("events");
const fs = __importStar(require("node:fs/promises"));
const path = __importStar(require("node:path"));
const winston = require("winston");
const zod_1 = require("zod");
exports.defaultPluginConfig = {
    autoLoad: true,
    pluginDirectory: './plugins',
    allowedPermissions: ['read', 'write', 'execute', 'network', 'file'],
    maxPluginMemory: 100 * 1024 * 1024, // 100MB
    pluginTimeout: 30000, // 30 seconds
    enableSandboxing: true
};
// Plugin validation schemas
exports.PluginManifestSchema = zod_1.z.object({
    id: zod_1.z.string().min(1),
    name: zod_1.z.string().min(1),
    version: zod_1.z.string().regex(/^\d+\.\d+\.\d+$/),
    description: zod_1.z.string().min(1),
    author: zod_1.z.string().min(1),
    license: zod_1.z.string().min(1),
    main: zod_1.z.string().min(1),
    dependencies: zod_1.z.array(zod_1.z.string()).optional(),
    peerDependencies: zod_1.z.array(zod_1.z.string()).optional(),
    tools: zod_1.z.array(zod_1.z.object({
        id: zod_1.z.string().min(1),
        name: zod_1.z.string().min(1),
        description: zod_1.z.string().min(1),
        inputSchema: zod_1.z.any(),
        outputSchema: zod_1.z.any(),
        category: zod_1.z.string().min(1),
        icon: zod_1.z.string().optional(),
        examples: zod_1.z.array(zod_1.z.object({
            name: zod_1.z.string().min(1),
            description: zod_1.z.string().min(1),
            input: zod_1.z.any(),
            output: zod_1.z.any()
        })).optional()
    })).min(1),
    permissions: zod_1.z.array(zod_1.z.string()).optional(),
    configSchema: zod_1.z.any().optional(),
    icon: zod_1.z.string().optional(),
    tags: zod_1.z.array(zod_1.z.string()).optional(),
    repository: zod_1.z.string().optional(),
    homepage: zod_1.z.string().optional(),
    bugs: zod_1.z.string().optional()
});
// Plugin manager
class PluginManager extends events_1.EventEmitter {
    plugins = new Map();
    config;
    logger;
    pluginDirectory;
    loadedModules = new Map();
    constructor(config = exports.defaultPluginConfig) {
        super();
        this.config = config;
        this.pluginDirectory = path.resolve(config.pluginDirectory);
        this.logger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
            transports: [
                new winston.transports.File({ filename: 'logs/plugins.log' }),
                new winston.transports.Console({
                    format: winston.format.simple()
                })
            ]
        });
        this.ensurePluginDirectory();
    }
    async ensurePluginDirectory() {
        try {
            await fs.access(this.pluginDirectory);
        }
        catch {
            await fs.mkdir(this.pluginDirectory, { recursive: true });
            this.logger.info('Plugin directory created', { path: this.pluginDirectory });
        }
    }
    // Plugin discovery and loading
    async discoverPlugins() {
        const manifests = [];
        try {
            const entries = await fs.readdir(this.pluginDirectory, { withFileTypes: true });
            for (const entry of entries) {
                if (entry.isDirectory()) {
                    const pluginPath = path.join(this.pluginDirectory, entry.name);
                    const manifestPath = path.join(pluginPath, 'package.json');
                    try {
                        const manifestContent = await fs.readFile(manifestPath, 'utf-8');
                        const manifest = JSON.parse(manifestContent);
                        // Validate manifest
                        const validatedManifest = exports.PluginManifestSchema.parse(manifest);
                        manifests.push(validatedManifest);
                        this.logger.debug('Plugin manifest discovered', { pluginId: validatedManifest.id, path: pluginPath });
                    }
                    catch (error) {
                        this.logger.warn('Invalid plugin manifest', { path: manifestPath, error: error instanceof Error ? error.message : String(error) });
                    }
                }
            }
        }
        catch (error) {
            this.logger.error('Failed to discover plugins', { error: error instanceof Error ? error.message : String(error) });
        }
        return manifests;
    }
    async loadPlugin(pluginId) {
        try {
            const manifests = await this.discoverPlugins();
            const manifest = manifests.find(m => m.id === pluginId);
            if (!manifest) {
                throw new Error(`Plugin manifest not found: ${pluginId}`);
            }
            // Check if plugin is already loaded
            if (this.plugins.has(pluginId)) {
                this.logger.warn('Plugin already loaded', { pluginId });
                return this.plugins.get(pluginId) || null;
            }
            // Validate permissions
            if (!this.validatePluginPermissions(manifest)) {
                throw new Error(`Plugin requires unauthorized permissions: ${manifest.permissions?.join(', ')}`);
            }
            // Load plugin module
            const pluginPath = path.join(this.pluginDirectory, manifest.id);
            const mainPath = path.join(pluginPath, manifest.main);
            const startTime = Date.now();
            const pluginModule = await this.loadPluginModule(mainPath);
            const loadTime = Date.now() - startTime;
            // Create plugin instance
            const plugin = {
                id: pluginId,
                manifest,
                instance: pluginModule,
                status: 'active',
                loadTime,
                usageCount: 0,
                config: {},
                enabled: true
            };
            this.plugins.set(pluginId, plugin);
            this.loadedModules.set(pluginId, pluginModule);
            this.logger.info('Plugin loaded successfully', {
                pluginId,
                name: manifest.name,
                version: manifest.version,
                loadTime,
                tools: manifest.tools.length
            });
            this.emit('pluginLoaded', plugin);
            return plugin;
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            this.logger.error('Failed to load plugin', { pluginId, error: errorMessage });
            // Create error plugin entry
            const errorPlugin = {
                id: pluginId,
                manifest: {},
                instance: null,
                status: 'error',
                error: errorMessage,
                usageCount: 0,
                config: {},
                enabled: false
            };
            this.plugins.set(pluginId, errorPlugin);
            this.emit('pluginLoadError', { pluginId, error: errorMessage });
            return null;
        }
    }
    async loadPluginModule(modulePath) {
        try {
            // Dynamic import with timeout
            const modulePromise = Promise.resolve(`${modulePath}`).then(s => __importStar(require(s)));
            const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Plugin load timeout')), this.config.pluginTimeout));
            const module = await Promise.race([modulePromise, timeoutPromise]);
            // Validate module structure
            if (typeof module.default === 'function') {
                return new module.default();
            }
            else if (typeof module.init === 'function') {
                return module.init();
            }
            else {
                return module;
            }
        }
        catch (error) {
            throw new Error(`Failed to load plugin module: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    validatePluginPermissions(manifest) {
        if (!manifest.permissions || manifest.permissions.length === 0) {
            return true; // No permissions required
        }
        return manifest.permissions.every(permission => this.config.allowedPermissions.includes(permission));
    }
    async loadAllPlugins() {
        const manifests = await this.discoverPlugins();
        const loadedPlugins = [];
        for (const manifest of manifests) {
            try {
                const plugin = await this.loadPlugin(manifest.id);
                if (plugin) {
                    loadedPlugins.push(plugin);
                }
            }
            catch (error) {
                this.logger.error('Failed to load plugin during bulk load', {
                    pluginId: manifest.id,
                    error: error instanceof Error ? error.message : String(error)
                });
            }
        }
        this.logger.info('Bulk plugin loading completed', {
            total: manifests.length,
            loaded: loadedPlugins.length,
            failed: manifests.length - loadedPlugins.length
        });
        return loadedPlugins;
    }
    // Plugin management
    async unloadPlugin(pluginId) {
        const plugin = this.plugins.get(pluginId);
        if (!plugin) {
            return false;
        }
        try {
            // Call cleanup method if available
            if (plugin.instance && typeof plugin.instance.cleanup === 'function') {
                await plugin.instance.cleanup();
            }
            this.plugins.delete(pluginId);
            this.loadedModules.delete(pluginId);
            this.logger.info('Plugin unloaded', { pluginId, name: plugin.manifest.name });
            this.emit('pluginUnloaded', plugin);
            return true;
        }
        catch (error) {
            this.logger.error('Failed to unload plugin', {
                pluginId,
                error: error instanceof Error ? error.message : String(error)
            });
            return false;
        }
    }
    async reloadPlugin(pluginId) {
        await this.unloadPlugin(pluginId);
        return await this.loadPlugin(pluginId);
    }
    async enablePlugin(pluginId) {
        const plugin = this.plugins.get(pluginId);
        if (!plugin) {
            return false;
        }
        plugin.enabled = true;
        plugin.status = 'active';
        this.logger.info('Plugin enabled', { pluginId, name: plugin.manifest.name });
        this.emit('pluginEnabled', plugin);
        return true;
    }
    async disablePlugin(pluginId) {
        const plugin = this.plugins.get(pluginId);
        if (!plugin) {
            return false;
        }
        plugin.enabled = false;
        plugin.status = 'disabled';
        this.logger.info('Plugin disabled', { pluginId, name: plugin.manifest.name });
        this.emit('pluginDisabled', plugin);
        return true;
    }
    // Plugin tool execution
    async executePluginTool(pluginId, toolId, input) {
        const plugin = this.plugins.get(pluginId);
        if (!plugin) {
            throw new Error(`Plugin not found: ${pluginId}`);
        }
        if (!plugin.enabled) {
            throw new Error(`Plugin is disabled: ${pluginId}`);
        }
        if (plugin.status !== 'active') {
            throw new Error(`Plugin is not active: ${pluginId}`);
        }
        const tool = plugin.manifest.tools.find(t => t.id === toolId);
        if (!tool) {
            throw new Error(`Tool not found: ${toolId} in plugin ${pluginId}`);
        }
        try {
            // Validate input against schema
            if (tool.inputSchema) {
                // This would use a schema validation library like Zod or Joi
                // For now, we'll skip validation
            }
            // Execute tool
            const startTime = Date.now();
            let result;
            if (typeof plugin.instance.executeTool === 'function') {
                result = await plugin.instance.executeTool(toolId, input);
            }
            else if (typeof plugin.instance[toolId] === 'function') {
                result = await plugin.instance[toolId](input);
            }
            else {
                throw new Error(`Tool execution method not found: ${toolId}`);
            }
            const executionTime = Date.now() - startTime;
            // Update plugin usage statistics
            plugin.usageCount++;
            plugin.lastUsed = new Date();
            this.logger.debug('Plugin tool executed', {
                pluginId,
                toolId,
                executionTime,
                usageCount: plugin.usageCount
            });
            // Validate output against schema
            if (tool.outputSchema) {
                // This would use a schema validation library
                // For now, we'll skip validation
            }
            return result;
        }
        catch (error) {
            this.logger.error('Plugin tool execution failed', {
                pluginId,
                toolId,
                error: error instanceof Error ? error.message : String(error)
            });
            throw error;
        }
    }
    // Plugin information
    getPlugin(pluginId) {
        return this.plugins.get(pluginId);
    }
    getAllPlugins() {
        return Array.from(this.plugins.values());
    }
    getPluginTools(pluginId) {
        const plugin = this.plugins.get(pluginId);
        return plugin ? plugin.manifest.tools : [];
    }
    getAllPluginTools() {
        const tools = [];
        for (const plugin of Array.from(this.plugins.values())) {
            if (plugin.enabled && plugin.status === 'active') {
                tools.push(...plugin.manifest.tools);
            }
        }
        return tools;
    }
    // Plugin configuration
    async updatePluginConfig(pluginId, config) {
        const plugin = this.plugins.get(pluginId);
        if (!plugin) {
            return false;
        }
        try {
            // Validate config against schema if available
            if (plugin.manifest.configSchema) {
                // This would validate the config against the schema
                // For now, we'll accept any config
            }
            plugin.config = { ...plugin.config, ...config };
            // Apply config to plugin instance if method available
            if (plugin.instance && typeof plugin.instance.configure === 'function') {
                await plugin.instance.configure(plugin.config);
            }
            this.logger.info('Plugin configuration updated', { pluginId, config });
            this.emit('pluginConfigUpdated', { pluginId, config });
            return true;
        }
        catch (error) {
            this.logger.error('Failed to update plugin configuration', {
                pluginId,
                error: error instanceof Error ? error.message : String(error)
            });
            return false;
        }
    }
    // Plugin marketplace integration
    async searchPlugins(query, tags) {
        // This would integrate with a plugin marketplace API
        // For now, return local plugins that match the query
        const manifests = await this.discoverPlugins();
        return manifests.filter(manifest => {
            const matchesQuery = !query ||
                manifest.name.toLowerCase().includes(query.toLowerCase()) ||
                manifest.description.toLowerCase().includes(query.toLowerCase());
            const matchesTags = !tags || tags.length === 0 ||
                tags.some(tag => manifest.tags?.includes(tag));
            return matchesQuery && matchesTags;
        });
    }
    async installPluginFromMarketplace(pluginId) {
        // This would download and install a plugin from the marketplace
        // For now, return false
        this.logger.warn('Plugin marketplace installation not implemented', { pluginId });
        return false;
    }
    // Plugin health and monitoring
    async getPluginHealth(pluginId) {
        const plugin = this.plugins.get(pluginId);
        if (!plugin) {
            throw new Error(`Plugin not found: ${pluginId}`);
        }
        // This would collect actual health metrics
        // For now, return basic information
        return {
            status: plugin.status,
            memoryUsage: 0, // Would be actual memory usage
            uptime: plugin.lastUsed ? Date.now() - plugin.lastUsed.getTime() : 0,
            errorRate: plugin.status === 'error' ? 1 : 0,
            lastError: plugin.error
        };
    }
    // Cleanup
    async cleanup() {
        for (const plugin of Array.from(this.plugins.values())) {
            try {
                if (plugin.instance && typeof plugin.instance.cleanup === 'function') {
                    await plugin.instance.cleanup();
                }
            }
            catch (error) {
                this.logger.error('Failed to cleanup plugin', {
                    pluginId: plugin.id,
                    error: error instanceof Error ? error.message : String(error)
                });
            }
        }
        this.plugins.clear();
        this.loadedModules.clear();
        this.logger.info('Plugin manager cleaned up');
    }
}
exports.PluginManager = PluginManager;
