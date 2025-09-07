/**
 * Provider registry for managing AI service configurations
 */

import * as fs from 'fs-extra';
import * as path from 'path';
import { z } from 'zod';

// Provider configuration schema
const ProviderConfigSchema = z.object({
  name: z.string(),
  url: z.string().url(),
  loginSignal: z.string(),
  input: z.string(),
  send: z.object({
    gesture: z.string().optional(),
    button: z.string().optional()
  }),
  assistantContainer: z.string(),
  completionSignals: z.array(z.string()).optional(),
  platforms: z.array(z.enum(['desktop', 'android', 'ios'])),
  capabilities: z.object({
    streaming: z.boolean(),
    fileUpload: z.boolean(),
    codeExecution: z.boolean(),
    imageGeneration: z.boolean()
  }),
  selectors: z.record(z.string()).optional()
});

export type ProviderConfig = z.infer<typeof ProviderConfigSchema>;

export interface ProviderRegistry {
  [key: string]: ProviderConfig;
}

export class ProviderManager {
  private configPath: string;
  private registry: ProviderRegistry = {};

  constructor(configPath: string = './providers.json') {
    this.configPath = configPath;
  }

  /**
   * Load provider configurations from file
   */
  async loadProviders(): Promise<ProviderRegistry> {
    try {
      if (!(await fs.pathExists(this.configPath))) {
        console.warn(`Provider config file not found: ${this.configPath}`);
        return {};
      }

      const configData = await fs.readJson(this.configPath);
      this.registry = {};

      // Validate each provider configuration
      for (const [key, config] of Object.entries(configData)) {
        try {
          this.registry[key] = ProviderConfigSchema.parse(config);
        } catch (error) {
          console.warn(`Invalid provider config for ${key}:`, error);
        }
      }

      return this.registry;
    } catch (error) {
      console.error('Failed to load provider configurations:', error);
      return {};
    }
  }

  /**
   * Save provider configurations to file
   */
  async saveProviders(): Promise<void> {
    try {
      await fs.ensureDir(path.dirname(this.configPath));
      await fs.writeJson(this.configPath, this.registry, { spaces: 2 });
    } catch (error) {
      console.error('Failed to save provider configurations:', error);
      throw error;
    }
  }

  /**
   * Get a specific provider configuration
   */
  getProvider(providerId: string): ProviderConfig | null {
    return this.registry[providerId] || null;
  }

  /**
   * Add or update a provider configuration
   */
  setProvider(providerId: string, config: ProviderConfig): void {
    try {
      // Validate configuration
      ProviderConfigSchema.parse(config);
      this.registry[providerId] = config;
    } catch (error) {
      throw new Error(`Invalid provider configuration: ${error}`);
    }
  }

  /**
   * Remove a provider configuration
   */
  removeProvider(providerId: string): boolean {
    if (providerId in this.registry) {
      delete this.registry[providerId];
      return true;
    }
    return false;
  }

  /**
   * List all available providers
   */
  listProviders(): Array<{ id: string; name: string; platforms: string[]; capabilities: any }> {
    return Object.entries(this.registry).map(([id, config]) => ({
      id,
      name: config.name,
      platforms: config.platforms,
      capabilities: config.capabilities
    }));
  }

  /**
   * Get providers compatible with a specific platform
   */
  getProvidersForPlatform(platform: 'desktop' | 'android' | 'ios'): Array<{ id: string; name: string; capabilities: any }> {
    return Object.entries(this.registry)
      .filter(([_, config]) => config.platforms.includes(platform))
      .map(([id, config]) => ({
        id,
        name: config.name,
        capabilities: config.capabilities
      }));
  }

  /**
   * Validate provider configuration
   */
  validateProvider(config: any): { valid: boolean; errors: string[] } {
    try {
      ProviderConfigSchema.parse(config);
      return { valid: true, errors: [] };
    } catch (error) {
      if (error instanceof z.ZodError) {
        return {
          valid: false,
          errors: error.errors.map(e => `${e.path.join('.')}: ${e.message}`)
        };
      }
      return { valid: false, errors: ['Unknown validation error'] };
    }
  }

  /**
   * Get provider capabilities summary
   */
  getCapabilitiesSummary(): Record<string, any> {
    const summary: Record<string, any> = {};
    
    for (const [id, config] of Object.entries(this.registry)) {
      summary[id] = {
        name: config.name,
        platforms: config.platforms,
        capabilities: config.capabilities,
        hasStreaming: config.capabilities.streaming,
        hasFileUpload: config.capabilities.fileUpload,
        hasCodeExecution: config.capabilities.codeExecution,
        hasImageGeneration: config.capabilities.imageGeneration
      };
    }
    
    return summary;
  }
}

// Global provider manager instance
export const providerManager = new ProviderManager(
  process.env.PROVIDER_CONFIG_PATH || './providers.json'
);

/**
 * Load provider configuration by ID
 */
export async function loadProvider(providerId: string): Promise<ProviderConfig> {
  await providerManager.loadProviders();
  const config = providerManager.getProvider(providerId);
  
  if (!config) {
    throw new Error(`Provider not found: ${providerId}`);
  }
  
  return config;
}

/**
 * Get all available providers
 */
export async function getAllProviders(): Promise<Array<{ id: string; name: string; platforms: string[]; capabilities: any }>> {
  await providerManager.loadProviders();
  return providerManager.listProviders();
}
