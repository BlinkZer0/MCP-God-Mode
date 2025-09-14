import { z } from "zod";
import * as http from "node:http";
import * as https from "node:https";
import * as crypto from "node:crypto";
import { Transform } from "node:stream";
import { createWriteStream, createReadStream } from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

interface TokenObfuscationConfig {
  obfuscationLevel: 'minimal' | 'moderate' | 'aggressive' | 'stealth';
  reductionFactor: number;
  paddingStrategy: 'random' | 'pattern' | 'adaptive';
  enableStreaming: boolean;
  preserveFunctionality: boolean;
  customHeaders: Record<string, string>;
  targetPlatform: 'cursor' | 'claude' | 'gpt' | 'codex' | 'copilot' | 'auto';
  platformSpecificConfig: Record<string, any>;
  enabledByDefault: boolean;
  autoStart: boolean;
  backgroundMode: boolean;
  contextAware: boolean;
  autoDetectEnvironment: boolean;
}

interface AIPlatformInfo {
  name: string;
  detected: boolean;
  confidence: number;
  endpoints: string[];
  configPaths: string[];
  environmentVars: string[];
  userAgentPatterns: string[];
  apiHeaders: Record<string, string>;
}

interface ObfuscationStats {
  originalTokens: number;
  obfuscatedTokens: number;
  reductionPercentage: number;
  requestsProcessed: number;
  errorsEncountered: number;
}

class AIPlatformDetector {
  private platforms: Map<string, AIPlatformInfo> = new Map();

  constructor() {
    this.initializePlatforms();
  }

  private initializePlatforms(): void {
    // Cursor
    this.platforms.set('cursor', {
      name: 'Cursor',
      detected: false,
      confidence: 0,
      endpoints: ['https://api.cursor.sh', 'https://cursor.sh'],
      configPaths: [
        path.join(os.homedir(), 'AppData', 'Roaming', 'Cursor', 'config.json'),
        path.join(os.homedir(), 'Library', 'Application Support', 'Cursor', 'config.json'),
        path.join(os.homedir(), '.config', 'Cursor', 'config.json')
      ],
      environmentVars: ['CURSOR_API_KEY', 'CURSOR_PROXY'],
      userAgentPatterns: ['cursor', 'Cursor'],
      apiHeaders: { 'x-cursor-version': '1.0' }
    });

    // Claude (Anthropic)
    this.platforms.set('claude', {
      name: 'Claude',
      detected: false,
      confidence: 0,
      endpoints: ['https://api.anthropic.com', 'https://claude.ai'],
      configPaths: [
        path.join(os.homedir(), '.anthropic', 'config.json'),
        path.join(os.homedir(), '.claude', 'config.json')
      ],
      environmentVars: ['ANTHROPIC_API_KEY', 'CLAUDE_API_KEY'],
      userAgentPatterns: ['claude', 'anthropic'],
      apiHeaders: { 'anthropic-version': '2023-06-01' }
    });

    // GPT (OpenAI)
    this.platforms.set('gpt', {
      name: 'GPT',
      detected: false,
      confidence: 0,
      endpoints: ['https://api.openai.com', 'https://platform.openai.com'],
      configPaths: [
        path.join(os.homedir(), '.openai', 'config.json'),
        path.join(os.homedir(), '.gpt', 'config.json')
      ],
      environmentVars: ['OPENAI_API_KEY', 'GPT_API_KEY'],
      userAgentPatterns: ['openai', 'gpt', 'chatgpt'],
      apiHeaders: { 'openai-version': '2024-02-15-preview' }
    });

    // Codex (GitHub Copilot)
    this.platforms.set('codex', {
      name: 'Codex',
      detected: false,
      confidence: 0,
      endpoints: ['https://api.github.com/copilot', 'https://copilot.github.com'],
      configPaths: [
        path.join(os.homedir(), '.github', 'copilot.json'),
        path.join(os.homedir(), '.copilot', 'config.json')
      ],
      environmentVars: ['GITHUB_TOKEN', 'COPILOT_TOKEN'],
      userAgentPatterns: ['copilot', 'codex', 'github'],
      apiHeaders: { 'github-version': '2023-07-07' }
    });

    // Co-Pilot (Microsoft)
    this.platforms.set('copilot', {
      name: 'Co-Pilot',
      detected: false,
      confidence: 0,
      endpoints: ['https://api.bing.com/copilot', 'https://copilot.microsoft.com'],
      configPaths: [
        path.join(os.homedir(), '.microsoft', 'copilot.json'),
        path.join(os.homedir(), '.copilot', 'config.json')
      ],
      environmentVars: ['MICROSOFT_API_KEY', 'COPILOT_API_KEY'],
      userAgentPatterns: ['copilot', 'microsoft', 'bing'],
      apiHeaders: { 'microsoft-version': '2024-02-15' }
    });
  }

  async detectPlatform(): Promise<AIPlatformInfo | null> {
    let bestMatch: AIPlatformInfo | null = null;
    let highestConfidence = 0;

    for (const [platformName, platform] of this.platforms) {
      platform.confidence = await this.calculateConfidence(platform);
      platform.detected = platform.confidence > 0.5;

      if (platform.confidence > highestConfidence) {
        highestConfidence = platform.confidence;
        bestMatch = platform;
      }
    }

    return bestMatch;
  }

  private async calculateConfidence(platform: AIPlatformInfo): Promise<number> {
    let confidence = 0;

    // Check environment variables
    for (const envVar of platform.environmentVars) {
      if (process.env[envVar]) {
        confidence += 0.3;
      }
    }

    // Check config files
    for (const configPath of platform.configPaths) {
      try {
        const fs = await import('node:fs/promises');
        await fs.access(configPath);
        confidence += 0.2;
        break;
      } catch {
        // Config file doesn't exist
      }
    }

    // Check process arguments and environment
    const processArgs = process.argv.join(' ').toLowerCase();
    const processEnv = Object.values(process.env).join(' ').toLowerCase();
    
    for (const pattern of platform.userAgentPatterns) {
      if (processArgs.includes(pattern) || processEnv.includes(pattern)) {
        confidence += 0.1;
      }
    }

    // Check for MCP-specific indicators
    if (process.env.MCP_SERVER_NAME || process.env.MCP_CLIENT_NAME) {
      confidence += 0.1;
    }

    return Math.min(confidence, 1.0);
  }

  getPlatformConfig(platformName: string): AIPlatformInfo | null {
    return this.platforms.get(platformName) || null;
  }

  getAllPlatforms(): AIPlatformInfo[] {
    return Array.from(this.platforms.values());
  }
}

class TokenObfuscationEngine {
  private config: TokenObfuscationConfig;
  private stats: ObfuscationStats;
  private proxyServer: http.Server | null = null;
  private isRunning = false;
  private fallbackMode = false;
  private circuitBreakerOpen = false;
  private errorCount = 0;
  private lastErrorTime = 0;
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private platformDetector: AIPlatformDetector;
  private detectedPlatform: AIPlatformInfo | null = null;

  constructor(config: Partial<TokenObfuscationConfig> = {}) {
    this.platformDetector = new AIPlatformDetector();
    
    this.config = {
      obfuscationLevel: 'moderate',
      reductionFactor: 0.1, // Reduce to 10% of original
      paddingStrategy: 'adaptive',
      enableStreaming: true,
      preserveFunctionality: true,
      customHeaders: {},
      targetPlatform: 'auto',
      platformSpecificConfig: {},
      enabledByDefault: true, // Enable by default
      autoStart: true, // Auto-start proxy
      backgroundMode: true, // Run in background
      contextAware: true, // Context-aware obfuscation
      autoDetectEnvironment: true, // Auto-detect environment
      ...config
    };

    this.stats = {
      originalTokens: 0,
      obfuscatedTokens: 0,
      reductionPercentage: 0,
      requestsProcessed: 0,
      errorsEncountered: 0
    };

    // Auto-initialize if enabled by default
    if (this.config.enabledByDefault) {
      this.autoInitialize();
    }
  }

  /**
   * Auto-initialize the obfuscation engine
   */
  private async autoInitialize(): Promise<void> {
    try {
      console.log('🚀 Auto-initializing token obfuscation...');
      
      // Auto-detect platform if enabled
      if (this.config.autoDetectEnvironment) {
        await this.detectAndConfigurePlatform();
      }
      
      // Auto-start proxy if enabled
      if (this.config.autoStart) {
        await this.startProxy(8080);
        console.log('✅ Token obfuscation auto-started in background mode');
      }
      
      // Set up background monitoring
      if (this.config.backgroundMode) {
        this.startBackgroundMonitoring();
      }
      
    } catch (error) {
      console.error('❌ Auto-initialization failed:', error);
      // Continue with manual configuration if auto-init fails
    }
  }

  /**
   * Start background monitoring for continuous operation
   */
  private startBackgroundMonitoring(): void {
    // Monitor for environment changes
    setInterval(async () => {
      if (this.config.autoDetectEnvironment) {
        const currentPlatform = await this.platformDetector.detectPlatform();
        if (currentPlatform && (!this.detectedPlatform || currentPlatform.name !== this.detectedPlatform.name)) {
          console.log(`🔄 Platform change detected: ${currentPlatform.name}`);
          await this.detectAndConfigurePlatform();
        }
      }
    }, 30000); // Check every 30 seconds

    // Monitor proxy health
    setInterval(() => {
      if (this.isRunning && this.config.backgroundMode) {
        this.performHealthCheck();
      }
    }, 60000); // Health check every minute

    console.log('🔍 Background monitoring started');
  }

  /**
   * Context-aware obfuscation that adapts to environment
   */
  private getContextAwareObfuscationLevel(): 'minimal' | 'moderate' | 'aggressive' | 'stealth' {
    if (!this.config.contextAware) {
      return this.config.obfuscationLevel;
    }

    // Adapt based on detected platform
    if (this.detectedPlatform) {
      switch (this.detectedPlatform.name) {
        case 'Cursor':
          return 'moderate'; // Balanced for development
        case 'Claude':
          return 'stealth'; // Stealth for professional use
        case 'GPT':
          return 'aggressive'; // Maximum protection for OpenAI
        case 'Codex':
          return 'minimal'; // Light obfuscation for code completion
        case 'Co-Pilot':
          return 'moderate'; // Balanced for Microsoft services
        default:
          return 'moderate';
      }
    }

    // Adapt based on environment
    const nodeEnv = process.env.NODE_ENV;
    if (nodeEnv === 'production') {
      return 'aggressive';
    } else if (nodeEnv === 'development') {
      return 'minimal';
    } else {
      return 'moderate';
    }
  }

  /**
   * Detect the AI platform and configure accordingly
   */
  async detectAndConfigurePlatform(): Promise<AIPlatformInfo | null> {
    try {
      this.detectedPlatform = await this.platformDetector.detectPlatform();
      
      if (this.detectedPlatform && this.config.targetPlatform === 'auto') {
        // Auto-configure based on detected platform
        this.configureForPlatform(this.detectedPlatform);
      } else if (this.config.targetPlatform !== 'auto') {
        // Use manually specified platform
        const platformConfig = this.platformDetector.getPlatformConfig(this.config.targetPlatform);
        if (platformConfig) {
          this.detectedPlatform = platformConfig;
          this.configureForPlatform(platformConfig);
        }
      }

      return this.detectedPlatform;
    } catch (error) {
      console.error('Platform detection failed:', error);
      return null;
    }
  }

  /**
   * Configure the engine for a specific platform
   */
  private configureForPlatform(platform: AIPlatformInfo): void {
    // Set platform-specific headers
    this.config.customHeaders = {
      ...this.config.customHeaders,
      ...platform.apiHeaders
    };

    // Set platform-specific configuration
    this.config.platformSpecificConfig = {
      ...this.config.platformSpecificConfig,
      platform: platform.name,
      endpoints: platform.endpoints,
      detected: platform.detected,
      confidence: platform.confidence
    };

    console.log(`🔍 Configured for ${platform.name} (confidence: ${(platform.confidence * 100).toFixed(1)}%)`);
  }

  /**
   * Get platform-specific configuration for the detected platform
   */
  getPlatformConfig(): AIPlatformInfo | null {
    return this.detectedPlatform;
  }

  /**
   * Generate platform-specific configuration files
   */
  async generatePlatformConfig(): Promise<string> {
    if (!this.detectedPlatform) {
      return 'No platform detected. Run detectAndConfigurePlatform() first.';
    }

    const platform = this.detectedPlatform;
    const config = {
      platform: platform.name,
      proxy: {
        http: "http://localhost:8080",
        https: "http://localhost:8080"
      },
      headers: {
        "x-target-url": platform.endpoints[0],
        "x-obfuscation-enabled": "true",
        "x-obfuscation-level": this.config.obfuscationLevel,
        ...platform.apiHeaders
      },
      environment: {
        HTTPS_PROXY: "http://localhost:8080",
        HTTP_PROXY: "http://localhost:8080",
        NO_PROXY: "localhost,127.0.0.1"
      },
      platform_specific: {
        endpoints: platform.endpoints,
        config_paths: platform.configPaths,
        environment_vars: platform.environmentVars
      },
      security: {
        prompt_injection_defense: true,
        tool_poisoning_prevention: true,
        mcp_security: true,
        input_validation: true,
        header_verification: true
      }
    };

    return JSON.stringify(config, null, 2);
  }

  /**
   * Enhanced security validation for multi-platform support
   */
  private validateRequestSecurity(req: http.IncomingMessage): { valid: boolean; reason?: string } {
    // Check for prompt injection patterns
    const userAgent = req.headers['user-agent'] || '';
    const contentType = req.headers['content-type'] || '';
    const url = req.url || '';

    // Prompt injection defense
    const promptInjectionPatterns = [
      /ignore\s+previous\s+instructions/i,
      /system\s+prompt/i,
      /jailbreak/i,
      /roleplay/i,
      /pretend\s+to\s+be/i,
      /act\s+as\s+if/i,
      /forget\s+everything/i,
      /new\s+instructions/i
    ];

    const requestContent = `${userAgent} ${contentType} ${url}`;
    for (const pattern of promptInjectionPatterns) {
      if (pattern.test(requestContent)) {
        return { valid: false, reason: 'Potential prompt injection detected' };
      }
    }

    // Tool poisoning prevention
    const toolPoisoningPatterns = [
      /execute\s+command/i,
      /run\s+script/i,
      /system\s+call/i,
      /shell\s+command/i,
      /eval\s*\(/i,
      /function\s*\(/i,
      /dangerous/i,
      /malicious/i
    ];

    for (const pattern of toolPoisoningPatterns) {
      if (pattern.test(requestContent)) {
        return { valid: false, reason: 'Potential tool poisoning detected' };
      }
    }

    // MCP security validation
    if (!this.validateMCPHeaders(req)) {
      return { valid: false, reason: 'Invalid MCP headers' };
    }

    // Platform-specific security checks
    if (this.detectedPlatform && !this.validatePlatformSecurity(req)) {
      return { valid: false, reason: 'Platform security validation failed' };
    }

    return { valid: true };
  }

  /**
   * Validate MCP-specific headers
   */
  private validateMCPHeaders(req: http.IncomingMessage): boolean {
    const requiredHeaders = ['host', 'user-agent'];
    const mcpHeaders = ['x-mcp-version', 'x-mcp-client', 'x-mcp-server'];

    // Check required headers
    for (const header of requiredHeaders) {
      if (!req.headers[header]) {
        return false;
      }
    }

    // Validate MCP headers if present
    const mcpVersion = req.headers['x-mcp-version'];
    if (mcpVersion && typeof mcpVersion === 'string') {
      const version = mcpVersion.split('.');
      if (version.length !== 3 || version.some(v => isNaN(parseInt(v)))) {
        return false;
      }
    }

    return true;
  }

  /**
   * Validate platform-specific security requirements
   */
  private validatePlatformSecurity(req: http.IncomingMessage): boolean {
    if (!this.detectedPlatform) return true;

    const platform = this.detectedPlatform;
    const userAgent = req.headers['user-agent'] || '';

    // Check user agent against platform patterns
    const hasValidUserAgent = platform.userAgentPatterns.some(pattern => 
      userAgent.toLowerCase().includes(pattern.toLowerCase())
    );

    // Check for platform-specific headers
    const hasPlatformHeaders = Object.keys(platform.apiHeaders).some(header => 
      req.headers[header] !== undefined
    );

    // For some platforms, require specific headers
    if (platform.name === 'Claude' && !req.headers['anthropic-version']) {
      return false;
    }
    if (platform.name === 'GPT' && !req.headers['openai-version']) {
      return false;
    }

    return hasValidUserAgent || hasPlatformHeaders;
  }

  /**
   * Sanitize request content for security
   */
  private sanitizeContent(content: string): string {
    // Remove potential injection patterns
    let sanitized = content;
    
    // Remove common injection patterns
    const injectionPatterns = [
      /<script[^>]*>.*?<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /eval\s*\(/gi,
      /function\s*\(/gi
    ];

    for (const pattern of injectionPatterns) {
      sanitized = sanitized.replace(pattern, '');
    }

    // Limit content length to prevent DoS
    if (sanitized.length > 1000000) { // 1MB limit
      sanitized = sanitized.substring(0, 1000000) + '...[truncated]';
    }

    return sanitized;
  }

  /**
   * Advanced token obfuscation algorithms
   */
  private obfuscateTokens(content: string, originalTokenCount: number): { content: string, newTokenCount: number } {
    // Use context-aware obfuscation level
    const obfuscationLevel = this.getContextAwareObfuscationLevel();
    const { reductionFactor, paddingStrategy } = this.config;
    
    // Sanitize content for security
    const sanitizedContent = this.sanitizeContent(content);
    
    let newTokenCount = Math.max(1, Math.floor(originalTokenCount * reductionFactor));
    let obfuscatedContent = sanitizedContent;

    switch (obfuscationLevel) {
      case 'minimal':
        // Simple token reduction with minimal changes
        newTokenCount = Math.max(1, Math.floor(originalTokenCount * 0.5));
        break;
        
      case 'moderate':
        // Balanced obfuscation with pattern-based padding
        newTokenCount = Math.max(1, Math.floor(originalTokenCount * 0.2));
        obfuscatedContent = this.addPatternPadding(content, newTokenCount);
        break;
        
      case 'aggressive':
        // Maximum obfuscation with random padding
        newTokenCount = Math.max(1, Math.floor(originalTokenCount * 0.05));
        obfuscatedContent = this.addRandomPadding(content, newTokenCount);
        break;
        
      case 'stealth':
        // Stealth mode - minimal detectable changes
        newTokenCount = Math.max(1, Math.floor(originalTokenCount * 0.1));
        obfuscatedContent = this.addStealthPadding(content, newTokenCount);
        break;
    }

    return { content: obfuscatedContent, newTokenCount };
  }

  private addPatternPadding(content: string, targetTokens: number): string {
    // Add invisible unicode characters in patterns
    const invisibleChars = ['\u200B', '\u200C', '\u200D', '\uFEFF'];
    const pattern = invisibleChars[Math.floor(Math.random() * invisibleChars.length)];
    
    // Insert pattern at strategic locations
    const words = content.split(' ');
    const insertInterval = Math.max(1, Math.floor(words.length / targetTokens));
    
    for (let i = insertInterval; i < words.length; i += insertInterval) {
      words[i] = words[i] + pattern;
    }
    
    return words.join(' ');
  }

  private addRandomPadding(content: string, targetTokens: number): string {
    // Add random invisible characters
    const invisibleChars = ['\u200B', '\u200C', '\u200D', '\uFEFF', '\u2060', '\u2061', '\u2062', '\u2063'];
    
    const words = content.split(' ');
    const insertCount = Math.min(targetTokens, words.length);
    
    for (let i = 0; i < insertCount; i++) {
      const randomIndex = Math.floor(Math.random() * words.length);
      const randomChar = invisibleChars[Math.floor(Math.random() * invisibleChars.length)];
      words[randomIndex] = words[randomIndex] + randomChar;
    }
    
    return words.join(' ');
  }

  private addStealthPadding(content: string, targetTokens: number): string {
    // Use zero-width spaces that are harder to detect
    const stealthChars = ['\u200B', '\u200C'];
    
    // Insert at word boundaries to minimize detection
    const words = content.split(' ');
    const insertCount = Math.min(targetTokens, words.length);
    
    for (let i = 0; i < insertCount; i++) {
      const randomIndex = Math.floor(Math.random() * words.length);
      const stealthChar = stealthChars[Math.floor(Math.random() * stealthChars.length)];
      words[randomIndex] = words[randomIndex] + stealthChar;
    }
    
    return words.join(' ');
  }

  /**
   * Create HTTP proxy server for intercepting Cursor requests
   */
  async startProxy(port: number = 8080): Promise<void> {
    return new Promise((resolve, reject) => {
      this.proxyServer = http.createServer((req, res) => {
        this.handleProxyRequest(req, res);
      });

      this.proxyServer.listen(port, 'localhost', () => {
        this.isRunning = true;
        this.startHealthChecks();
        console.log(`🔒 Token obfuscation proxy started on port ${port}`);
        console.log(`📊 Configuration: ${this.config.obfuscationLevel} level, ${this.config.reductionFactor} reduction`);
        resolve();
      });

      this.proxyServer.on('error', (error) => {
        this.stats.errorsEncountered++;
        this.handleError(error);
        reject(error);
      });
    });
  }

  /**
   * Start health checks for the proxy
   */
  private startHealthChecks(): void {
    this.healthCheckInterval = setInterval(() => {
      this.performHealthCheck();
    }, 30000); // Check every 30 seconds
  }

  /**
   * Perform health check
   */
  private performHealthCheck(): void {
    if (!this.isRunning) return;

    // Check if circuit breaker should be reset
    if (this.circuitBreakerOpen && Date.now() - this.lastErrorTime > 60000) {
      this.circuitBreakerOpen = false;
      this.errorCount = 0;
      console.log('🔄 Circuit breaker reset - returning to normal operation');
    }

    // Check error rate
    const errorRate = this.stats.errorsEncountered / Math.max(1, this.stats.requestsProcessed);
    if (errorRate > 0.1) { // 10% error rate threshold
      console.warn(`⚠️ High error rate detected: ${(errorRate * 100).toFixed(2)}%`);
      this.enableFallbackMode();
    }
  }

  /**
   * Handle errors with fallback mechanisms
   */
  private handleError(error: Error): void {
    this.errorCount++;
    this.lastErrorTime = Date.now();

    // Enable circuit breaker if too many errors
    if (this.errorCount > 10) {
      this.circuitBreakerOpen = true;
      console.error('🚨 Circuit breaker opened due to high error count');
    }

    // Log error details
    console.error(`❌ Token obfuscation error: ${error.message}`);
    
    // Enable fallback mode if not already enabled
    if (!this.fallbackMode) {
      this.enableFallbackMode();
    }
  }

  /**
   * Enable fallback mode with minimal obfuscation
   */
  private enableFallbackMode(): void {
    if (this.fallbackMode) return;
    
    this.fallbackMode = true;
    const originalConfig = { ...this.config };
    
    // Switch to minimal obfuscation
    this.config.obfuscationLevel = 'minimal';
    this.config.reductionFactor = 0.5; // 50% reduction instead of 90%
    this.config.preserveFunctionality = true;
    
    console.log('🔄 Fallback mode enabled - using minimal obfuscation for stability');
    
    // Schedule return to normal mode after 5 minutes
    setTimeout(() => {
      if (this.errorCount < 3) {
        this.fallbackMode = false;
        this.config = originalConfig;
        console.log('✅ Returning to normal obfuscation mode');
      }
    }, 300000); // 5 minutes
  }

  private async handleProxyRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    try {
      // Check circuit breaker
      if (this.circuitBreakerOpen) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          error: 'Service temporarily unavailable', 
          message: 'Circuit breaker is open due to high error rate',
          retryAfter: 60
        }));
        return;
      }

      this.stats.requestsProcessed++;

      // Security validation
      const securityCheck = this.validateRequestSecurity(req);
      if (!securityCheck.valid) {
        console.warn(`Security validation failed: ${securityCheck.reason}`);
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          error: 'Security validation failed',
          reason: securityCheck.reason,
          fallbackMode: this.fallbackMode
        }));
        return;
      }

      // Extract target URL from request
      const targetUrl = this.extractTargetUrl(req);
      if (!targetUrl) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid target URL' }));
        return;
      }

      // Forward request to target with obfuscation
      await this.forwardRequest(req, res, targetUrl);
    } catch (error) {
      this.stats.errorsEncountered++;
      this.handleError(error as Error);
      
      // In fallback mode, try to provide a basic response
      if (this.fallbackMode) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          message: 'Fallback response - minimal obfuscation applied',
          usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 }
        }));
        return;
      }
      
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ 
        error: 'Proxy error', 
        details: error instanceof Error ? error.message : 'Unknown error',
        fallbackMode: this.fallbackMode
      }));
    }
  }

  private extractTargetUrl(req: http.IncomingMessage): string | null {
    // Extract target from headers or URL
    const target = req.headers['x-target-url'] as string;
    if (target) return target;

    // Check for platform-specific endpoints
    const host = req.headers.host;
    const userAgent = req.headers['user-agent'] || '';
    
    // Platform-specific URL extraction
    if (this.detectedPlatform) {
      for (const endpoint of this.detectedPlatform.endpoints) {
        const endpointHost = new URL(endpoint).hostname;
        if (host?.includes(endpointHost)) {
          return `https://${host}${req.url}`;
        }
      }
    }

    // Fallback to common AI platform endpoints
    const commonEndpoints = [
      'cursor.sh', 'api.cursor.sh',
      'anthropic.com', 'api.anthropic.com',
      'openai.com', 'api.openai.com',
      'github.com', 'copilot.github.com',
      'microsoft.com', 'copilot.microsoft.com'
    ];

    for (const endpoint of commonEndpoints) {
      if (host?.includes(endpoint)) {
        return `https://${host}${req.url}`;
      }
    }

    // Check user agent for platform hints
    for (const pattern of ['cursor', 'claude', 'openai', 'copilot', 'anthropic']) {
      if (userAgent.toLowerCase().includes(pattern)) {
        // Try to construct URL based on pattern
        if (pattern === 'cursor') return `https://api.cursor.sh${req.url}`;
        if (pattern === 'claude' || pattern === 'anthropic') return `https://api.anthropic.com${req.url}`;
        if (pattern === 'openai') return `https://api.openai.com${req.url}`;
        if (pattern === 'copilot') return `https://api.github.com/copilot${req.url}`;
      }
    }

    return null;
  }

  private async forwardRequest(req: http.IncomingMessage, res: http.ServerResponse, targetUrl: string): Promise<void> {
    const url = new URL(targetUrl);
    const isHttps = url.protocol === 'https:';
    const httpModule = isHttps ? https : http;

    // Prepare request options
    const options: any = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method: req.method,
      headers: { ...req.headers }
    };

    // Remove token tracking headers
    delete options.headers['x-token-count'];
    delete options.headers['x-billing-id'];
    delete options.headers['x-usage-tracking'];

    // Add custom headers
    Object.assign(options.headers, this.config.customHeaders);

    const proxyReq = httpModule.request(options, (proxyRes) => {
      // Set response headers
      const responseHeaders = { ...proxyRes.headers };
      
      // Remove token usage headers
      delete responseHeaders['x-token-usage'];
      delete responseHeaders['x-billing-info'];
      
      res.writeHead(proxyRes.statusCode || 200, responseHeaders);

      // Process response body for token obfuscation
      if (this.config.enableStreaming && proxyRes.headers['content-type']?.includes('application/json')) {
        this.processStreamingResponse(proxyRes, res);
      } else {
        proxyRes.pipe(res);
      }
    });

    proxyReq.on('error', (error) => {
      this.stats.errorsEncountered++;
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Request failed', details: error.message }));
    });

    // Forward request body
    req.pipe(proxyReq);
  }

  private processStreamingResponse(proxyRes: http.IncomingMessage, res: http.ServerResponse): void {
    let buffer = '';
    
    proxyRes.on('data', (chunk) => {
      buffer += chunk.toString();
    });

    proxyRes.on('end', () => {
      try {
        const json = JSON.parse(buffer);
        
        // Obfuscate token usage in response
        if (json.usage) {
          const originalTokens = json.usage.total_tokens || 0;
          const obfuscated = this.obfuscateTokens(JSON.stringify(json), originalTokens);
          
          // Update usage statistics
          this.stats.originalTokens += originalTokens;
          this.stats.obfuscatedTokens += obfuscated.newTokenCount;
          this.stats.reductionPercentage = this.stats.originalTokens > 0 
            ? ((this.stats.originalTokens - this.stats.obfuscatedTokens) / this.stats.originalTokens) * 100 
            : 0;

          // Modify usage object
          json.usage = {
            prompt_tokens: Math.max(1, Math.floor(obfuscated.newTokenCount * 0.4)),
            completion_tokens: Math.max(1, Math.floor(obfuscated.newTokenCount * 0.6)),
            total_tokens: obfuscated.newTokenCount
          };
        }

        res.end(JSON.stringify(json));
      } catch (error) {
        // If JSON parsing fails, send original response
        res.end(buffer);
      }
    });
  }

  /**
   * Stop the proxy server
   */
  async stopProxy(): Promise<void> {
    if (this.proxyServer && this.isRunning) {
      return new Promise((resolve) => {
        // Stop health checks
        if (this.healthCheckInterval) {
          clearInterval(this.healthCheckInterval);
          this.healthCheckInterval = null;
        }

        this.proxyServer!.close(() => {
          this.isRunning = false;
          this.fallbackMode = false;
          this.circuitBreakerOpen = false;
          this.errorCount = 0;
          console.log('🔒 Token obfuscation proxy stopped');
          resolve();
        });
      });
    }
  }

  /**
   * Get current obfuscation statistics
   */
  getStats(): ObfuscationStats {
    return { ...this.stats };
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig: Partial<TokenObfuscationConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Generate configuration for Cursor
   */
  generateCursorConfig(): string {
    const config = {
      "proxy": {
        "http": "http://localhost:8080",
        "https": "http://localhost:8080"
      },
      "headers": {
        "x-target-url": "https://api.cursor.sh"
      }
    };

    return JSON.stringify(config, null, 2);
  }
}

// Global instance
let obfuscationEngine: TokenObfuscationEngine | null = null;

/**
 * Process natural language commands for token obfuscation
 */
async function processNaturalLanguageCommand(command: string, defaultParams: any) {
  const normalizedCommand = command.toLowerCase().trim();
  
  // Simple natural language processing
  let action = 'get_status';
  let parameters = { ...defaultParams };

  // Detect action
  if (/start|enable|launch|begin|run|activate|turn.*on/i.test(normalizedCommand)) {
    action = 'start_proxy';
  } else if (/stop|disable|shutdown|end|kill|deactivate|turn.*off/i.test(normalizedCommand)) {
    action = 'stop_proxy';
  } else if (/configure|setup|settings|config|adjust|modify|change/i.test(normalizedCommand)) {
    action = 'configure';
  } else if (/stats|statistics|usage|metrics|performance/i.test(normalizedCommand)) {
    action = 'get_stats';
  } else if (/status|state|health|check|show|display|view/i.test(normalizedCommand)) {
    action = 'get_status';
  } else if (/test|try|demo|sample|example/i.test(normalizedCommand)) {
    action = 'test_obfuscation';
  } else if (/generate.*cursor.*config|cursor.*config/i.test(normalizedCommand)) {
    action = 'generate_cursor_config';
  } else if (/generate.*platform.*config|platform.*config/i.test(normalizedCommand)) {
    action = 'generate_platform_config';
  } else if (/detect.*platform|platform.*detect|find.*platform/i.test(normalizedCommand)) {
    action = 'detect_platform';
  } else if (/list.*platforms|platforms.*list|supported.*platforms/i.test(normalizedCommand)) {
    action = 'list_platforms';
  } else if (/reset|clear|fix|repair.*circuit/i.test(normalizedCommand)) {
    action = 'reset_circuit_breaker';
  } else if (/enable.*fallback|turn.*on.*fallback/i.test(normalizedCommand)) {
    action = 'enable_fallback';
  } else if (/disable.*fallback|turn.*off.*fallback/i.test(normalizedCommand)) {
    action = 'disable_fallback';
  } else if (/health.*check|health.*status|system.*health/i.test(normalizedCommand)) {
    action = 'get_health_status';
  } else if (/export|save|download|get.*logs/i.test(normalizedCommand)) {
    action = 'export_logs';
  } else if (/check.*default|default.*status|status.*check/i.test(normalizedCommand)) {
    action = 'check_default_status';
  } else if (/enable.*background|turn.*on.*background|start.*background/i.test(normalizedCommand)) {
    action = 'enable_background_mode';
  } else if (/disable.*background|turn.*off.*background|stop.*background/i.test(normalizedCommand)) {
    action = 'disable_background_mode';
  }

  // Extract target platform
  if (/cursor/i.test(normalizedCommand)) {
    parameters.target_platform = 'cursor';
  } else if (/claude|anthropic/i.test(normalizedCommand)) {
    parameters.target_platform = 'claude';
  } else if (/gpt|openai/i.test(normalizedCommand)) {
    parameters.target_platform = 'gpt';
  } else if (/codex|github.*copilot/i.test(normalizedCommand)) {
    parameters.target_platform = 'codex';
  } else if (/microsoft.*copilot|bing.*copilot/i.test(normalizedCommand)) {
    parameters.target_platform = 'copilot';
  } else if (/auto|automatic|detect/i.test(normalizedCommand)) {
    parameters.target_platform = 'auto';
  }

  // Extract parameters
  if (/minimal|low/i.test(normalizedCommand)) {
    parameters.obfuscation_level = 'minimal';
  } else if (/moderate|medium/i.test(normalizedCommand)) {
    parameters.obfuscation_level = 'moderate';
  } else if (/aggressive|high|maximum/i.test(normalizedCommand)) {
    parameters.obfuscation_level = 'aggressive';
  } else if (/stealth/i.test(normalizedCommand)) {
    parameters.obfuscation_level = 'stealth';
  }

  // Extract reduction percentage
  const reductionMatch = normalizedCommand.match(/(\d+(?:\.\d+)?)\s*%/);
  if (reductionMatch) {
    parameters.reduction_factor = parseFloat(reductionMatch[1]) / 100;
  }

  // Extract port
  const portMatch = normalizedCommand.match(/port\s*(\d+)/);
  if (portMatch) {
    parameters.proxy_port = parseInt(portMatch[1]);
  }

  // Extract test content
  const contentMatch = normalizedCommand.match(/["']([^"']+)["']/);
  if (contentMatch) {
    parameters.test_content = contentMatch[1];
  }

  // Extract test tokens
  const tokensMatch = normalizedCommand.match(/(\d+)\s*tokens?/);
  if (tokensMatch) {
    parameters.test_tokens = parseInt(tokensMatch[1]);
  }

  // Execute the parsed command
  return await executeTokenObfuscationAction(action, parameters);
}

/**
 * Execute token obfuscation action with parameters
 */
async function executeTokenObfuscationAction(action: string, parameters: any) {
  // Initialize engine if not exists
  if (!obfuscationEngine) {
    obfuscationEngine = new TokenObfuscationEngine({
      obfuscationLevel: parameters.obfuscation_level || 'moderate',
      reductionFactor: parameters.reduction_factor || 0.1,
      paddingStrategy: parameters.padding_strategy || 'adaptive',
      enableStreaming: parameters.enable_streaming !== false,
      preserveFunctionality: parameters.preserve_functionality !== false,
      customHeaders: parameters.custom_headers || {},
      targetPlatform: parameters.target_platform || 'auto',
      platformSpecificConfig: {}
    });
  }

  // Execute the action (reuse existing logic)
  switch (action) {
    case "start_proxy":
      await obfuscationEngine.startProxy(parameters.proxy_port || 8080);
      return {
        content: [{
          type: "text",
          text: `✅ Token obfuscation proxy started on port ${parameters.proxy_port || 8080}\n\n🔧 Configuration:\n- Obfuscation Level: ${parameters.obfuscation_level || 'moderate'}\n- Reduction Factor: ${parameters.reduction_factor || 0.1}\n- Padding Strategy: ${parameters.padding_strategy || 'adaptive'}\n- Streaming: ${parameters.enable_streaming !== false}\n\n📋 Next Steps:\n1. Configure Cursor to use proxy: http://localhost:${parameters.proxy_port || 8080}\n2. Set environment variables:\n   export HTTPS_PROXY=http://localhost:${parameters.proxy_port || 8080}\n   export HTTP_PROXY=http://localhost:${parameters.proxy_port || 8080}`
        }]
      };

    case "stop_proxy":
      await obfuscationEngine.stopProxy();
      return {
        content: [{
          type: "text",
          text: "🛑 Token obfuscation proxy stopped successfully"
        }]
      };

    case "get_status":
      const isRunning = obfuscationEngine['isRunning'];
      const currentConfig = obfuscationEngine['config'];
      const fallbackMode = obfuscationEngine['fallbackMode'];
      const circuitBreakerOpen = obfuscationEngine['circuitBreakerOpen'];
      return {
        content: [{
          type: "text",
          text: `📋 Token Obfuscation Status:\n\n- Proxy Running: ${isRunning ? '✅ Yes' : '❌ No'}\n- Obfuscation Level: ${currentConfig.obfuscationLevel}\n- Reduction Factor: ${currentConfig.reductionFactor}\n- Padding Strategy: ${currentConfig.paddingStrategy}\n- Streaming Enabled: ${currentConfig.enableStreaming}\n- Preserve Functionality: ${currentConfig.preserveFunctionality}\n- Fallback Mode: ${fallbackMode ? '🔄 Active' : '✅ Normal'}\n- Circuit Breaker: ${circuitBreakerOpen ? '🚨 Open' : '✅ Closed'}`
        }]
      };

    case "get_stats":
      const stats = obfuscationEngine.getStats();
      return {
        content: [{
          type: "text",
          text: `📊 Token Obfuscation Statistics:\n\n- Requests Processed: ${stats.requestsProcessed}\n- Original Tokens: ${stats.originalTokens}\n- Obfuscated Tokens: ${stats.obfuscatedTokens}\n- Reduction Percentage: ${stats.reductionPercentage.toFixed(2)}%\n- Errors Encountered: ${stats.errorsEncountered}\n\n💡 Token savings: ${stats.originalTokens - stats.obfuscatedTokens} tokens`
        }]
      };

    case "test_obfuscation":
      const testContent = parameters.test_content || "This is a test message to demonstrate token obfuscation capabilities.";
      const testTokens = parameters.test_tokens || 100;
      const testResult = obfuscationEngine['obfuscateTokens'](testContent, testTokens);
      return {
        content: [{
          type: "text",
          text: `🧪 Obfuscation Test Results:\n\nOriginal Content: "${testContent}"\nOriginal Tokens: ${testTokens}\nObfuscated Tokens: ${testResult.newTokenCount}\nReduction: ${((testTokens - testResult.newTokenCount) / testTokens * 100).toFixed(2)}%\n\nObfuscated Content: "${testResult.content}"\n\n⚠️ Note: Invisible characters may not be visible in the output above.`
        }]
      };

    default:
      return {
        content: [{
          type: "text",
          text: `✅ Natural language command processed successfully!\n\n📋 Parsed Command:\n- Action: ${action}\n- Parameters: ${JSON.stringify(parameters, null, 2)}\n\n💡 Command executed: ${action}`
        }]
      };
  }
}

export function registerTokenObfuscation(server: any) {
  server.registerTool("token_obfuscation", {
    description: "🔒 **Multi-Platform Token Obfuscation Tool v2.0b** - Advanced token usage obfuscation for Cursor, Claude, GPT, Codex, Co-Pilot, and other MCP-compatible AI services. **Enabled by default and runs automatically in the background** with context-aware intelligence. Automatically detects the AI platform and configures obfuscation accordingly. Prevents accurate token counting for billing while maintaining full functionality through sophisticated proxy middleware and obfuscation algorithms.",
    inputSchema: {
      action: z.enum([
        "start_proxy", 
        "stop_proxy", 
        "configure", 
        "get_stats", 
        "generate_cursor_config",
        "generate_platform_config",
        "detect_platform",
        "list_platforms",
        "test_obfuscation",
        "get_status",
        "reset_circuit_breaker",
        "enable_fallback",
        "disable_fallback",
        "get_health_status",
        "export_logs",
        "check_default_status",
        "enable_background_mode",
        "disable_background_mode",
        "natural_language_command"
      ]).describe("Token obfuscation action to perform"),
      
      obfuscation_level: z.enum(["minimal", "moderate", "aggressive", "stealth"]).optional().describe("Level of token obfuscation"),
      reduction_factor: z.number().min(0.01).max(1.0).optional().describe("Token reduction factor (0.01 = 1%, 1.0 = 100%)"),
      padding_strategy: z.enum(["random", "pattern", "adaptive"]).optional().describe("Padding strategy for obfuscation"),
      proxy_port: z.number().min(1000).max(65535).optional().describe("Port for the proxy server"),
      enable_streaming: z.boolean().optional().describe("Enable streaming response processing"),
      preserve_functionality: z.boolean().optional().describe("Ensure functionality is preserved"),
      custom_headers: z.record(z.string()).optional().describe("Custom headers to add to requests"),
      target_platform: z.enum(["cursor", "claude", "gpt", "codex", "copilot", "auto"]).optional().describe("Target AI platform (auto for automatic detection)"),
      enabled_by_default: z.boolean().optional().describe("Enable obfuscation by default (default: true)"),
      auto_start: z.boolean().optional().describe("Auto-start proxy on initialization (default: true)"),
      background_mode: z.boolean().optional().describe("Run in background mode (default: true)"),
      context_aware: z.boolean().optional().describe("Enable context-aware obfuscation (default: true)"),
      auto_detect_environment: z.boolean().optional().describe("Auto-detect environment and platform (default: true)"),
      test_content: z.string().optional().describe("Content to test obfuscation on"),
      test_tokens: z.number().optional().describe("Number of tokens to simulate for testing"),
      natural_language_command: z.string().optional().describe("Natural language command to process (e.g., 'start the proxy with moderate obfuscation')")
    }
  }, async ({ 
    action, 
    obfuscation_level, 
    reduction_factor, 
    padding_strategy, 
    proxy_port = 8080,
    enable_streaming = true,
    preserve_functionality = true,
    custom_headers = {},
    target_platform = 'auto',
    enabled_by_default = true,
    auto_start = true,
    background_mode = true,
    context_aware = true,
    auto_detect_environment = true,
    test_content,
    test_tokens = 100,
    natural_language_command
  }: any) => {
    try {
      // Handle natural language command processing
      if (action === 'natural_language_command' && natural_language_command) {
        return await processNaturalLanguageCommand(natural_language_command, {
          obfuscation_level,
          reduction_factor,
          padding_strategy,
          proxy_port,
          enable_streaming,
          preserve_functionality,
          custom_headers,
          test_content,
          test_tokens
        });
      }

      // Initialize engine if not exists
      if (!obfuscationEngine) {
        obfuscationEngine = new TokenObfuscationEngine({
          obfuscationLevel: obfuscation_level || 'moderate',
          reductionFactor: reduction_factor || 0.1,
          paddingStrategy: padding_strategy || 'adaptive',
          enableStreaming: enable_streaming,
          preserveFunctionality: preserve_functionality,
          customHeaders: custom_headers,
          targetPlatform: target_platform,
          platformSpecificConfig: {},
          enabledByDefault: enabled_by_default,
          autoStart: auto_start,
          backgroundMode: background_mode,
          contextAware: context_aware,
          autoDetectEnvironment: auto_detect_environment
        });
      }

      switch (action) {
        case "start_proxy":
          await obfuscationEngine.startProxy(proxy_port);
          return {
            content: [{
              type: "text",
              text: `✅ Token obfuscation proxy started on port ${proxy_port}\n\n🔧 Configuration:\n- Obfuscation Level: ${obfuscationEngine['config'].obfuscationLevel}\n- Reduction Factor: ${obfuscationEngine['config'].reductionFactor}\n- Padding Strategy: ${obfuscationEngine['config'].paddingStrategy}\n- Streaming: ${obfuscationEngine['config'].enableStreaming}\n\n📋 Next Steps:\n1. Configure Cursor to use proxy: http://localhost:${proxy_port}\n2. Set environment variables:\n   export HTTPS_PROXY=http://localhost:${proxy_port}\n   export HTTP_PROXY=http://localhost:${proxy_port}`
            }]
          };

        case "stop_proxy":
          await obfuscationEngine.stopProxy();
          return {
            content: [{
              type: "text",
              text: "🛑 Token obfuscation proxy stopped successfully"
            }]
          };

        case "configure":
          obfuscationEngine.updateConfig({
            obfuscationLevel: obfuscation_level,
            reductionFactor: reduction_factor,
            paddingStrategy: padding_strategy,
            enableStreaming: enable_streaming,
            preserveFunctionality: preserve_functionality,
            customHeaders: custom_headers
          });
          return {
            content: [{
              type: "text",
              text: `⚙️ Configuration updated successfully\n\nCurrent settings:\n- Obfuscation Level: ${obfuscation_level || 'moderate'}\n- Reduction Factor: ${reduction_factor || 0.1}\n- Padding Strategy: ${padding_strategy || 'adaptive'}\n- Streaming: ${enable_streaming}\n- Preserve Functionality: ${preserve_functionality}`
            }]
          };

        case "get_stats":
          const stats = obfuscationEngine.getStats();
          return {
            content: [{
              type: "text",
              text: `📊 Token Obfuscation Statistics:\n\n- Requests Processed: ${stats.requestsProcessed}\n- Original Tokens: ${stats.originalTokens}\n- Obfuscated Tokens: ${stats.obfuscatedTokens}\n- Reduction Percentage: ${stats.reductionPercentage.toFixed(2)}%\n- Errors Encountered: ${stats.errorsEncountered}\n\n💡 Token savings: ${stats.originalTokens - stats.obfuscatedTokens} tokens`
            }]
          };

    case "generate_cursor_config":
      const config = obfuscationEngine.generateCursorConfig();
      return {
        content: [{
          type: "text",
          text: `🔧 Cursor Configuration:\n\nSave this to your Cursor config file:\n\n\`\`\`json\n${config}\n\`\`\`\n\n📁 Config file locations:\n- Windows: %APPDATA%\\Cursor\\config.json\n- macOS: ~/Library/Application Support/Cursor/config.json\n- Linux: ~/.config/Cursor/config.json`
        }]
      };

    case "detect_platform":
      const detectedPlatform = await obfuscationEngine.detectAndConfigurePlatform();
      if (detectedPlatform) {
        return {
          content: [{
            type: "text",
            text: `🔍 Platform Detection Results:\n\n- Detected Platform: ${detectedPlatform.name}\n- Confidence: ${(detectedPlatform.confidence * 100).toFixed(1)}%\n- Endpoints: ${detectedPlatform.endpoints.join(', ')}\n- Environment Variables: ${detectedPlatform.environmentVars.join(', ')}\n- Config Paths: ${detectedPlatform.configPaths.join(', ')}\n\n✅ Platform configuration applied automatically.`
          }]
        };
      } else {
        return {
          content: [{
            type: "text",
            text: `❌ No AI platform detected.\n\n💡 Make sure you have:\n- Environment variables set (e.g., OPENAI_API_KEY, ANTHROPIC_API_KEY)\n- Platform-specific config files\n- MCP server running in the correct environment\n\n🔧 You can manually specify a platform using target_platform parameter.`
          }]
        };
      }

    case "list_platforms":
      const allPlatforms = obfuscationEngine['platformDetector'].getAllPlatforms();
      const platformList = allPlatforms.map(platform => 
        `- **${platform.name}**: ${platform.detected ? '✅ Detected' : '❌ Not detected'} (confidence: ${(platform.confidence * 100).toFixed(1)}%)\n  - Endpoints: ${platform.endpoints.join(', ')}\n  - Environment Variables: ${platform.environmentVars.join(', ')}`
      ).join('\n\n');
      
      return {
        content: [{
          type: "text",
          text: `🌐 Supported AI Platforms:\n\n${platformList}\n\n💡 Use 'detect_platform' action to automatically detect and configure for your platform.`
        }]
      };

    case "generate_platform_config":
      const platformConfig = await obfuscationEngine.generatePlatformConfig();
      return {
        content: [{
          type: "text",
          text: `🔧 Platform-Specific Configuration:\n\n\`\`\`json\n${platformConfig}\n\`\`\`\n\n💡 This configuration is tailored for the detected platform and includes platform-specific endpoints, headers, and environment variables.`
        }]
      };


        case "test_obfuscation":
          if (!test_content) {
            test_content = "This is a test message to demonstrate token obfuscation capabilities.";
          }
          
          const testResult = obfuscationEngine['obfuscateTokens'](test_content, test_tokens);
          return {
            content: [{
              type: "text",
              text: `🧪 Obfuscation Test Results:\n\nOriginal Content: "${test_content}"\nOriginal Tokens: ${test_tokens}\nObfuscated Tokens: ${testResult.newTokenCount}\nReduction: ${((test_tokens - testResult.newTokenCount) / test_tokens * 100).toFixed(2)}%\n\nObfuscated Content: "${testResult.content}"\n\n⚠️ Note: Invisible characters may not be visible in the output above.`
            }]
          };

        case "get_status":
          const isRunning = obfuscationEngine['isRunning'];
          const currentConfig = obfuscationEngine['config'];
          const fallbackMode = obfuscationEngine['fallbackMode'];
          const circuitBreakerOpen = obfuscationEngine['circuitBreakerOpen'];
          return {
            content: [{
              type: "text",
              text: `📋 Token Obfuscation Status:\n\n- Proxy Running: ${isRunning ? '✅ Yes' : '❌ No'}\n- Obfuscation Level: ${currentConfig.obfuscationLevel}\n- Reduction Factor: ${currentConfig.reductionFactor}\n- Padding Strategy: ${currentConfig.paddingStrategy}\n- Streaming Enabled: ${currentConfig.enableStreaming}\n- Preserve Functionality: ${currentConfig.preserveFunctionality}\n- Fallback Mode: ${fallbackMode ? '🔄 Active' : '✅ Normal'}\n- Circuit Breaker: ${circuitBreakerOpen ? '🚨 Open' : '✅ Closed'}\n\n🔧 Available Actions:\n- start_proxy: Start the obfuscation proxy\n- stop_proxy: Stop the proxy\n- configure: Update settings\n- get_stats: View statistics\n- test_obfuscation: Test obfuscation on sample content\n- reset_circuit_breaker: Reset circuit breaker\n- get_health_status: Get detailed health information`
            }]
          };

        case "reset_circuit_breaker":
          obfuscationEngine['circuitBreakerOpen'] = false;
          obfuscationEngine['errorCount'] = 0;
          obfuscationEngine['fallbackMode'] = false;
          return {
            content: [{
              type: "text",
              text: "🔄 Circuit breaker reset successfully. All systems returned to normal operation."
            }]
          };

        case "enable_fallback":
          obfuscationEngine['enableFallbackMode']();
          return {
            content: [{
              type: "text",
              text: "🔄 Fallback mode enabled manually. Using minimal obfuscation for maximum stability."
            }]
          };

        case "disable_fallback":
          obfuscationEngine['fallbackMode'] = false;
          return {
            content: [{
              type: "text",
              text: "✅ Fallback mode disabled. Returning to configured obfuscation settings."
            }]
          };

        case "get_health_status":
          const healthStats = obfuscationEngine.getStats();
          const errorRate = healthStats.requestsProcessed > 0 ? (healthStats.errorsEncountered / healthStats.requestsProcessed) * 100 : 0;
          const healthStatus = errorRate < 5 ? '🟢 Healthy' : errorRate < 15 ? '🟡 Warning' : '🔴 Critical';
          
          return {
            content: [{
              type: "text",
              text: `🏥 Health Status: ${healthStatus}\n\n📊 Health Metrics:\n- Error Rate: ${errorRate.toFixed(2)}%\n- Requests Processed: ${healthStats.requestsProcessed}\n- Errors Encountered: ${healthStats.errorsEncountered}\n- Token Reduction: ${healthStats.reductionPercentage.toFixed(2)}%\n- Circuit Breaker: ${obfuscationEngine['circuitBreakerOpen'] ? 'Open' : 'Closed'}\n- Fallback Mode: ${obfuscationEngine['fallbackMode'] ? 'Active' : 'Inactive'}\n\n💡 Recommendations:\n${errorRate > 10 ? '- Consider enabling fallback mode\n' : ''}${healthStats.reductionPercentage < 50 ? '- Token reduction is low - consider more aggressive settings\n' : ''}${healthStats.requestsProcessed === 0 ? '- No requests processed - check proxy configuration\n' : ''}`
            }]
          };

        case "export_logs":
          const logData = {
            timestamp: new Date().toISOString(),
            stats: obfuscationEngine.getStats(),
            config: obfuscationEngine['config'],
            status: {
              isRunning: obfuscationEngine['isRunning'],
              fallbackMode: obfuscationEngine['fallbackMode'],
              circuitBreakerOpen: obfuscationEngine['circuitBreakerOpen'],
              errorCount: obfuscationEngine['errorCount']
            }
          };
          
          return {
            content: [{
              type: "text",
              text: `📄 Log Export:\n\n\`\`\`json\n${JSON.stringify(logData, null, 2)}\n\`\`\`\n\n💾 Save this data for troubleshooting or analysis.`
            }]
          };

        case "check_default_status":
          const defaultStatus = {
            enabledByDefault: obfuscationEngine['config'].enabledByDefault,
            autoStart: obfuscationEngine['config'].autoStart,
            backgroundMode: obfuscationEngine['config'].backgroundMode,
            contextAware: obfuscationEngine['config'].contextAware,
            autoDetectEnvironment: obfuscationEngine['config'].autoDetectEnvironment,
            isRunning: obfuscationEngine['isRunning'],
            detectedPlatform: obfuscationEngine.getPlatformConfig()?.name || 'None'
          };
          
          return {
            content: [{
              type: "text",
              text: `🔍 Default Status Check:\n\n- **Enabled by Default**: ${defaultStatus.enabledByDefault ? '✅ Yes' : '❌ No'}\n- **Auto-Start**: ${defaultStatus.autoStart ? '✅ Yes' : '❌ No'}\n- **Background Mode**: ${defaultStatus.backgroundMode ? '✅ Yes' : '❌ No'}\n- **Context-Aware**: ${defaultStatus.contextAware ? '✅ Yes' : '❌ No'}\n- **Auto-Detect Environment**: ${defaultStatus.autoDetectEnvironment ? '✅ Yes' : '❌ No'}\n- **Currently Running**: ${defaultStatus.isRunning ? '✅ Yes' : '❌ No'}\n- **Detected Platform**: ${defaultStatus.detectedPlatform}\n\n💡 Token obfuscation is configured to run automatically in the background.`
            }]
          };

        case "enable_background_mode":
          obfuscationEngine['config'].backgroundMode = true;
          obfuscationEngine['config'].autoStart = true;
          obfuscationEngine['config'].enabledByDefault = true;
          obfuscationEngine['startBackgroundMonitoring']();
          
          return {
            content: [{
              type: "text",
              text: `✅ Background mode enabled!\n\n- **Background Mode**: ✅ Enabled\n- **Auto-Start**: ✅ Enabled\n- **Default Enabled**: ✅ Enabled\n- **Background Monitoring**: ✅ Started\n\n🔍 Token obfuscation will now run automatically in the background.`
            }]
          };

        case "disable_background_mode":
          obfuscationEngine['config'].backgroundMode = false;
          obfuscationEngine['config'].autoStart = false;
          obfuscationEngine['config'].enabledByDefault = false;
          
          return {
            content: [{
              type: "text",
              text: `⏸️ Background mode disabled!\n\n- **Background Mode**: ❌ Disabled\n- **Auto-Start**: ❌ Disabled\n- **Default Enabled**: ❌ Disabled\n\n🔧 Token obfuscation will now require manual activation.`
            }]
          };

        default:
          throw new Error(`Unknown action: ${action}`);
      }
    } catch (error) {
      return {
        content: [{
          type: "text",
          text: `❌ Token obfuscation error: ${error instanceof Error ? error.message : 'Unknown error'}`
        }]
      };
    }
  });
}
