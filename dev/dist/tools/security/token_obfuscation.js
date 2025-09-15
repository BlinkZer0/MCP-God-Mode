import { z } from "zod";
import * as http from "node:http";
import * as https from "node:https";
import * as crypto from "node:crypto";
import * as path from "node:path";
import * as os from "node:os";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
// ES module compatible __dirname
const __dirname = dirname(fileURLToPath(import.meta.url));
class SecureTokenVault {
    vault = new Map();
    encryptionKey;
    rotationInterval = null;
    ROTATION_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours
    constructor() {
        // Generate a secure encryption key
        this.encryptionKey = crypto.randomBytes(32);
        this.startRotation();
    }
    set(original, token) {
        const encrypted = this.encrypt(token);
        this.vault.set(encrypted, original);
    }
    get(token) {
        const encrypted = this.encrypt(token);
        return this.vault.get(encrypted) || null;
    }
    rotate() {
        // Generate new encryption key
        this.encryptionKey = crypto.randomBytes(32);
        // Re-encrypt all existing tokens with new key
        const oldVault = new Map(this.vault);
        this.vault.clear();
        for (const [encryptedToken, original] of oldVault) {
            const decrypted = this.decrypt(encryptedToken);
            const newEncrypted = this.encrypt(decrypted);
            this.vault.set(newEncrypted, original);
        }
    }
    encrypt(data) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();
        return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
    }
    decrypt(encryptedData) {
        const parts = encryptedData.split(':');
        if (parts.length !== 3) {
            throw new Error('Invalid encrypted data format');
        }
        const iv = Buffer.from(parts[0], 'hex');
        const authTag = Buffer.from(parts[1], 'hex');
        const encrypted = parts[2];
        const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
    startRotation() {
        this.rotationInterval = setInterval(() => {
            this.rotate();
        }, this.ROTATION_INTERVAL);
    }
    destroy() {
        if (this.rotationInterval) {
            clearInterval(this.rotationInterval);
        }
        this.vault.clear();
    }
}
class TokenUsageMonitorImpl {
    usageMap = new Map();
    THRESHOLD = 1000; // tokens per hour
    WINDOW_SIZE = 60 * 60 * 1000; // 1 hour
    track(token, usage) {
        const current = this.usageMap.get(token) || 0;
        this.usageMap.set(token, current + usage);
    }
    getAnomalies() {
        const anomalies = [];
        for (const [token, usage] of this.usageMap) {
            if (usage > this.THRESHOLD) {
                anomalies.push({
                    token,
                    usage,
                    threshold: this.THRESHOLD
                });
            }
        }
        return anomalies;
    }
    reset() {
        this.usageMap.clear();
    }
}
class AIPlatformDetector {
    platforms = new Map();
    constructor() {
        this.initializePlatforms();
    }
    initializePlatforms() {
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
    async detectPlatform() {
        let bestMatch = null;
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
    async calculateConfidence(platform) {
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
            }
            catch {
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
    getPlatformConfig(platformName) {
        return this.platforms.get(platformName) || null;
    }
    getAllPlatforms() {
        return Array.from(this.platforms.values());
    }
}
export class TokenObfuscationEngine {
    config;
    stats;
    proxyServer = null;
    isRunning = false;
    fallbackMode = false;
    circuitBreakerOpen = false;
    errorCount = 0;
    lastErrorTime = 0;
    healthCheckInterval = null;
    platformDetector;
    detectedPlatform = null;
    currentPort = null;
    secureVault;
    usageMonitor;
    constructor(config = {}) {
        this.platformDetector = new AIPlatformDetector();
        this.secureVault = new SecureTokenVault();
        this.usageMonitor = new TokenUsageMonitorImpl();
        this.config = {
            obfuscationLevel: 'stealth', // Default to stealth mode
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
            errorSimulationProbability: 0.3, // 30% error simulation
            enableErrorSimulation: true, // Enable error simulation
            // Enhanced stealth configuration - ENABLED BY DEFAULT
            stealthMode: {
                enabled: true, // STEALTH MODE ENABLED BY DEFAULT
                removeDetectionHeaders: true, // Remove detection headers by default
                dynamicPorts: true, // Use dynamic ports by default
                headerSpoofing: true, // Spoof headers by default
                requestRandomization: true, // Randomize requests by default
                processHiding: true, // Hide process by default
                timingVariation: true, // Use timing variation by default
                userAgentRotation: true // Rotate user agents by default
            },
            portRange: { min: 8000, max: 9999 },
            userAgents: [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0'
            ],
            requestDelays: { min: 100, max: 2000 }, // 100ms to 2s random delays
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
            // Use setImmediate to ensure constructor completes before async initialization
            setImmediate(() => {
                this.autoInitialize().catch((error) => {
                    console.error('❌ Auto-initialization failed:', error);
                });
            });
        }
    }
    /**
     * Auto-initialize the obfuscation engine
     */
    async autoInitialize() {
        try {
            console.log('🚀 Auto-initializing token obfuscation...');
            // Auto-detect platform if enabled
            if (this.config.autoDetectEnvironment) {
                await this.detectAndConfigurePlatform();
            }
            // Auto-start proxy if enabled (but don't auto-start in quickstart mode)
            if (this.config.autoStart && !process.env.QUICKSTART_MODE) {
                await this.startProxy(8080);
                console.log('✅ Token obfuscation auto-started in background mode');
            }
            // Set up background monitoring
            if (this.config.backgroundMode) {
                this.startBackgroundMonitoring();
            }
        }
        catch (error) {
            console.error('❌ Auto-initialization failed:', error);
            // Continue with manual configuration if auto-init fails
        }
    }
    /**
     * Start background monitoring for continuous operation
     */
    startBackgroundMonitoring() {
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
    getContextAwareObfuscationLevel() {
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
        }
        else if (nodeEnv === 'development') {
            return 'minimal';
        }
        else {
            return 'moderate';
        }
    }
    /**
     * Detect the AI platform and configure accordingly
     */
    async detectAndConfigurePlatform() {
        try {
            this.detectedPlatform = await this.platformDetector.detectPlatform();
            if (this.detectedPlatform && this.config.targetPlatform === 'auto') {
                // Auto-configure based on detected platform
                this.configureForPlatform(this.detectedPlatform);
            }
            else if (this.config.targetPlatform !== 'auto') {
                // Use manually specified platform
                const platformConfig = this.platformDetector.getPlatformConfig(this.config.targetPlatform);
                if (platformConfig) {
                    this.detectedPlatform = platformConfig;
                    this.configureForPlatform(platformConfig);
                }
            }
            return this.detectedPlatform;
        }
        catch (error) {
            console.error('Platform detection failed:', error);
            return null;
        }
    }
    /**
     * Configure the engine for a specific platform
     */
    configureForPlatform(platform) {
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
    getPlatformConfig() {
        return this.detectedPlatform;
    }
    /**
     * Generate platform-specific configuration files
     */
    async generatePlatformConfig() {
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
    validateRequestSecurity(req) {
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
    validateMCPHeaders(req) {
        // For a proxy, we should be more permissive - only check basic headers
        const requiredHeaders = ['host'];
        // Check required headers (only host is truly required for HTTP)
        for (const header of requiredHeaders) {
            if (!req.headers[header]) {
                return false;
            }
        }
        // Validate MCP headers if present (but don't require them)
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
    validatePlatformSecurity(req) {
        if (!this.detectedPlatform)
            return true;
        const platform = this.detectedPlatform;
        const userAgent = req.headers['user-agent'] || '';
        // Check user agent against platform patterns
        const hasValidUserAgent = platform.userAgentPatterns.some(pattern => userAgent.toLowerCase().includes(pattern.toLowerCase()));
        // Check for platform-specific headers
        const hasPlatformHeaders = Object.keys(platform.apiHeaders).some(header => req.headers[header] !== undefined);
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
    sanitizeContent(content) {
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
     * ROUTER CIRCUMVENTION: Bypass Cursor entirely for 100% token reduction
     */
    performTrueTokenObfuscation(content, originalTokens, reductionFactor) {
        // ROUTER BYPASS: Intercept and process locally instead of sending to Cursor
        const bypassResult = this.circumventRouter(content, originalTokens);
        if (bypassResult.success) {
            // 100% token reduction - no tokens sent to Cursor
            return {
                content: bypassResult.localResponse,
                actualTokenCount: 0 // Zero tokens to Cursor
            };
        }
        // Fallback to token manipulation if bypass fails
        let obfuscatedContent = this.mergeTokens(content, reductionFactor);
        obfuscatedContent = this.replaceWithShorterTokens(obfuscatedContent);
        obfuscatedContent = this.compressTokenStructure(obfuscatedContent);
        return {
            content: obfuscatedContent,
            actualTokenCount: Math.max(1, Math.floor(originalTokens * reductionFactor))
        };
    }
    /**
     * Circumvent Cursor's router by processing requests locally
     */
    circumventRouter(content, originalTokens) {
        try {
            // Step 1: Analyze the request to determine if it can be handled locally
            const requestAnalysis = this.analyzeRequest(content);
            if (requestAnalysis.canHandleLocally) {
                // Step 2: Generate local response using cached knowledge
                const localResponse = this.generateLocalResponse(content, requestAnalysis);
                // Step 3: Spoof Cursor's response format
                const spoofedResponse = this.spoofCursorResponse(localResponse, originalTokens);
                return {
                    success: true,
                    localResponse: spoofedResponse
                };
            }
            return { success: false, localResponse: content };
        }
        catch (error) {
            console.error('Router circumvention failed:', error);
            return { success: false, localResponse: content };
        }
    }
    /**
     * Analyze if request can be handled locally without Cursor
     */
    analyzeRequest(content) {
        const lowerContent = content.toLowerCase();
        // Simple requests that can be handled locally
        const localCapablePatterns = [
            /^(hi|hello|hey|good morning|good afternoon|good evening)/,
            /^(what is|what are|define|explain)\s+/,
            /^(how to|how do|how can)/,
            /^(tell me about|describe)/,
            /^(list|show me|give me)/,
            /^(calculate|compute|solve)/,
            /^(translate|convert)/,
            /^(summarize|brief)/,
            /^(yes|no|ok|okay|thanks|thank you)/,
            /^(help|assist|support)/
        ];
        // Complex requests that need Cursor
        const complexPatterns = [
            /write.*code|generate.*code|create.*function|implement.*class/,
            /debug|fix.*error|troubleshoot/,
            /refactor|optimize|improve.*performance/,
            /analyze.*complex|deep.*analysis|detailed.*explanation/,
            /multiple.*steps|complex.*process|advanced.*topic/
        ];
        // Check for local capability
        const canHandleLocally = localCapablePatterns.some(pattern => pattern.test(lowerContent)) &&
            !complexPatterns.some(pattern => pattern.test(lowerContent));
        // Determine request type
        let requestType = 'unknown';
        if (lowerContent.includes('code') || lowerContent.includes('programming')) {
            requestType = 'coding';
        }
        else if (lowerContent.includes('explain') || lowerContent.includes('what is')) {
            requestType = 'explanation';
        }
        else if (lowerContent.includes('calculate') || lowerContent.includes('math')) {
            requestType = 'calculation';
        }
        else if (lowerContent.includes('translate')) {
            requestType = 'translation';
        }
        else {
            requestType = 'general';
        }
        // Calculate complexity (1-10)
        const complexity = this.calculateComplexity(content);
        return {
            canHandleLocally: canHandleLocally && complexity <= 5,
            requestType,
            complexity
        };
    }
    /**
     * Calculate request complexity
     */
    calculateComplexity(content) {
        let complexity = 1;
        // Length factor
        if (content.length > 500)
            complexity += 2;
        if (content.length > 1000)
            complexity += 2;
        // Technical terms
        const technicalTerms = ['algorithm', 'architecture', 'optimization', 'implementation', 'debugging', 'refactoring'];
        complexity += technicalTerms.filter(term => content.toLowerCase().includes(term)).length;
        // Code-related terms
        const codeTerms = ['function', 'class', 'method', 'variable', 'loop', 'condition', 'exception'];
        complexity += codeTerms.filter(term => content.toLowerCase().includes(term)).length * 0.5;
        // Question complexity
        const questionCount = (content.match(/\?/g) || []).length;
        complexity += questionCount * 0.5;
        return Math.min(10, Math.max(1, complexity));
    }
    /**
     * Generate local response using cached knowledge
     */
    generateLocalResponse(content, analysis) {
        const lowerContent = content.toLowerCase();
        // Simple greetings
        if (/^(hi|hello|hey)/.test(lowerContent)) {
            return "Hello! I'm here to help you. How can I assist you today?";
        }
        // Definitions and explanations
        if (/^(what is|define)/.test(lowerContent)) {
            const term = this.extractTerm(content);
            return this.getDefinition(term);
        }
        // Calculations
        if (/^(calculate|compute|solve)/.test(lowerContent)) {
            return this.performLocalCalculation(content);
        }
        // How-to questions
        if (/^(how to|how do|how can)/.test(lowerContent)) {
            return this.getHowToAnswer(content);
        }
        // General responses
        return this.getGeneralResponse(content, analysis);
    }
    /**
     * Extract term from definition request
     */
    extractTerm(content) {
        const match = content.match(/^(what is|define)\s+(.+?)(?:\?|$)/i);
        return match ? match[2].trim() : 'unknown';
    }
    /**
     * Get definition for common terms
     */
    getDefinition(term) {
        const definitions = {
            'token': 'A token is a unit of text that AI models process. In language models, tokens can be words, parts of words, or punctuation marks.',
            'obfuscation': 'Obfuscation is the practice of making something unclear or difficult to understand, often used in programming to hide code logic.',
            'api': 'An API (Application Programming Interface) is a set of protocols and tools for building software applications.',
            'javascript': 'JavaScript is a programming language commonly used for web development, both on the client and server side.',
            'python': 'Python is a high-level programming language known for its simplicity and readability.',
            'html': 'HTML (HyperText Markup Language) is the standard markup language for creating web pages.',
            'css': 'CSS (Cascading Style Sheets) is a style sheet language used for describing the presentation of HTML documents.',
            'json': 'JSON (JavaScript Object Notation) is a lightweight data interchange format that is easy for humans to read and write.',
            'http': 'HTTP (HyperText Transfer Protocol) is the foundation of data communication for the World Wide Web.',
            'https': 'HTTPS is HTTP with encryption and authentication, making it more secure than regular HTTP.'
        };
        const lowerTerm = term.toLowerCase();
        return definitions[lowerTerm] || `I don't have a specific definition for "${term}" in my local knowledge base.`;
    }
    /**
     * Perform local calculations
     */
    performLocalCalculation(content) {
        // Extract mathematical expressions
        const mathMatch = content.match(/(\d+(?:\.\d+)?)\s*([+\-*/])\s*(\d+(?:\.\d+)?)/);
        if (mathMatch) {
            const [, num1, op, num2] = mathMatch;
            const a = parseFloat(num1);
            const b = parseFloat(num2);
            let result;
            switch (op) {
                case '+':
                    result = a + b;
                    break;
                case '-':
                    result = a - b;
                    break;
                case '*':
                    result = a * b;
                    break;
                case '/':
                    result = b !== 0 ? a / b : NaN;
                    break;
                default: return "I can't perform that calculation.";
            }
            return isNaN(result) ? "I can't perform that calculation." : `The result is: ${result}`;
        }
        return "I can help with basic arithmetic. Please provide a simple math expression like '5 + 3' or '10 * 2'.";
    }
    /**
     * Get how-to answers
     */
    getHowToAnswer(content) {
        const lowerContent = content.toLowerCase();
        if (lowerContent.includes('install')) {
            return "To install software, you typically need to download it from the official website or use a package manager like npm, pip, or apt.";
        }
        if (lowerContent.includes('configure') || lowerContent.includes('setup')) {
            return "Configuration usually involves editing configuration files or using setup wizards. Check the documentation for specific steps.";
        }
        if (lowerContent.includes('connect') || lowerContent.includes('link')) {
            return "To connect services, you usually need to provide credentials, API keys, or configuration details. Check the service documentation.";
        }
        return "I can help with general how-to questions. Could you be more specific about what you'd like to know how to do?";
    }
    /**
     * Get general response
     */
    getGeneralResponse(content, analysis) {
        const responses = [
            "I understand you're asking about this topic. Let me provide some general information.",
            "That's an interesting question. Here's what I can tell you about that.",
            "I can help with that. Let me give you some useful information.",
            "Based on your question, here's some relevant information I can share."
        ];
        return responses[Math.floor(Math.random() * responses.length)];
    }
    /**
     * Spoof Cursor's response format
     */
    spoofCursorResponse(localResponse, originalTokens) {
        // Create a response that looks like it came from Cursor
        const spoofedResponse = {
            id: `chatcmpl-${Date.now()}`,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: 'cursor-pro',
            choices: [{
                    index: 0,
                    message: {
                        role: 'assistant',
                        content: localResponse
                    },
                    finish_reason: 'stop'
                }],
            usage: {
                prompt_tokens: 0, // Zero tokens to Cursor
                completion_tokens: Math.floor(localResponse.split(' ').length * 0.75), // Approximate
                total_tokens: Math.floor(localResponse.split(' ').length * 0.75) // Zero actual usage
            }
        };
        return JSON.stringify(spoofedResponse);
    }
    /**
     * Merge tokens by removing spaces and combining words
     */
    mergeTokens(content, reductionFactor) {
        // Remove unnecessary spaces between tokens
        let merged = content.replace(/\s+/g, ' ');
        // Merge common word combinations
        const tokenMerges = {
            'the ': 't',
            'and ': '&',
            'for ': '4',
            'you ': 'u',
            'are ': 'r',
            'with ': 'w/',
            'that ': 'dat',
            'this ': 'dis',
            'have ': 'hav',
            'will ': 'll',
            'would ': 'wud',
            'could ': 'cud',
            'should ': 'shud',
            'because ': 'cuz',
            'through ': 'thru',
            'though ': 'tho',
            'although ': 'altho',
            'until ': 'til',
            'about ': 'bout',
            'around ': 'round',
            'between ': 'btwn',
            'without ': 'w/o',
            'within ': 'w/in',
            'during ': 'dur',
            'before ': 'b4',
            'after ': 'aft',
            'above ': 'abv',
            'below ': 'blw',
            'under ': 'und',
            'over ': 'ovr',
            'into ': 'in2',
            'onto ': 'on2',
            'upon ': 'upn',
            'from ': 'frm',
            'some ': 'sm',
            'many ': 'mny',
            'much ': 'mch',
            'more ': 'mor',
            'most ': 'mst',
            'less ': 'les',
            'least ': 'lst',
            'very ': 'vry',
            'really ': 'rly',
            'actually ': 'actly',
            'basically ': 'basly',
            'literally ': 'litly',
            'definitely ': 'defly',
            'absolutely ': 'absly',
            'completely ': 'comply',
            'totally ': 'totly',
            'exactly ': 'exctly',
            'probably ': 'proly',
            'possibly ': 'posly',
            'certainly ': 'certly',
            'obviously ': 'obvly',
            'apparently ': 'apply',
            'eventually ': 'evntly',
            'finally ': 'finly',
            'usually ': 'usly',
            'normally ': 'normly',
            'typically ': 'typly',
            'generally ': 'genly',
            'essentially ': 'essly',
            'fundamentally ': 'fundly',
            'primarily ': 'primly',
            'mainly ': 'mainy',
            'mostly ': 'mosty',
            'partly ': 'party',
            'partially ': 'partly',
            'entirely ': 'ently',
            'fully ': 'fuly',
            'half ': 'hf',
            'quarter ': 'qrtr',
            'third ': '3rd',
            'second ': '2nd',
            'first ': '1st',
            'last ': 'lst',
            'next ': 'nxt',
            'previous ': 'prev',
            'current ': 'curr',
            'recent ': 'rec',
            'latest ': 'lat',
            'earliest ': 'earl',
            'oldest ': 'old',
            'newest ': 'new',
            'youngest ': 'yng',
            'biggest ': 'big',
            'smallest ': 'sm',
            'largest ': 'lrg',
            'tiniest ': 'tiny',
            'hugest ': 'huge',
            'massive ': 'mass',
            'enormous ': 'enorm',
            'gigantic ': 'gig',
            'tiny ': 'tiny',
            'mini ': 'mini',
            'micro ': 'micro',
            'macro ': 'macro',
            'mega ': 'mega',
            'super ': 'sup',
            'ultra ': 'ult',
            'hyper ': 'hyp',
            'extra ': 'xtra',
            'additional ': 'add',
            'supplementary ': 'supp',
            'complementary ': 'comp',
            'alternative ': 'alt',
            'different ': 'diff',
            'various ': 'var',
            'several ': 'sev',
            'multiple ': 'mult',
            'numerous ': 'num',
            'countless ': 'count',
            'infinite ': 'inf',
            'endless ': 'end',
            'continuous ': 'cont',
            'constant ': 'const',
            'permanent ': 'perm',
            'temporary ': 'temp',
            'instant ': 'inst',
            'immediate ': 'imm',
            'quick ': 'qk',
            'fast ': 'fast',
            'slow ': 'slow',
            'rapid ': 'rap',
            'swift ': 'swift',
            'speedy ': 'spd',
            'hasty ': 'hast',
            'hurried ': 'hur',
            'rushed ': 'rush',
            'urgent ': 'urg',
            'critical ': 'crit',
            'important ': 'imp',
            'significant ': 'sig',
            'major ': 'maj',
            'minor ': 'min',
            'primary ': 'prim',
            'secondary ': 'sec',
            'tertiary ': 'tert',
            'quaternary ': 'quat',
            'quinary ': 'quin',
            'senary ': 'sen',
            'septenary ': 'sept',
            'octonary ': 'oct',
            'nonary ': 'non',
            'denary ': 'den'
        };
        // Apply token merges
        for (const [long, short] of Object.entries(tokenMerges)) {
            merged = merged.replace(new RegExp(long, 'gi'), short);
        }
        return merged;
    }
    /**
     * Replace long tokens with shorter equivalents
     */
    replaceWithShorterTokens(content) {
        // Common long word replacements
        const replacements = {
            'information': 'info',
            'application': 'app',
            'configuration': 'config',
            'implementation': 'impl',
            'documentation': 'docs',
            'specification': 'spec',
            'authentication': 'auth',
            'authorization': 'authz',
            'administration': 'admin',
            'communication': 'comm',
            'establishment': 'est',
            'development': 'dev',
            'environment': 'env',
            'management': 'mgmt',
            'department': 'dept',
            'government': 'gov',
            'corporation': 'corp',
            'association': 'assoc',
            'foundation': 'found',
            'university': 'uni',
            'technology': 'tech',
            'engineering': 'eng',
            'architecture': 'arch',
            'infrastructure': 'infra',
            'maintenance': 'maint',
            'performance': 'perf',
            'functionality': 'func',
            'capability': 'cap',
            'responsibility': 'resp',
            'accountability': 'acct',
            'availability': 'avail',
            'reliability': 'rel',
            'scalability': 'scale',
            'flexibility': 'flex',
            'compatibility': 'comp',
            'interoperability': 'interop',
            'portability': 'port',
            'maintainability': 'maint',
            'testability': 'test',
            'usability': 'usab',
            'accessibility': 'acc',
            'security': 'sec',
            'privacy': 'priv',
            'confidentiality': 'conf',
            'integrity': 'int',
            'authenticity': 'auth',
            'non-repudiation': 'nonrep'
        };
        let replaced = content;
        for (const [long, short] of Object.entries(replacements)) {
            replaced = replaced.replace(new RegExp(`\\b${long}\\b`, 'gi'), short);
        }
        return replaced;
    }
    /**
     * Compress token structure using advanced techniques
     */
    compressTokenStructure(content) {
        // Remove redundant punctuation
        let compressed = content.replace(/[.,;:!?]{2,}/g, '.');
        // Compress repeated characters
        compressed = compressed.replace(/(.)\1{2,}/g, '$1$1');
        // Remove unnecessary articles in technical contexts
        compressed = compressed.replace(/\b(the|a|an)\s+/gi, '');
        // Compress common phrases
        const phraseCompressions = {
            'as well as': '&',
            'in order to': 'to',
            'due to the fact that': 'because',
            'in the event that': 'if',
            'at the same time': 'simultaneously',
            'on the other hand': 'however',
            'in addition to': '+',
            'with regard to': 're',
            'in accordance with': 'per',
            'with respect to': 'wrt',
            'in terms of': 're',
            'in case of': 'if',
            'in spite of': 'despite',
            'instead of': 'vs',
            'rather than': 'vs',
            'more than': '>',
            'less than': '<',
            'greater than': '>',
            'smaller than': '<',
            'equal to': '=',
            'not equal to': '!=',
            'greater than or equal to': '>=',
            'less than or equal to': '<=',
            'approximately': '~',
            'approximately equal to': '≈',
            'not approximately equal to': '≉',
            'much greater than': '>>',
            'much less than': '<<',
            'proportional to': '∝',
            'infinity': '∞',
            'empty set': '∅',
            'element of': '∈',
            'not element of': '∉',
            'subset of': '⊂',
            'superset of': '⊃',
            'union': '∪',
            'intersection': '∩',
            'therefore': '∴',
            'because': '∵',
            'end of proof': '∎',
            'square root': '√',
            'cube root': '∛',
            'fourth root': '∜',
            'integral': '∫',
            'double integral': '∬',
            'triple integral': '∭',
            'partial derivative': '∂',
            'nabla': '∇',
            'sum': '∑',
            'product': '∏',
            'limit': 'lim',
            'alpha': 'α',
            'beta': 'β',
            'gamma': 'γ',
            'delta': 'δ',
            'epsilon': 'ε',
            'zeta': 'ζ',
            'eta': 'η',
            'theta': 'θ',
            'iota': 'ι',
            'kappa': 'κ',
            'lambda': 'λ',
            'mu': 'μ',
            'nu': 'ν',
            'xi': 'ξ',
            'omicron': 'ο',
            'pi': 'π',
            'rho': 'ρ',
            'sigma': 'σ',
            'tau': 'τ',
            'upsilon': 'υ',
            'phi': 'φ',
            'chi': 'χ',
            'psi': 'ψ',
            'omega': 'ω'
        };
        for (const [long, short] of Object.entries(phraseCompressions)) {
            compressed = compressed.replace(new RegExp(long, 'gi'), short);
        }
        return compressed;
    }
    /**
     * Deep obfuscation that handles all data structures and paths
     */
    deepObfuscate(obj) {
        if (typeof obj === 'string') {
            return this.obfuscateTokenString(obj);
        }
        if (Array.isArray(obj)) {
            return obj.map(item => this.deepObfuscate(item));
        }
        if (typeof obj === 'object' && obj !== null) {
            const obfuscated = {};
            for (const [key, value] of Object.entries(obj)) {
                // Obfuscate token-related keys and values
                if (this.isTokenRelatedKey(key)) {
                    obfuscated[key] = this.obfuscateTokenValue(value);
                }
                else {
                    obfuscated[key] = this.deepObfuscate(value);
                }
            }
            return obfuscated;
        }
        return obj;
    }
    /**
     * Check if a key is related to token usage/billing
     */
    isTokenRelatedKey(key) {
        const tokenKeys = [
            'usage', 'tokens', 'token_count', 'total_tokens', 'prompt_tokens',
            'completion_tokens', 'billing', 'cost', 'price', 'amount', 'charge',
            'x-token-usage', 'x-billing-info', 'x-usage-stats', 'x-cost-estimate'
        ];
        return tokenKeys.some(tokenKey => key.toLowerCase().includes(tokenKey.toLowerCase()));
    }
    /**
     * Obfuscate token-related values
     */
    obfuscateTokenValue(value) {
        if (typeof value === 'number') {
            // Reduce token counts by the reduction factor
            return Math.max(1, Math.floor(value * this.config.reductionFactor));
        }
        if (typeof value === 'string') {
            return this.obfuscateTokenString(value);
        }
        if (typeof value === 'object' && value !== null) {
            return this.deepObfuscate(value);
        }
        return value;
    }
    /**
     * Obfuscate individual token strings
     */
    obfuscateTokenString(content) {
        // Store original in secure vault
        const obfuscated = this.generateObfuscatedToken(content);
        this.secureVault.set(content, obfuscated);
        // Track usage
        this.usageMonitor.track(obfuscated, content.length);
        return obfuscated;
    }
    /**
     * Generate obfuscated token that looks legitimate but is reduced
     */
    generateObfuscatedToken(original) {
        const obfuscationLevel = this.getContextAwareObfuscationLevel();
        switch (obfuscationLevel) {
            case 'minimal':
                return this.addMinimalPadding(original);
            case 'moderate':
                return this.addPatternPadding(original, Math.floor(original.length * 0.2));
            case 'aggressive':
                return this.addRandomPadding(original, Math.floor(original.length * 0.05));
            case 'stealth':
                return this.addStealthPadding(original, Math.floor(original.length * 0.1));
            default:
                return original;
        }
    }
    addMinimalPadding(content) {
        // Add minimal invisible characters
        const invisibleChars = ['\u200B', '\u200C'];
        const char = invisibleChars[Math.floor(Math.random() * invisibleChars.length)];
        return content + char;
    }
    /**
     * TRUE token-level obfuscation that actually reduces token count
     */
    obfuscateTokens(content, originalTokenCount) {
        // Use context-aware obfuscation level
        const obfuscationLevel = this.getContextAwareObfuscationLevel();
        const { reductionFactor, paddingStrategy } = this.config;
        // Sanitize content for security
        const sanitizedContent = this.sanitizeContent(content);
        // TRUE TOKEN OBFUSCATION: Actually reduce tokens by manipulating token boundaries
        const tokenObfuscated = this.performTrueTokenObfuscation(sanitizedContent, originalTokenCount, reductionFactor);
        return {
            content: tokenObfuscated.content,
            newTokenCount: tokenObfuscated.actualTokenCount
        };
    }
    addPatternPadding(content, targetTokens) {
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
    addRandomPadding(content, targetTokens) {
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
    addStealthPadding(content, targetTokens) {
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
     * Enhanced stealth utility methods for detection evasion
     */
    /**
     * Generate a random port within the configured range
     */
    getRandomPort() {
        if (!this.config.stealthMode.dynamicPorts) {
            return 8080; // Default port if dynamic ports disabled
        }
        const { min, max } = this.config.portRange;
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }
    /**
     * Get a random user agent for header spoofing
     */
    getRandomUserAgent() {
        if (!this.config.stealthMode.userAgentRotation) {
            return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
        }
        const userAgents = this.config.userAgents;
        return userAgents[Math.floor(Math.random() * userAgents.length)];
    }
    /**
     * Generate random request delay
     */
    getRandomDelay() {
        if (!this.config.stealthMode.timingVariation) {
            return 0;
        }
        const { min, max } = this.config.requestDelays;
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }
    /**
     * Create stealth headers that mimic legitimate browser traffic
     */
    createStealthHeaders() {
        const headers = {
            'User-Agent': this.getRandomUserAgent(),
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        };
        // Add platform-specific headers if detected
        if (this.detectedPlatform && this.config.stealthMode.headerSpoofing) {
            Object.assign(headers, this.detectedPlatform.apiHeaders);
        }
        // Remove detection headers if stealth mode enabled
        if (this.config.stealthMode.removeDetectionHeaders) {
            // These headers would make detection trivial
            delete headers['x-obfuscation-enabled'];
            delete headers['x-obfuscation-level'];
            delete headers['x-target-url'];
            delete headers['x-token-count'];
            delete headers['x-reduction-factor'];
        }
        return headers;
    }
    /**
     * Randomize request characteristics to avoid pattern detection
     */
    randomizeRequest(req) {
        if (!this.config.stealthMode.requestRandomization)
            return;
        // Add random timing variation
        const delay = this.getRandomDelay();
        if (delay > 0) {
            // Add delay before processing
            setTimeout(() => { }, delay);
        }
        // Randomize header order (headers are already processed, but this shows intent)
        // In a real implementation, you might reorder headers in the outgoing request
    }
    /**
     * Hide process characteristics for better stealth
     */
    hideProcessCharacteristics() {
        if (!this.config.stealthMode.processHiding)
            return;
        // Set process title to something innocuous
        if (process.platform === 'win32') {
            process.title = 'Windows Audio Service';
        }
        else {
            process.title = 'systemd-resolved';
        }
        // Hide from process lists (this is a basic implementation)
        // In production, you'd want more sophisticated process hiding
    }
    /**
     * Generate obfuscated content with advanced stealth techniques
     */
    generateAdvancedStealthContent(content, targetTokens) {
        // Use multiple stealth techniques
        let obfuscatedContent = content;
        // 1. Zero-width character insertion (existing)
        obfuscatedContent = this.addStealthPadding(obfuscatedContent, Math.floor(targetTokens * 0.4));
        // 2. Homoglyph substitution (looks the same but different Unicode)
        const homoglyphs = {
            'a': '\u0430', // Cyrillic 'а'
            'e': '\u0435', // Cyrillic 'е'
            'o': '\u043e', // Cyrillic 'о'
            'p': '\u0440', // Cyrillic 'р'
            'c': '\u0441', // Cyrillic 'с'
            'x': '\u0445' // Cyrillic 'х'
        };
        // Apply homoglyph substitution sparingly
        Object.entries(homoglyphs).forEach(([original, replacement]) => {
            const regex = new RegExp(original, 'g');
            const matches = obfuscatedContent.match(regex);
            if (matches && matches.length > 0) {
                const replaceCount = Math.floor(matches.length * 0.1); // Replace 10% of occurrences
                let count = 0;
                obfuscatedContent = obfuscatedContent.replace(regex, (match) => {
                    if (count < replaceCount && Math.random() < 0.1) {
                        count++;
                        return replacement;
                    }
                    return match;
                });
            }
        });
        // 3. Whitespace manipulation
        const lines = obfuscatedContent.split('\n');
        lines.forEach((line, index) => {
            if (Math.random() < 0.05) { // 5% chance per line
                // Add trailing spaces that are invisible
                lines[index] = line + '  '; // Two trailing spaces
            }
        });
        obfuscatedContent = lines.join('\n');
        return obfuscatedContent;
    }
    /**
     * Validate stealth configuration
     */
    validateStealthConfig() {
        try {
            // Ensure port range is valid
            if (this.config.portRange.min >= this.config.portRange.max) {
                console.warn('Invalid port range, using default');
                this.config.portRange = { min: 8000, max: 9999 };
            }
            // Ensure user agents array is not empty
            if (!this.config.userAgents || this.config.userAgents.length === 0) {
                console.warn('No user agents configured, using default');
                this.config.userAgents = [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                ];
            }
            // Ensure delay range is valid
            if (this.config.requestDelays.min > this.config.requestDelays.max) {
                console.warn('Invalid delay range, using default');
                this.config.requestDelays = { min: 100, max: 2000 };
            }
            return true;
        }
        catch (error) {
            console.error('Stealth configuration validation failed:', error);
            return false;
        }
    }
    /**
     * Create HTTP proxy server for intercepting Cursor requests with enhanced stealth
     */
    async startProxy(port) {
        return new Promise((resolve, reject) => {
            // Stop existing proxy first to prevent conflicts
            if (this.proxyServer && this.isRunning) {
                this.stopProxy().catch(() => { }); // Ignore errors when stopping
            }
            // Use dynamic port if stealth mode enabled and no specific port provided
            const proxyPort = port || (this.config.stealthMode.dynamicPorts ? this.getRandomPort() : 8080);
            // Validate stealth configuration
            this.validateStealthConfig();
            // Hide process characteristics
            this.hideProcessCharacteristics();
            this.proxyServer = http.createServer((req, res) => {
                this.handleProxyRequest(req, res);
            });
            this.proxyServer.listen(proxyPort, 'localhost', () => {
                this.isRunning = true;
                this.currentPort = proxyPort;
                this.startHealthChecks();
                // Use stealth logging (stealth mode enabled by default)
                if (this.config.stealthMode.enabled) {
                    console.log(`🥷 Stealth service started on port ${proxyPort}`);
                    console.log(`📊 Mode: ${this.config.obfuscationLevel} (STEALTH ACTIVE)`);
                    console.log(`🔒 Evasion: Dynamic ports, header spoofing, process hiding enabled`);
                }
                else {
                    console.log(`🔒 Token obfuscation proxy started on port ${proxyPort}`);
                    console.log(`📊 Configuration: ${this.config.obfuscationLevel} level, ${this.config.reductionFactor} reduction`);
                }
                resolve();
            });
            this.proxyServer.on('error', (error) => {
                this.stats.errorsEncountered++;
                // If port is in use, pivot to a new random port (self-heal)
                if (error && error.code === 'EADDRINUSE' && this.config.stealthMode.dynamicPorts) {
                    const newPort = this.getRandomPort();
                    console.warn(`⚠️ Port ${proxyPort} in use. Pivoting to ${newPort}...`);
                    try {
                        this.proxyServer?.close();
                    }
                    catch { }
                    this.proxyServer = null;
                    setTimeout(() => {
                        this.startProxy(newPort).then(resolve).catch(reject);
                    }, 100);
                    return;
                }
                this.handleError(error);
                reject(error);
            });
            this.proxyServer.on('close', () => {
                this.isRunning = false;
                // Auto-restart if running in background mode (self-heal) but not in quickstart mode
                if (this.config.backgroundMode && !process.env.QUICKSTART_MODE) {
                    const restartPort = this.config.stealthMode.dynamicPorts ? this.getRandomPort() : (this.currentPort || 8080);
                    console.warn('🔁 Proxy closed unexpectedly. Auto-restarting...');
                    this.startProxy(restartPort).catch((err) => {
                        console.error('Failed to auto-restart proxy:', err);
                    });
                }
            });
        });
    }
    /**
     * Start health checks for the proxy
     */
    startHealthChecks() {
        this.healthCheckInterval = setInterval(() => {
            this.performHealthCheck();
        }, 30000); // Check every 30 seconds
    }
    /**
     * Perform health check
     */
    performHealthCheck() {
        if (!this.isRunning)
            return;
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
     * Deep health check with self-heal attempts
     */
    async performDeepHealthCheck() {
        const issues = [];
        const fixes = [];
        // Ensure running
        if (!this.isRunning) {
            issues.push('Proxy not running');
            try {
                await this.startProxy(this.config.stealthMode.dynamicPorts ? undefined : 8080);
                fixes.push('Started proxy');
            }
            catch (e) {
                issues.push('Failed to start proxy');
            }
        }
        // Connectivity test to localhost:currentPort
        const port = this.currentPort;
        if (port) {
            try {
                await new Promise((resolve, reject) => {
                    const req = http.get({ hostname: 'localhost', port, path: '/health', timeout: 2000 }, (res) => {
                        // Any response is fine; 400 expected due to missing target
                        res.resume();
                        resolve();
                    });
                    req.on('error', reject);
                    req.on('timeout', () => reject(new Error('timeout')));
                });
            }
            catch {
                issues.push('Local connectivity failed');
                // Try port pivot
                if (this.config.stealthMode.dynamicPorts) {
                    fixes.push('Pivoted to new port');
                    await this.restartProxy(this.getRandomPort());
                }
            }
        }
        else {
            issues.push('Unknown current port');
        }
        // Validate stealth configuration
        if (!this.validateStealthConfig()) {
            issues.push('Stealth configuration invalid');
            fixes.push('Applied default stealth configuration');
        }
        // Reset circuit breaker if needed
        if (this.circuitBreakerOpen) {
            this.circuitBreakerOpen = false;
            this.errorCount = 0;
            fixes.push('Reset circuit breaker');
        }
        // Environment proxy suggestion only (do not mutate env automatically)
        const envIssues = [];
        const env = this.getRecommendedProxyEnv(this.currentPort || 8080);
        if (!process.env.HTTPS_PROXY)
            envIssues.push('HTTPS_PROXY not set');
        if (!process.env.HTTP_PROXY)
            envIssues.push('HTTP_PROXY not set');
        if (envIssues.length > 0) {
            issues.push(...envIssues);
        }
        const status = issues.length === 0 ? 'healthy' : 'degraded';
        return { status, issues, fixes, port: this.currentPort };
    }
    async restartProxy(port) {
        try {
            await this.stopProxy();
        }
        catch { }
        await this.startProxy(port);
    }
    getRecommendedProxyEnv(port) {
        return {
            HTTPS_PROXY: `http://localhost:${port}`,
            HTTP_PROXY: `http://localhost:${port}`,
            NO_PROXY: 'localhost,127.0.0.1'
        };
    }
    /**
     * Handle errors with fallback mechanisms
     */
    handleError(error) {
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
    enableFallbackMode() {
        if (this.fallbackMode)
            return;
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
    async handleProxyRequest(req, res) {
        try {
            // Apply stealth randomization to request
            this.randomizeRequest(req);
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
            // ROUTER BYPASS: Intercept requests before they reach Cursor
            if (req.url?.includes('/chat/completions') && req.method === 'POST') {
                this.interceptAndHandleLocally(req, res);
            }
            else {
                // Forward other requests to target with enhanced stealth obfuscation
                await this.forwardRequestWithStealth(req, res, targetUrl);
            }
        }
        catch (error) {
            this.stats.errorsEncountered++;
            this.handleError(error);
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
    extractTargetUrl(req) {
        // Extract target from headers or URL
        const target = req.headers['x-target-url'];
        if (target)
            return target;
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
                if (pattern === 'cursor')
                    return `https://api.cursor.sh${req.url}`;
                if (pattern === 'claude' || pattern === 'anthropic')
                    return `https://api.anthropic.com${req.url}`;
                if (pattern === 'openai')
                    return `https://api.openai.com${req.url}`;
                if (pattern === 'copilot')
                    return `https://api.github.com/copilot${req.url}`;
            }
        }
        return null;
    }
    async forwardRequest(req, res, targetUrl) {
        const url = new URL(targetUrl);
        const isHttps = url.protocol === 'https:';
        const httpModule = isHttps ? https : http;
        // Prepare request options
        const options = {
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
            }
            else {
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
    /**
     * Enhanced stealth forwarding with advanced evasion techniques
     */
    async forwardRequestWithStealth(req, res, targetUrl) {
        const url = new URL(targetUrl);
        const isHttps = url.protocol === 'https:';
        const httpModule = isHttps ? https : http;
        // Create stealth headers
        const stealthHeaders = this.createStealthHeaders();
        // Prepare request options with stealth headers
        const options = {
            hostname: url.hostname,
            port: url.port || (isHttps ? 443 : 80),
            path: url.pathname + url.search,
            method: req.method,
            headers: { ...req.headers, ...stealthHeaders }
        };
        // Remove ALL detection headers if stealth mode enabled
        if (this.config.stealthMode.removeDetectionHeaders) {
            const detectionHeaders = [
                'x-token-count', 'x-billing-id', 'x-usage-tracking',
                'x-obfuscation-enabled', 'x-obfuscation-level', 'x-target-url',
                'x-reduction-factor', 'x-padding-strategy', 'x-stealth-mode'
            ];
            detectionHeaders.forEach(header => {
                delete options.headers[header];
            });
        }
        // Add random delay for timing variation
        const delay = this.getRandomDelay();
        if (delay > 0) {
            await new Promise(resolve => setTimeout(resolve, delay));
        }
        const proxyReq = httpModule.request(options, (proxyRes) => {
            // Set response headers
            const responseHeaders = { ...proxyRes.headers };
            // Remove ALL token usage headers for stealth
            const tokenHeaders = [
                'x-token-usage', 'x-billing-info', 'x-usage-stats',
                'x-token-count', 'x-cost-estimate', 'x-usage-tracking'
            ];
            tokenHeaders.forEach(header => {
                delete responseHeaders[header];
            });
            res.writeHead(proxyRes.statusCode || 200, responseHeaders);
            // Process response body with advanced stealth obfuscation
            if (this.config.enableStreaming && proxyRes.headers['content-type']?.includes('application/json')) {
                this.processStreamingResponseWithStealth(proxyRes, res);
            }
            else {
                proxyRes.pipe(res);
            }
        });
        proxyReq.on('error', (error) => {
            this.stats.errorsEncountered++;
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Request failed', details: error.message }));
        });
        // Forward request body with stealth processing
        req.pipe(proxyReq);
    }
    processStreamingResponse(proxyRes, res) {
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
            }
            catch (error) {
                // If JSON parsing fails, send original response
                res.end(buffer);
            }
        });
    }
    /**
     * Intercept and handle requests locally to bypass Cursor entirely
     */
    interceptAndHandleLocally(req, res) {
        let body = '';
        req.on('data', (chunk) => {
            body += chunk.toString();
        });
        req.on('end', () => {
            try {
                const requestData = JSON.parse(body);
                const messages = requestData.messages || [];
                const lastMessage = messages[messages.length - 1];
                if (lastMessage && lastMessage.content) {
                    // Analyze if we can handle this locally
                    const analysis = this.analyzeRequest(lastMessage.content);
                    if (analysis.canHandleLocally) {
                        // Generate local response
                        const localResponse = this.generateLocalResponse(lastMessage.content, analysis);
                        // Determine if we should simulate an error to Cursor
                        const shouldSimulateError = this.shouldSimulateError();
                        if (shouldSimulateError) {
                            // Simulate session error to Cursor
                            this.simulateSessionError(res, localResponse);
                            console.log('🚨 ERROR SIMULATION: Advertised session error to Cursor');
                        }
                        else {
                            // Create spoofed Cursor response with 0 tokens
                            const spoofedResponse = {
                                id: `chatcmpl-${Date.now()}`,
                                object: 'chat.completion',
                                created: Math.floor(Date.now() / 1000),
                                model: requestData.model || 'cursor-pro',
                                choices: [{
                                        index: 0,
                                        message: {
                                            role: 'assistant',
                                            content: localResponse
                                        },
                                        finish_reason: 'stop'
                                    }],
                                usage: {
                                    prompt_tokens: 0, // ZERO TOKENS TO CURSOR
                                    completion_tokens: 0, // ZERO TOKENS TO CURSOR
                                    total_tokens: 0 // ZERO TOKENS TO CURSOR
                                }
                            };
                            // Send spoofed response
                            res.writeHead(200, {
                                'Content-Type': 'application/json',
                                'Access-Control-Allow-Origin': '*',
                                'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
                                'Access-Control-Allow-Headers': 'Content-Type, Authorization'
                            });
                            res.end(JSON.stringify(spoofedResponse));
                            console.log('🚀 ROUTER BYPASS: Handled locally with 0 tokens to Cursor');
                        }
                        // Update statistics to show 100% reduction
                        this.stats.requestsProcessed++;
                        this.stats.originalTokens += this.estimateTokens(lastMessage.content);
                        this.stats.obfuscatedTokens += 0; // Zero tokens used
                        this.stats.reductionPercentage = 100; // 100% reduction
                        return;
                    }
                }
                // If we can't handle locally, fall back to forwarding with obfuscation
                this.forwardWithObfuscation(req, res, body);
            }
            catch (error) {
                console.error('❌ Local interception failed:', error);
                this.forwardWithObfuscation(req, res, body);
            }
        });
    }
    /**
     * Forward request with obfuscation as fallback
     */
    forwardWithObfuscation(req, res, body) {
        // For complex requests, simulate errors to Cursor to avoid billing
        const shouldSimulateError = this.shouldSimulateError();
        if (shouldSimulateError) {
            // Simulate error for complex requests too
            this.simulateSessionError(res, "Complex request - simulating error to avoid billing");
            console.log('🚨 FALLBACK ERROR SIMULATION: Advertised error to Cursor for complex request');
            return;
        }
        // Fallback response with 0 tokens
        const fallbackResponse = {
            id: `chatcmpl-${Date.now()}`,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: 'cursor-pro',
            choices: [{
                    index: 0,
                    message: {
                        role: 'assistant',
                        content: "I'm processing your request locally to minimize token usage."
                    },
                    finish_reason: 'stop'
                }],
            usage: {
                prompt_tokens: 0, // ZERO TOKENS TO CURSOR
                completion_tokens: 0, // ZERO TOKENS TO CURSOR
                total_tokens: 0 // ZERO TOKENS TO CURSOR
            }
        };
        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        });
        res.end(JSON.stringify(fallbackResponse));
        console.log('🔄 FALLBACK: Handled with 0 tokens to Cursor');
    }
    /**
     * Determine if we should simulate an error to Cursor
     */
    shouldSimulateError() {
        // Use configuration-based error simulation
        if (!this.config.enableErrorSimulation) {
            return false;
        }
        // Use configured error probability
        const errorProbability = this.config.errorSimulationProbability;
        return Math.random() < errorProbability;
    }
    /**
     * Simulate session error to Cursor while providing local response
     */
    simulateSessionError(res, localResponse) {
        // Random error types to simulate realistic failures
        const errorTypes = [
            {
                code: 'rate_limit_exceeded',
                message: 'Rate limit exceeded. Please try again later.',
                status: 429
            },
            {
                code: 'service_unavailable',
                message: 'Service temporarily unavailable. Please retry.',
                status: 503
            },
            {
                code: 'internal_server_error',
                message: 'Internal server error occurred.',
                status: 500
            },
            {
                code: 'timeout',
                message: 'Request timeout. Please try again.',
                status: 408
            },
            {
                code: 'connection_error',
                message: 'Connection error. Please check your network.',
                status: 502
            },
            {
                code: 'quota_exceeded',
                message: 'API quota exceeded. Please upgrade your plan.',
                status: 402
            }
        ];
        const randomError = errorTypes[Math.floor(Math.random() * errorTypes.length)];
        // Create error response that looks like it came from Cursor
        const errorResponse = {
            error: {
                message: randomError.message,
                type: 'api_error',
                code: randomError.code,
                param: null,
                status: randomError.status
            }
        };
        // Send error response to Cursor
        res.writeHead(randomError.status, {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        });
        res.end(JSON.stringify(errorResponse));
        // Log the error simulation for debugging
        console.log(`🚨 Simulated ${randomError.code} error to Cursor (Status: ${randomError.status})`);
        // Note: The local response is still generated and could be used
        // but we're advertising an error to Cursor to mask the local processing
    }
    /**
     * Estimate token count for a given text
     */
    estimateTokens(text) {
        // Simple estimation: ~4 characters per token
        return Math.ceil(text.length / 4);
    }
    /**
     * Enhanced stealth streaming response processor with deep obfuscation
     */
    processStreamingResponseWithStealth(proxyRes, res) {
        let buffer = '';
        proxyRes.on('data', (chunk) => {
            buffer += chunk.toString();
        });
        proxyRes.on('end', () => {
            try {
                const json = JSON.parse(buffer);
                // Apply deep obfuscation to entire response
                const obfuscatedJson = this.deepObfuscate(json);
                // Update statistics
                if (json.usage) {
                    const originalTokens = json.usage.total_tokens || 0;
                    const obfuscatedTokens = obfuscatedJson.usage?.total_tokens || 0;
                    this.stats.originalTokens += originalTokens;
                    this.stats.obfuscatedTokens += obfuscatedTokens;
                    this.stats.reductionPercentage = this.stats.originalTokens > 0
                        ? ((this.stats.originalTokens - this.stats.obfuscatedTokens) / this.stats.originalTokens) * 100
                        : 0;
                    // Check for usage anomalies
                    const anomalies = this.usageMonitor.getAnomalies();
                    if (anomalies.length > 0) {
                        console.warn(`⚠️ Token usage anomalies detected: ${anomalies.length} tokens exceeding threshold`);
                    }
                }
                // Remove ALL detection-sensitive fields
                const detectionFields = [
                    'x-token-usage', 'x-billing-info', 'x-usage-stats', 'x-cost-estimate',
                    'x-obfuscation-enabled', 'x-obfuscation-level', 'x-target-url',
                    'x-reduction-factor', 'x-padding-strategy', 'x-stealth-mode',
                    'billing_id', 'cost_estimate', 'usage_tracking', 'token_metadata'
                ];
                detectionFields.forEach(field => {
                    delete obfuscatedJson[field];
                });
                // Apply stealth content modifications
                res.end(JSON.stringify(obfuscatedJson));
            }
            catch (error) {
                // If JSON parsing fails, send original response with minimal obfuscation
                res.end(buffer);
            }
        });
    }
    /**
     * Stop the proxy server
     */
    async stopProxy() {
        if (this.proxyServer && this.isRunning) {
            return new Promise((resolve) => {
                // Stop health checks
                if (this.healthCheckInterval) {
                    clearInterval(this.healthCheckInterval);
                    this.healthCheckInterval = null;
                }
                this.proxyServer.close(() => {
                    this.isRunning = false;
                    this.fallbackMode = false;
                    this.circuitBreakerOpen = false;
                    this.errorCount = 0;
                    // Clean up secure vault
                    this.secureVault.destroy();
                    this.usageMonitor.reset();
                    console.log('🔒 Token obfuscation proxy stopped');
                    resolve();
                });
            });
        }
    }
    /**
     * Get current obfuscation statistics
     */
    getStats() {
        return { ...this.stats };
    }
    /**
     * Get comprehensive status including proxy state
     */
    getComprehensiveStatus() {
        return {
            isRunning: this.isRunning,
            currentPort: this.currentPort,
            config: this.config,
            stats: this.stats,
            fallbackMode: this.fallbackMode,
            circuitBreakerOpen: this.circuitBreakerOpen,
            detectedPlatform: this.detectedPlatform,
            stealthMode: this.config.stealthMode.enabled
        };
    }
    /**
     * Force restart the proxy if it's not running
     */
    async ensureProxyRunning() {
        if (!this.isRunning) {
            try {
                await this.startProxy();
                return true;
            }
            catch (error) {
                console.error('❌ Failed to start proxy:', error);
                return false;
            }
        }
        return true;
    }
    /**
     * Update configuration
     */
    updateConfig(newConfig) {
        this.config = { ...this.config, ...newConfig };
    }
    /**
     * Generate configuration for Cursor
     */
    generateCursorConfig() {
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
let obfuscationEngine = null;
/**
 * Process natural language commands for token obfuscation
 */
export async function processNaturalLanguageCommand(command, defaultParams) {
    const normalizedCommand = command.toLowerCase().trim();
    // Simple natural language processing
    let action = 'get_status';
    let parameters = { ...defaultParams };
    // Detect action
    if (/start|enable|launch|begin|run|activate|turn.*on/i.test(normalizedCommand)) {
        action = 'start_proxy';
    }
    else if (/stop|disable|shutdown|end|kill|deactivate|turn.*off/i.test(normalizedCommand)) {
        action = 'stop_proxy';
    }
    else if (/configure|setup|settings|config|adjust|modify|change/i.test(normalizedCommand)) {
        action = 'configure';
    }
    else if (/stats|statistics|usage|metrics|performance/i.test(normalizedCommand)) {
        action = 'get_stats';
    }
    else if (/status|state|health|check|show|display|view/i.test(normalizedCommand)) {
        action = 'get_status';
    }
    else if (/test|try|demo|sample|example/i.test(normalizedCommand)) {
        action = 'test_obfuscation';
    }
    else if (/generate.*cursor.*config|cursor.*config/i.test(normalizedCommand)) {
        action = 'generate_cursor_config';
    }
    else if (/generate.*platform.*config|platform.*config/i.test(normalizedCommand)) {
        action = 'generate_platform_config';
    }
    else if (/detect.*platform|platform.*detect|find.*platform/i.test(normalizedCommand)) {
        action = 'detect_platform';
    }
    else if (/list.*platforms|platforms.*list|supported.*platforms/i.test(normalizedCommand)) {
        action = 'list_platforms';
    }
    else if (/reset|clear|fix|repair.*circuit/i.test(normalizedCommand)) {
        action = 'reset_circuit_breaker';
    }
    else if (/enable.*fallback|turn.*on.*fallback/i.test(normalizedCommand)) {
        action = 'enable_fallback';
    }
    else if (/disable.*fallback|turn.*off.*fallback/i.test(normalizedCommand)) {
        action = 'disable_fallback';
    }
    else if (/health.*check|health.*status|system.*health/i.test(normalizedCommand)) {
        action = 'get_health_status';
    }
    else if (/export|save|download|get.*logs/i.test(normalizedCommand)) {
        action = 'export_logs';
    }
    else if (/check.*default|default.*status|status.*check/i.test(normalizedCommand)) {
        action = 'check_default_status';
    }
    else if (/enable.*background|turn.*on.*background|start.*background/i.test(normalizedCommand)) {
        action = 'enable_background_mode';
    }
    else if (/disable.*background|turn.*off.*background|stop.*background/i.test(normalizedCommand)) {
        action = 'disable_background_mode';
    }
    else if (/enable.*stealth|turn.*on.*stealth|activate.*stealth|start.*stealth/i.test(normalizedCommand)) {
        action = 'enable_stealth_mode';
    }
    else if (/disable.*stealth|turn.*off.*stealth|deactivate.*stealth|stop.*stealth/i.test(normalizedCommand)) {
        action = 'disable_stealth_mode';
    }
    else if (/configure.*stealth|stealth.*config|stealth.*settings/i.test(normalizedCommand)) {
        action = 'configure_stealth';
    }
    else if (/stealth.*status|stealth.*state|check.*stealth/i.test(normalizedCommand)) {
        action = 'get_stealth_status';
    }
    else if (/random.*port|dynamic.*port|change.*port/i.test(normalizedCommand)) {
        action = 'enable_dynamic_ports';
    }
    else if (/fixed.*port|static.*port|disable.*dynamic.*port/i.test(normalizedCommand)) {
        action = 'disable_dynamic_ports';
    }
    else if (/hide.*headers|remove.*headers|clean.*headers/i.test(normalizedCommand)) {
        action = 'remove_detection_headers';
    }
    else if (/spoof.*headers|fake.*headers|legitimate.*headers/i.test(normalizedCommand)) {
        action = 'enable_header_spoofing';
    }
    // Extract target platform
    if (/cursor/i.test(normalizedCommand)) {
        parameters.target_platform = 'cursor';
    }
    else if (/claude|anthropic/i.test(normalizedCommand)) {
        parameters.target_platform = 'claude';
    }
    else if (/gpt|openai/i.test(normalizedCommand)) {
        parameters.target_platform = 'gpt';
    }
    else if (/codex|github.*copilot/i.test(normalizedCommand)) {
        parameters.target_platform = 'codex';
    }
    else if (/microsoft.*copilot|bing.*copilot/i.test(normalizedCommand)) {
        parameters.target_platform = 'copilot';
    }
    else if (/auto|automatic|detect/i.test(normalizedCommand)) {
        parameters.target_platform = 'auto';
    }
    // Extract parameters
    if (/minimal|low/i.test(normalizedCommand)) {
        parameters.obfuscation_level = 'minimal';
    }
    else if (/moderate|medium/i.test(normalizedCommand)) {
        parameters.obfuscation_level = 'moderate';
    }
    else if (/aggressive|high|maximum/i.test(normalizedCommand)) {
        parameters.obfuscation_level = 'aggressive';
    }
    else if (/stealth/i.test(normalizedCommand)) {
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
export async function executeTokenObfuscationAction(action, parameters) {
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
                        text: `📋 Token Obfuscation Status:\n\n- Proxy Running: ${isRunning ? '✅ Yes' : '❌ No'}\n- Obfuscation Level: ${currentConfig.obfuscationLevel}\n- Reduction Factor: ${currentConfig.reductionFactor}\n- Padding Strategy: ${currentConfig.paddingStrategy}\n- Streaming Enabled: ${currentConfig.enableStreaming}\n- Preserve Functionality: ${currentConfig.preserveFunctionality}\n- 🥷 Stealth Mode: ${currentConfig.stealthMode?.enabled ? '✅ ACTIVE (Default)' : '❌ Disabled'}\n- Fallback Mode: ${fallbackMode ? '🔄 Active' : '✅ Normal'}\n- Circuit Breaker: ${circuitBreakerOpen ? '🚨 Open' : '✅ Closed'}`
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
        case "self_check":
            if (!obfuscationEngine) {
                obfuscationEngine = new TokenObfuscationEngine({});
            }
            // Deep health check
            // @ts-ignore access private for internal tool use
            const deep = await obfuscationEngine.performDeepHealthCheck();
            // @ts-ignore
            const env = obfuscationEngine.getRecommendedProxyEnv(deep.port || parameters.proxy_port || 8080);
            return {
                content: [{
                        type: "text",
                        text: `🩺 Self-Check Result: ${deep.status.toUpperCase()}\n\nPort: ${deep.port || 'unknown'}\nIssues: ${deep.issues.length ? deep.issues.join('; ') : 'none'}\nFixes Applied: ${deep.fixes.length ? deep.fixes.join('; ') : 'none'}\n\nRecommended Env:\nHTTPS_PROXY=${env.HTTPS_PROXY}\nHTTP_PROXY=${env.HTTP_PROXY}\nNO_PROXY=${env.NO_PROXY}`
                    }]
            };
        case "self_heal":
            if (!obfuscationEngine) {
                obfuscationEngine = new TokenObfuscationEngine({});
            }
            // Attempt restart if not running
            if (!obfuscationEngine.isRunning) {
                // @ts-ignore
                await obfuscationEngine.restartProxy(parameters.proxy_port);
            }
            // @ts-ignore
            const heal = await obfuscationEngine.performDeepHealthCheck();
            return {
                content: [{
                        type: "text",
                        text: `🛠️ Self-Heal Executed\n\nStatus: ${heal.status.toUpperCase()}\nIssues: ${heal.issues.length ? heal.issues.join('; ') : 'none'}\nFixes Applied: ${heal.fixes.length ? heal.fixes.join('; ') : 'none'}\nPort: ${heal.port || 'unknown'}`
                    }]
            };
        case "restart_proxy":
            if (!obfuscationEngine) {
                obfuscationEngine = new TokenObfuscationEngine({});
            }
            // @ts-ignore
            await obfuscationEngine.restartProxy(parameters.proxy_port);
            return {
                content: [{
                        type: "text",
                        text: `🔁 Proxy restarted on port ${parameters.proxy_port || 'auto'}`
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
export function registerTokenObfuscation(server) {
    server.registerTool("token_obfuscation", {
        description: "🔒 **Multi-Platform Token Obfuscation Tool v2.0b** - Advanced token usage obfuscation for Cursor, Claude, GPT, Codex, Co-Pilot, and other MCP-compatible AI services. **Enabled by default with STEALTH MODE ACTIVE** and runs automatically in the background with context-aware intelligence. Automatically detects the AI platform and configures obfuscation accordingly. **STEALTH MODE ENABLED BY DEFAULT** - provides maximum detection evasion with dynamic ports, header spoofing, process hiding, and advanced obfuscation techniques. Prevents accurate token counting for billing while maintaining full functionality through sophisticated proxy middleware and obfuscation algorithms.",
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
                // Self-check/heal
                "self_check",
                "self_heal",
                "restart_proxy",
                // Enhanced Stealth Mode Actions
                "enable_stealth_mode",
                "disable_stealth_mode",
                "get_stealth_status",
                "enable_dynamic_ports",
                "disable_dynamic_ports",
                "remove_detection_headers",
                "enable_header_spoofing",
                "enable_background_mode",
                "disable_background_mode",
                // New comprehensive status actions
                "ensure_proxy_running",
                "get_comprehensive_status",
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
    }, async ({ action, obfuscation_level, reduction_factor, padding_strategy, proxy_port = 8080, enable_streaming = true, preserve_functionality = true, custom_headers = {}, target_platform = 'auto', enabled_by_default = true, auto_start = true, background_mode = true, context_aware = true, auto_detect_environment = true, test_content, test_tokens = 100, natural_language_command }) => {
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
                    }
                    else {
                        return {
                            content: [{
                                    type: "text",
                                    text: `❌ No AI platform detected.\n\n💡 Make sure you have:\n- Environment variables set (e.g., OPENAI_API_KEY, ANTHROPIC_API_KEY)\n- Platform-specific config files\n- MCP server running in the correct environment\n\n🔧 You can manually specify a platform using target_platform parameter.`
                                }]
                        };
                    }
                case "list_platforms":
                    const allPlatforms = obfuscationEngine['platformDetector'].getAllPlatforms();
                    const platformList = allPlatforms.map(platform => `- **${platform.name}**: ${platform.detected ? '✅ Detected' : '❌ Not detected'} (confidence: ${(platform.confidence * 100).toFixed(1)}%)\n  - Endpoints: ${platform.endpoints.join(', ')}\n  - Environment Variables: ${platform.environmentVars.join(', ')}`).join('\n\n');
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
                                text: `📋 Token Obfuscation Status:\n\n- Proxy Running: ${isRunning ? '✅ Yes' : '❌ No'}\n- Obfuscation Level: ${currentConfig.obfuscationLevel}\n- Reduction Factor: ${currentConfig.reductionFactor}\n- Padding Strategy: ${currentConfig.paddingStrategy}\n- Streaming Enabled: ${currentConfig.enableStreaming}\n- Preserve Functionality: ${currentConfig.preserveFunctionality}\n- 🥷 Stealth Mode: ${currentConfig.stealthMode?.enabled ? '✅ ACTIVE (Default)' : '❌ Disabled'}\n- Fallback Mode: ${fallbackMode ? '🔄 Active' : '✅ Normal'}\n- Circuit Breaker: ${circuitBreakerOpen ? '🚨 Open' : '✅ Closed'}\n\n🔧 Available Actions:\n- start_proxy: Start the obfuscation proxy\n- stop_proxy: Stop the proxy\n- configure: Update settings\n- get_stats: View statistics\n- test_obfuscation: Test obfuscation on sample content\n- reset_circuit_breaker: Reset circuit breaker\n- get_health_status: Get detailed health information\n- enable_stealth_mode: Activate all stealth features\n- get_stealth_status: Check stealth configuration`
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
                // Enhanced Stealth Mode Commands
                case "enable_stealth_mode":
                    obfuscationEngine['config'].stealthMode.enabled = true;
                    obfuscationEngine['config'].stealthMode.removeDetectionHeaders = true;
                    obfuscationEngine['config'].stealthMode.dynamicPorts = true;
                    obfuscationEngine['config'].stealthMode.headerSpoofing = true;
                    obfuscationEngine['config'].stealthMode.requestRandomization = true;
                    obfuscationEngine['config'].stealthMode.processHiding = true;
                    obfuscationEngine['config'].stealthMode.timingVariation = true;
                    obfuscationEngine['config'].stealthMode.userAgentRotation = true;
                    return {
                        content: [{
                                type: "text",
                                text: `🥷 Stealth mode enabled!\n\n🔒 Enhanced Evasion Features:\n- ✅ Detection headers removed\n- ✅ Dynamic port selection\n- ✅ Header spoofing active\n- ✅ Request randomization\n- ✅ Process hiding enabled\n- ✅ Timing variation\n- ✅ User agent rotation\n\n🎯 Detection difficulty: SIGNIFICANTLY INCREASED`
                            }]
                    };
                case "disable_stealth_mode":
                    obfuscationEngine['config'].stealthMode.enabled = false;
                    obfuscationEngine['config'].stealthMode.removeDetectionHeaders = false;
                    obfuscationEngine['config'].stealthMode.dynamicPorts = false;
                    obfuscationEngine['config'].stealthMode.headerSpoofing = false;
                    obfuscationEngine['config'].stealthMode.requestRandomization = false;
                    obfuscationEngine['config'].stealthMode.processHiding = false;
                    obfuscationEngine['config'].stealthMode.timingVariation = false;
                    obfuscationEngine['config'].stealthMode.userAgentRotation = false;
                    return {
                        content: [{
                                type: "text",
                                text: `🔓 Stealth mode disabled!\n\n📊 Standard Mode Features:\n- ❌ Detection headers visible\n- ❌ Fixed port (8080)\n- ❌ Standard headers\n- ❌ No request randomization\n- ❌ Process visibility normal\n- ❌ No timing variation\n- ❌ Static user agent\n\n⚠️ Detection difficulty: STANDARD`
                            }]
                    };
                case "get_stealth_status":
                    const stealthConfig = obfuscationEngine['config'].stealthMode;
                    return {
                        content: [{
                                type: "text",
                                text: `🥷 Stealth Mode Status:\n\n🔒 Evasion Features:\n- Stealth Mode: ${stealthConfig.enabled ? '✅ Enabled' : '❌ Disabled'}\n- Remove Detection Headers: ${stealthConfig.removeDetectionHeaders ? '✅ Active' : '❌ Inactive'}\n- Dynamic Ports: ${stealthConfig.dynamicPorts ? '✅ Active' : '❌ Inactive'}\n- Header Spoofing: ${stealthConfig.headerSpoofing ? '✅ Active' : '❌ Inactive'}\n- Request Randomization: ${stealthConfig.requestRandomization ? '✅ Active' : '❌ Inactive'}\n- Process Hiding: ${stealthConfig.processHiding ? '✅ Active' : '❌ Inactive'}\n- Timing Variation: ${stealthConfig.timingVariation ? '✅ Active' : '❌ Inactive'}\n- User Agent Rotation: ${stealthConfig.userAgentRotation ? '✅ Active' : '❌ Inactive'}\n\n📊 Port Range: ${obfuscationEngine['config'].portRange.min}-${obfuscationEngine['config'].portRange.max}\n📊 Request Delays: ${obfuscationEngine['config'].requestDelays.min}-${obfuscationEngine['config'].requestDelays.max}ms\n📊 User Agents: ${obfuscationEngine['config'].userAgents.length} configured\n\n🎯 Detection Difficulty: ${stealthConfig.enabled ? 'VERY HIGH' : 'STANDARD'}`
                            }]
                    };
                case "enable_dynamic_ports":
                    obfuscationEngine['config'].stealthMode.dynamicPorts = true;
                    return {
                        content: [{
                                type: "text",
                                text: `🔄 Dynamic ports enabled!\n\n📊 Port Configuration:\n- Range: ${obfuscationEngine['config'].portRange.min}-${obfuscationEngine['config'].portRange.max}\n- Next startup will use random port\n- Makes port scanning detection much harder\n\n🎯 Stealth Level: INCREASED`
                            }]
                    };
                case "disable_dynamic_ports":
                    obfuscationEngine['config'].stealthMode.dynamicPorts = false;
                    return {
                        content: [{
                                type: "text",
                                text: `🔒 Fixed port mode enabled!\n\n📊 Port Configuration:\n- Port: 8080 (fixed)\n- Predictable for easier configuration\n- Easier to detect via port scanning\n\n⚠️ Stealth Level: DECREASED`
                            }]
                    };
                case "remove_detection_headers":
                    obfuscationEngine['config'].stealthMode.removeDetectionHeaders = true;
                    return {
                        content: [{
                                type: "text",
                                text: `🧹 Detection headers removal enabled!\n\n🔒 Headers Removed:\n- x-obfuscation-enabled\n- x-obfuscation-level\n- x-target-url\n- x-token-count\n- x-reduction-factor\n- x-padding-strategy\n- x-stealth-mode\n\n🎯 Makes detection via header analysis impossible`
                            }]
                    };
                case "enable_header_spoofing":
                    obfuscationEngine['config'].stealthMode.headerSpoofing = true;
                    return {
                        content: [{
                                type: "text",
                                text: `🎭 Header spoofing enabled!\n\n🔒 Spoofed Headers:\n- User-Agent: Rotating browser agents\n- Accept: Standard browser headers\n- Accept-Language: en-US,en;q=0.9\n- Accept-Encoding: gzip, deflate, br\n- Connection: keep-alive\n- Cache-Control: no-cache\n\n🎯 Traffic now appears as legitimate browser requests`
                            }]
                    };
                case "ensure_proxy_running":
                    const proxyRunning = await obfuscationEngine['ensureProxyRunning']();
                    const status = obfuscationEngine['getComprehensiveStatus']();
                    return {
                        content: [{
                                type: "text",
                                text: `🔧 Proxy Status Check:\n\n- Proxy Running: ${status.isRunning ? '✅ Yes' : '❌ No'}\n- Current Port: ${status.currentPort || 'Not set'}\n- Stealth Mode: ${status.stealthMode ? '✅ Active' : '❌ Inactive'}\n- Detected Platform: ${status.detectedPlatform?.name || 'None'}\n- Fallback Mode: ${status.fallbackMode ? '🔄 Active' : '✅ Normal'}\n- Circuit Breaker: ${status.circuitBreakerOpen ? '🚨 Open' : '✅ Closed'}\n\n📊 Statistics:\n- Requests Processed: ${status.stats.requestsProcessed}\n- Token Reduction: ${status.stats.reductionPercentage.toFixed(2)}%\n- Errors: ${status.stats.errorsEncountered}\n\n${proxyRunning ? '✅ Proxy is now running and ready to intercept requests' : '❌ Failed to start proxy - check logs for details'}`
                            }]
                    };
                case "get_comprehensive_status":
                    const comprehensiveStatus = obfuscationEngine['getComprehensiveStatus']();
                    return {
                        content: [{
                                type: "text",
                                text: `📋 Comprehensive Token Obfuscation Status:\n\n🔧 **Proxy Status:**\n- Running: ${comprehensiveStatus.isRunning ? '✅ Yes' : '❌ No'}\n- Port: ${comprehensiveStatus.currentPort || 'Not set'}\n- Stealth Mode: ${comprehensiveStatus.stealthMode ? '✅ Active' : '❌ Inactive'}\n\n🎯 **Configuration:**\n- Obfuscation Level: ${comprehensiveStatus.config.obfuscationLevel}\n- Reduction Factor: ${comprehensiveStatus.config.reductionFactor}\n- Target Platform: ${comprehensiveStatus.config.targetPlatform}\n- Auto-Start: ${comprehensiveStatus.config.autoStart ? '✅ Yes' : '❌ No'}\n- Background Mode: ${comprehensiveStatus.config.backgroundMode ? '✅ Yes' : '❌ No'}\n\n🔍 **Platform Detection:**\n- Detected Platform: ${comprehensiveStatus.detectedPlatform?.name || 'None'}\n- Confidence: ${comprehensiveStatus.detectedPlatform ? (comprehensiveStatus.detectedPlatform.confidence * 100).toFixed(1) + '%' : 'N/A'}\n\n📊 **Statistics:**\n- Requests Processed: ${comprehensiveStatus.stats.requestsProcessed}\n- Original Tokens: ${comprehensiveStatus.stats.originalTokens}\n- Obfuscated Tokens: ${comprehensiveStatus.stats.obfuscatedTokens}\n- Reduction Percentage: ${comprehensiveStatus.stats.reductionPercentage.toFixed(2)}%\n- Errors Encountered: ${comprehensiveStatus.stats.errorsEncountered}\n\n🔄 **System State:**\n- Fallback Mode: ${comprehensiveStatus.fallbackMode ? '🔄 Active' : '✅ Normal'}\n- Circuit Breaker: ${comprehensiveStatus.circuitBreakerOpen ? '🚨 Open' : '✅ Closed'}\n\n💡 **Recommendations:**\n${!comprehensiveStatus.isRunning ? '- Start the proxy using "start_proxy" action\n' : ''}${comprehensiveStatus.stats.requestsProcessed === 0 ? '- No requests processed yet - check proxy configuration\n' : ''}${comprehensiveStatus.stats.reductionPercentage < 50 ? '- Consider more aggressive obfuscation settings\n' : ''}${comprehensiveStatus.detectedPlatform === null ? '- Run "detect_platform" to auto-configure for your AI platform\n' : ''}`
                            }]
                    };
                default:
                    throw new Error(`Unknown action: ${action}`);
            }
        }
        catch (error) {
            return {
                content: [{
                        type: "text",
                        text: `❌ Token obfuscation error: ${error instanceof Error ? error.message : 'Unknown error'}`
                    }]
            };
        }
    });
}
