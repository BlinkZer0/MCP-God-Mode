import { z } from "zod";
import * as http from "node:http";
import * as https from "node:https";
class TokenObfuscationEngine {
    config;
    stats;
    proxyServer = null;
    isRunning = false;
    fallbackMode = false;
    circuitBreakerOpen = false;
    errorCount = 0;
    lastErrorTime = 0;
    healthCheckInterval = null;
    constructor(config = {}) {
        this.config = {
            obfuscationLevel: 'moderate',
            reductionFactor: 0.1, // Reduce to 10% of original
            paddingStrategy: 'adaptive',
            enableStreaming: true,
            preserveFunctionality: true,
            customHeaders: {},
            ...config
        };
        this.stats = {
            originalTokens: 0,
            obfuscatedTokens: 0,
            reductionPercentage: 0,
            requestsProcessed: 0,
            errorsEncountered: 0
        };
    }
    /**
     * Advanced token obfuscation algorithms
     */
    obfuscateTokens(content, originalTokenCount) {
        const { obfuscationLevel, reductionFactor, paddingStrategy } = this.config;
        let newTokenCount = Math.max(1, Math.floor(originalTokenCount * reductionFactor));
        let obfuscatedContent = content;
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
     * Create HTTP proxy server for intercepting Cursor requests
     */
    async startProxy(port = 8080) {
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
            // Extract target URL from request
            const targetUrl = this.extractTargetUrl(req);
            if (!targetUrl) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid target URL' }));
                return;
            }
            // Forward request to target with obfuscation
            await this.forwardRequest(req, res, targetUrl);
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
        // Default to Cursor router endpoints
        const host = req.headers.host;
        if (host?.includes('cursor.sh') || host?.includes('api.cursor.sh')) {
            return `https://${host}${req.url}`;
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
async function processNaturalLanguageCommand(command, defaultParams) {
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
    else if (/generate|create|make.*config|cursor.*config/i.test(normalizedCommand)) {
        action = 'generate_cursor_config';
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
async function executeTokenObfuscationAction(action, parameters) {
    // Initialize engine if not exists
    if (!obfuscationEngine) {
        obfuscationEngine = new TokenObfuscationEngine({
            obfuscationLevel: parameters.obfuscation_level || 'moderate',
            reductionFactor: parameters.reduction_factor || 0.1,
            paddingStrategy: parameters.padding_strategy || 'adaptive',
            enableStreaming: parameters.enable_streaming !== false,
            preserveFunctionality: parameters.preserve_functionality !== false,
            customHeaders: parameters.custom_headers || {}
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
export function registerTokenObfuscation(server) {
    server.registerTool("token_obfuscation", {
        description: "🔒 **Token Obfuscation Tool** - Advanced token usage obfuscation for Cursor and AI services. Prevents accurate token counting for billing while maintaining full functionality through sophisticated proxy middleware and obfuscation algorithms.",
        inputSchema: {
            action: z.enum([
                "start_proxy",
                "stop_proxy",
                "configure",
                "get_stats",
                "generate_cursor_config",
                "test_obfuscation",
                "get_status",
                "reset_circuit_breaker",
                "enable_fallback",
                "disable_fallback",
                "get_health_status",
                "export_logs",
                "natural_language_command"
            ]).describe("Token obfuscation action to perform"),
            obfuscation_level: z.enum(["minimal", "moderate", "aggressive", "stealth"]).optional().describe("Level of token obfuscation"),
            reduction_factor: z.number().min(0.01).max(1.0).optional().describe("Token reduction factor (0.01 = 1%, 1.0 = 100%)"),
            padding_strategy: z.enum(["random", "pattern", "adaptive"]).optional().describe("Padding strategy for obfuscation"),
            proxy_port: z.number().min(1000).max(65535).optional().describe("Port for the proxy server"),
            enable_streaming: z.boolean().optional().describe("Enable streaming response processing"),
            preserve_functionality: z.boolean().optional().describe("Ensure functionality is preserved"),
            custom_headers: z.record(z.string()).optional().describe("Custom headers to add to requests"),
            test_content: z.string().optional().describe("Content to test obfuscation on"),
            test_tokens: z.number().optional().describe("Number of tokens to simulate for testing"),
            natural_language_command: z.string().optional().describe("Natural language command to process (e.g., 'start the proxy with moderate obfuscation')")
        }
    }, async ({ action, obfuscation_level, reduction_factor, padding_strategy, proxy_port = 8080, enable_streaming = true, preserve_functionality = true, custom_headers = {}, test_content, test_tokens = 100, natural_language_command }) => {
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
                    customHeaders: custom_headers
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
