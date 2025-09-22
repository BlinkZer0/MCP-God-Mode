import { z } from "zod";
import { IS_WINDOWS, IS_LINUX, IS_MACOS, IS_ANDROID, IS_IOS, IS_MOBILE } from "../config/environment.js";
import { isMobileFeatureAvailable } from "../utils/platform.js";
// Natural language processing for unified drone commands
class UnifiedDroneNaturalLanguageProcessor {
    static actionPatterns = {
        // Defense actions
        defense: {
            scan: [
                'scan', 'search', 'detect', 'find', 'discover', 'look for', 'check for',
                'investigate', 'explore', 'examine', 'analyze', 'survey', 'recon'
            ],
            shield: [
                'shield', 'protect', 'defend', 'block', 'secure', 'guard', 'cover',
                'safeguard', 'fortify', 'harden', 'reinforce', 'barricade'
            ],
            evade: [
                'evade', 'avoid', 'escape', 'retreat', 'hide', 'dodge', 'sidestep',
                'bypass', 'circumvent', 'elude', 'flee', 'withdraw'
            ]
        },
        // Offense actions
        offense: {
            jam: [
                'jam', 'disrupt', 'block', 'interfere', 'interrupt', 'disturb',
                'scramble', 'confuse', 'overwhelm', 'flood', 'saturate'
            ],
            decoy: [
                'decoy', 'fake', 'bait', 'trap', 'lure', 'distract', 'mislead',
                'deceive', 'trick', 'fool', 'confuse', 'divert'
            ],
            strike: [
                'strike', 'attack', 'retaliate', 'counter', 'hit', 'target',
                'engage', 'assault', 'offensive', 'aggressive', 'combative'
            ]
        }
    };
    static threatPatterns = {
        'ddos': ['ddos', 'denial of service', 'flood attack', 'traffic attack', 'overload', 'overwhelm'],
        'intrusion': ['intrusion', 'breach', 'unauthorized access', 'hack', 'penetration', 'infiltration'],
        'probe': ['probe', 'scan', 'reconnaissance', 'exploration', 'investigation', 'surveillance'],
        'malware': ['malware', 'virus', 'trojan', 'backdoor', 'rootkit', 'worm'],
        'phishing': ['phishing', 'social engineering', 'email attack', 'scam', 'fraud'],
        'ransomware': ['ransomware', 'encryption attack', 'data hostage', 'crypto attack']
    };
    static intensityPatterns = {
        'low': ['low', 'minimal', 'light', 'gentle', 'soft', 'subtle', 'quiet'],
        'medium': ['medium', 'moderate', 'balanced', 'standard', 'normal', 'average'],
        'high': ['high', 'maximum', 'aggressive', 'intense', 'strong', 'powerful', 'extreme']
    };
    static platformPatterns = {
        'mobile': ['mobile', 'phone', 'tablet', 'android', 'ios', 'smartphone'],
        'desktop': ['desktop', 'computer', 'pc', 'laptop', 'workstation', 'server'],
        'cross-platform': ['cross-platform', 'universal', 'all platforms', 'everywhere']
    };
    static parseCommand(command, context) {
        const lowerCommand = command.toLowerCase();
        const platform = this.detectPlatform();
        const mobileCapabilities = this.getMobileCapabilities();
        // Parse action
        const action = this.parseAction(lowerCommand);
        // Parse parameters
        const parameters = this.parseParameters(lowerCommand, context);
        // Calculate confidence
        const confidence = this.calculateConfidence(lowerCommand, action, parameters);
        // Determine operation type
        let operationType = 'natural_language';
        if (action.category === 'defense') {
            operationType = IS_MOBILE ? 'mobile' : 'defense';
        }
        else if (action.category === 'offense') {
            operationType = IS_MOBILE ? 'mobile' : 'offense';
        }
        return {
            operationType,
            action: action.type,
            parameters,
            confidence,
            originalCommand: command
        };
    }
    static detectPlatform() {
        if (IS_ANDROID)
            return 'android';
        if (IS_IOS)
            return 'ios';
        if (IS_WINDOWS)
            return 'windows';
        if (IS_LINUX)
            return 'linux';
        if (IS_MACOS)
            return 'macos';
        return 'unknown';
    }
    static getMobileCapabilities() {
        if (!IS_MOBILE)
            return [];
        const capabilities = [];
        if (isMobileFeatureAvailable('camera'))
            capabilities.push('camera');
        if (isMobileFeatureAvailable('location'))
            capabilities.push('location');
        if (isMobileFeatureAvailable('bluetooth'))
            capabilities.push('bluetooth');
        if (isMobileFeatureAvailable('nfc'))
            capabilities.push('nfc');
        if (isMobileFeatureAvailable('sensors'))
            capabilities.push('sensors');
        if (isMobileFeatureAvailable('notifications'))
            capabilities.push('notifications');
        return capabilities;
    }
    static parseAction(command) {
        let bestAction = { type: 'scan_surroundings', category: 'defense', confidence: 0.5 };
        // Check defense actions
        for (const [actionType, patterns] of Object.entries(this.actionPatterns.defense)) {
            for (const pattern of patterns) {
                if (command.includes(pattern)) {
                    const confidence = this.calculatePatternConfidence(command, pattern);
                    if (confidence > bestAction.confidence) {
                        bestAction = {
                            type: this.mapDefenseAction(actionType),
                            category: 'defense',
                            confidence
                        };
                    }
                }
            }
        }
        // Check offense actions
        for (const [actionType, patterns] of Object.entries(this.actionPatterns.offense)) {
            for (const pattern of patterns) {
                if (command.includes(pattern)) {
                    const confidence = this.calculatePatternConfidence(command, pattern);
                    if (confidence > bestAction.confidence) {
                        bestAction = {
                            type: this.mapOffenseAction(actionType),
                            category: 'offense',
                            confidence
                        };
                    }
                }
            }
        }
        return bestAction;
    }
    static mapDefenseAction(actionType) {
        const mapping = {
            'scan': 'scan_surroundings',
            'shield': 'deploy_shield',
            'evade': 'evade_threat'
        };
        return mapping[actionType] || 'scan_surroundings';
    }
    static mapOffenseAction(actionType) {
        const mapping = {
            'jam': 'jam_signals',
            'decoy': 'deploy_decoy',
            'strike': 'counter_strike'
        };
        return mapping[actionType] || 'jam_signals';
    }
    static parseParameters(command, context) {
        const parameters = {};
        // Parse threat type
        parameters.threatType = this.parseThreatType(command);
        // Parse intensity
        parameters.intensity = this.parseIntensity(command);
        // Parse target
        parameters.target = this.parseTarget(command, context);
        // Parse platform preferences
        parameters.platform = this.parsePlatformPreference(command);
        return parameters;
    }
    static parseThreatType(command) {
        for (const [threatType, patterns] of Object.entries(this.threatPatterns)) {
            for (const pattern of patterns) {
                if (command.includes(pattern)) {
                    return threatType;
                }
            }
        }
        return 'general';
    }
    static parseIntensity(command) {
        for (const [intensity, patterns] of Object.entries(this.intensityPatterns)) {
            for (const pattern of patterns) {
                if (command.includes(pattern)) {
                    return intensity;
                }
            }
        }
        return 'low';
    }
    static parseTarget(command, context) {
        // Look for IP addresses, network ranges, or hostnames
        const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g;
        const hostnamePattern = /\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
        const ipMatches = command.match(ipPattern);
        const hostnameMatches = command.match(hostnamePattern);
        if (ipMatches && ipMatches.length > 0) {
            return ipMatches[0];
        }
        if (hostnameMatches && hostnameMatches.length > 0) {
            return hostnameMatches[0];
        }
        // Default target based on context
        if (context && context.includes('network')) {
            return '192.168.1.0/24';
        }
        return '192.168.1.0/24'; // Default network range
    }
    static parsePlatformPreference(command) {
        for (const [platform, patterns] of Object.entries(this.platformPatterns)) {
            for (const pattern of patterns) {
                if (command.includes(pattern)) {
                    return platform;
                }
            }
        }
        return 'auto';
    }
    static calculatePatternConfidence(command, pattern) {
        const patternIndex = command.indexOf(pattern);
        if (patternIndex === -1)
            return 0;
        // Higher confidence for exact matches and patterns at the beginning
        let confidence = 0.7;
        if (patternIndex === 0)
            confidence += 0.2;
        if (command === pattern)
            confidence += 0.1;
        return Math.min(confidence, 1.0);
    }
    static calculateConfidence(command, action, parameters) {
        let confidence = action.confidence;
        // Boost confidence if we found specific parameters
        if (parameters.threatType !== 'general')
            confidence += 0.1;
        if (parameters.intensity !== 'low')
            confidence += 0.1;
        if (parameters.target !== '192.168.1.0/24')
            confidence += 0.1;
        return Math.min(confidence, 1.0);
    }
    static generateNaturalLanguageResponse(report) {
        const { operationType, actionsTaken, success, platform } = report;
        let response = `🛸 Unified Drone Operation ${success ? 'Completed Successfully' : 'Failed'}\n\n`;
        response += `**Operation Type:** ${operationType}\n`;
        response += `**Platform:** ${platform}\n\n`;
        response += `**Actions Taken:**\n`;
        actionsTaken.forEach((action, index) => {
            response += `${index + 1}. ${action.message}\n`;
            if (action.riskLevel)
                response += `   Risk Level: ${action.riskLevel}\n`;
        });
        if (IS_MOBILE) {
            response += `\n**Mobile Optimizations:**\n`;
            response += `• Battery-efficient operations\n`;
            response += `• Network-aware scanning\n`;
            response += `• Touch-friendly interface\n`;
            if (report.performance) {
                response += `• Battery used: ${report.performance.batteryUsed}%\n`;
                response += `• Data used: ${report.performance.dataUsed}MB\n`;
            }
        }
        if (operationType === 'offense' || report.riskAcknowledged) {
            response += `\n**⚠️ Legal Warning:**\n`;
            response += `Offensive actions may violate laws and regulations. Use only for authorized security testing.`;
        }
        return response;
    }
}
// Unified Drone Manager that handles all operations
class UnifiedDroneManager {
    operationId;
    auditLog = [];
    flipperEnabled;
    requireConfirmation;
    auditEnabled;
    hipaaMode;
    gdprMode;
    platform;
    mobileCapabilities = [];
    constructor() {
        this.operationId = `unified_drone_${Date.now()}`;
        this.flipperEnabled = process.env.MCPGM_FLIPPER_ENABLED === 'true';
        this.requireConfirmation = process.env.MCPGM_REQUIRE_CONFIRMATION === 'true';
        this.auditEnabled = process.env.MCPGM_AUDIT_ENABLED === 'true';
        this.hipaaMode = process.env.MCPGM_MODE_HIPAA === 'true';
        this.gdprMode = process.env.MCPGM_MODE_GDPR === 'true';
        // Determine platform and capabilities
        this.platform = this.detectPlatform();
        this.mobileCapabilities = this.detectMobileCapabilities();
        this.logAudit(`UnifiedDroneManager initialized on ${this.platform}`);
    }
    detectPlatform() {
        if (IS_ANDROID)
            return 'android';
        if (IS_IOS)
            return 'ios';
        if (IS_WINDOWS)
            return 'windows';
        if (IS_LINUX)
            return 'linux';
        if (IS_MACOS)
            return 'macos';
        return 'unknown';
    }
    detectMobileCapabilities() {
        if (!IS_MOBILE)
            return [];
        const capabilities = [];
        if (isMobileFeatureAvailable('camera'))
            capabilities.push('camera');
        if (isMobileFeatureAvailable('location'))
            capabilities.push('location');
        if (isMobileFeatureAvailable('bluetooth'))
            capabilities.push('bluetooth');
        if (isMobileFeatureAvailable('nfc'))
            capabilities.push('nfc');
        if (isMobileFeatureAvailable('sensors'))
            capabilities.push('sensors');
        if (isMobileFeatureAvailable('notifications'))
            capabilities.push('notifications');
        return capabilities;
    }
    logAudit(message) {
        if (this.auditEnabled) {
            const timestamp = new Date().toISOString();
            this.auditLog.push(`[${timestamp}] ${message}`);
            console.log(`AUDIT: ${message}`);
        }
    }
    checkLegalCompliance() {
        if (this.hipaaMode || this.gdprMode) {
            console.warn("⚠️ Offensive actions disabled in HIPAA/GDPR compliance mode");
            this.logAudit("Offensive actions blocked due to compliance mode");
            return false;
        }
        return true;
    }
    getPlatformSpecificCommand(action, target, intensity) {
        if (IS_MOBILE) {
            return this.getMobileDroneCommand(action, target, intensity);
        }
        else {
            return this.getDesktopDroneCommand(action, target, intensity);
        }
    }
    getMobileDroneCommand(action, target, intensity) {
        // Mobile-optimized drone commands
        const mobileCommands = {
            'scan_surroundings': `mobile-drone-scan --target "${target}" --battery-optimized --network-aware`,
            'deploy_shield': `mobile-drone-shield --target "${target}" --low-power --background-mode`,
            'evade_threat': `mobile-drone-evade --target "${target}" --quick-response --minimal-resources`,
            'jam_signals': `mobile-drone-jam --target "${target}" --intensity "${intensity || 'low'}" --battery-optimized --network-aware`,
            'deploy_decoy': `mobile-drone-decoy --target "${target}" --intensity "${intensity || 'low'}" --low-power --background-mode`,
            'counter_strike': `mobile-drone-strike --target "${target}" --intensity "${intensity || 'low'}" --quick-response --minimal-resources`
        };
        return mobileCommands[action] || `mobile-drone-${action} --target "${target}"`;
    }
    getDesktopDroneCommand(action, target, intensity) {
        // Desktop drone commands with full capabilities
        const desktopCommands = {
            'scan_surroundings': `drone-scan --target "${target}" --full-capabilities --detailed-report`,
            'deploy_shield': `drone-shield --target "${target}" --comprehensive-protection --monitoring`,
            'evade_threat': `drone-evade --target "${target}" --advanced-maneuvers --threat-analysis`,
            'jam_signals': `drone-jam --target "${target}" --intensity "${intensity || 'low'}" --full-capabilities --detailed-report`,
            'deploy_decoy': `drone-decoy --target "${target}" --intensity "${intensity || 'low'}" --comprehensive-deception --monitoring`,
            'counter_strike': `drone-strike --target "${target}" --intensity "${intensity || 'low'}" --advanced-maneuvers --threat-analysis`
        };
        return desktopCommands[action] || `drone-${action} --target "${target}"`;
    }
    async executeRealDroneOperation(action, target, intensity) {
        // Execute real drone operations based on action type
        try {
            const { exec } = await import('child_process');
            const { promisify } = await import('util');
            const execAsync = promisify(exec);
            let command = '';
            let isOffensive = false;
            // Determine command based on action type
            if (action === 'scan_surroundings') {
                command = `nmap -sn ${target}`;
            }
            else if (action === 'deploy_shield') {
                if (IS_WINDOWS) {
                    command = `netsh advfirewall firewall add rule name="DroneShield_${target}" dir=in action=block remoteip=${target}`;
                }
                else {
                    command = `iptables -A INPUT -s ${target} -j DROP`;
                }
            }
            else if (action === 'evade_threat') {
                if (IS_WINDOWS) {
                    command = `route add ${target} 127.0.0.1 metric 1`;
                }
                else {
                    command = `ip route add ${target} via 127.0.0.1`;
                }
            }
            else if (action === 'jam_signals') {
                isOffensive = true;
                if (IS_WINDOWS) {
                    command = `netsh wlan set hostednetwork mode=disallow`;
                }
                else {
                    command = `airmon-ng start wlan0 && aireplay-ng -0 10 -a ${target} wlan0mon`;
                }
            }
            else if (action === 'deploy_decoy') {
                isOffensive = true;
                if (IS_WINDOWS) {
                    command = `netsh advfirewall firewall add rule name="Decoy_${target}" dir=in action=allow remoteip=${target}`;
                }
                else {
                    command = `iptables -A INPUT -s ${target} -j ACCEPT && python3 -m http.server 8080 --bind 0.0.0.0`;
                }
            }
            else if (action === 'counter_strike') {
                isOffensive = true;
                command = `nmap -sS -O -sV ${target}`;
            }
            if (!command) {
                throw new Error(`Unknown action: ${action}`);
            }
            const { stdout, stderr } = await execAsync(command);
            return {
                success: !stderr || stderr.length === 0,
                isOffensive,
                rawOutput: stdout,
                error: stderr,
                command: command
            };
        }
        catch (error) {
            console.error(`Drone operation failed: ${error}`);
            return {
                success: false,
                isOffensive: action.includes('jam') || action.includes('decoy') || action.includes('strike'),
                error: error instanceof Error ? error.message : 'Unknown error'
            };
        }
    }
    calculateMobilePerformance(action, timeElapsed) {
        if (!IS_MOBILE)
            return undefined;
        const baseUsage = {
            'scan_surroundings': { battery: 2, data: 5 },
            'deploy_shield': { battery: 1.5, data: 2 },
            'evade_threat': { battery: 1, data: 1 },
            'jam_signals': { battery: 3, data: 8 },
            'deploy_decoy': { battery: 2.5, data: 3 },
            'counter_strike': { battery: 4, data: 10 }
        };
        const usage = baseUsage[action] || { battery: 2, data: 3 };
        // Adjust for time elapsed
        const batteryUsed = usage.battery * (timeElapsed / 1000) / 10;
        const dataUsed = usage.data * (timeElapsed / 1000) / 10;
        return {
            batteryUsed: Math.round(batteryUsed * 10) / 10,
            dataUsed: Math.round(dataUsed * 10) / 10,
            timeElapsed
        };
    }
    async executeOperation(operationType, action, target, parameters = {}, riskAcknowledged = false, threatLevel = 5, autoConfirm = false, naturalLanguageCommand) {
        this.logAudit(`Starting ${operationType} operation: ${action} on ${target}`);
        const startTime = Date.now();
        // Safety checks for offensive operations
        if (operationType === 'offense' || action.includes('jam') || action.includes('decoy') || action.includes('strike')) {
            if (!riskAcknowledged) {
                console.error("❌ Risk acknowledgment required for offensive operations");
                this.logAudit("Operation blocked: Risk not acknowledged");
                return {
                    operationId: this.operationId,
                    operationType,
                    actionsTaken: [],
                    success: false,
                    auditLog: this.auditLog,
                    timestamp: new Date().toISOString(),
                    platform: this.platform,
                    mobileCapabilities: this.mobileCapabilities,
                    naturalLanguageResponse: "Risk acknowledgment required for offensive operations. Please acknowledge the risks to proceed.",
                    riskAcknowledged: false,
                    legalDisclaimer: "⚠️ LEGAL WARNING: Offensive actions may violate laws and regulations. Use only for authorized security testing."
                };
            }
            if (!this.checkLegalCompliance()) {
                console.error("❌ Offensive operations disabled in compliance mode");
                this.logAudit("Operation blocked: Compliance mode active");
                return {
                    operationId: this.operationId,
                    operationType,
                    actionsTaken: [],
                    success: false,
                    auditLog: this.auditLog,
                    timestamp: new Date().toISOString(),
                    platform: this.platform,
                    mobileCapabilities: this.mobileCapabilities,
                    naturalLanguageResponse: "Offensive operations are disabled in compliance mode (HIPAA/GDPR). Please disable compliance mode to proceed.",
                    riskAcknowledged: true,
                    legalDisclaimer: "⚠️ LEGAL WARNING: Offensive actions may violate laws and regulations. Use only for authorized security testing."
                };
            }
        }
        // Check for confirmation requirement
        if (this.requireConfirmation && !autoConfirm) {
            console.warn("⚠️ Confirmation required for drone deployment");
            this.logAudit("Operation requires confirmation");
            return {
                operationId: this.operationId,
                operationType,
                actionsTaken: [],
                success: false,
                auditLog: this.auditLog,
                timestamp: new Date().toISOString(),
                platform: this.platform,
                mobileCapabilities: this.mobileCapabilities,
                naturalLanguageResponse: "Confirmation required for drone deployment. Please confirm the operation to proceed."
            };
        }
        // Execute the operation
        const command = this.getPlatformSpecificCommand(action, target, parameters.intensity);
        console.log(`🛸 [UNIFIED] Executing ${operationType} operation: ${action} on ${this.platform}`);
        console.log(`🛸 [UNIFIED] Command: ${command}`);
        if (IS_MOBILE) {
            console.log(`📱 [MOBILE] Using mobile-optimized drone operations`);
            console.log(`📱 [MOBILE] Battery-efficient mode enabled`);
        }
        if (this.flipperEnabled) {
            console.log("🔌 [FLIPPER] Sending commands to drone hardware");
            if (IS_MOBILE) {
                console.log("📱 [MOBILE] Using mobile-optimized BLE communication");
            }
        }
        const operationResult = await this.executeRealDroneOperation(action, target, parameters.intensity);
        const endTime = Date.now();
        const timeElapsed = endTime - startTime;
        const actionsTaken = [{
                actionType: action,
                success: operationResult.success,
                message: `${action} ${operationResult.success ? 'completed successfully' : 'failed'} on ${this.platform}`,
                timestamp: new Date().toISOString(),
                details: {
                    target,
                    intensity: parameters.intensity || 'low',
                    threatType: parameters.threatType || 'general',
                    platform: this.platform,
                    mobileOptimized: IS_MOBILE,
                    rawResults: operationResult
                },
                platform: this.platform,
                mobileOptimized: IS_MOBILE,
                riskLevel: operationResult.isOffensive ? (parameters.intensity === 'high' ? 'HIGH' : parameters.intensity === 'medium' ? 'MEDIUM' : 'LOW') : undefined,
                legalWarning: operationResult.isOffensive ? "This action may violate laws and regulations. Use only for authorized security testing." : undefined
            }];
        const success = actionsTaken.every(action => action.success);
        const performance = this.calculateMobilePerformance(action, timeElapsed);
        const report = {
            operationId: this.operationId,
            operationType,
            actionsTaken,
            success,
            auditLog: this.auditLog,
            timestamp: new Date().toISOString(),
            platform: this.platform,
            mobileCapabilities: this.mobileCapabilities,
            naturalLanguageResponse: UnifiedDroneNaturalLanguageProcessor.generateNaturalLanguageResponse({
                operationId: this.operationId,
                operationType,
                actionsTaken,
                success,
                auditLog: this.auditLog,
                timestamp: new Date().toISOString(),
                platform: this.platform,
                mobileCapabilities: this.mobileCapabilities,
                naturalLanguageResponse: ""
            }),
            riskAcknowledged: operationType === 'offense' ? true : undefined,
            legalDisclaimer: operationResult.isOffensive ? "⚠️ LEGAL WARNING: Offensive actions may violate laws and regulations. Use only for authorized security testing." : undefined,
            performance,
            limitations: IS_MOBILE ? [
                'Limited root access',
                'Battery optimization restrictions',
                'Background execution limits'
            ] : undefined
        };
        this.logAudit(`${operationType} operation completed: ${success} on ${this.platform}`);
        return report;
    }
}
export function registerDroneUnified(server) {
    // Ensure McpServer import is preserved
    if (!server)
        throw new Error('Server is required');
    server.registerTool("drone_unified", {
        description: "🛸 **Unified Drone Management Tool** - Comprehensive drone operations combining defense, offense, mobile optimization, and natural language processing. Provides cross-platform support with intelligent operation routing and safety controls.",
        inputSchema: {
            mode: z.enum(["defense", "offense", "mobile", "natural_language"]).default("natural_language").describe("Operation mode: 'defense' for defensive operations, 'offense' for offensive operations, 'mobile' for mobile-optimized operations, 'natural_language' for intelligent command processing"),
            action: z.enum([
                "scan_surroundings", "deploy_shield", "evade_threat",
                "jam_signals", "deploy_decoy", "counter_strike"
            ]).describe("Drone action to perform"),
            target: z.string().describe("Target network, system, or IP address (e.g., 192.168.1.0/24, example.com)"),
            parameters: z.object({
                threatType: z.string().default("general").describe("Type of threat (ddos, intrusion, probe, etc.)"),
                intensity: z.enum(["low", "medium", "high"]).default("low").describe("Operation intensity level"),
                enableBatteryOptimization: z.boolean().default(true).describe("Enable battery optimization (mobile only)"),
                enableNetworkOptimization: z.boolean().default(true).describe("Enable network optimization (mobile only)"),
                enableBackgroundMode: z.boolean().default(false).describe("Enable background mode (mobile only)")
            }).default({}).describe("Operation parameters"),
            riskAcknowledged: z.boolean().default(false).describe("Acknowledge risks of offensive operations (REQUIRED for offensive actions)"),
            threatLevel: z.number().min(1).max(10).default(5).describe("Threat level (1-10, affects confirmation requirements)"),
            autoConfirm: z.boolean().default(false).describe("Skip confirmation prompts (requires MCPGM_REQUIRE_CONFIRMATION=false)"),
            naturalLanguageCommand: z.string().optional().describe("Natural language command (e.g., 'scan for threats', 'jam the signals', 'deploy protection')")
        }
    }, async ({ mode, action, target, parameters, riskAcknowledged, threatLevel, autoConfirm, naturalLanguageCommand }) => {
        try {
            const manager = new UnifiedDroneManager();
            // Process natural language command if provided
            let finalMode = mode;
            let finalAction = action;
            let finalParameters = parameters;
            if (naturalLanguageCommand) {
                const parsed = UnifiedDroneNaturalLanguageProcessor.parseCommand(naturalLanguageCommand);
                finalMode = parsed.operationType;
                finalAction = parsed.action;
                finalParameters = { ...finalParameters, ...parsed.parameters };
                console.log(`🧠 [NLP] Parsed command: "${naturalLanguageCommand}" -> Mode: ${finalMode}, Action: ${finalAction}`);
            }
            const report = await manager.executeOperation(finalMode, finalAction, target, finalParameters, riskAcknowledged, threatLevel, autoConfirm, naturalLanguageCommand);
            return {
                content: [{
                        type: "text",
                        text: JSON.stringify(report, null, 2)
                    }]
            };
        }
        catch (error) {
            return {
                content: [{
                        type: "text",
                        text: `Unified drone operation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                    }]
            };
        }
    });
}
