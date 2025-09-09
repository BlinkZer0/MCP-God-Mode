import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { 
  IS_WINDOWS, IS_LINUX, IS_MACOS, IS_ANDROID, IS_IOS, IS_MOBILE, 
  MOBILE_CONFIG
} from "../config/environment.js";
import { 
  getMobileDeviceInfo, isMobileFeatureAvailable
} from "../utils/platform.js";

interface NaturalLanguageRequest {
  command: string;
  context?: string;
  platform?: string;
  userIntent?: string;
  confidence?: number;
}

interface NaturalLanguageResponse {
  parsedCommand: {
    action: string;
    parameters: Record<string, any>;
    confidence: number;
    originalCommand: string;
  };
  platformOptimizations: {
    platform: string;
    mobileCapabilities: string[];
    optimizations: string[];
  };
  safetyChecks: {
    riskLevel: string;
    requiresConfirmation: boolean;
    legalWarnings: string[];
    complianceChecks: string[];
  };
  suggestedActions: string[];
  naturalLanguageResponse: string;
}

class DroneNaturalLanguageProcessor {
  private static actionPatterns = {
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

  private static threatPatterns = {
    'ddos': ['ddos', 'denial of service', 'flood attack', 'traffic attack', 'overload', 'overwhelm'],
    'intrusion': ['intrusion', 'breach', 'unauthorized access', 'hack', 'penetration', 'infiltration'],
    'probe': ['probe', 'scan', 'reconnaissance', 'exploration', 'investigation', 'surveillance'],
    'malware': ['malware', 'virus', 'trojan', 'backdoor', 'rootkit', 'worm'],
    'phishing': ['phishing', 'social engineering', 'email attack', 'scam', 'fraud'],
    'ransomware': ['ransomware', 'encryption attack', 'data hostage', 'crypto attack']
  };

  private static intensityPatterns = {
    'low': ['low', 'minimal', 'light', 'gentle', 'soft', 'subtle', 'quiet'],
    'medium': ['medium', 'moderate', 'balanced', 'standard', 'normal', 'average'],
    'high': ['high', 'maximum', 'aggressive', 'intense', 'strong', 'powerful', 'extreme']
  };

  private static platformPatterns = {
    'mobile': ['mobile', 'phone', 'tablet', 'android', 'ios', 'smartphone'],
    'desktop': ['desktop', 'computer', 'pc', 'laptop', 'workstation', 'server'],
    'cross-platform': ['cross-platform', 'universal', 'all platforms', 'everywhere']
  };

  static parseCommand(command: string, context?: string): NaturalLanguageResponse {
    const lowerCommand = command.toLowerCase();
    const platform = this.detectPlatform();
    const mobileCapabilities = this.getMobileCapabilities();
    
    // Parse action
    const action = this.parseAction(lowerCommand);
    
    // Parse parameters
    const parameters = this.parseParameters(lowerCommand, context);
    
    // Calculate confidence
    const confidence = this.calculateConfidence(lowerCommand, action, parameters);
    
    // Get platform optimizations
    const platformOptimizations = this.getPlatformOptimizations(platform, mobileCapabilities);
    
    // Perform safety checks
    const safetyChecks = this.performSafetyChecks(action, parameters);
    
    // Generate suggested actions
    const suggestedActions = this.generateSuggestedActions(action, parameters, platform);
    
    // Generate natural language response
    const naturalLanguageResponse = this.generateNaturalLanguageResponse(
      action, parameters, platform, safetyChecks
    );

    return {
      parsedCommand: {
        action: action.type,
        parameters,
        confidence,
        originalCommand: command
      },
      platformOptimizations,
      safetyChecks,
      suggestedActions,
      naturalLanguageResponse
    };
  }

  private static detectPlatform(): string {
    if (IS_ANDROID) return 'android';
    if (IS_IOS) return 'ios';
    if (IS_WINDOWS) return 'windows';
    if (IS_LINUX) return 'linux';
    if (IS_MACOS) return 'macos';
    return 'unknown';
  }

  private static getMobileCapabilities(): string[] {
    if (!IS_MOBILE) return [];
    
    const capabilities: string[] = [];
    
    if (isMobileFeatureAvailable('camera')) capabilities.push('camera');
    if (isMobileFeatureAvailable('location')) capabilities.push('location');
    if (isMobileFeatureAvailable('bluetooth')) capabilities.push('bluetooth');
    if (isMobileFeatureAvailable('nfc')) capabilities.push('nfc');
    if (isMobileFeatureAvailable('sensors')) capabilities.push('sensors');
    if (isMobileFeatureAvailable('notifications')) capabilities.push('notifications');
    
    return capabilities;
  }

  private static parseAction(command: string): { type: string; category: string; confidence: number } {
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

  private static mapDefenseAction(actionType: string): string {
    const mapping = {
      'scan': 'scan_surroundings',
      'shield': 'deploy_shield',
      'evade': 'evade_threat'
    };
    return mapping[actionType] || 'scan_surroundings';
  }

  private static mapOffenseAction(actionType: string): string {
    const mapping = {
      'jam': 'jam_signals',
      'decoy': 'deploy_decoy',
      'strike': 'counter_strike'
    };
    return mapping[actionType] || 'jam_signals';
  }

  private static parseParameters(command: string, context?: string): Record<string, any> {
    const parameters: Record<string, any> = {};
    
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

  private static parseThreatType(command: string): string {
    for (const [threatType, patterns] of Object.entries(this.threatPatterns)) {
      for (const pattern of patterns) {
        if (command.includes(pattern)) {
          return threatType;
        }
      }
    }
    return 'general';
  }

  private static parseIntensity(command: string): string {
    for (const [intensity, patterns] of Object.entries(this.intensityPatterns)) {
      for (const pattern of patterns) {
        if (command.includes(pattern)) {
          return intensity;
        }
      }
    }
    return 'low';
  }

  private static parseTarget(command: string, context?: string): string {
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

  private static parsePlatformPreference(command: string): string {
    for (const [platform, patterns] of Object.entries(this.platformPatterns)) {
      for (const pattern of patterns) {
        if (command.includes(pattern)) {
          return platform;
        }
      }
    }
    return 'auto';
  }

  private static calculatePatternConfidence(command: string, pattern: string): number {
    const patternIndex = command.indexOf(pattern);
    if (patternIndex === -1) return 0;
    
    // Higher confidence for exact matches and patterns at the beginning
    let confidence = 0.7;
    
    if (patternIndex === 0) confidence += 0.2;
    if (command === pattern) confidence += 0.1;
    
    return Math.min(confidence, 1.0);
  }

  private static calculateConfidence(command: string, action: any, parameters: any): number {
    let confidence = action.confidence;
    
    // Boost confidence if we found specific parameters
    if (parameters.threatType !== 'general') confidence += 0.1;
    if (parameters.intensity !== 'low') confidence += 0.1;
    if (parameters.target !== '192.168.1.0/24') confidence += 0.1;
    
    return Math.min(confidence, 1.0);
  }

  private static getPlatformOptimizations(platform: string, mobileCapabilities: string[]): any {
    const optimizations: string[] = [];
    
    if (IS_MOBILE) {
      optimizations.push('Battery-efficient operations');
      optimizations.push('Network-aware scanning');
      optimizations.push('Touch-friendly interface');
      optimizations.push('Background mode support');
    } else {
      optimizations.push('Full desktop capabilities');
      optimizations.push('Advanced monitoring');
      optimizations.push('Comprehensive reporting');
      optimizations.push('Multi-threaded operations');
    }
    
    return {
      platform,
      mobileCapabilities,
      optimizations
    };
  }

  private static performSafetyChecks(action: any, parameters: any): any {
    const riskLevel = action.category === 'offense' ? 'HIGH' : 'MEDIUM';
    const requiresConfirmation = action.category === 'offense' || parameters.intensity === 'high';
    
    const legalWarnings: string[] = [];
    const complianceChecks: string[] = [];
    
    if (action.category === 'offense') {
      legalWarnings.push('Offensive actions may violate laws and regulations');
      legalWarnings.push('Ensure proper authorization before deployment');
      complianceChecks.push('Risk acknowledgment required');
      complianceChecks.push('Legal compliance verification');
    }
    
    if (parameters.intensity === 'high') {
      legalWarnings.push('High-intensity operations require additional confirmation');
      complianceChecks.push('Double confirmation required');
    }
    
    return {
      riskLevel,
      requiresConfirmation,
      legalWarnings,
      complianceChecks
    };
  }

  private static generateSuggestedActions(action: any, parameters: any, platform: string): string[] {
    const suggestions: string[] = [];
    
    if (action.category === 'defense') {
      suggestions.push('Consider running a comprehensive threat assessment first');
      suggestions.push('Enable audit logging for compliance tracking');
      suggestions.push('Set up automated monitoring for ongoing protection');
    } else {
      suggestions.push('Ensure you have proper authorization for offensive operations');
      suggestions.push('Consider starting with low-intensity operations');
      suggestions.push('Enable comprehensive audit logging');
    }
    
    if (IS_MOBILE) {
      suggestions.push('Use battery-optimized mode for extended operations');
      suggestions.push('Enable network-aware scanning to conserve data');
    }
    
    return suggestions;
  }

  private static generateNaturalLanguageResponse(
    action: any, 
    parameters: any, 
    platform: string, 
    safetyChecks: any
  ): string {
    let response = `🧠 **Natural Language Processing Results**\n\n`;
    
    response += `**Command:** ${action.type}\n`;
    response += `**Category:** ${action.category}\n`;
    response += `**Confidence:** ${Math.round(action.confidence * 100)}%\n`;
    response += `**Platform:** ${platform}\n\n`;
    
    response += `**Parameters:**\n`;
    response += `• Threat Type: ${parameters.threatType}\n`;
    response += `• Intensity: ${parameters.intensity}\n`;
    response += `• Target: ${parameters.target}\n\n`;
    
    response += `**Safety Checks:**\n`;
    response += `• Risk Level: ${safetyChecks.riskLevel}\n`;
    response += `• Requires Confirmation: ${safetyChecks.requiresConfirmation ? 'Yes' : 'No'}\n`;
    
    if (safetyChecks.legalWarnings.length > 0) {
      response += `\n**⚠️ Legal Warnings:**\n`;
      safetyChecks.legalWarnings.forEach((warning: string) => {
        response += `• ${warning}\n`;
      });
    }
    
    return response;
  }
}

export function registerDroneNaturalLanguageInterface(server: McpServer) {
  // Ensure McpServer import is preserved
  if (!server) throw new Error('Server is required');
  
  server.registerTool("drone_natural_language", {
    description: "🧠 **Drone Natural Language Interface** - Process natural language commands for drone operations with cross-platform support, intelligent parsing, safety checks, and platform-specific optimizations. Supports commands like 'scan for threats', 'deploy protection', 'jam the signals', etc.",
    inputSchema: {
      command: z.string().describe("Natural language command for drone operations"),
      context: z.string().optional().describe("Additional context about the operation"),
      userIntent: z.string().optional().describe("User's intended goal or objective"),
      platform: z.string().optional().describe("Target platform preference (auto-detect if not specified)")
    }
  }, async ({ command, context, userIntent, platform }) => {
    try {
      const response = DroneNaturalLanguageProcessor.parseCommand(command, context);
      
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: "text",
          text: `Natural language processing failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        }]
      };
    }
  });
}
