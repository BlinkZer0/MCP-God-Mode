import { z } from "zod";

/**
 * Natural Language Interface for Token Obfuscation Tool
 * Processes natural language commands and converts them to structured token obfuscation operations
 */

interface TokenObfuscationNLCommand {
  action: string;
  parameters: Record<string, any>;
  confidence: number;
  originalCommand: string;
}

class TokenObfuscationNLParser {
  private actionPatterns: Map<string, RegExp[]> = new Map();
  private parameterPatterns: Map<string, RegExp[]> = new Map();

  constructor() {
    this.initializePatterns();
  }

  private initializePatterns(): void {
    // Action patterns
    this.actionPatterns.set('start_proxy', [
      /start.*proxy/i,
      /enable.*proxy/i,
      /launch.*proxy/i,
      /begin.*proxy/i,
      /run.*proxy/i,
      /activate.*proxy/i,
      /turn.*on.*proxy/i
    ]);

    this.actionPatterns.set('stop_proxy', [
      /stop.*proxy/i,
      /disable.*proxy/i,
      /shutdown.*proxy/i,
      /end.*proxy/i,
      /kill.*proxy/i,
      /deactivate.*proxy/i,
      /turn.*off.*proxy/i
    ]);

    this.actionPatterns.set('configure', [
      /configure/i,
      /setup/i,
      /settings/i,
      /config/i,
      /adjust/i,
      /modify/i,
      /change.*settings/i,
      /update.*config/i
    ]);

    this.actionPatterns.set('get_stats', [
      /stats/i,
      /statistics/i,
      /usage/i,
      /metrics/i,
      /performance/i,
      /show.*stats/i,
      /display.*stats/i,
      /get.*stats/i,
      /view.*stats/i
    ]);

    this.actionPatterns.set('get_status', [
      /status/i,
      /state/i,
      /health/i,
      /check.*status/i,
      /show.*status/i,
      /display.*status/i,
      /get.*status/i,
      /view.*status/i,
      /is.*running/i,
      /is.*active/i
    ]);

    this.actionPatterns.set('test_obfuscation', [
      /test/i,
      /try/i,
      /demo/i,
      /sample/i,
      /example/i,
      /test.*obfuscation/i,
      /try.*obfuscation/i,
      /demo.*obfuscation/i
    ]);

    this.actionPatterns.set('generate_cursor_config', [
      /generate.*config/i,
      /create.*config/i,
      /make.*config/i,
      /cursor.*config/i,
      /config.*file/i,
      /setup.*cursor/i,
      /configure.*cursor/i
    ]);

    this.actionPatterns.set('reset_circuit_breaker', [
      /reset.*circuit/i,
      /reset.*breaker/i,
      /clear.*circuit/i,
      /clear.*breaker/i,
      /fix.*circuit/i,
      /repair.*circuit/i
    ]);

    this.actionPatterns.set('enable_fallback', [
      /enable.*fallback/i,
      /turn.*on.*fallback/i,
      /activate.*fallback/i,
      /start.*fallback/i,
      /use.*fallback/i
    ]);

    this.actionPatterns.set('disable_fallback', [
      /disable.*fallback/i,
      /turn.*off.*fallback/i,
      /deactivate.*fallback/i,
      /stop.*fallback/i,
      /remove.*fallback/i
    ]);

    this.actionPatterns.set('get_health_status', [
      /health/i,
      /health.*check/i,
      /health.*status/i,
      /system.*health/i,
      /check.*health/i,
      /monitor.*health/i,
      /health.*monitor/i
    ]);

    this.actionPatterns.set('export_logs', [
      /export.*logs/i,
      /save.*logs/i,
      /download.*logs/i,
      /get.*logs/i,
      /backup.*logs/i,
      /dump.*logs/i
    ]);

    // Parameter patterns
    this.parameterPatterns.set('obfuscation_level', [
      /minimal/i,
      /moderate/i,
      /aggressive/i,
      /stealth/i,
      /low/i,
      /medium/i,
      /high/i,
      /maximum/i
    ]);

    this.parameterPatterns.set('reduction_factor', [
      /(\d+(?:\.\d+)?)\s*%/i,
      /(\d+(?:\.\d+)?)\s*percent/i,
      /reduce.*by.*(\d+(?:\.\d+)?)/i,
      /cut.*by.*(\d+(?:\.\d+)?)/i
    ]);

    this.parameterPatterns.set('proxy_port', [
      /port\s*(\d+)/i,
      /on\s*port\s*(\d+)/i,
      /using\s*port\s*(\d+)/i,
      /at\s*port\s*(\d+)/i
    ]);

    this.parameterPatterns.set('padding_strategy', [
      /random/i,
      /pattern/i,
      /adaptive/i,
      /smart/i,
      /intelligent/i
    ]);

    this.parameterPatterns.set('test_content', [
      /test.*with.*["']([^"']+)["']/i,
      /try.*["']([^"']+)["']/i,
      /sample.*["']([^"']+)["']/i,
      /example.*["']([^"']+)["']/i
    ]);

    this.parameterPatterns.set('test_tokens', [
      /(\d+)\s*tokens/i,
      /(\d+)\s*token/i,
      /with.*(\d+)\s*tokens/i,
      /using.*(\d+)\s*tokens/i
    ]);
  }

  /**
   * Parse natural language command into structured parameters
   */
  parseCommand(command: string): TokenObfuscationNLCommand {
    const normalizedCommand = command.toLowerCase().trim();
    
    // Find the best matching action
    let bestAction = '';
    let bestConfidence = 0;

    for (const [action, patterns] of this.actionPatterns) {
      for (const pattern of patterns) {
        if (pattern.test(normalizedCommand)) {
          const confidence = this.calculateConfidence(normalizedCommand, pattern);
          if (confidence > bestConfidence) {
            bestAction = action;
            bestConfidence = confidence;
          }
        }
      }
    }

    // Extract parameters
    const parameters = this.extractParameters(normalizedCommand);

    return {
      action: bestAction || 'get_status', // Default to get_status if no action found
      parameters,
      confidence: bestConfidence,
      originalCommand: command
    };
  }

  private calculateConfidence(command: string, pattern: RegExp): number {
    const match = command.match(pattern);
    if (!match) return 0;

    // Base confidence from pattern match
    let confidence = 0.5;

    // Boost confidence for exact matches
    if (match[0] === command.trim()) {
      confidence += 0.3;
    }

    // Boost confidence for longer matches
    confidence += Math.min(match[0].length / command.length, 0.2);

    return Math.min(confidence, 1.0);
  }

  private extractParameters(command: string): Record<string, any> {
    const parameters: Record<string, any> = {};

    // Extract obfuscation level
    const levelMatch = command.match(/(minimal|moderate|aggressive|stealth|low|medium|high|maximum)/i);
    if (levelMatch) {
      const level = levelMatch[1].toLowerCase();
      if (['low', 'minimal'].includes(level)) {
        parameters.obfuscation_level = 'minimal';
      } else if (['medium', 'moderate'].includes(level)) {
        parameters.obfuscation_level = 'moderate';
      } else if (['high', 'aggressive', 'maximum'].includes(level)) {
        parameters.obfuscation_level = 'aggressive';
      } else if (level === 'stealth') {
        parameters.obfuscation_level = 'stealth';
      }
    }

    // Extract reduction factor
    const reductionMatch = command.match(/(\d+(?:\.\d+)?)\s*%/i);
    if (reductionMatch) {
      const percentage = parseFloat(reductionMatch[1]);
      parameters.reduction_factor = percentage / 100;
    }

    // Extract proxy port
    const portMatch = command.match(/port\s*(\d+)/i);
    if (portMatch) {
      parameters.proxy_port = parseInt(portMatch[1]);
    }

    // Extract padding strategy
    const strategyMatch = command.match(/(random|pattern|adaptive|smart|intelligent)/i);
    if (strategyMatch) {
      const strategy = strategyMatch[1].toLowerCase();
      if (['smart', 'intelligent'].includes(strategy)) {
        parameters.padding_strategy = 'adaptive';
      } else {
        parameters.padding_strategy = strategy;
      }
    }

    // Extract test content
    const contentMatch = command.match(/["']([^"']+)["']/);
    if (contentMatch) {
      parameters.test_content = contentMatch[1];
    }

    // Extract test tokens
    const tokensMatch = command.match(/(\d+)\s*tokens?/i);
    if (tokensMatch) {
      parameters.test_tokens = parseInt(tokensMatch[1]);
    }

    // Extract boolean flags
    if (/enable|turn\s*on|activate|start/i.test(command)) {
      parameters.enable_streaming = true;
      parameters.preserve_functionality = true;
    }

    if (/disable|turn\s*off|deactivate|stop/i.test(command)) {
      parameters.enable_streaming = false;
    }

    return parameters;
  }

  /**
   * Generate a human-readable response for the parsed command
   */
  generateResponse(parsedCommand: TokenObfuscationNLCommand): string {
    const { action, parameters, confidence, originalCommand } = parsedCommand;

    if (confidence < 0.3) {
      return `I'm not sure what you want to do with token obfuscation. Could you be more specific? I can help you start/stop the proxy, configure settings, check status, or test obfuscation.`;
    }

    let response = `I'll help you ${action.replace('_', ' ')} the token obfuscation system.`;

    if (Object.keys(parameters).length > 0) {
      response += `\n\nDetected parameters:`;
      for (const [key, value] of Object.entries(parameters)) {
        response += `\n- ${key.replace('_', ' ')}: ${value}`;
      }
    }

    response += `\n\nConfidence: ${(confidence * 100).toFixed(0)}%`;

    return response;
  }
}

export function registerTokenObfuscationNL(server: any) {
  const parser = new TokenObfuscationNLParser();

  server.registerTool("token_obfuscation_nl", {
    description: "🔒 **Token Obfuscation Natural Language Interface** - Process natural language commands for token obfuscation operations. Converts conversational requests like 'start the proxy with moderate obfuscation' into structured token obfuscation commands.",
    inputSchema: {
      command: z.string().describe("Natural language command for token obfuscation (e.g., 'start the proxy with moderate obfuscation', 'check the status', 'test obfuscation with 100 tokens')")
    }
  }, async ({ command }: any) => {
    try {
      // Parse the natural language command
      const parsedCommand = parser.parseCommand(command);
      
      // Execute automatically if we have a clear action; otherwise return parsed info
      if (parsedCommand.action) {
        const { executeTokenObfuscationAction } = await import("./token_obfuscation.js");
        const result = await executeTokenObfuscationAction(parsedCommand.action, parsedCommand.parameters);
        return result;
      }

      // Fallback to parsed info
      const response = parser.generateResponse(parsedCommand);
      return {
        content: [{
          type: "text",
          text: `🔒 Token Obfuscation Natural Language Processing\n\n${response}\n\n📋 Parsed Command:\n- Action: ${parsedCommand.action}\n- Parameters: ${JSON.stringify(parsedCommand.parameters, null, 2)}\n- Confidence: ${(parsedCommand.confidence * 100).toFixed(0)}%`
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: "text",
          text: `❌ Error processing natural language command: ${error instanceof Error ? error.message : 'Unknown error'}\n\n💡 Try rephrasing your request. Examples:\n- "start the proxy with moderate obfuscation"\n- "check the status"\n- "test obfuscation with 100 tokens"\n- "stop the proxy"`
        }]
      };
    }
  });
}
