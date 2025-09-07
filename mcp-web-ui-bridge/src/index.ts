/**
 * MCP Web UI Bridge Server
 * Main entry point for the MCP server that enables AI to interact with web-based AI services
 */

import { Server, Tool } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { getDriverFromEnv, DriverConfig } from './drivers/driver-bridge.js';
import { loadProvider, getAllProviders, providerManager } from './providers/registry.js';
import { recordMacro, runMacro, macroRecorder, macroRunner } from './core/macro.js';
import { sessionManager, SessionHelpers } from './core/session.js';
import { ProviderWizard, QuickSetupWizard } from './core/wizard.js';
import { TextStreamer } from './core/streaming.js';

// Initialize session manager
await sessionManager.initializeEncryption();

// Load providers
await providerManager.loadProviders();

/**
 * Web UI Chat Tool
 * Sends prompts to AI services via their web interfaces
 */
const webUiChat: Tool = {
  name: 'web_ui_chat',
  description: 'Chat with AI services through their web interfaces without APIs. Supports streaming responses and session persistence.',
  inputSchema: {
    type: 'object',
    properties: {
      provider: {
        type: 'string',
        description: 'Provider ID (e.g., "chatgpt", "grok", "claude", "huggingface", or custom provider)'
      },
      prompt: {
        type: 'string',
        description: 'The message to send to the AI service'
      },
      timeoutMs: {
        type: 'number',
        description: 'Timeout in milliseconds (default: 240000)',
        default: 240000
      },
      variables: {
        type: 'object',
        description: 'Variables to substitute in provider scripts/macros',
        additionalProperties: { type: 'string' }
      },
      platform: {
        type: 'string',
        enum: ['desktop', 'android', 'ios'],
        description: 'Target platform (default: from environment)'
      },
      headless: {
        type: 'boolean',
        description: 'Run browser in headless mode (default: false)'
      }
    },
    required: ['provider', 'prompt']
  }
};

/**
 * Providers List Tool
 * Lists all available AI service providers and their capabilities
 */
const providersList: Tool = {
  name: 'providers_list',
  description: 'List all available AI service providers and their capabilities.',
  inputSchema: {
    type: 'object',
    properties: {
      platform: {
        type: 'string',
        enum: ['desktop', 'android', 'ios'],
        description: 'Filter providers by platform'
      }
    }
  }
};

/**
 * Provider Wizard Tool
 * Interactive setup wizard for configuring custom AI service providers
 */
const providerWizard: Tool = {
  name: 'provider_wizard',
  description: 'Interactive wizard to set up custom AI service providers by capturing selectors and testing the configuration.',
  inputSchema: {
    type: 'object',
    properties: {
      startUrl: {
        type: 'string',
        description: 'URL of the AI service chat interface'
      },
      providerName: {
        type: 'string',
        description: 'Name for the provider (e.g., "My Custom AI")'
      },
      platform: {
        type: 'string',
        enum: ['desktop', 'android', 'ios'],
        description: 'Target platform for the provider'
      },
      headless: {
        type: 'boolean',
        description: 'Run browser in headless mode during setup'
      }
    },
    required: ['startUrl', 'providerName', 'platform']
  }
};

/**
 * Macro Record Tool
 * Records user actions into a portable JSON script
 */
const macroRecord: Tool = {
  name: 'macro_record',
  description: 'Record a macro by capturing user actions on a web page or app.',
  inputSchema: {
    type: 'object',
    properties: {
      target: {
        type: 'object',
        properties: {
          provider: { type: 'string', description: 'Provider ID to record against' },
          url: { type: 'string', description: 'Direct URL to record against' }
        },
        description: 'Target for recording (either provider session or raw URL)'
      },
      scope: {
        type: 'string',
        enum: ['dom', 'driver', 'auto'],
        description: 'Recording scope - DOM for web elements, driver for mobile actions, auto to choose best',
        default: 'auto'
      },
      name: {
        type: 'string',
        description: 'Name for the macro'
      },
      description: {
        type: 'string',
        description: 'Description of what the macro does'
      },
      platform: {
        type: 'string',
        enum: ['desktop', 'android', 'ios'],
        description: 'Target platform for recording'
      }
    },
    required: ['target']
  }
};

/**
 * Macro Run Tool
 * Executes a saved macro with optional variables
 */
const macroRun: Tool = {
  name: 'macro_run',
  description: 'Execute a saved macro with optional variable substitution.',
  inputSchema: {
    type: 'object',
    properties: {
      macroId: {
        type: 'string',
        description: 'ID of the macro to execute'
      },
      variables: {
        type: 'object',
        description: 'Variables to substitute in the macro',
        additionalProperties: { type: 'string' }
      },
      dryRun: {
        type: 'boolean',
        description: 'Print the planned actions without executing them',
        default: false
      }
    },
    required: ['macroId']
  }
};

/**
 * Session Management Tool
 * Manage encrypted sessions for providers
 */
const sessionManagement: Tool = {
  name: 'session_management',
  description: 'Manage encrypted sessions for AI service providers.',
  inputSchema: {
    type: 'object',
    properties: {
      action: {
        type: 'string',
        enum: ['list', 'clear', 'cleanup'],
        description: 'Session management action'
      },
      provider: {
        type: 'string',
        description: 'Provider ID (required for clear action)'
      },
      platform: {
        type: 'string',
        enum: ['desktop', 'android', 'ios'],
        description: 'Platform (required for clear action)'
      }
    },
    required: ['action']
  }
};

// Create MCP server
const server = new Server(
  {
    name: 'mcp-web-ui-bridge',
    version: '0.1.0'
  },
  {
    capabilities: {
      tools: {}
    }
  }
);

// Tool handlers
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [webUiChat, providersList, providerWizard, macroRecord, macroRun, sessionManagement]
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'web_ui_chat':
        return await handleWebUiChat(args);
      
      case 'providers_list':
        return await handleProvidersList(args);
      
      case 'provider_wizard':
        return await handleProviderWizard(args);
      
      case 'macro_record':
        return await handleMacroRecord(args);
      
      case 'macro_run':
        return await handleMacroRun(args);
      
      case 'session_management':
        return await handleSessionManagement(args);
      
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${error instanceof Error ? error.message : String(error)}`
        }
      ],
      isError: true
    };
  }
});

/**
 * Handle web UI chat requests
 */
async function handleWebUiChat(args: any) {
  const { provider, prompt, timeoutMs = 240000, variables = {}, platform, headless } = args;
  
  // Get provider configuration
  const config = await loadProvider(provider);
  
  // Determine platform
  const targetPlatform = platform || process.env.PLATFORM || 'desktop';
  
  // Get driver
  const driverConfig: DriverConfig = {
    platform: targetPlatform as any,
    headless: headless ?? false
  };
  const driver = await getDriverFromEnv();
  
  try {
    // Ensure session is available
    await SessionHelpers.ensureSession(sessionManager, provider, targetPlatform, driver);
    
    // Navigate to provider URL
    await driver.open(config.url);
    
    // Ensure login
    await driver.ensureLogin(config.loginSignal, 120000);
    
    // Fill input with prompt
    await driver.fill(config.input, prompt);
    
    // Send message
    if (config.send?.gesture === 'enter') {
      await driver.press('Enter');
    } else if (config.send?.button) {
      await driver.click(config.send.button);
    }
    
    // Stream response
    const streamer = new TextStreamer({ timeoutMs });
    let finalText = '';
    
    const result = await streamer.streamText(
      config.assistantContainer,
      (delta) => {
        // Stream delta back to client
        // Note: This would need to be implemented with proper MCP streaming
        finalText += delta;
      }
    );
    
    // Save session
    await SessionHelpers.saveSession(sessionManager, provider, targetPlatform, driver);
    
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            text: result.text,
            meta: {
              provider,
              platform: targetPlatform,
              duration: result.metadata?.duration,
              chunks: result.metadata?.chunks
            }
          })
        }
      ]
    };
  } finally {
    await driver.close();
  }
}

/**
 * Handle providers list requests
 */
async function handleProvidersList(args: any) {
  const { platform } = args;
  
  let providers;
  if (platform) {
    providers = providerManager.getProvidersForPlatform(platform);
  } else {
    providers = await getAllProviders();
  }
  
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify({ providers })
      }
    ]
  };
}

/**
 * Handle provider wizard requests
 */
async function handleProviderWizard(args: any) {
  const { startUrl, providerName, platform, headless } = args;
  
  const wizard = new ProviderWizard(providerManager);
  const result = await wizard.runWizard({
    startUrl,
    providerName,
    platform,
    headless
  });
  
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(result)
      }
    ]
  };
}

/**
 * Handle macro record requests
 */
async function handleMacroRecord(args: any) {
  const { target, scope = 'auto', name, description, platform } = args;
  
  // Determine target URL
  let targetUrl: string;
  if (target.provider) {
    const config = await loadProvider(target.provider);
    targetUrl = config.url;
  } else if (target.url) {
    targetUrl = target.url;
  } else {
    throw new Error('Either provider or url must be specified in target');
  }
  
  // Get driver
  const targetPlatform = platform || process.env.PLATFORM || 'desktop';
  const driverConfig: DriverConfig = {
    platform: targetPlatform as any,
    headless: false // Always use headful for recording
  };
  const driver = await getDriverFromEnv();
  
  try {
    // Start recording
    await macroRecorder.startRecording(driver, targetUrl, targetPlatform as any, scope);
    
    // Wait for user to complete actions
    // Note: In a real implementation, this would need proper user interaction handling
    await new Promise(resolve => setTimeout(resolve, 30000)); // 30 second timeout for demo
    
    // Stop recording
    const macro = macroRecorder.stopRecording();
    
    // Set name and description if provided
    if (name) macro.name = name;
    if (description) macro.description = description;
    
    // Save macro
    await macroRunner.saveMacro(macro);
    
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            macroId: macro.id,
            steps: macro.steps,
            name: macro.name
          })
        }
      ]
    };
  } finally {
    await driver.close();
  }
}

/**
 * Handle macro run requests
 */
async function handleMacroRun(args: any) {
  const { macroId, variables = {}, dryRun = false } = args;
  
  const result = await macroRunner.runMacro(macroId, { variables, dryRun });
  
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(result)
      }
    ]
  };
}

/**
 * Handle session management requests
 */
async function handleSessionManagement(args: any) {
  const { action, provider, platform } = args;
  
  switch (action) {
    case 'list':
      const sessions = await sessionManager.listSessions();
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ sessions })
          }
        ]
      };
    
    case 'clear':
      if (!provider || !platform) {
        throw new Error('Provider and platform are required for clear action');
      }
      await sessionManager.clearSession(provider, platform);
      return {
        content: [
          {
            type: 'text',
            text: `Session cleared for ${provider} on ${platform}`
          }
        ]
      };
    
    case 'cleanup':
      await sessionManager.cleanupExpiredSessions();
      return {
        content: [
          {
            type: 'text',
            text: 'Expired sessions cleaned up'
          }
        ]
      };
    
    default:
      throw new Error(`Unknown session action: ${action}`);
  }
}

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('MCP Web UI Bridge server running on stdio');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}
