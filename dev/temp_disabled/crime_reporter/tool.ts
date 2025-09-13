/**
 * Crime Reporter Tool Registration
 * 
 * Registers the crime reporter tool with the MCP server
 * and provides the natural language interface.
 */

import { z } from 'zod';
import { CrimeReporterTool } from './index';
import { CrimeReporterConfig } from './schema/types';

// Initialize the tool instance
let crimeReporterTool: CrimeReporterTool | null = null;

/**
 * Initialize the crime reporter tool
 */
function initializeTool(): CrimeReporterTool {
  if (!crimeReporterTool) {
    const config: Partial<CrimeReporterConfig> = {
      // Configuration will be loaded from environment variables
    };
    crimeReporterTool = new CrimeReporterTool(config);
  }
  return crimeReporterTool;
}

/**
 * Crime Reporter Tool Definition
 */
export const crimeReporterToolDefinition = {
  name: 'crime_reporter',
  description: 'Comprehensive crime reporting tool with jurisdiction resolution, case preparation, and automated filing via forms or email',
  version: '1.0.0',
  author: 'MCP God Mode',
  category: 'legal',
  tags: ['crime', 'reporting', 'legal', 'jurisdiction', 'forms', 'email'],
  
  commands: [
    {
      name: 'searchJurisdiction',
      description: 'Search for appropriate law enforcement jurisdictions and reporting channels',
      parameters: {
        type: 'object',
        properties: {
          location: {
            type: 'string',
            description: 'Location string (e.g., "Minneapolis, MN") or coordinates object {lat, lon}'
          },
          crimeType: {
            type: 'string',
            description: 'Type of crime (e.g., "theft", "cyber fraud", "assault")',
            optional: true
          },
          maxResults: {
            type: 'number',
            description: 'Maximum number of jurisdictions to return',
            default: 10
          },
          includeFederal: {
            type: 'boolean',
            description: 'Include federal agencies (FBI, IC3) for applicable crimes',
            default: true
          }
        },
        required: ['location']
      }
    },
    {
      name: 'prepareReport',
      description: 'Prepare a normalized crime report from case bundle with anonymization',
      parameters: {
        type: 'object',
        properties: {
          caseBundle: {
            type: 'object',
            description: 'Case bundle containing crime details, evidence, and timeline',
            properties: {
              caseId: { type: 'string', description: 'Unique case identifier' },
              narrative: { type: 'string', description: 'Detailed description of the incident' },
              location: { 
                type: 'object', 
                properties: {
                  raw: { type: 'string', description: 'Location description' },
                  lat: { type: 'number', description: 'Latitude', optional: true },
                  lon: { type: 'number', description: 'Longitude', optional: true }
                },
                required: ['raw']
              },
              crimeType: { type: 'string', description: 'Type of crime', optional: true },
              anonymous: { type: 'boolean', description: 'Whether to anonymize the report', default: true },
              evidence: {
                type: 'array',
                description: 'Evidence files, URLs, or text',
                items: {
                  type: 'object',
                  properties: {
                    kind: { type: 'string', enum: ['file', 'url', 'text'] },
                    path: { type: 'string', description: 'File path (for file kind)' },
                    url: { type: 'string', description: 'URL (for url kind)' },
                    content: { type: 'string', description: 'Text content (for text kind)' },
                    description: { type: 'string', description: 'Evidence description', optional: true }
                  }
                }
              },
              timeline: {
                type: 'array',
                description: 'Timeline of events',
                items: {
                  type: 'object',
                  properties: {
                    when: { type: 'string', description: 'ISO timestamp' },
                    title: { type: 'string', description: 'Event title' },
                    details: { type: 'string', description: 'Event details', optional: true }
                  }
                }
              },
              aiNotes: {
                type: 'array',
                description: 'AI model analysis notes',
                items: {
                  type: 'object',
                  properties: {
                    model: { type: 'string', description: 'AI model name' },
                    summary: { type: 'string', description: 'Analysis summary' },
                    confidence: { type: 'number', description: 'Confidence score 0-1', optional: true },
                    provenance: { type: 'string', description: 'Source or prompt ID', optional: true }
                  }
                }
              }
            },
            required: ['narrative', 'location']
          },
          targetJurisdiction: {
            type: 'object',
            description: 'Target jurisdiction for the report',
            optional: true
          },
          anonymous: {
            type: 'boolean',
            description: 'Whether to anonymize the report (overrides caseBundle.anonymous)',
            default: true
          },
          includeAiNotes: {
            type: 'boolean',
            description: 'Whether to include AI analysis notes in the report',
            default: true
          }
        },
        required: ['caseBundle']
      }
    },
    {
      name: 'fileReport',
      description: 'File a crime report via official form or email with legal acknowledgment',
      parameters: {
        type: 'object',
        properties: {
          report: {
            type: 'object',
            description: 'Normalized report from prepareReport command'
          },
          mode: {
            type: 'string',
            enum: ['auto', 'form', 'email'],
            description: 'Submission mode: auto (prefer form), form (force form), email (force email)',
            default: 'auto'
          },
          headful: {
            type: 'boolean',
            description: 'Run browser in visible mode for debugging',
            default: false
          },
          acknowledgeLegal: {
            type: 'boolean',
            description: 'Acknowledge legal requirements and false reporting penalties',
            default: false
          },
          withIdentity: {
            type: 'boolean',
            description: 'Include personal identity information (overrides anonymous setting)',
            default: false
          },
          timeout: {
            type: 'number',
            description: 'Timeout in milliseconds',
            default: 30000
          },
          retryAttempts: {
            type: 'number',
            description: 'Number of retry attempts on failure',
            default: 3
          }
        },
        required: ['report', 'acknowledgeLegal']
      }
    },
    {
      name: 'previewReport',
      description: 'Generate a preview of the report in HTML, PDF, or Markdown format',
      parameters: {
        type: 'object',
        properties: {
          report: {
            type: 'object',
            description: 'Normalized report from prepareReport command'
          },
          format: {
            type: 'string',
            enum: ['html', 'pdf', 'markdown'],
            description: 'Preview format',
            default: 'html'
          }
        },
        required: ['report']
      }
    },
    {
      name: 'getStatus',
      description: 'Get filing status and history for a case',
      parameters: {
        type: 'object',
        properties: {
          caseId: {
            type: 'string',
            description: 'Case ID to check status for'
          }
        },
        required: ['caseId']
      }
    },
    {
      name: 'exportCase',
      description: 'Export case bundle with all artifacts in JSON, PDF, or ZIP format',
      parameters: {
        type: 'object',
        properties: {
          caseId: {
            type: 'string',
            description: 'Case ID to export'
          },
          format: {
            type: 'string',
            enum: ['json', 'pdf', 'zip'],
            description: 'Export format',
            default: 'json'
          }
        },
        required: ['caseId']
      }
    }
  ],

  naturalLanguagePatterns: [
    {
      pattern: /report\s+(?:a\s+)?(.+?)\s+(?:in|at|near)\s+(.+?)(?:\s+with\s+(.+?))?(?:\s+anonymously)?/i,
      description: 'Report a crime with location and optional evidence',
      example: 'Report a theft in Minneapolis, MN with these photos, anonymously'
    },
    {
      pattern: /file\s+(?:a\s+)?(.+?)\s+(?:report|case)\s+(?:in|at|near)\s+(.+?)(?:\s+with\s+(.+?))?/i,
      description: 'File a crime report with location and evidence',
      example: 'File a cyber fraud report in Hennepin County with these screenshots'
    },
    {
      pattern: /find\s+(?:the\s+)?(?:right\s+)?(?:department|jurisdiction|agency)\s+(?:for|in)\s+(.+?)(?:\s+and\s+(?:submit|file))?/i,
      description: 'Find appropriate jurisdiction and optionally submit',
      example: 'Find the right department for Mora, MN and submit my case'
    },
    {
      pattern: /(?:submit|send)\s+(?:to\s+)?(.+?)\s+(?:with|using)\s+(?:my\s+)?(?:identity|name)/i,
      description: 'Submit report with identity information',
      example: 'Submit to Minneapolis Police with my identity'
    },
    {
      pattern: /preview\s+(?:my\s+)?(?:report|case)\s+(?:in\s+)?(.+?)\s+format/i,
      description: 'Preview report in specific format',
      example: 'Preview my report in PDF format'
    },
    {
      pattern: /(?:check\s+)?(?:status|progress)\s+(?:of\s+)?(?:case|report)\s+(.+)/i,
      description: 'Check status of a case',
      example: 'Check status of case CR-ABC123'
    },
    {
      pattern: /export\s+(?:case|report)\s+(.+?)(?:\s+in\s+(.+?)\s+format)?/i,
      description: 'Export case in specific format',
      example: 'Export case CR-ABC123 in ZIP format'
    }
  ],

  legalWarnings: [
    'False reporting is a crime and may result in criminal charges',
    'This tool is for legitimate crime reporting only',
    'All submissions are subject to local, state, and federal laws',
    'Evidence must be authentic and legally obtained',
    'Reports are submitted in good faith and may be investigated'
  ],

  safetyFeatures: [
    'Default anonymous reporting to protect privacy',
    'PII redaction and anonymization capabilities',
    'Legal acknowledgment requirements',
    'CAPTCHA handling with user interaction',
    'Rate limiting and retry mechanisms',
    'Comprehensive audit logging',
    'Evidence validation and size limits'
  ]
};

/**
 * Execute crime reporter command
 */
export async function executeCrimeReporterCommand(
  command: string,
  parameters: any
): Promise<any> {
  const tool = initializeTool();

  try {
    switch (command) {
      case 'searchJurisdiction':
        return await tool.searchJurisdiction(parameters);
      
      case 'prepareReport':
        return await tool.prepareReport(parameters);
      
      case 'fileReport':
        return await tool.fileReport(parameters.report, parameters);
      
      case 'previewReport':
        return await tool.previewReport(parameters.report, parameters.format);
      
      case 'getStatus':
        return await tool.getStatus(parameters.caseId);
      
      case 'exportCase':
        return await tool.exportCase(parameters.caseId, parameters.format);
      
      default:
        throw new Error(`Unknown command: ${command}`);
    }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
      command,
      parameters
    };
  }
}

/**
 * Process natural language command
 */
export async function processNaturalLanguageCommand(command: string): Promise<any> {
  const tool = initializeTool();
  return await tool.processNaturalLanguageCommand(command);
}

/**
 * Get tool information
 */
export function getCrimeReporterToolInfo() {
  return {
    ...crimeReporterToolDefinition,
    initialized: crimeReporterTool !== null,
    config: crimeReporterTool ? 'loaded' : 'not loaded'
  };
}

/**
 * Test tool configuration
 */
export async function testCrimeReporterConfiguration(): Promise<any> {
  const tool = initializeTool();
  
  try {
    // Test jurisdiction search
    const searchResult = await tool.searchJurisdiction({
      location: 'Minneapolis, MN',
      crimeType: 'theft',
      maxResults: 3
    });

    // Test email configuration
    const emailTest = await tool['emailSubmitter'].testConfiguration();

    return {
      success: true,
      tests: {
        jurisdictionSearch: searchResult.success,
        emailConfiguration: emailTest.success
      },
      message: 'Crime reporter tool configuration test completed'
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      message: 'Crime reporter tool configuration test failed'
    };
  }
}

/**
 * Register crime reporter tool with MCP server (for modular server)
 */
export function registerCrimeReporter(server: any) {
  try {
    const crimeReporterInfo = getCrimeReporterToolInfo();
    
    // Register main crime reporter command
    server.registerTool("crime_reporter", {
      description: crimeReporterInfo.description,
      inputSchema: {
        command: z.string().describe("Crime reporter command: searchJurisdiction, prepareReport, fileReport, previewReport, getStatus, exportCase"),
        parameters: z.object({}).passthrough().describe("Command parameters")
      }
    }, async ({ command, parameters }: { command: string; parameters: any }) => {
      try {
        return await executeCrimeReporterCommand(command, parameters);
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error occurred',
          command,
          parameters
        };
      }
    });

    // Register natural language interface
    server.registerTool("crime_reporter_nl", {
      description: "🚨 **Crime Reporter Natural Language Interface** - Process natural language commands for crime reporting with jurisdiction resolution, case preparation, and automated filing.",
      inputSchema: {
        command: z.string().describe("Natural language command for crime reporting (e.g., 'Report a theft in Minneapolis with these photos, anonymously')")
      }
    }, async ({ command }: { command: string }) => {
      try {
        return await processNaturalLanguageCommand(command);
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error occurred',
          command
        };
      }
    });

    // Register configuration test
    server.registerTool("crime_reporter_test", {
      description: "🧪 **Crime Reporter Configuration Test** - Test crime reporter tool configuration and connectivity.",
      inputSchema: {}
    }, async () => {
      try {
        return await testCrimeReporterConfiguration();
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error occurred'
        };
      }
    });

    console.log("✅ Crime Reporter Tool registered with modular server");
    return true;
  } catch (error) {
    console.warn("Warning: Failed to register Crime Reporter Tool:", error);
    return false;
  }
}
