import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export function registerHackGPTNaturalLanguage(server: McpServer) {
  server.registerTool("hack_gpt_natural_language", {
    description: "🤖 **HackGPT Natural Language Interface** - Process natural language commands for HackGPT offensive security operations. Converts conversational requests like 'scan the web application for vulnerabilities' into structured HackGPT commands.",
    inputSchema: {
      command: z.string().describe("Natural language command for HackGPT operations (e.g., 'scan the web application for vulnerabilities', 'generate exploit for SQL injection', 'perform OSINT on the target', 'run Burp Suite scan', 'use Nuclei to find CVEs')")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string(),
      parsed_command: z.object({
        action: z.string(),
        target: z.string().optional(),
        tool_integration: z.string().optional(),
        attack_vector: z.string().optional(),
        intensity: z.string().optional(),
        safe_mode: z.boolean().optional(),
        additional_params: z.record(z.string()).optional()
      }).optional(),
      suggestions: z.array(z.string()).optional(),
      confidence: z.number().optional()
    }
  }, async ({ command }) => {
    try {
      const parsedCommand = parseNaturalLanguageCommand(command);
      
      return {
        success: true,
        message: `Successfully parsed HackGPT command: "${command}"`,
        parsed_command: parsedCommand,
        suggestions: generateSuggestions(parsedCommand.action),
        confidence: calculateConfidence(parsedCommand)
      };
    } catch (error) {
      return {
        success: false,
        message: `Failed to parse HackGPT command: ${error instanceof Error ? error.message : String(error)}`
      };
    }
  });
}

function parseNaturalLanguageCommand(command: string) {
  const commandLower = command.toLowerCase();
  
  // Initialize default values
  let action = "reconnaissance";
  let target: string | undefined;
  let tool_integration: string | undefined;
  let attack_vector: string | undefined;
  let intensity: string | undefined;
  let safe_mode = false;
  const additional_params: Record<string, string> = {};
  
  // Extract target
  const targetPatterns = [
    /(?:target|scan|test|attack|hack|exploit)\s+(?:the\s+)?([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?)/,
    /([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?)\s+(?:for|to|with)/,
    /(?:on|against)\s+([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?)/
  ];
  
  for (const pattern of targetPatterns) {
    const match = commandLower.match(pattern);
    if (match && match[1]) {
      target = match[1];
      break;
    }
  }
  
  // Parse actions based on keywords
  if (commandLower.includes("scan") || commandLower.includes("vulnerability") || commandLower.includes("vuln")) {
    action = "vulnerability_scan";
    
    if (commandLower.includes("nuclei")) {
      tool_integration = "nuclei";
    } else if (commandLower.includes("burp")) {
      tool_integration = "burp_suite";
    } else if (commandLower.includes("web")) {
      tool_integration = "burp_suite";
      attack_vector = "web";
    }
  } else if (commandLower.includes("recon") || commandLower.includes("reconnaissance") || commandLower.includes("gather")) {
    action = "reconnaissance";
    
    if (commandLower.includes("osint")) {
      action = "osint_gathering";
    } else if (commandLower.includes("shodan")) {
      action = "shodan_search";
    }
  } else if (commandLower.includes("exploit") || commandLower.includes("generate")) {
    action = "exploit_generation";
    
    if (commandLower.includes("payload")) {
      action = "payload_creation";
    } else if (commandLower.includes("chain")) {
      action = "exploit_chaining";
    }
  } else if (commandLower.includes("burp") && commandLower.includes("suite")) {
    action = "burp_suite_scan";
    tool_integration = "burp_suite";
  } else if (commandLower.includes("nuclei")) {
    action = "nuclei_scan";
    tool_integration = "nuclei";
  } else if (commandLower.includes("shodan")) {
    action = "shodan_search";
    tool_integration = "shodan";
  } else if (commandLower.includes("osint")) {
    action = "osint_gathering";
    tool_integration = "osint";
  } else if (commandLower.includes("web") && (commandLower.includes("test") || commandLower.includes("app"))) {
    action = "web_app_testing";
    attack_vector = "web";
  } else if (commandLower.includes("api") && commandLower.includes("test")) {
    action = "api_security_test";
    attack_vector = "api";
  } else if (commandLower.includes("zero") && commandLower.includes("day")) {
    action = "zero_day_research";
  } else if (commandLower.includes("social") || commandLower.includes("engineering")) {
    action = "social_engineering";
    attack_vector = "social";
  } else if (commandLower.includes("phishing")) {
    action = "phishing_simulation";
    attack_vector = "social";
  } else if (commandLower.includes("credential") || commandLower.includes("harvest")) {
    action = "credential_harvesting";
  } else if (commandLower.includes("persistence") || commandLower.includes("backdoor")) {
    action = "persistence_setup";
  } else if (commandLower.includes("lateral") || commandLower.includes("movement")) {
    action = "lateral_movement";
  } else if (commandLower.includes("privilege") || commandLower.includes("escalation")) {
    action = "privilege_escalation";
  } else if (commandLower.includes("exfiltrate") || commandLower.includes("data")) {
    action = "data_exfiltration";
  } else if (commandLower.includes("cleanup") || commandLower.includes("trace")) {
    action = "cleanup_traces";
  } else if (commandLower.includes("report") || commandLower.includes("assessment")) {
    action = "report_generation";
  } else if (commandLower.includes("threat") && commandLower.includes("model")) {
    action = "threat_modeling";
  } else if (commandLower.includes("risk") && commandLower.includes("assess")) {
    action = "risk_assessment";
  } else if (commandLower.includes("compliance")) {
    action = "compliance_check";
  } else if (commandLower.includes("ai") && commandLower.includes("prompt")) {
    action = "ai_prompt_injection";
  } else if (commandLower.includes("hunt") && commandLower.includes("vulnerability")) {
    action = "vulnerability_hunting";
  } else if (commandLower.includes("automated") && commandLower.includes("exploit")) {
    action = "automated_exploitation";
  }
  
  // Parse intensity
  if (commandLower.includes("low") || commandLower.includes("gentle") || commandLower.includes("stealth")) {
    intensity = "low";
  } else if (commandLower.includes("medium") || commandLower.includes("moderate")) {
    intensity = "medium";
  } else if (commandLower.includes("high") || commandLower.includes("aggressive") || commandLower.includes("intensive")) {
    intensity = "high";
  } else if (commandLower.includes("aggressive") || commandLower.includes("brutal")) {
    intensity = "aggressive";
  }
  
  // Parse safe mode
  if (commandLower.includes("safe") || commandLower.includes("simulation") || commandLower.includes("test") || commandLower.includes("demo")) {
    safe_mode = true;
  }
  
  // Parse attack vectors
  if (commandLower.includes("web")) {
    attack_vector = "web";
  } else if (commandLower.includes("network")) {
    attack_vector = "network";
  } else if (commandLower.includes("mobile")) {
    attack_vector = "mobile";
  } else if (commandLower.includes("social")) {
    attack_vector = "social";
  } else if (commandLower.includes("physical")) {
    attack_vector = "physical";
  } else if (commandLower.includes("cloud")) {
    attack_vector = "cloud";
  } else if (commandLower.includes("api")) {
    attack_vector = "api";
  }
  
  // Parse payload types
  if (commandLower.includes("reverse") && commandLower.includes("shell")) {
    additional_params.payload_type = "reverse_shell";
  } else if (commandLower.includes("bind") && commandLower.includes("shell")) {
    additional_params.payload_type = "bind_shell";
  } else if (commandLower.includes("meterpreter")) {
    additional_params.payload_type = "meterpreter";
  } else if (commandLower.includes("web") && commandLower.includes("shell")) {
    additional_params.payload_type = "web_shell";
  }
  
  // Parse output format
  if (commandLower.includes("json")) {
    additional_params.output_format = "json";
  } else if (commandLower.includes("report")) {
    additional_params.output_format = "report";
  } else if (commandLower.includes("executive")) {
    additional_params.output_format = "executive";
  } else if (commandLower.includes("technical")) {
    additional_params.output_format = "technical";
  } else if (commandLower.includes("streamlit")) {
    additional_params.output_format = "streamlit";
  }
  
  // Parse specific vulnerability types
  if (commandLower.includes("sql") && commandLower.includes("injection")) {
    additional_params.vulnerability_type = "sql_injection";
  } else if (commandLower.includes("xss") || commandLower.includes("cross") && commandLower.includes("site")) {
    additional_params.vulnerability_type = "xss";
  } else if (commandLower.includes("rce") || commandLower.includes("remote") && commandLower.includes("code")) {
    additional_params.vulnerability_type = "rce";
  } else if (commandLower.includes("csrf")) {
    additional_params.vulnerability_type = "csrf";
  }
  
  return {
    action,
    target,
    tool_integration,
    attack_vector,
    intensity,
    safe_mode,
    additional_params
  };
}

function generateSuggestions(action: string): string[] {
  const suggestions: Record<string, string[]> = {
    reconnaissance: [
      "Try: 'Perform OSINT gathering on target.com'",
      "Try: 'Use Shodan to search for open ports'",
      "Try: 'Gather social media intelligence'"
    ],
    vulnerability_scan: [
      "Try: 'Scan target.com with Nuclei for CVEs'",
      "Try: 'Use Burp Suite to scan web application'",
      "Try: 'Perform comprehensive vulnerability assessment'"
    ],
    exploit_generation: [
      "Try: 'Generate SQL injection exploit'",
      "Try: 'Create XSS payload for target'",
      "Try: 'Generate reverse shell payload'"
    ],
    burp_suite_scan: [
      "Try: 'Run Burp Suite passive scan'",
      "Try: 'Perform active Burp Suite scan with authentication'",
      "Try: 'Use Burp Suite to test for OWASP Top 10'"
    ],
    nuclei_scan: [
      "Try: 'Run Nuclei with latest templates'",
      "Try: 'Use Nuclei to scan for specific CVEs'",
      "Try: 'Perform Nuclei scan with custom templates'"
    ],
    shodan_search: [
      "Try: 'Search Shodan for Apache servers'",
      "Try: 'Find open SSH ports on target'",
      "Try: 'Search for IoT devices in location'"
    ],
    osint_gathering: [
      "Try: 'Gather OSINT on company employees'",
      "Try: 'Find subdomains and DNS records'",
      "Try: 'Analyze social media profiles'"
    ],
    web_app_testing: [
      "Try: 'Test web application for OWASP vulnerabilities'",
      "Try: 'Perform comprehensive web security assessment'",
      "Try: 'Test for authentication bypass'"
    ],
    api_security_test: [
      "Try: 'Test API endpoints for vulnerabilities'",
      "Try: 'Check for broken authentication in API'",
      "Try: 'Test API rate limiting and input validation'"
    ],
    zero_day_research: [
      "Try: 'Research zero-day vulnerabilities in target software'",
      "Try: 'Analyze custom application for logic flaws'",
      "Try: 'Investigate third-party component vulnerabilities'"
    ],
    social_engineering: [
      "Try: 'Perform social engineering assessment'",
      "Try: 'Test employee security awareness'",
      "Try: 'Simulate phishing campaign'"
    ],
    report_generation: [
      "Try: 'Generate executive security report'",
      "Try: 'Create technical vulnerability report'",
      "Try: 'Export findings to JSON format'"
    ]
  };
  
  return suggestions[action] || [
    "Try: 'Scan target.com for vulnerabilities'",
    "Try: 'Generate exploit for SQL injection'",
    "Try: 'Perform OSINT reconnaissance'"
  ];
}

function calculateConfidence(parsedCommand: any): number {
  let confidence = 0.5; // Base confidence
  
  // Increase confidence based on specific indicators
  if (parsedCommand.target) confidence += 0.2;
  if (parsedCommand.tool_integration) confidence += 0.15;
  if (parsedCommand.attack_vector) confidence += 0.1;
  if (Object.keys(parsedCommand.additional_params || {}).length > 0) confidence += 0.05;
  
  // Decrease confidence for ambiguous commands
  if (parsedCommand.action === "reconnaissance" && !parsedCommand.tool_integration) confidence -= 0.1;
  
  return Math.min(Math.max(confidence, 0), 1);
}
