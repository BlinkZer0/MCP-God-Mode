import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export function registerHexStrikeAINaturalLanguage(server: McpServer) {
  server.registerTool("hexstrike_ai_natural_language", {
    description: "🤖 **HexStrike AI Natural Language Interface** - Process natural language commands for HexStrike AI penetration testing operations. Converts conversational requests like 'perform autonomous penetration test on the target' into structured HexStrike AI commands.",
    inputSchema: {
      command: z.string().describe("Natural language command for HexStrike AI operations (e.g., 'perform autonomous penetration test on target', 'generate custom exploits for the system', 'run AI-powered vulnerability assessment', 'deploy reconnaissance agents')")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string(),
      parsed_command: z.object({
        action: z.string(),
        target: z.string().optional(),
        parameters: z.record(z.string()).optional()
      }).optional(),
      suggested_tools: z.array(z.string()).optional(),
      confidence: z.number().optional()
    }
  }, async ({ command }) => {
    try {
      const parsed = parseHexStrikeCommand(command);
      
      return {
        success: true,
        message: `Parsed HexStrike AI command: "${command}"`,
        parsed_command: parsed,
        suggested_tools: getSuggestedTools(parsed.action),
        confidence: calculateConfidence(command, parsed.action)
      };
    } catch (error) {
      return {
        success: false,
        message: `Failed to parse HexStrike AI command: ${error instanceof Error ? error.message : String(error)}`
      };
    }
  });
}

function parseHexStrikeCommand(command: string): {
  action: string;
  target?: string;
  parameters?: Record<string, string>;
} {
  const commandLower = command.toLowerCase();
  
  // Extract target from command
  const targetPatterns = [
    /(?:on|target|against|to)\s+([a-zA-Z0-9.-]+)/,
    /([a-zA-Z0-9.-]+\.(?:com|org|net|gov))/,
    /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/,
    /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})/
  ];
  
  let target: string | undefined;
  for (const pattern of targetPatterns) {
    const match = commandLower.match(pattern);
    if (match) {
      target = match[1];
      break;
    }
  }
  
  // Parse action based on keywords
  if (commandLower.includes("autonomous") || commandLower.includes("ai") || commandLower.includes("intelligent")) {
    return { action: "autonomous_attack", target, parameters: { intensity: "medium" } };
  } else if (commandLower.includes("reconnaissance") || commandLower.includes("recon") || commandLower.includes("gather information")) {
    return { action: "run_reconnaissance", target, parameters: { attack_vector: "network" } };
  } else if (commandLower.includes("vulnerability") && commandLower.includes("scan")) {
    return { action: "vulnerability_scan", target, parameters: { attack_vector: "network" } };
  } else if (commandLower.includes("exploit") && commandLower.includes("generate")) {
    return { action: "exploit_generation", target, parameters: { attack_vector: "network" } };
  } else if (commandLower.includes("attack") && commandLower.includes("simulate")) {
    return { action: "attack_simulation", target, parameters: { intensity: "medium" } };
  } else if (commandLower.includes("cve") && commandLower.includes("analyze")) {
    return { action: "cve_analysis", target };
  } else if (commandLower.includes("threat") && commandLower.includes("model")) {
    return { action: "threat_modeling", target, parameters: { attack_vector: "network" } };
  } else if (commandLower.includes("risk") && commandLower.includes("assess")) {
    return { action: "risk_assessment", target, parameters: { attack_vector: "network" } };
  } else if (commandLower.includes("report") && commandLower.includes("generate")) {
    return { action: "generate_report", target, parameters: { output_format: "executive" } };
  } else if (commandLower.includes("ai") && commandLower.includes("decision")) {
    return { action: "ai_decision_engine", target, parameters: { attack_vector: "network" } };
  } else if (commandLower.includes("deploy") && commandLower.includes("agent")) {
    return { action: "deploy_agent", target, parameters: { agent_type: "ai_coordinator" } };
  } else if (commandLower.includes("list") && commandLower.includes("agent")) {
    return { action: "list_agents", target };
  } else if (commandLower.includes("start") && commandLower.includes("hexstrike")) {
    return { action: "start_hexstrike", target };
  } else if (commandLower.includes("stop") && commandLower.includes("hexstrike")) {
    return { action: "stop_hexstrike", target };
  } else if (commandLower.includes("custom") && commandLower.includes("exploit")) {
    return { action: "custom_exploit", target };
  } else if (commandLower.includes("chain") && commandLower.includes("execution")) {
    return { action: "chain_execution", target };
  } else if (commandLower.includes("target") && commandLower.includes("analyze")) {
    return { action: "target_analysis", target, parameters: { attack_vector: "network" } };
  } else if (commandLower.includes("attack") && commandLower.includes("path")) {
    return { action: "attack_path_generation", target, parameters: { attack_vector: "network" } };
  } else if (commandLower.includes("payload") && commandLower.includes("generate")) {
    return { action: "payload_generation", target, parameters: { attack_vector: "network" } };
  } else if (commandLower.includes("persistence") && commandLower.includes("setup")) {
    return { action: "persistence_setup", target };
  } else if (commandLower.includes("lateral") && commandLower.includes("movement")) {
    return { action: "lateral_movement", target };
  } else if (commandLower.includes("privilege") && commandLower.includes("escalation")) {
    return { action: "privilege_escalation", target };
  } else if (commandLower.includes("data") && commandLower.includes("exfiltration")) {
    return { action: "data_exfiltration", target };
  } else if (commandLower.includes("cleanup") && commandLower.includes("traces")) {
    return { action: "cleanup_traces", target };
  } else if (commandLower.includes("status") || commandLower.includes("check")) {
    return { action: "get_status", target };
  } else if (commandLower.includes("module") && commandLower.includes("list")) {
    return { action: "list_modules", target };
  } else if (commandLower.includes("module") && commandLower.includes("execution")) {
    return { action: "module_execution", target };
  } else {
    // Default to general penetration testing
    return { action: "autonomous_attack", target, parameters: { intensity: "medium" } };
  }
}

function getSuggestedTools(action: string): string[] {
  const toolMappings: Record<string, string[]> = {
    "autonomous_attack": ["hexstrike_ai", "metasploit_framework", "exploit_framework"],
    "run_reconnaissance": ["hexstrike_ai", "nmap_scanner", "osint_reconnaissance"],
    "vulnerability_scan": ["hexstrike_ai", "vulnerability_scanner", "nmap_scanner"],
    "exploit_generation": ["hexstrike_ai", "metasploit_framework", "exploit_framework"],
    "attack_simulation": ["hexstrike_ai", "penetration_testing_toolkit", "red_team_toolkit"],
    "cve_analysis": ["hexstrike_ai", "vulnerability_assessment", "threat_intelligence"],
    "threat_modeling": ["hexstrike_ai", "advanced_security_assessment", "threat_intelligence"],
    "risk_assessment": ["hexstrike_ai", "compliance_assessment", "advanced_security_assessment"],
    "generate_report": ["hexstrike_ai", "penetration_testing_toolkit", "forensics_analysis"],
    "ai_decision_engine": ["hexstrike_ai", "ai_adversarial_prompt", "advanced_analytics_engine"],
    "deploy_agent": ["hexstrike_ai", "cobalt_strike", "empire_powershell"],
    "list_agents": ["hexstrike_ai", "metasploit_framework", "cobalt_strike"],
    "start_hexstrike": ["hexstrike_ai", "metasploit_framework", "penetration_testing_toolkit"],
    "stop_hexstrike": ["hexstrike_ai", "metasploit_framework", "penetration_testing_toolkit"],
    "custom_exploit": ["hexstrike_ai", "exploit_framework", "metasploit_framework"],
    "chain_execution": ["hexstrike_ai", "exploit_framework", "red_team_toolkit"],
    "target_analysis": ["hexstrike_ai", "osint_reconnaissance", "network_discovery"],
    "attack_path_generation": ["hexstrike_ai", "bloodhound_ad", "penetration_testing_toolkit"],
    "payload_generation": ["hexstrike_ai", "metasploit_framework", "exploit_framework"],
    "persistence_setup": ["hexstrike_ai", "cobalt_strike", "empire_powershell"],
    "lateral_movement": ["hexstrike_ai", "cobalt_strike", "bloodhound_ad"],
    "privilege_escalation": ["hexstrike_ai", "mimikatz_enhanced", "cobalt_strike"],
    "data_exfiltration": ["hexstrike_ai", "cobalt_strike", "empire_powershell"],
    "cleanup_traces": ["hexstrike_ai", "forensics_analysis", "incident_commander"],
    "get_status": ["hexstrike_ai", "system_info", "health"],
    "list_modules": ["hexstrike_ai", "metasploit_framework", "exploit_framework"],
    "module_execution": ["hexstrike_ai", "metasploit_framework", "exploit_framework"]
  };
  
  return toolMappings[action] || ["hexstrike_ai", "penetration_testing_toolkit"];
}

function calculateConfidence(command: string, action: string): number {
  const commandLower = command.toLowerCase();
  const actionKeywords: Record<string, string[]> = {
    "autonomous_attack": ["autonomous", "ai", "intelligent", "automatic"],
    "run_reconnaissance": ["reconnaissance", "recon", "gather", "information", "discover"],
    "vulnerability_scan": ["vulnerability", "scan", "weakness", "security"],
    "exploit_generation": ["exploit", "generate", "create", "develop"],
    "attack_simulation": ["attack", "simulate", "test", "penetration"],
    "cve_analysis": ["cve", "analyze", "vulnerability", "database"],
    "threat_modeling": ["threat", "model", "assess", "evaluate"],
    "risk_assessment": ["risk", "assess", "evaluate", "measure"],
    "generate_report": ["report", "generate", "create", "summary"],
    "ai_decision_engine": ["ai", "decision", "engine", "intelligent"],
    "deploy_agent": ["deploy", "agent", "start", "launch"],
    "list_agents": ["list", "agent", "show", "display"],
    "start_hexstrike": ["start", "hexstrike", "begin", "launch"],
    "stop_hexstrike": ["stop", "hexstrike", "end", "terminate"],
    "custom_exploit": ["custom", "exploit", "specialized", "targeted"],
    "chain_execution": ["chain", "execution", "sequence", "series"],
    "target_analysis": ["target", "analyze", "examine", "study"],
    "attack_path_generation": ["attack", "path", "route", "trajectory"],
    "payload_generation": ["payload", "generate", "create", "build"],
    "persistence_setup": ["persistence", "setup", "maintain", "sustain"],
    "lateral_movement": ["lateral", "movement", "spread", "expand"],
    "privilege_escalation": ["privilege", "escalation", "elevate", "promote"],
    "data_exfiltration": ["data", "exfiltration", "extract", "steal"],
    "cleanup_traces": ["cleanup", "traces", "remove", "erase"],
    "get_status": ["status", "check", "state", "condition"],
    "list_modules": ["module", "list", "show", "display"],
    "module_execution": ["module", "execution", "run", "execute"]
  };
  
  const keywords = actionKeywords[action] || [];
  let matches = 0;
  
  for (const keyword of keywords) {
    if (commandLower.includes(keyword)) {
      matches++;
    }
  }
  
  return Math.min(matches / keywords.length, 1);
}
