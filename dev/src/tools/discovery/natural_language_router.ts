import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { routeNaturalLanguageQuery } from "../../utils/natural-language-router.js";

export function registerNaturalLanguageRouter(server: McpServer) {
  server.registerTool("natural_language_router", {
    description: "Route natural language requests to appropriate tools with intelligent matching",
    inputSchema: {
      query: z.string().describe("Natural language query to route to appropriate tools"),
      context: z.string().optional().describe("Additional context about the request"),
      user_intent: z.string().optional().describe("User's intended goal or objective")
    },
    outputSchema: {
      suggested_tools: z.array(z.string()),
      confidence: z.number(),
      reasoning: z.string(),
      alternative_tools: z.array(z.string()).optional(),
      recommended_actions: z.array(z.string()).optional(),
      query_analysis: z.object({
        detected_intent: z.string(),
        key_terms: z.array(z.string()),
        suggested_category: z.string().optional()
      })
    }
  }, async ({ query, context, user_intent }) => {
    // Route the natural language query
    const routing = routeNaturalLanguageQuery(query);
    
    // Analyze the query for additional insights
    const queryLower = query.toLowerCase();
    const keyTerms = queryLower.split(/\s+/).filter(term => term.length > 3);
    
    // Detect intent based on common patterns
    let detectedIntent = "general";
    if (queryLower.includes("hack") || queryLower.includes("break") || queryLower.includes("penetrate")) {
      detectedIntent = "security_testing";
    } else if (queryLower.includes("analyze") || queryLower.includes("examine") || queryLower.includes("investigate")) {
      detectedIntent = "analysis";
    } else if (queryLower.includes("monitor") || queryLower.includes("watch") || queryLower.includes("track")) {
      detectedIntent = "monitoring";
    } else if (queryLower.includes("manage") || queryLower.includes("control") || queryLower.includes("administer")) {
      detectedIntent = "management";
    } else if (queryLower.includes("test") || queryLower.includes("check") || queryLower.includes("verify")) {
      detectedIntent = "testing";
    }
    
    // Suggest category based on intent and terms
    let suggestedCategory = "general";
    if (detectedIntent === "security_testing" || keyTerms.some(term => 
      ["security", "vulnerability", "penetration", "hack", "exploit"].includes(term))) {
      suggestedCategory = "security";
    } else if (keyTerms.some(term => 
      ["network", "wifi", "bluetooth", "radio", "packet"].includes(term))) {
      suggestedCategory = "network";
    } else if (keyTerms.some(term => 
      ["file", "directory", "folder", "storage"].includes(term))) {
      suggestedCategory = "file_system";
    } else if (keyTerms.some(term => 
      ["mobile", "android", "ios", "device"].includes(term))) {
      suggestedCategory = "mobile";
    } else if (keyTerms.some(term => 
      ["web", "browser", "scrape", "automation"].includes(term))) {
      suggestedCategory = "web";
    } else if (keyTerms.some(term => 
      ["video", "audio", "image", "media", "edit"].includes(term))) {
      suggestedCategory = "media";
    }
    
    // Generate recommended actions based on the top suggested tool
    let recommendedActions: string[] = [];
    if (routing.suggestedTools.length > 0) {
      const topTool = routing.suggestedTools[0];
      switch (topTool) {
        case "wifi_security_toolkit":
          recommendedActions = [
            "Scan for nearby Wi-Fi networks",
            "Test network security vulnerabilities",
            "Capture WPA handshakes for analysis",
            "Perform penetration testing"
          ];
          break;
        case "bluetooth_security_toolkit":
          recommendedActions = [
            "Scan for Bluetooth devices",
            "Test Bluetooth security",
            "Analyze device vulnerabilities",
            "Perform pairing security tests"
          ];
          break;
        case "sdr_security_toolkit":
          recommendedActions = [
            "Detect SDR hardware",
            "Scan radio frequencies",
            "Analyze radio signals",
            "Decode radio protocols"
          ];
          break;
        case "wifi_disrupt":
          recommendedActions = [
            "Perform deauthentication attacks",
            "Flood malformed packets",
            "Occupy airtime to disrupt networks",
            "Test Wi-Fi interference capabilities"
          ];
          break;
        case "cellular_triangulate":
          recommendedActions = [
            "Triangulate location using cell towers",
            "Scan for nearby cellular towers",
            "Estimate location with RSSI signals",
            "Query tower locations via OpenCellID API"
          ];
          break;
        case "network_diagnostics":
          recommendedActions = [
            "Test network connectivity",
            "Run ping tests",
            "Perform traceroute analysis",
            "Check DNS resolution"
          ];
          break;
        case "system_info":
          recommendedActions = [
            "Get system information",
            "Check hardware details",
            "View system specifications",
            "Display system configuration"
          ];
          break;
        case "metasploit_framework":
          recommendedActions = [
            "List available exploits",
            "Generate payloads with msfvenom",
            "Run post-exploitation modules",
            "Execute exploit development"
          ];
          break;
        case "cobalt_strike":
          recommendedActions = [
            "Connect to team server",
            "Deploy beacons for lateral movement",
            "Establish persistence mechanisms",
            "Perform advanced threat simulation"
          ];
          break;
        case "empire_powershell":
          recommendedActions = [
            "Start Empire listener",
            "Generate PowerShell stagers",
            "Execute post-exploitation modules",
            "Manage PowerShell agents"
          ];
          break;
        case "bloodhound_ad":
          recommendedActions = [
            "Collect Active Directory data",
            "Analyze attack paths",
            "Visualize AD relationships",
            "Find privilege escalation opportunities"
          ];
          break;
        case "mimikatz_credentials":
          recommendedActions = [
            "Extract credentials from LSASS",
            "Dump Kerberos tickets",
            "Perform pass-the-hash attacks",
            "Create golden tickets"
          ];
          break;
        case "mimikatz_enhanced":
          recommendedActions = [
            "Extract cross-platform credentials",
            "Access iOS keychain data",
            "Harvest Android keystore",
            "Perform advanced evasion techniques"
          ];
          break;
        case "nmap_scanner":
          recommendedActions = [
            "Perform network host discovery",
            "Scan for open ports",
            "Detect running services",
            "Fingerprint operating systems"
          ];
          break;
        case "frida_toolkit":
          recommendedActions = [
            "Hook functions in mobile apps",
            "Intercept API calls",
            "Patch memory at runtime",
            "Extract secrets from applications"
          ];
          break;
        case "ghidra_reverse_engineering":
          recommendedActions = [
            "Analyze binary files",
            "Disassemble executable code",
            "Decompile functions",
            "Detect vulnerabilities in binaries"
          ];
          break;
        case "pacu_aws_exploitation":
          recommendedActions = [
            "Enumerate AWS services",
            "Test IAM permissions",
            "Escalate privileges in AWS",
            "Exfiltrate data from S3 buckets"
          ];
          break;
        default:
          recommendedActions = [
            `Use ${topTool.replace(/_/g, ' ')} functionality`,
            "Check tool documentation for specific actions",
            "Explore available parameters and options"
          ];
      }
    }
    
    return {
      content: [{
        type: "text",
        text: `Natural language routing analysis for: "${query}"\n\n` +
              `Detected Intent: ${detectedIntent}\n` +
              `Suggested Category: ${suggestedCategory}\n` +
              `Confidence: ${(routing.confidence * 100).toFixed(1)}%\n\n` +
              `Top Suggested Tools: ${routing.suggestedTools.slice(0, 3).join(', ')}\n\n` +
              `Reasoning: ${routing.reasoning}`
      }],
      structuredContent: {
        suggested_tools: routing.suggestedTools,
        confidence: routing.confidence,
        reasoning: routing.reasoning,
        alternative_tools: routing.suggestedTools.slice(3),
        recommended_actions: recommendedActions,
        query_analysis: {
          detected_intent: detectedIntent,
          key_terms: keyTerms,
          suggested_category: suggestedCategory
        }
      }
    };
  });
}
