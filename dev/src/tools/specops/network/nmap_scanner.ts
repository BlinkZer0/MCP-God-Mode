import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PLATFORM } from "../../../config/environment.js";
import { spawn, exec } from "node:child_process";
import { promisify } from "util";
import * as os from "node:os";

const execAsync = promisify(exec);

export function registerNmapScanner(server: McpServer) {
  server.registerTool("nmap_scanner", {
    description: "Advanced Nmap network discovery and security auditing tool with full cross-platform support (Windows, Linux, macOS, iOS, Android). Provides comprehensive network scanning capabilities including host discovery, port scanning, service detection, OS fingerprinting, and vulnerability detection. Supports natural language interface for intuitive network reconnaissance across all platforms.",
    inputSchema: {
      action: z.enum([
        "host_discovery", "port_scan", "service_scan", "os_detection", "vulnerability_scan",
        "stealth_scan", "udp_scan", "sctp_scan", "ip_protocol_scan", "idle_scan",
        "fragment_scan", "xmas_scan", "null_scan", "fin_scan", "ack_scan",
        "window_scan", "maimon_scan", "custom_scan", "script_scan", "timing_scan"
      ]).describe("Nmap scan action to perform"),
      target: z.string().describe("Target host or network (e.g., '192.168.1.1', '192.168.1.0/24')"),
      ports: z.string().optional().describe("Port range or specific ports (e.g., '1-1000', '22,80,443')"),
      scan_type: z.enum(["tcp_syn", "tcp_connect", "tcp_ack", "tcp_window", "tcp_maimon", "tcp_null", "tcp_fin", "tcp_xmas", "udp", "sctp", "ip_protocol"]).optional().describe("Scan type"),
      timing: z.enum(["T0", "T1", "T2", "T3", "T4", "T5"]).optional().describe("Timing template"),
      scripts: z.array(z.string()).optional().describe("NSE scripts to run"),
      output_format: z.enum(["normal", "xml", "grepable", "sCRiPt KiDDi3"]).optional().describe("Output format"),
      output_file: z.string().optional().describe("Output file path"),
      platform: z.enum(["windows", "linux", "macos", "ios", "android", "auto"]).optional().describe("Target platform"),
      architecture: z.enum(["x86", "x64", "arm", "arm64"]).optional().describe("Target architecture"),
      natural_language_command: z.string().optional().describe("Natural language command for Nmap operations (e.g., 'scan the network for open ports', 'find all hosts on the subnet', 'detect services running on the target', 'perform a stealth scan of the target')"),
      safe_mode: z.boolean().default(false).describe("Enable safe mode to prevent actual scanning (disabled by default for full functionality)"),
      verbose: z.boolean().default(false).describe("Enable verbose output")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string(),
      platform_info: z.object({
        detected_platform: z.string(),
        architecture: z.string(),
        nmap_available: z.boolean(),
        alternative_tools: z.array(z.string()).optional()
      }).optional(),
      scan_results: z.object({
        target: z.string(),
        scan_type: z.string(),
        ports_open: z.number(),
        ports_closed: z.number(),
        ports_filtered: z.number(),
        services: z.array(z.object({
          port: z.number(),
          protocol: z.string(),
          state: z.string(),
          service: z.string().optional(),
          version: z.string().optional(),
          product: z.string().optional()
        })).optional(),
        os_info: z.object({
          os_family: z.string().optional(),
          os_version: z.string().optional(),
          accuracy: z.number().optional()
        }).optional(),
        vulnerabilities: z.array(z.object({
          port: z.number(),
          service: z.string(),
          vulnerability: z.string(),
          severity: z.string(),
          description: z.string()
        })).optional()
      }).optional()
    }
  }, async ({ 
    action, target, ports, scan_type, timing, scripts, output_format, 
    output_file, platform, architecture, natural_language_command, safe_mode, verbose 
  }) => {
    try {
      // Detect platform if not specified
      const detectedPlatform = platform || detectPlatform();
      const detectedArch = architecture || detectArchitecture();
      
      // Legal compliance check
      if (safe_mode !== true) {
        return {
          success: false,
          message: "⚠️ LEGAL WARNING: Safe mode is disabled. This tool is for authorized network scanning only. Ensure you have explicit written permission before proceeding.",
          platform_info: {
            detected_platform: detectedPlatform,
            architecture: detectedArch,
            nmap_available: isNmapAvailable(detectedPlatform),
            alternative_tools: getAlternativeTools(detectedPlatform)
          }
        };
      }

      let result: any = { success: true, message: "" };

      switch (action) {
        case "host_discovery":
          result = await hostDiscovery(target, safe_mode);
          break;
        case "port_scan":
          result = await portScan(target, ports, scan_type, timing, safe_mode);
          break;
        case "service_scan":
          result = await serviceScan(target, ports, safe_mode);
          break;
        case "os_detection":
          result = await osDetection(target, safe_mode);
          break;
        case "vulnerability_scan":
          result = await vulnerabilityScan(target, ports, safe_mode);
          break;
        case "stealth_scan":
          result = await stealthScan(target, ports, safe_mode);
          break;
        case "udp_scan":
          result = await udpScan(target, ports, safe_mode);
          break;
        case "sctp_scan":
          result = await sctpScan(target, ports, safe_mode);
          break;
        case "ip_protocol_scan":
          result = await ipProtocolScan(target, safe_mode);
          break;
        case "idle_scan":
          result = await idleScan(target, ports, safe_mode);
          break;
        case "fragment_scan":
          result = await fragmentScan(target, ports, safe_mode);
          break;
        case "xmas_scan":
          result = await xmasScan(target, ports, safe_mode);
          break;
        case "null_scan":
          result = await nullScan(target, ports, safe_mode);
          break;
        case "fin_scan":
          result = await finScan(target, ports, safe_mode);
          break;
        case "ack_scan":
          result = await ackScan(target, ports, safe_mode);
          break;
        case "window_scan":
          result = await windowScan(target, ports, safe_mode);
          break;
        case "maimon_scan":
          result = await maimonScan(target, ports, safe_mode);
          break;
        case "custom_scan":
          result = await customScan(target, ports, safe_mode);
          break;
        case "script_scan":
          result = await scriptScan(target, ports, scripts, safe_mode);
          break;
        case "timing_scan":
          result = await timingScan(target, ports, timing, safe_mode);
          break;
        default:
          result = { success: false, message: "Unknown action specified" };
      }

      return result;
    } catch (error) {
      return {
        success: false,
        message: `Nmap operation failed: ${error instanceof Error ? error.message : String(error)}`
      };
    }
  });
}

// Nmap Functions
async function hostDiscovery(target: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Host discovery simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "host_discovery",
        ports_open: 0,
        ports_closed: 0,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    const { stdout } = await execAsync(`nmap -sn ${target}`);
    return {
      success: true,
      message: "Host discovery completed",
      scan_results: parseNmapOutput(stdout, "host_discovery")
    };
  } catch (error) {
    return {
      success: false,
      message: `Host discovery failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function portScan(target: string, ports: string, scanType: string, timing: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Port scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "port_scan",
        ports_open: 3,
        ports_closed: 97,
        ports_filtered: 0,
        services: [
          { port: 22, protocol: "tcp", state: "open", service: "ssh" },
          { port: 80, protocol: "tcp", state: "open", service: "http" },
          { port: 443, protocol: "tcp", state: "open", service: "https" }
        ]
      }
    };
  }

  try {
    let command = `nmap -sS ${target}`;
    if (ports) command += ` -p ${ports}`;
    if (timing) command += ` -${timing}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "Port scan completed",
      scan_results: parseNmapOutput(stdout, "port_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `Port scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function serviceScan(target: string, ports: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Service scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "service_scan",
        ports_open: 3,
        ports_closed: 97,
        ports_filtered: 0,
        services: [
          { port: 22, protocol: "tcp", state: "open", service: "ssh", version: "OpenSSH 8.2" },
          { port: 80, protocol: "tcp", state: "open", service: "http", version: "Apache 2.4.41" },
          { port: 443, protocol: "tcp", state: "open", service: "https", version: "Apache 2.4.41" }
        ]
      }
    };
  }

  try {
    let command = `nmap -sV ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "Service scan completed",
      scan_results: parseNmapOutput(stdout, "service_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `Service scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function osDetection(target: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: OS detection simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "os_detection",
        ports_open: 0,
        ports_closed: 0,
        ports_filtered: 0,
        services: [],
        os_info: {
          os_family: "Linux",
          os_version: "Ubuntu 20.04",
          accuracy: 95
        }
      }
    };
  }

  try {
    const { stdout } = await execAsync(`nmap -O ${target}`);
    return {
      success: true,
      message: "OS detection completed",
      scan_results: parseNmapOutput(stdout, "os_detection")
    };
  } catch (error) {
    return {
      success: false,
      message: `OS detection failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function vulnerabilityScan(target: string, ports: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Vulnerability scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "vulnerability_scan",
        ports_open: 3,
        ports_closed: 97,
        ports_filtered: 0,
        services: [],
        vulnerabilities: [
          { port: 22, service: "ssh", vulnerability: "CVE-2020-14145", severity: "Medium", description: "SSH vulnerability" },
          { port: 80, service: "http", vulnerability: "CVE-2021-44228", severity: "Critical", description: "Log4j vulnerability" }
        ]
      }
    };
  }

  try {
    let command = `nmap --script vuln ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "Vulnerability scan completed",
      scan_results: parseNmapOutput(stdout, "vulnerability_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `Vulnerability scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function stealthScan(target: string, ports: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Stealth scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "stealth_scan",
        ports_open: 2,
        ports_closed: 98,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    let command = `nmap -sS -f ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "Stealth scan completed",
      scan_results: parseNmapOutput(stdout, "stealth_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `Stealth scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function udpScan(target: string, ports: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: UDP scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "udp_scan",
        ports_open: 1,
        ports_closed: 99,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    let command = `nmap -sU ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "UDP scan completed",
      scan_results: parseNmapOutput(stdout, "udp_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `UDP scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function sctpScan(target: string, ports: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: SCTP scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "sctp_scan",
        ports_open: 0,
        ports_closed: 100,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    let command = `nmap -sY ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "SCTP scan completed",
      scan_results: parseNmapOutput(stdout, "sctp_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `SCTP scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function ipProtocolScan(target: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: IP protocol scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "ip_protocol_scan",
        ports_open: 3,
        ports_closed: 97,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    const { stdout } = await execAsync(`nmap -sO ${target}`);
    return {
      success: true,
      message: "IP protocol scan completed",
      scan_results: parseNmapOutput(stdout, "ip_protocol_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `IP protocol scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function idleScan(target: string, ports: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Idle scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "idle_scan",
        ports_open: 2,
        ports_closed: 98,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    let command = `nmap -sI zombie_host ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "Idle scan completed",
      scan_results: parseNmapOutput(stdout, "idle_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `Idle scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function fragmentScan(target: string, ports: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Fragment scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "fragment_scan",
        ports_open: 2,
        ports_closed: 98,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    let command = `nmap -sS -f ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "Fragment scan completed",
      scan_results: parseNmapOutput(stdout, "fragment_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `Fragment scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function xmasScan(target: string, ports: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Xmas scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "xmas_scan",
        ports_open: 2,
        ports_closed: 98,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    let command = `nmap -sX ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "Xmas scan completed",
      scan_results: parseNmapOutput(stdout, "xmas_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `Xmas scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function nullScan(target: string, ports: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Null scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "null_scan",
        ports_open: 2,
        ports_closed: 98,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    let command = `nmap -sN ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "Null scan completed",
      scan_results: parseNmapOutput(stdout, "null_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `Null scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function finScan(target: string, ports: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: FIN scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "fin_scan",
        ports_open: 2,
        ports_closed: 98,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    let command = `nmap -sF ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "FIN scan completed",
      scan_results: parseNmapOutput(stdout, "fin_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `FIN scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function ackScan(target: string, ports: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: ACK scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "ack_scan",
        ports_open: 2,
        ports_closed: 98,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    let command = `nmap -sA ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "ACK scan completed",
      scan_results: parseNmapOutput(stdout, "ack_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `ACK scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function windowScan(target: string, ports: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Window scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "window_scan",
        ports_open: 2,
        ports_closed: 98,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    let command = `nmap -sW ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "Window scan completed",
      scan_results: parseNmapOutput(stdout, "window_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `Window scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function maimonScan(target: string, ports: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Maimon scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "maimon_scan",
        ports_open: 2,
        ports_closed: 98,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    let command = `nmap -sM ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "Maimon scan completed",
      scan_results: parseNmapOutput(stdout, "maimon_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `Maimon scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function customScan(target: string, ports: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Custom scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "custom_scan",
        ports_open: 3,
        ports_closed: 97,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    let command = `nmap -sS -sV -O ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "Custom scan completed",
      scan_results: parseNmapOutput(stdout, "custom_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `Custom scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function scriptScan(target: string, ports: string, scripts: string[], safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Script scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "script_scan",
        ports_open: 3,
        ports_closed: 97,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    let command = `nmap --script ${scripts?.join(',') || 'default'} ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "Script scan completed",
      scan_results: parseNmapOutput(stdout, "script_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `Script scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function timingScan(target: string, ports: string, timing: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Timing scan simulated. No actual scan performed.",
      scan_results: {
        target,
        scan_type: "timing_scan",
        ports_open: 3,
        ports_closed: 97,
        ports_filtered: 0,
        services: []
      }
    };
  }

  try {
    let command = `nmap -sS -${timing || 'T4'} ${target}`;
    if (ports) command += ` -p ${ports}`;
    
    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: "Timing scan completed",
      scan_results: parseNmapOutput(stdout, "timing_scan")
    };
  } catch (error) {
    return {
      success: false,
      message: `Timing scan failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

// Helper function to parse Nmap output
function parseNmapOutput(output: string, scanType: string) {
  const lines = output.split('\n');
  const services: any[] = [];
  let portsOpen = 0;
  let portsClosed = 0;
  let portsFiltered = 0;
  
  for (const line of lines) {
    if (line.includes('open')) {
      portsOpen++;
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        const portParts = parts[0].split('/');
        services.push({
          port: parseInt(portParts[0]),
          protocol: portParts[1] || 'tcp',
          state: 'open',
          service: parts[2] || 'unknown'
        });
      }
    } else if (line.includes('closed')) {
      portsClosed++;
    } else if (line.includes('filtered')) {
      portsFiltered++;
    }
  }
  
  return {
    target: "parsed_target",
    scan_type: scanType,
    ports_open: portsOpen,
    ports_closed: portsClosed,
    ports_filtered: portsFiltered,
    services
  };
}

// Platform detection functions
function detectPlatform(): string {
  const platform = os.platform();
  switch (platform) {
    case "win32": return "windows";
    case "linux": return "linux";
    case "darwin": return "macos";
    default: return "unknown";
  }
}

function detectArchitecture(): string {
  const arch = os.arch();
  switch (arch) {
    case "x64": return "x64";
    case "x32": return "x86";
    case "arm": return "arm";
    case "arm64": return "arm64";
    default: return "unknown";
  }
}

function isNmapAvailable(platform: string): boolean {
  switch (platform) {
    case "windows": return true;
    case "linux": return true;
    case "macos": return true;
    case "ios": return false; // Requires jailbreak and alternative tools
    case "android": return false; // Requires root and alternative tools
    default: return false;
  }
}

function getAlternativeTools(platform: string): string[] {
  switch (platform) {
    case "windows":
      return ["nmap.exe", "nping.exe", "ndiff.exe"];
    case "linux":
      return ["nmap", "nping", "ndiff", "masscan", "zmap"];
    case "macos":
      return ["nmap", "nping", "ndiff", "masscan"];
    case "ios":
      return ["frida", "cycript", "network_scanner", "ping"];
    case "android":
      return ["frida", "network_scanner", "ping", "netstat"];
    default:
      return [];
  }
}
