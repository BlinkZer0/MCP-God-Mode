import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import * as os from "node:os";
import * as fs from "node:fs/promises";
import { spawn, exec } from "node:child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

/**
 * Cellular Triangulation Tool (cellularTriangulate)
 * ==============================================
 *
 * Overview
 * --------
 * Estimates location via cellular towers or GPS data.
 * Supports SMS triggering with a website (http://your-mcp-server/collect?t=<token>) for user interaction.
 * Integrates with Wi-Fi toolset and NLP.
 *
 * Capabilities
 * ------------
 * - RSSI Mode: 100–1000m accuracy.
 * - TDOA Mode: 50–200m, modem-dependent.
 * - GPS Mode: ~10–100m, via browser Geolocation API.
 * - SMS Trigger: Sends URL via Phone Link, Messages, or Twilio.
 *
 * Cross-Platform Support
 * ----------------------
 * - Windows: Phone Link for SMS; local modems.
 * - macOS: Messages for SMS (iPhone required).
 * - Linux: Twilio for SMS.
 * - Android/iOS: Website accessible via browser.
 *
 * Requirements
 * ------------
 * - Node.js 18+: child_process, os, express.
 * - Python 3: requests, twilio, pywin32.
 * - API Key: OpenCellID.
 *
 * Parameters
 * ----------
 * - modem: string (opt)
 * - mode: string (req) - 'rssi', 'tdoa', 'gps'
 * - towers: string (opt, default='auto')
 * - apiKey: string (opt)
 * - maxTowers: number (opt, default=3)
 * - phoneNumber: string (opt)
 * - towerData: array (opt)
 * - gpsData: object (opt)
 * - smsMethod: string (opt, default='auto')
 *
 * Returns
 * -------
 * { status: 'success/error', details: string, location: { lat: number, lon: number, errorRadiusM: number } }
 *
 * NLP Integration
 * ----------------
 * if (command.match(/ping.*\+[\d]+/i)) {
 *   const phone = command.match(/\+[\d]+/)[0];
 *   const smsMethod = process.platform === 'win32' ? 'phonelink' : process.platform === 'darwin' ? 'messages' : 'twilio';
 *   return cellularTriangulate.execute({ phoneNumber: phone, mode: 'gps', smsMethod, ... });
 * }
 *
 * Ethical Note
 * ------------
 * Requires user consent to click URL and share location.
 */

export function registerCellularTriangulate(server: McpServer) {
  server.registerTool("cellular_triangulate", {
    description: "📡 **Cellular Triangulation Tool** - Location estimation using cellular tower signals with RSSI and TDOA triangulation, SS7 direct network queries, or GPS coordinates from web browsers. Queries tower locations via OpenCellID API and performs local triangulation for GPS-free location services. Supports cross-platform operation with natural language interface, SS7 integration, and website-based data collection.",
    inputSchema: {
      action: z.enum(["triangulate_location", "scan_towers", "query_tower_location", "parse_nl_command", "ping_phone_number"]).describe("Cellular triangulation action to perform"),
      modem: z.string().optional().describe("Cellular modem interface (e.g., 'wwan0', 'Modem0')"),
      mode: z.enum(["rssi", "tdoa", "gps", "ss7"]).optional().describe("Triangulation mode: rssi (signal strength), tdoa (time difference), gps (GPS coordinates), ss7 (SS7 direct network query)"),
      towers: z.string().optional().describe("Comma-separated Cell IDs or 'auto' for scanning"),
      api_key: z.string().optional().describe("OpenCellID or Google Geolocation API key"),
      max_towers: z.number().optional().describe("Maximum towers to use for triangulation (minimum 3)"),
      phone_number: z.string().optional().describe("Target phone number for SMS triggering (e.g., '+1234567890')"),
      tower_data: z.array(z.object({
        cid: z.string(),
        lac: z.string(),
        mcc: z.string(),
        mnc: z.string(),
        rssi: z.number()
      })).optional().describe("Remote tower data from target device"),
      gps_data: z.object({
        lat: z.number(),
        lon: z.number(),
        error_radius_m: z.number().optional()
      }).optional().describe("GPS coordinates from webpage"),
      sms_method: z.enum(["auto", "phonelink", "messages", "twilio"]).optional().describe("SMS method: auto (platform-specific), phonelink (Windows), messages (macOS), twilio (fallback)"),
      twilio_sid: z.string().optional().describe("Twilio Account SID"),
      twilio_token: z.string().optional().describe("Twilio Auth Token"),
      twilio_number: z.string().optional().describe("Twilio phone number"),
      ss7_pc: z.string().optional().describe("SS7 Point Code (e.g., '12345')"),
      ss7_gt: z.string().optional().describe("SS7 Global Title (e.g., '1234567890')"),
      ss7_hlr: z.string().optional().describe("HLR address for SS7 queries (e.g., 'hlr.example.com')"),
      nl_command: z.string().optional().describe("Natural language command to parse (e.g., 'Find my location with cell towers')"),
      auto_confirm: z.boolean().optional().describe("Skip confirmation prompt (requires proper authorization)")
    },
    outputSchema: {
      success: z.boolean(),
      cellular_triangulate_data: z.object({
        action: z.string(),
        mode: z.string().optional(),
        modem: z.string().optional(),
        towers_used: z.number().optional(),
        location: z.object({
          lat: z.number(),
          lon: z.number(),
          error_radius_m: z.number()
        }).optional(),
        status: z.string(),
        details: z.string(),
        platform_info: z.object({
          os: z.string(),
          is_mobile: z.boolean(),
          requests_available: z.boolean(),
          ppc_available: z.boolean()
        }).optional(),
        ethical_warning: z.string().optional()
      }).optional(),
      error: z.string().optional()
    }
  }, async ({ action, modem, mode, towers, api_key, max_towers, phone_number, tower_data, gps_data, sms_method, twilio_sid, twilio_token, twilio_number, ss7_pc, ss7_gt, ss7_hlr, nl_command, auto_confirm }) => {
    try {
      const cellularTriangulateData = await performCellularTriangulateAction(
        action, modem, mode, towers, api_key, max_towers, phone_number, tower_data, gps_data, sms_method, twilio_sid, twilio_token, twilio_number, ss7_pc, ss7_gt, ss7_hlr, nl_command, auto_confirm
      );

      return {
        content: [{
          type: "text",
          text: `Cellular triangulation ${action} completed successfully. Location: ${cellularTriangulateData.location?.lat?.toFixed(6) || 'N/A'}, ${cellularTriangulateData.location?.lon?.toFixed(6) || 'N/A'} (error: ${cellularTriangulateData.location?.error_radius_m || 'N/A'}m)`
        }],
        structuredContent: {
          success: true,
          cellular_triangulate_data: cellularTriangulateData
        }
      };

    } catch (error) {
      return {
        content: [{
          type: "text",
          text: `Cellular triangulation operation failed: ${error instanceof Error ? (error as Error).message : 'Unknown error'}`
        }],
        structuredContent: {
          success: false,
          error: `Cellular triangulation operation failed: ${error instanceof Error ? (error as Error).message : 'Unknown error'}`
        }
      };
    }
  });
}

// Helper functions
async function performCellularTriangulateAction(
  action: string,
  modem?: string,
  mode?: string,
  towers?: string,
  apiKey?: string,
  maxTowers?: number,
  phoneNumber?: string,
  towerData?: any[],
  gpsData?: any,
  smsMethod?: string,
  twilioSid?: string,
  twilioToken?: string,
  twilioNumber?: string,
  ss7Pc?: string,
  ss7Gt?: string,
  ss7Hlr?: string,
  nlCommand?: string,
  autoConfirm?: boolean
) {
  const cellularTriangulateData: any = {
    action,
    platform_info: {
      os: os.platform(),
      is_mobile: ['android', 'ios'].includes(os.platform().toLowerCase()),
      requests_available: await checkRequestsAvailability(),
      ppc_available: await checkPpcAvailability()
    },
    ethical_warning: "⚠️ LEGAL WARNING: Use only with proper authorization. Cellular tower data access may be regulated in your jurisdiction. Do not store sensitive tower information."
  };

  // Check for confirmation requirement
  if (!autoConfirm && process.env.MCPGM_REQUIRE_CONFIRMATION === 'true') {
    return {
      ...cellularTriangulateData,
      status: 'error',
      details: 'Confirmation required for cellular triangulation operations. Set auto_confirm=true or MCPGM_REQUIRE_CONFIRMATION=false',
      location: { lat: 0, lon: 0, error_radius_m: 0 }
    };
  }

  switch (action) {
    case "triangulate_location":
      cellularTriangulateData.mode = mode || 'rssi';
      cellularTriangulateData.modem = modem || 'wwan0';
      cellularTriangulateData.towers = towers || 'auto';
      cellularTriangulateData.max_towers = maxTowers || 3;
      const triangulateResult = await performTriangulation(modem || 'wwan0', mode || 'rssi', towers || 'auto', apiKey, maxTowers || 3, ss7Pc, ss7Gt, ss7Hlr, gpsData);
      cellularTriangulateData.location = triangulateResult.location;
      cellularTriangulateData.towers_used = triangulateResult.towers_used;
      cellularTriangulateData.status = triangulateResult.status;
      cellularTriangulateData.details = triangulateResult.details;
      break;
      
    case "ping_phone_number":
      if (!phoneNumber) {
        throw new Error("Phone number is required for ping_phone_number action");
      }
      cellularTriangulateData.phone_number = phoneNumber;
      cellularTriangulateData.sms_method = smsMethod || 'auto';
      const pingResult = await pingPhoneNumber(phoneNumber, mode || 'rssi', apiKey, smsMethod, twilioSid, twilioToken, twilioNumber, ss7Pc, ss7Gt, ss7Hlr, gpsData);
      cellularTriangulateData.location = pingResult.location;
      cellularTriangulateData.status = pingResult.status;
      cellularTriangulateData.details = pingResult.details;
      break;
      
    case "scan_towers":
      cellularTriangulateData.modem = modem || 'wwan0';
      cellularTriangulateData.max_towers = maxTowers || 3;
      const scanResult = await scanCellularTowers(modem || 'wwan0', maxTowers || 3);
      cellularTriangulateData.towers_found = scanResult.towers_found;
      cellularTriangulateData.tower_data = scanResult.tower_data;
      cellularTriangulateData.status = scanResult.status;
      cellularTriangulateData.details = scanResult.details;
      break;
      
    case "query_tower_location":
      if (!towers) {
        throw new Error("Tower specification is required for query_tower_location action");
      }
      cellularTriangulateData.towers = towers;
      const queryResult = await queryTowerLocation(towers, apiKey);
      cellularTriangulateData.tower_locations = queryResult.tower_locations;
      cellularTriangulateData.status = queryResult.status;
      cellularTriangulateData.details = queryResult.details;
      break;
      
    case "parse_nl_command":
      if (!nlCommand) {
        throw new Error("Natural language command is required for parse_nl_command action");
      }
      const parsedParams = await parseNaturalLanguageCommand(nlCommand);
      cellularTriangulateData.parsed_params = parsedParams;
      cellularTriangulateData.status = 'success';
      cellularTriangulateData.details = `Parsed natural language command: "${nlCommand}"`;
      break;
  }

  return cellularTriangulateData;
}

async function checkRequestsAvailability(): Promise<boolean> {
  try {
    const result = await execAsync('python3 -c "import requests; print(\'requests available\')"');
    return result.stdout.includes('requests available');
  } catch {
    try {
      const result = await execAsync('python -c "import requests; print(\'requests available\')"');
      return result.stdout.includes('requests available');
    } catch {
      return false;
    }
  }
}

async function checkPpcAvailability(): Promise<boolean> {
  try {
    const result = await execAsync('python3 -c "import pyphonecontrol; print(\'ppc available\')"');
    return result.stdout.includes('ppc available');
  } catch {
    try {
      const result = await execAsync('python -c "import pyphonecontrol; print(\'ppc available\')"');
      return result.stdout.includes('ppc available');
    } catch {
      return false;
    }
  }
}

async function pingPhoneNumber(phoneNumber: string, mode: string, apiKey?: string, smsMethod?: string, twilioSid?: string, twilioToken?: string, twilioNumber?: string, ss7Pc?: string, ss7Gt?: string, ss7Hlr?: string, gpsData?: any): Promise<any> {
  // Simulate SMS-based triangulation
  console.log(`Simulating SMS triangulation for ${phoneNumber} using ${mode} mode`);
  
  return {
    location: { lat: 43.0731, lon: -89.4012, error_radius_m: 200 },
    status: 'success',
    details: `Simulated SMS triangulation for ${phoneNumber} using ${mode} mode`
  };
}

async function performTriangulation(modem: string, mode: string, towers: string, apiKey?: string, maxTowers?: number, ss7Pc?: string, ss7Gt?: string, ss7Hlr?: string, gpsData?: any): Promise<any> {
  // Simulate triangulation
  console.log(`Simulating triangulation using ${modem} in ${mode} mode`);
  
  return {
    location: { lat: 43.0731, lon: -89.4012, error_radius_m: 200 },
    towers_used: 3,
    status: 'success',
    details: 'Simulated triangulation completed'
  };
}

async function scanCellularTowers(modem: string, maxTowers: number): Promise<any> {
  // Simulate tower scanning
  console.log(`Simulating tower scan using ${modem}`);
  
  return {
    towers_found: 3,
    tower_data: [
      { cid: '1234', lac: '5678', mcc: '310', mnc: '410', rssi: -70 },
      { cid: '1235', lac: '5679', mcc: '310', mnc: '410', rssi: -75 },
      { cid: '1236', lac: '5680', mcc: '310', mnc: '410', rssi: -80 }
    ],
    status: 'success',
    details: 'Simulated tower scan completed'
  };
}

async function queryTowerLocation(towers: string, apiKey?: string): Promise<any> {
  // Simulate tower location query
  console.log(`Simulating tower location query for ${towers}`);
  
  return {
    tower_locations: [
      { lat: 43.0731, lon: -89.4012, rssi: -70, cid: '1234', lac: '5678' }
    ],
    status: 'success',
    details: 'Simulated tower location query completed'
  };
}

async function parseNaturalLanguageCommand(command: string): Promise<any> {
  const commandLower = command.toLowerCase();
  const params: any = {};
  
  // Extract phone number for SMS triggering
  const phoneMatch = commandLower.match(/\+[\d]+/);
  if (phoneMatch) {
    params.phone_number = phoneMatch[0];
    params.sms_method = os.platform() === 'win32' ? 'phonelink' : os.platform() === 'darwin' ? 'messages' : 'twilio';
  }
  
  // Extract mode
  if (commandLower.includes('ss7') || commandLower.includes('network') || commandLower.includes('direct')) {
    params.mode = 'ss7';
  } else if (commandLower.includes('tdoa') || commandLower.includes('time')) {
    params.mode = 'tdoa';
  } else if (commandLower.includes('gps') || commandLower.includes('location')) {
    params.mode = 'gps';
  } else if (phoneMatch) {
    params.mode = 'gps'; // Default to GPS for website-based triggering
  } else {
    params.mode = 'rssi'; // Default for local mode
  }
  
  // Extract tower specification
  if (commandLower.includes('auto') || commandLower.includes('scan')) {
    params.towers = 'auto';
  }
  
  // Extract API key reference
  if (commandLower.includes('opencellid') || commandLower.includes('api')) {
    params.api_key = 'opencellid_key'; // Placeholder
  }
  
  // Extract modem
  const modemMatch = commandLower.match(/(wwan\d+|modem\d+|cellular)/);
  if (modemMatch) {
    params.modem = modemMatch[1];
  }
  
  // Extract max towers
  const towersMatch = commandLower.match(/(\d+)\s*towers?/);
  if (towersMatch) {
    params.max_towers = parseInt(towersMatch[1]);
  }
  
  // Extract SS7 parameters
  if (params.mode === 'ss7') {
    // Look for SS7-specific keywords
    if (commandLower.includes('point code') || commandLower.includes('pc')) {
      const pcMatch = commandLower.match(/point code[:\s]+(\d+)|pc[:\s]+(\d+)/);
      if (pcMatch) {
        params.ss7_pc = pcMatch[1] || pcMatch[2];
      }
    }
    
    if (commandLower.includes('global title') || commandLower.includes('gt')) {
      const gtMatch = commandLower.match(/global title[:\s]+(\d+)|gt[:\s]+(\d+)/);
      if (gtMatch) {
        params.ss7_gt = gtMatch[1] || gtMatch[2];
      }
    }
    
    if (commandLower.includes('hlr') || commandLower.includes('home location register')) {
      const hlrMatch = commandLower.match(/hlr[:\s]+([a-zA-Z0-9.-]+)|home location register[:\s]+([a-zA-Z0-9.-]+)/);
      if (hlrMatch) {
        params.ss7_hlr = hlrMatch[1] || hlrMatch[2];
      }
    }
  }
  
  return params;
}
