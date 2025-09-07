/**
 * Consolidated Flipper Zero MCP Tool
 * Single tool that consolidates all 24 individual Flipper Zero operations
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { 
  assertEnabled, 
  assertUsbEnabled, 
  assertBleEnabled,
  newSession, 
  endSession, 
  listSessions,
  getConfig 
} from './session.js';
import { usbTransport, findFlipperUsbDevices, testUsbConnection } from './transport/usbSerial.js';
import { bleTransport, scanForFlipperDevices, testBleConnection, isBleAvailable } from './transport/ble.js';
import { bridgeTransport } from './transport/bridge.js';

// Import operations
import { getDeviceInfo } from './ops/info.js';
import { listFiles, readFile, writeFile, deleteFile } from './ops/fs.js';
import { sendIrSignal, sendRawIrSignal } from './ops/ir.js';
import { transmitSubghzSignal, transmitRawSubghzSignal } from './ops/subghz.js';
import { readNfcCard, dumpNfcCard } from './ops/nfc.js';
import { readRfidCard, dumpRfidCard } from './ops/rfid.js';
import { sendBadusbScript, sendDuckyScript } from './ops/badusb.js';
import { sniffUart } from './ops/uart.js';
import { setGpioPin, readGpioPin } from './ops/gpio.js';
import { scanBluetoothDevices, pairBluetoothDevice } from './ops/bleMgmt.js';

/**
 * Register the consolidated Flipper Zero tool
 */
export function registerFlipperZeroTool(server: McpServer): void {
  const config = getConfig();
  
  if (!config.enabled) {
    console.log('[Flipper] Integration disabled by environment');
    return;
  }

  console.log('[Flipper] Registering consolidated Flipper Zero tool...');

  server.registerTool("flipper_zero", {
    description: "🔌 **Flipper Zero Comprehensive Tool** - Complete Flipper Zero device management and operations including device discovery, connection management, file operations, IR/Sub-GHz transmission, NFC/RFID operations, BadUSB scripting, UART sniffing, GPIO control, and Bluetooth management. Consolidates 24 individual Flipper tools into a single action-based interface.",
    inputSchema: {
      action: z.enum([
        // Device Management
        "list_devices", "connect", "disconnect", "get_info", "list_sessions",
        // File System Operations
        "fs_list", "fs_read", "fs_write", "fs_delete",
        // Infrared Operations
        "ir_send", "ir_send_raw",
        // Sub-GHz Operations
        "subghz_tx", "subghz_tx_raw",
        // NFC Operations
        "nfc_read", "nfc_dump",
        // RFID Operations
        "rfid_read", "rfid_dump",
        // BadUSB Operations
        "badusb_send", "badusb_ducky",
        // UART Operations
        "uart_sniff",
        // GPIO Operations
        "gpio_set", "gpio_read",
        // Bluetooth Operations
        "ble_scan", "ble_pair"
      ]).describe("Flipper Zero operation to perform"),
      
      // Device Management Parameters
      device_id: z.string().optional().describe("Device ID from list_devices (required for connect)"),
      session_id: z.string().optional().describe("Session ID from connect (required for most operations)"),
      scan_ble: z.boolean().optional().default(true).describe("Whether to scan for BLE devices (for list_devices)"),
      scan_usb: z.boolean().optional().default(true).describe("Whether to scan for USB devices (for list_devices)"),
      include_bridge: z.boolean().optional().default(true).describe("Whether to include bridge endpoint (for list_devices)"),
      
      // File System Parameters
      path: z.string().optional().describe("File or directory path (for fs operations)"),
      content: z.string().optional().describe("File content to write (for fs_write)"),
      
      // IR Parameters
      file: z.string().optional().describe("IR file path on Flipper Zero (for ir_send)"),
      protocol: z.string().optional().describe("IR protocol name (for ir_send_raw)"),
      data: z.string().optional().describe("Raw IR data (for ir_send_raw)"),
      
      // Sub-GHz Parameters
      frequency: z.number().optional().describe("Frequency in Hz (for subghz_tx_raw)"),
      
      // NFC/RFID Parameters
      filename: z.string().optional().describe("Optional filename to save dump (for nfc_dump, rfid_dump)"),
      
      // BadUSB Parameters
      script: z.string().optional().describe("BadUSB or DuckyScript content (for badusb operations)"),
      
      // UART Parameters
      duration: z.number().optional().default(10).describe("Sniff duration in seconds (for uart_sniff)"),
      
      // GPIO Parameters
      pin: z.number().optional().describe("GPIO pin number (for gpio operations)"),
      value: z.boolean().optional().describe("Pin value true=high, false=low (for gpio_set)"),
      
      // Bluetooth Parameters
      address: z.string().optional().describe("Bluetooth device address (for ble_pair)")
    }
  }, async (args) => {
    assertEnabled();
    
    try {
      switch (args.action) {
        // Device Management
        case "list_devices": {
          const devices: any[] = [];
          
          // Scan USB devices
          if (args.scan_usb && config.usbEnabled) {
            try {
              const usbDevices = await findFlipperUsbDevices();
              for (const device of usbDevices) {
                devices.push({
                  id: `usb:${device.path}`,
                  name: 'Flipper Zero (USB)',
                  transport: 'usb',
                  path: device.path,
                  manufacturer: device.manufacturer,
                  serialNumber: device.serialNumber,
                  connected: false
                });
              }
            } catch (error) {
              console.warn('[Flipper] USB scan failed:', error);
            }
          }
          
          // Scan BLE devices
          if (args.scan_ble && config.bleEnabled) {
            try {
              const bleAvailable = await isBleAvailable();
              if (bleAvailable) {
                const bleDevices = await scanForFlipperDevices(5000);
                for (const device of bleDevices) {
                  devices.push({
                    id: `ble:${device.id}`,
                    name: device.name,
                    transport: 'ble',
                    address: device.id,
                    rssi: device.rssi,
                    connected: false
                  });
                }
              }
            } catch (error) {
              console.warn('[Flipper] BLE scan failed:', error);
            }
          }
          
          // Include bridge endpoint
          if (args.include_bridge && config.bridgeUrl) {
            try {
              const wsMod = await import('ws');
              const WS = (wsMod as any).WebSocket || (wsMod as any).default || (wsMod as any);
              const bridgeDevices: any[] = await new Promise((resolve) => {
                const list: any[] = [];
                const ws = new WS(config.bridgeUrl!);
                const timer = setTimeout(() => { try { ws.close(); } catch {}; resolve(list); }, 3500);
                ws.onopen = () => {
                  try { ws.send(JSON.stringify({ type: 'list_devices' })); } catch {}
                };
                ws.onmessage = (evt: any) => {
                  try {
                    const msg = JSON.parse(String(evt.data));
                    if (msg.type === 'devices') {
                      const usb = Array.isArray(msg.usb) ? msg.usb : [];
                      const ble = Array.isArray(msg.ble) ? msg.ble : [];
                      for (const d of usb) {
                        list.push({
                          id: `bridge:${config.bridgeUrl}|usb:${d.path}`,
                          name: `Bridge USB ${d.path}`,
                          transport: 'bridge',
                          connected: false,
                          bridgeUrl: config.bridgeUrl
                        });
                      }
                      for (const d of ble) {
                        list.push({
                          id: `bridge:${config.bridgeUrl}|ble:${d.id}`,
                          name: `Bridge BLE ${d.name || d.id}`,
                          transport: 'bridge',
                          connected: false,
                          bridgeUrl: config.bridgeUrl
                        });
                      }
                      clearTimeout(timer);
                      try { ws.close(); } catch {}
                      resolve(list);
                    }
                  } catch {}
                };
                ws.onerror = () => { /* ignore and resolve with empty list on timeout */ };
              });
              devices.push(...bridgeDevices);
            } catch (err) {
              devices.push({
                id: `bridge:${config.bridgeUrl}`,
                name: 'Flipper Bridge (WebSocket)',
                transport: 'bridge',
                connected: false,
                bridgeUrl: config.bridgeUrl
              });
            }
          }
          
          return {
            success: true,
            data: {
              devices,
              config: {
                enabled: config.enabled,
                usbEnabled: config.usbEnabled,
                bleEnabled: config.bleEnabled,
                allowTx: config.allowTx,
                bridgeUrl: config.bridgeUrl
              }
            }
          };
        }
        
        case "connect": {
          if (!args.device_id) {
            throw new Error("device_id is required for connect action");
          }
          
          const deviceId = args.device_id;
          const [transportKind, path] = deviceId.split(':');
          
          if (transportKind === 'usb') {
            assertUsbEnabled();
            const transport = usbTransport(path);
            await transport.open();
            const session = newSession(transport);
            
            return {
              success: true,
              data: {
                sessionId: session.id,
                deviceId,
                transportKind: 'usb'
              }
            };
          } else if (transportKind === 'ble') {
            assertBleEnabled();
            const transport = bleTransport(path);
            await transport.open();
            const session = newSession(transport);
            
            return {
              success: true,
              data: {
                sessionId: session.id,
                deviceId,
                transportKind: 'ble'
              }
            };
          } else if (transportKind === 'bridge') {
            const compound = path || getConfig().bridgeUrl || '';
            const [url, target] = compound.split('|');
            if (!url) {
              throw new Error('Bridge URL not configured (set MCPGM_FLIPPER_BRIDGE_URL or pass a full bridge:<ws_url>)');
            }
            const transport = bridgeTransport(url, 'flipper', target);
            await transport.open();
            const session = newSession(transport);
            return {
              success: true,
              data: {
                sessionId: session.id,
                deviceId: `bridge:${compound}`,
                transportKind: 'bridge'
              }
            };
          } else {
            throw new Error(`Unknown transport kind: ${transportKind}`);
          }
        }
        
        case "disconnect": {
          if (!args.session_id) {
            throw new Error("session_id is required for disconnect action");
          }
          const result = await endSession(args.session_id);
          return {
            success: true,
            data: result
          };
        }
        
        case "get_info": {
          if (!args.session_id) {
            throw new Error("session_id is required for get_info action");
          }
          return await getDeviceInfo(args.session_id);
        }
        
        case "list_sessions": {
          const sessions = listSessions();
          return {
            success: true,
            data: {
              sessions,
              count: sessions.length
            }
          };
        }
        
        // File System Operations
        case "fs_list": {
          if (!args.session_id) {
            throw new Error("session_id is required for fs_list action");
          }
          return await listFiles(args.session_id, args.path || '/');
        }
        
        case "fs_read": {
          if (!args.session_id || !args.path) {
            throw new Error("session_id and path are required for fs_read action");
          }
          return await readFile(args.session_id, args.path);
        }
        
        case "fs_write": {
          if (!args.session_id || !args.path || !args.content) {
            throw new Error("session_id, path, and content are required for fs_write action");
          }
          return await writeFile(args.session_id, args.path, args.content);
        }
        
        case "fs_delete": {
          if (!args.session_id || !args.path) {
            throw new Error("session_id and path are required for fs_delete action");
          }
          return await deleteFile(args.session_id, args.path);
        }
        
        // Infrared Operations
        case "ir_send": {
          if (!args.session_id || !args.file) {
            throw new Error("session_id and file are required for ir_send action");
          }
          return await sendIrSignal(args.session_id, args.file);
        }
        
        case "ir_send_raw": {
          if (!args.session_id || !args.protocol || !args.data) {
            throw new Error("session_id, protocol, and data are required for ir_send_raw action");
          }
          return await sendRawIrSignal(args.session_id, args.protocol, args.data);
        }
        
        // Sub-GHz Operations
        case "subghz_tx": {
          if (!args.session_id || !args.file) {
            throw new Error("session_id and file are required for subghz_tx action");
          }
          return await transmitSubghzSignal(args.session_id, args.file);
        }
        
        case "subghz_tx_raw": {
          if (!args.session_id || !args.frequency || !args.protocol || !args.data) {
            throw new Error("session_id, frequency, protocol, and data are required for subghz_tx_raw action");
          }
          return await transmitRawSubghzSignal(args.session_id, args.frequency, args.protocol, args.data);
        }
        
        // NFC Operations
        case "nfc_read": {
          if (!args.session_id) {
            throw new Error("session_id is required for nfc_read action");
          }
          return await readNfcCard(args.session_id);
        }
        
        case "nfc_dump": {
          if (!args.session_id) {
            throw new Error("session_id is required for nfc_dump action");
          }
          return await dumpNfcCard(args.session_id, args.filename);
        }
        
        // RFID Operations
        case "rfid_read": {
          if (!args.session_id) {
            throw new Error("session_id is required for rfid_read action");
          }
          return await readRfidCard(args.session_id);
        }
        
        case "rfid_dump": {
          if (!args.session_id) {
            throw new Error("session_id is required for rfid_dump action");
          }
          return await dumpRfidCard(args.session_id, args.filename);
        }
        
        // BadUSB Operations
        case "badusb_send": {
          if (!args.session_id || !args.script) {
            throw new Error("session_id and script are required for badusb_send action");
          }
          return await sendBadusbScript(args.session_id, args.script);
        }
        
        case "badusb_ducky": {
          if (!args.session_id || !args.script) {
            throw new Error("session_id and script are required for badusb_ducky action");
          }
          return await sendDuckyScript(args.session_id, args.script);
        }
        
        // UART Operations
        case "uart_sniff": {
          if (!args.session_id) {
            throw new Error("session_id is required for uart_sniff action");
          }
          return await sniffUart(args.session_id, args.duration || 10);
        }
        
        // GPIO Operations
        case "gpio_set": {
          if (!args.session_id || args.pin === undefined || args.value === undefined) {
            throw new Error("session_id, pin, and value are required for gpio_set action");
          }
          return await setGpioPin(args.session_id, args.pin, args.value);
        }
        
        case "gpio_read": {
          if (!args.session_id || args.pin === undefined) {
            throw new Error("session_id and pin are required for gpio_read action");
          }
          return await readGpioPin(args.session_id, args.pin);
        }
        
        // Bluetooth Operations
        case "ble_scan": {
          if (!args.session_id) {
            throw new Error("session_id is required for ble_scan action");
          }
          return await scanBluetoothDevices(args.session_id, args.duration || 10);
        }
        
        case "ble_pair": {
          if (!args.session_id || !args.address) {
            throw new Error("session_id and address are required for ble_pair action");
          }
          return await pairBluetoothDevice(args.session_id, args.address);
        }
        
        default:
          throw new Error(`Unknown action: ${args.action}`);
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  });

  console.log('[Flipper] Registered consolidated Flipper Zero tool');
}

/**
 * Get the consolidated tool name for parity verification
 */
export function getFlipperZeroToolName(): string {
  return 'flipper_zero';
}
