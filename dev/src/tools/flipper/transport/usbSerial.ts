/**
 * Flipper Zero USB CDC Serial Transport
 * Cross-platform USB serial communication using @serialport
 */

/// <reference path="../../../types/declarations.d.ts" />

import { Transport, FlipperTransportError } from '../types.js';

// USB Serial support - will be loaded dynamically when needed

/**
 * Create a USB serial transport for Flipper Zero
 */
export function usbTransport(path: string): Transport {
  let port: any = null;
  let parser: any = null;
  const listeners = new Set<(line: string) => void>();
  let isOpen = false;

  return {
    id: `usb:${path}`,
    kind: 'usb',
    
    async open() {
      if (isOpen) {
        throw new FlipperTransportError('USB transport already open');
      }

      try {
        // Dynamic import of serialport packages
        const serialportModule = await import('serialport');
        const parserModule = await import('@serialport/parser-readline');
        const { SerialPort } = serialportModule;
        const { ReadlineParser } = parserModule;

        port = new SerialPort({
          path,
          baudRate: 115200,
          dataBits: 8,
          stopBits: 1,
          parity: 'none',
          autoOpen: false
        });

        parser = port.pipe(new ReadlineParser({ delimiter: '\n' }));
        
        // Handle incoming data
        parser.on('data', (line: string) => {
          const trimmedLine = String(line).trim();
          if (trimmedLine) {
            listeners.forEach(cb => cb(trimmedLine));
          }
        });

        // Handle errors
        port.on('error', (error: any) => {
          console.error(`[Flipper USB] Error on ${path}:`, error);
          isOpen = false;
        });

        port.on('close', () => {
          isOpen = false;
        });

        // Open the port
        await new Promise<void>((resolve, reject) => {
          if (!port) {
            reject(new FlipperTransportError('Port not initialized'));
            return;
          }

          port.open((error: any) => {
            if (error) {
              reject(new FlipperTransportError(`Failed to open USB port ${path}: ${error.message}`));
            } else {
              isOpen = true;
              resolve();
            }
          });
        });

        // Wait a moment for the connection to stabilize
        await new Promise(resolve => setTimeout(resolve, 100));

      } catch (error: any) {
        if (port) {
          port.close();
          port = null;
        }
        parser = null;
        isOpen = false;
        throw error;
      }
    },

    async close() {
      if (!isOpen) {
        return;
      }

      try {
        // Remove all listeners
        listeners.clear();
        
        if (parser) {
          parser.removeAllListeners();
          parser = null;
        }

        if (port) {
          await new Promise<void>((resolve) => {
            port!.close((error: any) => {
              if (error) {
                console.warn(`[Flipper USB] Error closing port: ${error.message}`);
              }
              port = null;
              isOpen = false;
              resolve();
            });
          });
        }
      } catch (error: any) {
        console.warn(`[Flipper USB] Error closing port ${path}:`, error);
        isOpen = false;
      }
    },

    async write(data: string | Uint8Array) {
      if (!isOpen || !port) {
        throw new FlipperTransportError('USB transport not open');
      }

      try {
        await new Promise<void>((resolve, reject) => {
          port!.write(data, (error: any) => {
            if (error) {
              reject(new FlipperTransportError(`Write failed: ${error.message}`));
            } else {
              resolve();
            }
          });
        });

        // Add newline for string data
        if (typeof data === 'string') {
          await new Promise<void>((resolve, reject) => {
            port!.write('\n', (error: any) => {
              if (error) {
                reject(new FlipperTransportError(`Write newline failed: ${error.message}`));
              } else {
                resolve();
              }
            });
          });
        }
      } catch (error: any) {
        throw new FlipperTransportError(`USB write failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    },

    onLine(callback: (line: string) => void) {
      listeners.add(callback);
      return () => listeners.delete(callback);
    }
  };
}

/**
 * List available USB serial ports
 */
export async function listUsbPorts(): Promise<Array<{ path: string; manufacturer?: string; serialNumber?: string }>> {
  try {
    const serialportModule = await import('serialport');
    const { SerialPort } = serialportModule;
    const ports = await SerialPort.list();
    
    return ports
      .filter((port: any) => port.path) // Filter out invalid ports
      .map((port: any) => ({
        path: port.path,
        manufacturer: port.manufacturer,
        serialNumber: port.serialNumber
      }));
  } catch (error: any) {
    console.warn('[Flipper USB] Failed to list ports:', error);
    return [];
  }
}

/**
 * Find Flipper Zero USB devices
 */
export async function findFlipperUsbDevices(): Promise<Array<{ path: string; manufacturer?: string; serialNumber?: string }>> {
  const ports = await listUsbPorts();
  
  // Look for Flipper Zero devices by manufacturer or path patterns
  return ports.filter(port => {
    const manufacturer = port.manufacturer?.toLowerCase() || '';
    const path = port.path.toLowerCase();
    
    return (
      manufacturer.includes('flipper') ||
      manufacturer.includes('stm32') ||
      path.includes('flipper') ||
      path.includes('usbmodem') ||
      path.includes('ttyacm') ||
      path.includes('com') // Windows COM ports
    );
  });
}

/**
 * Test USB connection to a specific path
 */
export async function testUsbConnection(path: string): Promise<boolean> {
  const transport = usbTransport(path);
  
  try {
    await transport.open();
    await transport.write('device info');
    
    // Wait for response with timeout
    let responded = false;
    const unsubscribe = transport.onLine((line) => {
      if (line.includes('OK') || line.includes('Flipper')) {
        responded = true;
      }
    });
    
    // Wait up to 2 seconds for response
    await new Promise(resolve => setTimeout(resolve, 2000));
    unsubscribe();
    
    return responded;
  } catch (error) {
    return false;
  } finally {
    try {
      await transport.close();
    } catch (error) {
      // Ignore close errors
    }
  }
}
