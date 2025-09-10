/**
 * Flipper Zero BLE GATT Transport
 * Cross-platform Bluetooth Low Energy communication using @abandonware/noble
 */

import { Transport, FlipperTransportError } from '../types.js';

// BLE service and characteristic UUIDs for Flipper Zero
const FLIPPER_SERVICE_UUID = '00003082-0000-1000-8000-00805f9b34fb';
const FLIPPER_WRITE_CHAR_UUID = '00003081-0000-1000-8000-00805f9b34fb';
const FLIPPER_NOTIFY_CHAR_UUID = '00003082-0000-1000-8000-00805f9b34fb';

interface BLEPeripheral {
  id: string;
  address: string;
  addressType: string;
  connectable: boolean;
  advertisement: {
    localName?: string;
    serviceUuids?: string[];
  };
  rssi: number;
  connect(callback: (error?: Error) => void): void;
  disconnect(callback: (error?: Error) => void): void;
  discoverServices(serviceUuids: string[], callback: (error: Error | null, services: any[]) => void): void;
}

interface BLECharacteristic {
  uuid: string;
  properties: string[];
  read(callback: (error: Error | null, data: Buffer) => void): void;
  write(data: Buffer, withoutResponse: boolean, callback: (error?: Error) => void): void;
  subscribe(callback: (error?: Error) => void): void;
  unsubscribe(callback: (error?: Error) => void): void;
  on(event: string, callback: (data: Buffer) => void): void;
  removeAllListeners(): void;
}

/**
 * Create a BLE transport for Flipper Zero
 */
export function bleTransport(peripheralId: string): Transport {
  let noble: any = null;
  let peripheral: BLEPeripheral | null = null;
  let writeCharacteristic: BLECharacteristic | null = null;
  let notifyCharacteristic: BLECharacteristic | null = null;
  const listeners = new Set<(line: string) => void>();
  let isOpen = false;
  let buffer = '';

  return {
    id: `ble:${peripheralId}`,
    kind: 'ble',
    
    async open() {
      if (isOpen) {
        throw new FlipperTransportError('BLE transport already open');
      }

      try {
        // Import noble dynamically to handle optional dependency
        const nobleModule = await import('@abandonware/noble');
        noble = nobleModule.default;

        if (!noble) {
          throw new FlipperTransportError('BLE not available - noble module not found');
        }

        // Wait for noble to be ready
        if (noble._state === 'poweredOn') {
          await connectToPeripheral();
        } else {
          await new Promise<void>((resolve, reject) => {
            const timeout = setTimeout(() => {
              reject(new FlipperTransportError('BLE initialization timeout'));
            }, 10000);

            noble.once('stateChange', (state: string) => {
              clearTimeout(timeout);
              if (state === 'poweredOn') {
                connectToPeripheral().then(resolve).catch(reject);
              } else {
                reject(new FlipperTransportError(`BLE not powered on: ${state}`));
              }
            });
          });
        }

      } catch (error) {
        isOpen = false;
        throw new FlipperTransportError(`BLE connection failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    },

    async close() {
      if (!isOpen) {
        return;
      }

      try {
        listeners.clear();
        buffer = '';

        if (notifyCharacteristic) {
          notifyCharacteristic.removeAllListeners();
          notifyCharacteristic = null;
        }

        if (writeCharacteristic) {
          writeCharacteristic.removeAllListeners();
          writeCharacteristic = null;
        }

        if (peripheral) {
          await new Promise<void>((resolve) => {
            peripheral!.disconnect(() => {
              peripheral = null;
              isOpen = false;
              resolve();
            });
          });
        }
      } catch (error) {
        console.warn(`[Flipper BLE] Error closing connection:`, error);
        isOpen = false;
      }
    },

    async write(data: string | Uint8Array) {
      if (!isOpen || !writeCharacteristic) {
        throw new FlipperTransportError('BLE transport not open');
      }

      try {
        const buffer = typeof data === 'string' ? Buffer.from(data + '\n', 'utf8') : Buffer.from(data);
        
        await new Promise<void>((resolve, reject) => {
          writeCharacteristic!.write(buffer, false, (error) => {
            if (error) {
              reject(new FlipperTransportError(`BLE write failed: ${error.message}`));
            } else {
              resolve();
            }
          });
        });
      } catch (error) {
        throw new FlipperTransportError(`BLE write failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    },

    onLine(callback: (line: string) => void) {
      listeners.add(callback);
      return () => listeners.delete(callback);
    }
  };

  async function connectToPeripheral() {
    return new Promise<void>((resolve, reject) => {
      // Find the peripheral
      const foundPeripheral = noble._peripherals.get(peripheralId);
      if (!foundPeripheral) {
        reject(new FlipperTransportError(`BLE peripheral not found: ${peripheralId}`));
        return;
      }

      peripheral = foundPeripheral;

      // Connect to peripheral
      peripheral?.connect((error?: Error) => {
        if (error) {
          reject(new FlipperTransportError(`BLE connect failed: ${error.message}`));
          return;
        }

        // Discover services
        peripheral!.discoverServices([FLIPPER_SERVICE_UUID], (error: Error | null, services: any[]) => {
          if (error) {
            reject(new FlipperTransportError(`BLE service discovery failed: ${error.message}`));
            return;
          }

          if (services.length === 0) {
            reject(new FlipperTransportError('Flipper service not found'));
            return;
          }

          const service = services[0];

          // Discover characteristics
          service.discoverCharacteristics([FLIPPER_WRITE_CHAR_UUID, FLIPPER_NOTIFY_CHAR_UUID], (error: Error | null, characteristics: BLECharacteristic[]) => {
            if (error) {
              reject(new FlipperTransportError(`BLE characteristic discovery failed: ${error.message}`));
              return;
            }

            // Find write and notify characteristics
            writeCharacteristic = characteristics.find(c => c.uuid === FLIPPER_WRITE_CHAR_UUID) || null;
            notifyCharacteristic = characteristics.find(c => c.uuid === FLIPPER_NOTIFY_CHAR_UUID) || null;

            if (!writeCharacteristic || !notifyCharacteristic) {
              reject(new FlipperTransportError('Required BLE characteristics not found'));
              return;
            }

            // Subscribe to notifications
            notifyCharacteristic.subscribe((error?: Error) => {
              if (error) {
                reject(new FlipperTransportError(`BLE subscribe failed: ${error.message}`));
                return;
              }

              // Set up data handler
              notifyCharacteristic!.on('data', (data: Buffer) => {
                const text = data.toString('utf8');
                buffer += text;

                // Process complete lines
                const lines = buffer.split('\n');
                buffer = lines.pop() || ''; // Keep incomplete line in buffer

                for (const line of lines) {
                  const trimmedLine = line.trim();
                  if (trimmedLine) {
                    listeners.forEach(cb => cb(trimmedLine));
                  }
                }
              });

              isOpen = true;
              resolve();
            });
          });
        });
      });
    });
  }
}

/**
 * Scan for Flipper Zero BLE devices
 */
export async function scanForFlipperDevices(timeout: number = 10000): Promise<Array<{ id: string; name: string; rssi: number }>> {
  try {
    const nobleModule = await import('@abandonware/noble');
    const noble = nobleModule.default;

    if (!noble) {
      console.warn('[Flipper BLE] Noble not available');
      return [];
    }

    return new Promise((resolve) => {
      const devices: Array<{ id: string; name: string; rssi: number }> = [];
      const timeoutId = setTimeout(() => {
        noble.stopScanning();
        resolve(devices);
      }, timeout);

      noble.on('discover', (peripheral: BLEPeripheral) => {
        const name = peripheral.advertisement.localName || '';
        const isFlipper = name.toLowerCase().includes('flipper') || 
                         name.toLowerCase().includes('flip');

        if (isFlipper && peripheral.connectable) {
          devices.push({
            id: peripheral.id,
            name: name || 'Flipper Zero',
            rssi: peripheral.rssi
          });
        }
      });

      if (noble._state === 'poweredOn') {
        noble.startScanning();
      } else {
        noble.once('stateChange', (state: string) => {
          if (state === 'poweredOn') {
            noble.startScanning();
          } else {
            clearTimeout(timeoutId);
            resolve(devices);
          }
        });
      }
    });
  } catch (error) {
    console.warn('[Flipper BLE] Scan failed:', error);
    return [];
  }
}

/**
 * Test BLE connection to a specific device
 */
export async function testBleConnection(peripheralId: string): Promise<boolean> {
  const transport = bleTransport(peripheralId);
  
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
    
    // Wait up to 3 seconds for response (BLE can be slower)
    await new Promise(resolve => setTimeout(resolve, 3000));
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

/**
 * Check if BLE is available on this platform
 */
export async function isBleAvailable(): Promise<boolean> {
  try {
    const nobleModule = await import('@abandonware/noble');
    return !!nobleModule.default;
  } catch (error) {
    return false;
  }
}
