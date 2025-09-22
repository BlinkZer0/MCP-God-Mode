/**
 * Flipper Zero RPC Client
 * Minimal CLI/RPC wrapper for Flipper Zero communication
 */
import { FlipperRPCError } from '../types.js';
export class FlipperRPCClient {
    transport;
    constructor(transport) {
        this.transport = transport;
    }
    /**
     * Execute a command and wait for response
     */
    async runCommand(command, timeout = 5000) {
        const output = [];
        return new Promise(async (resolve, reject) => {
            let unsubscribe = null;
            let timeoutId = null;
            try {
                // Set up response handler
                unsubscribe = this.transport.onLine((line) => {
                    output.push(line);
                    // Check for command completion
                    if (line.startsWith('OK') || line.startsWith('ERR') || line.includes('>')) {
                        if (timeoutId) {
                            clearTimeout(timeoutId);
                        }
                        if (unsubscribe) {
                            unsubscribe();
                        }
                        resolve(output);
                    }
                });
                // Set timeout
                timeoutId = setTimeout(() => {
                    if (unsubscribe) {
                        unsubscribe();
                    }
                    reject(new FlipperRPCError(`Command timeout: ${command}`));
                }, timeout);
                // Send command
                await this.transport.write(command);
            }
            catch (error) {
                if (unsubscribe) {
                    unsubscribe();
                }
                if (timeoutId) {
                    clearTimeout(timeoutId);
                }
                reject(new FlipperRPCError(`Command failed: ${command} - ${error instanceof Error ? error.message : String(error)}`));
            }
        });
    }
    /**
     * Device Information
     */
    async info() {
        return this.runCommand('device info');
    }
    /**
     * File System Operations
     */
    async fsList(path = '/') {
        return this.runCommand(`storage list ${path}`);
    }
    async fsRead(path) {
        return this.runCommand(`storage read ${path}`);
    }
    async fsWriteBegin(path, length) {
        return this.runCommand(`storage write ${path} ${length}`);
    }
    async fsWriteData(data) {
        const buffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
        return this.runCommand(`storage write_data ${buffer.toString('hex')}`);
    }
    async fsWriteEnd() {
        return this.runCommand('storage write_end');
    }
    async fsDelete(path) {
        return this.runCommand(`storage delete ${path}`);
    }
    /**
     * Infrared Operations
     */
    async irSend(file) {
        return this.runCommand(`ir tx ${file}`, 10000); // Longer timeout for IR operations
    }
    /**
     * Sub-GHz Operations
     */
    async subghzTx(file) {
        return this.runCommand(`subghz tx ${file}`, 10000); // Longer timeout for Sub-GHz operations
    }
    /**
     * NFC Operations
     */
    async nfcRead() {
        return this.runCommand('nfc read', 15000); // NFC can take longer
    }
    async nfcDump() {
        return this.runCommand('nfc dump', 15000);
    }
    /**
     * RFID Operations
     */
    async rfidRead() {
        return this.runCommand('rfid read', 10000);
    }
    async rfidDump() {
        return this.runCommand('rfid dump', 10000);
    }
    /**
     * BadUSB Operations
     */
    async badusbSend(script) {
        // For BadUSB, we need to write the script to a file first, then execute it
        const scriptName = `badusb_script_${Date.now()}.txt`;
        try {
            // Write script to file
            await this.fsWriteBegin(scriptName, script.length);
            await this.fsWriteData(script);
            await this.fsWriteEnd();
            // Execute BadUSB script
            const result = await this.runCommand(`badusb run ${scriptName}`, 30000); // BadUSB can take a long time
            // Clean up script file
            try {
                await this.fsDelete(scriptName);
            }
            catch (error) {
                // Ignore cleanup errors
            }
            return result;
        }
        catch (error) {
            // Clean up script file on error
            try {
                await this.fsDelete(scriptName);
            }
            catch (cleanupError) {
                // Ignore cleanup errors
            }
            throw error;
        }
    }
    /**
     * UART Operations
     */
    async uartSniff(duration = 10) {
        return this.runCommand(`uart sniff ${duration}`, (duration + 5) * 1000);
    }
    /**
     * GPIO Operations
     */
    async gpioSet(pin, value) {
        return this.runCommand(`gpio set ${pin} ${value ? '1' : '0'}`);
    }
    async gpioRead(pin) {
        return this.runCommand(`gpio read ${pin}`);
    }
    /**
     * Bluetooth Operations
     */
    async bleScan(duration = 10) {
        return this.runCommand(`ble scan ${duration}`, (duration + 5) * 1000);
    }
    async blePair(address) {
        return this.runCommand(`ble pair ${address}`, 15000); // Pairing can take time
    }
}
/**
 * Create a new RPC client instance
 */
export function makeRPC(transport) {
    return new FlipperRPCClient(transport);
}
/**
 * Parse Flipper response for common patterns
 */
export function parseResponse(lines) {
    const lastLine = lines[lines.length - 1] || '';
    if (lastLine.startsWith('OK')) {
        return { success: true, data: lines.slice(0, -1) };
    }
    else if (lastLine.startsWith('ERR')) {
        return { success: false, error: lastLine };
    }
    else if (lines.length > 0) {
        return { success: true, data: lines };
    }
    else {
        return { success: false, error: 'No response received' };
    }
}
/**
 * Extract device information from info response
 */
export function parseDeviceInfo(lines) {
    const info = {};
    for (const line of lines) {
        const match = line.match(/^([^:]+):\s*(.+)$/);
        if (match) {
            const [, key, value] = match;
            info[key.trim()] = value.trim();
        }
    }
    return info;
}
/**
 * Extract file list from storage list response
 */
export function parseFileList(lines) {
    const files = [];
    for (const line of lines) {
        // Parse different file list formats
        const match = line.match(/^([D-])\s+(\d+)\s+(.+)$/);
        if (match) {
            const [, type, size, name] = match;
            files.push({
                name: name.trim(),
                size: parseInt(size, 10),
                type: type === 'D' ? 'directory' : 'file'
            });
        }
    }
    return files;
}
