/**
 * Flipper Zero Bluetooth Management Operations
 */
import { getSession, audit } from '../session.js';
/**
 * Scan for Bluetooth devices
 */
export async function scanBluetoothDevices(sessionId, duration = 10) {
    const session = getSession(sessionId);
    try {
        const response = await session.rpc.bleScan(duration);
        audit('ble_scan', {
            sessionId,
            deviceId: session.transport.id,
            duration,
            payload: { length: response.join('\n').length }
        });
        return {
            success: true,
            data: {
                duration,
                devices: response.join('\n'),
                rawResponse: response
            }
        };
    }
    catch (error) {
        audit('ble_scan_error', {
            sessionId,
            deviceId: session.transport.id,
            duration,
            error: error instanceof Error ? error.message : String(error)
        });
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}
/**
 * Pair with Bluetooth device
 */
export async function pairBluetoothDevice(sessionId, address) {
    const session = getSession(sessionId);
    try {
        const response = await session.rpc.blePair(address);
        audit('ble_pair', {
            sessionId,
            deviceId: session.transport.id,
            address
        });
        return {
            success: true,
            data: {
                address,
                rawResponse: response
            }
        };
    }
    catch (error) {
        audit('ble_pair_error', {
            sessionId,
            deviceId: session.transport.id,
            address,
            error: error instanceof Error ? error.message : String(error)
        });
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}
