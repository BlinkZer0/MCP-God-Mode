/**
 * Flipper Zero Device Information Operations
 */
import { getSession, audit } from '../session.js';
import { parseDeviceInfo } from '../rpc/rpcClient.js';
/**
 * Get device information
 */
export async function getDeviceInfo(sessionId) {
    const session = getSession(sessionId);
    try {
        const response = await session.rpc.info();
        const deviceInfo = parseDeviceInfo(response);
        audit('device_info', {
            sessionId,
            deviceId: session.transport.id,
            info: deviceInfo
        });
        return {
            success: true,
            data: {
                deviceId: session.transport.id,
                transportKind: session.transport.kind,
                info: deviceInfo,
                rawResponse: response
            }
        };
    }
    catch (error) {
        audit('device_info_error', {
            sessionId,
            deviceId: session.transport.id,
            error: error instanceof Error ? error.message : String(error)
        });
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}
