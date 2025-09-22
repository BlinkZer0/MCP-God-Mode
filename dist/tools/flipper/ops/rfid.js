/**
 * Flipper Zero RFID Operations
 */
import { getSession, audit } from '../session.js';
/**
 * Read RFID card
 */
export async function readRfidCard(sessionId) {
    const session = getSession(sessionId);
    try {
        const response = await session.rpc.rfidRead();
        audit('rfid_read', {
            sessionId,
            deviceId: session.transport.id,
            payload: { length: response.join('\n').length }
        });
        return {
            success: true,
            data: {
                rawResponse: response,
                content: response.join('\n')
            }
        };
    }
    catch (error) {
        audit('rfid_read_error', {
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
/**
 * Dump RFID card to file
 */
export async function dumpRfidCard(sessionId, filename) {
    const session = getSession(sessionId);
    try {
        const response = await session.rpc.rfidDump();
        // If filename provided, save the dump
        if (filename) {
            const dumpContent = response.join('\n');
            await session.rpc.fsWriteBegin(filename, dumpContent.length);
            await session.rpc.fsWriteData(dumpContent);
            await session.rpc.fsWriteEnd();
        }
        audit('rfid_dump', {
            sessionId,
            deviceId: session.transport.id,
            filename,
            payload: { length: response.join('\n').length }
        });
        return {
            success: true,
            data: {
                filename,
                rawResponse: response,
                content: response.join('\n')
            }
        };
    }
    catch (error) {
        audit('rfid_dump_error', {
            sessionId,
            deviceId: session.transport.id,
            filename,
            error: error instanceof Error ? error.message : String(error)
        });
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}
