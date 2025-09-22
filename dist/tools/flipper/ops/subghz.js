/**
 * Flipper Zero Sub-GHz Operations
 */
import { getSession, audit, assertTxAllowed, txSecondsCap } from '../session.js';
/**
 * Transmit Sub-GHz signal from file
 */
export async function transmitSubghzSignal(sessionId, file) {
    const session = getSession(sessionId);
    // Security check
    assertTxAllowed('SubGHz');
    try {
        const response = await session.rpc.subghzTx(file);
        audit('subghz_tx', {
            sessionId,
            deviceId: session.transport.id,
            file,
            txAllowed: true,
            maxDuration: txSecondsCap()
        });
        return {
            success: true,
            data: {
                file,
                rawResponse: response
            }
        };
    }
    catch (error) {
        audit('subghz_tx_error', {
            sessionId,
            deviceId: session.transport.id,
            file,
            error: error instanceof Error ? error.message : String(error)
        });
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}
/**
 * Transmit raw Sub-GHz signal
 */
export async function transmitRawSubghzSignal(sessionId, frequency, protocol, data) {
    const session = getSession(sessionId);
    // Security check
    assertTxAllowed('SubGHz');
    try {
        // Create a temporary Sub-GHz file with raw data
        const tempFile = `/tmp/subghz_raw_${Date.now()}.sub`;
        const subContent = `Filetype: Flipper SubGhz Key File
Version: 1
# ${protocol} raw signal
name: ${protocol}_raw
type: raw
frequency: ${frequency}
preset: FuriHalSubGhzPresetOok650Async
protocol: RAW
data: ${data}`;
        // Write Sub-GHz file
        await session.rpc.fsWriteBegin(tempFile, subContent.length);
        await session.rpc.fsWriteData(subContent);
        await session.rpc.fsWriteEnd();
        // Transmit signal
        const response = await session.rpc.subghzTx(tempFile);
        // Clean up temp file
        try {
            await session.rpc.fsDelete(tempFile);
        }
        catch (cleanupError) {
            // Ignore cleanup errors
        }
        audit('subghz_tx_raw', {
            sessionId,
            deviceId: session.transport.id,
            frequency,
            protocol,
            payload: { length: data.length },
            txAllowed: true,
            maxDuration: txSecondsCap()
        });
        return {
            success: true,
            data: {
                frequency,
                protocol,
                data,
                rawResponse: response
            }
        };
    }
    catch (error) {
        audit('subghz_tx_raw_error', {
            sessionId,
            deviceId: session.transport.id,
            frequency,
            protocol,
            error: error instanceof Error ? error.message : String(error)
        });
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}
