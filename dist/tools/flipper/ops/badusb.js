/**
 * Flipper Zero BadUSB Operations
 */
import { getSession, audit, assertTxAllowed, txSecondsCap } from '../session.js';
/**
 * Send BadUSB script
 */
export async function sendBadusbScript(sessionId, script) {
    const session = getSession(sessionId);
    // Security check
    assertTxAllowed('BadUSB');
    try {
        const response = await session.rpc.badusbSend(script);
        audit('badusb_send', {
            sessionId,
            deviceId: session.transport.id,
            payload: { length: script.length },
            txAllowed: true,
            maxDuration: txSecondsCap()
        });
        return {
            success: true,
            data: {
                scriptLength: script.length,
                rawResponse: response
            }
        };
    }
    catch (error) {
        audit('badusb_send_error', {
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
 * Send DuckyScript (converted to BadUSB format)
 */
export async function sendDuckyScript(sessionId, duckyScript) {
    const session = getSession(sessionId);
    // Security check
    assertTxAllowed('BadUSB');
    try {
        // Convert DuckyScript to BadUSB format
        const badusbScript = convertDuckyToBadusb(duckyScript);
        const response = await session.rpc.badusbSend(badusbScript);
        audit('badusb_ducky', {
            sessionId,
            deviceId: session.transport.id,
            payload: { length: duckyScript.length },
            txAllowed: true,
            maxDuration: txSecondsCap()
        });
        return {
            success: true,
            data: {
                originalScript: duckyScript,
                convertedScript: badusbScript,
                scriptLength: duckyScript.length,
                rawResponse: response
            }
        };
    }
    catch (error) {
        audit('badusb_ducky_error', {
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
 * Convert DuckyScript to BadUSB format
 */
function convertDuckyToBadusb(duckyScript) {
    const lines = duckyScript.split('\n');
    const badusbCommands = [];
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('REM')) {
            continue; // Skip empty lines and comments
        }
        const parts = trimmed.split(' ');
        const command = parts[0].toUpperCase();
        switch (command) {
            case 'DELAY':
                const delay = parseInt(parts[1], 10);
                if (delay > 0) {
                    badusbCommands.push(`DELAY ${delay}`);
                }
                break;
            case 'STRING':
                const text = parts.slice(1).join(' ');
                badusbCommands.push(`STRING ${text}`);
                break;
            case 'ENTER':
                badusbCommands.push('ENTER');
                break;
            case 'SPACE':
                badusbCommands.push('SPACE');
                break;
            case 'TAB':
                badusbCommands.push('TAB');
                break;
            case 'ESC':
                badusbCommands.push('ESC');
                break;
            case 'UP':
                badusbCommands.push('UP');
                break;
            case 'DOWN':
                badusbCommands.push('DOWN');
                break;
            case 'LEFT':
                badusbCommands.push('LEFT');
                break;
            case 'RIGHT':
                badusbCommands.push('RIGHT');
                break;
            case 'CTRL':
                if (parts[1]) {
                    badusbCommands.push(`CTRL-${parts[1].toUpperCase()}`);
                }
                break;
            case 'ALT':
                if (parts[1]) {
                    badusbCommands.push(`ALT-${parts[1].toUpperCase()}`);
                }
                break;
            case 'SHIFT':
                if (parts[1]) {
                    badusbCommands.push(`SHIFT-${parts[1].toUpperCase()}`);
                }
                break;
            case 'GUI':
                if (parts[1]) {
                    badusbCommands.push(`GUI-${parts[1].toUpperCase()}`);
                }
                break;
            default:
                // Try to handle as a single key
                if (trimmed.length === 1) {
                    badusbCommands.push(trimmed.toUpperCase());
                }
                break;
        }
    }
    return badusbCommands.join('\n');
}
