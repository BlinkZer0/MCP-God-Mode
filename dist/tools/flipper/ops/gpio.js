/**
 * Flipper Zero GPIO Operations
 */
import { getSession, audit } from '../session.js';
/**
 * Set GPIO pin value
 */
export async function setGpioPin(sessionId, pin, value) {
    const session = getSession(sessionId);
    try {
        const response = await session.rpc.gpioSet(pin, value);
        audit('gpio_set', {
            sessionId,
            deviceId: session.transport.id,
            pin,
            value
        });
        return {
            success: true,
            data: {
                pin,
                value,
                rawResponse: response
            }
        };
    }
    catch (error) {
        audit('gpio_set_error', {
            sessionId,
            deviceId: session.transport.id,
            pin,
            value,
            error: error instanceof Error ? error.message : String(error)
        });
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}
/**
 * Read GPIO pin value
 */
export async function readGpioPin(sessionId, pin) {
    const session = getSession(sessionId);
    try {
        const response = await session.rpc.gpioRead(pin);
        audit('gpio_read', {
            sessionId,
            deviceId: session.transport.id,
            pin
        });
        return {
            success: true,
            data: {
                pin,
                rawResponse: response,
                content: response.join('\n')
            }
        };
    }
    catch (error) {
        audit('gpio_read_error', {
            sessionId,
            deviceId: session.transport.id,
            pin,
            error: error instanceof Error ? error.message : String(error)
        });
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}
