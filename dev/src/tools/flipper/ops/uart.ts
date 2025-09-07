/**
 * Flipper Zero UART Operations
 */

import { getSession, audit } from '../session.js';

/**
 * Sniff UART communication
 */
export async function sniffUart(sessionId: string, duration: number = 10) {
  const session = getSession(sessionId);
  
  try {
    const response = await session.rpc.uartSniff(duration);
    
    audit('uart_sniff', {
      sessionId,
      deviceId: session.transport.id,
      duration,
      payload: { length: response.join('\n').length }
    });
    
    return {
      success: true,
      data: {
        duration,
        capturedData: response.join('\n'),
        rawResponse: response
      }
    };
  } catch (error) {
    audit('uart_sniff_error', {
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
