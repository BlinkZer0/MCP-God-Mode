/**
 * Flipper Zero Infrared Operations
 */

import { getSession, audit, assertTxAllowed, txSecondsCap } from '../session.js';

/**
 * Send IR signal from file
 */
export async function sendIrSignal(sessionId: string, file: string) {
  const session = getSession(sessionId);
  
  // Security check
  assertTxAllowed('IR');
  
  try {
    const response = await session.rpc.irSend(file);
    
    audit('ir_send', {
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
  } catch (error) {
    audit('ir_send_error', {
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
 * Send raw IR signal (if supported by firmware)
 */
export async function sendRawIrSignal(sessionId: string, protocol: string, data: string) {
  const session = getSession(sessionId);
  
  // Security check
  assertTxAllowed('IR');
  
  try {
    // Create a temporary IR file with raw data
    const tempFile = `/tmp/ir_raw_${Date.now()}.ir`;
    const irContent = `Filetype: IR signals file
Version: 1
# ${protocol} raw signal
name: ${protocol}_raw
type: raw
frequency: 38000
duty_cycle: 0.33
data: ${data}`;
    
    // Write IR file
    await session.rpc.fsWriteBegin(tempFile, irContent.length);
    await session.rpc.fsWriteData(irContent);
    await session.rpc.fsWriteEnd();
    
    // Send IR signal
    const response = await session.rpc.irSend(tempFile);
    
    // Clean up temp file
    try {
      await session.rpc.fsDelete(tempFile);
    } catch (cleanupError) {
      // Ignore cleanup errors
    }
    
    audit('ir_send_raw', {
      sessionId,
      deviceId: session.transport.id,
      protocol,
      payload: { length: data.length },
      txAllowed: true,
      maxDuration: txSecondsCap()
    });
    
    return {
      success: true,
      data: {
        protocol,
        data,
        rawResponse: response
      }
    };
  } catch (error) {
    audit('ir_send_raw_error', {
      sessionId,
      deviceId: session.transport.id,
      protocol,
      error: error instanceof Error ? error.message : String(error)
    });
    
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}
