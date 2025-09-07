/**
 * Flipper Zero NFC Operations
 */

import { getSession, audit } from '../session.js';

/**
 * Read NFC card
 */
export async function readNfcCard(sessionId: string) {
  const session = getSession(sessionId);
  
  try {
    const response = await session.rpc.nfcRead();
    
    audit('nfc_read', {
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
  } catch (error) {
    audit('nfc_read_error', {
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
 * Dump NFC card to file
 */
export async function dumpNfcCard(sessionId: string, filename?: string) {
  const session = getSession(sessionId);
  
  try {
    const response = await session.rpc.nfcDump();
    
    // If filename provided, save the dump
    if (filename) {
      const dumpContent = response.join('\n');
      await session.rpc.fsWriteBegin(filename, dumpContent.length);
      await session.rpc.fsWriteData(dumpContent);
      await session.rpc.fsWriteEnd();
    }
    
    audit('nfc_dump', {
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
  } catch (error) {
    audit('nfc_dump_error', {
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
