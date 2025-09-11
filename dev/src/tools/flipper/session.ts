/**
 * Flipper Zero Session Management and Security Guards
 * Handles session lifecycle, security checks, and audit logging
 */

import crypto from 'node:crypto';
import { Transport, Session, FlipperRPC, FlipperAuditLog, FlipperSecurityError, FlipperConfig } from './types.js';
import { makeRPC } from './rpc/rpcClient.js';

// Session storage
const SESSIONS = new Map<string, Session>();

/**
 * Create a new Flipper session
 */
export function newSession(transport: Transport): Session {
  const id = crypto.randomUUID();
  const rpc = makeRPC(transport);
  const session: Session = {
    id,
    transport,
    rpc,
    createdAt: Date.now()
  };
  
  SESSIONS.set(id, session);
  audit('session_created', { sessionId: id, transportKind: transport.kind });
  
  return session;
}

/**
 * Get an existing session by ID
 */
export function getSession(id: string): Session {
  const session = SESSIONS.get(id);
  if (!session) {
    throw new FlipperSecurityError(`No flipper session found: ${id}`, id);
  }
  return session;
}

/**
 * End a session and clean up resources
 */
export async function endSession(id: string): Promise<{ ok: boolean }> {
  const session = getSession(id);
  
  try {
    await session.transport.close();
  } catch (error) {
    // Ignore close errors, but log them
    console.warn(`[Flipper] Error closing transport for session ${id}:`, error);
  }
  
  SESSIONS.delete(id);
  audit('session_ended', { sessionId: id });
  
  return { ok: true };
}

/**
 * List all active sessions
 */
export function listSessions(): Array<{ id: string; createdAt: number; transportKind: string }> {
  return Array.from(SESSIONS.values()).map(session => ({
    id: session.id,
    createdAt: session.createdAt,
    transportKind: session.transport.kind
  }));
}

/**
 * Clean up expired sessions (older than 1 hour)
 */
export function cleanupExpiredSessions(): number {
  const now = Date.now();
  const maxAge = 60 * 60 * 1000; // 1 hour
  let cleaned = 0;
  
  for (const [id, session] of SESSIONS.entries()) {
    if (now - session.createdAt > maxAge) {
      endSession(id).catch(() => {}); // Clean up in background
      cleaned++;
    }
  }
  
  if (cleaned > 0) {
    audit('sessions_cleaned', { count: cleaned });
  }
  
  return cleaned;
}

/**
 * Security Guards
 */

/**
 * Assert that Flipper integration is enabled
 */
export function assertEnabled(): void {
  if (process.env.MCPGM_FLIPPER_ENABLED !== 'true') {
    throw new FlipperSecurityError('Flipper integration disabled by environment (MCPGM_FLIPPER_ENABLED!=true)');
  }
}

/**
 * Assert that USB transport is enabled
 */
export function assertUsbEnabled(): void {
  if (process.env.MCPGM_FLIPPER_USB_ENABLED !== 'true') {
    throw new FlipperSecurityError('Flipper USB transport disabled by environment (MCPGM_FLIPPER_USB_ENABLED!=true)');
  }
}

/**
 * Assert that BLE transport is enabled
 */
export function assertBleEnabled(): void {
  if (process.env.MCPGM_FLIPPER_BLE_ENABLED !== 'true') {
    throw new FlipperSecurityError('Flipper BLE transport disabled by environment (MCPGM_FLIPPER_BLE_ENABLED!=true)');
  }
}

/**
 * Assert that transmission operations are allowed
 */
export function assertTxAllowed(kind: 'IR' | 'SubGHz' | 'BadUSB'): void {
  if (process.env.MCPGM_FLIPPER_ALLOW_TX === 'false') {
    throw new FlipperSecurityError(`${kind} transmission blocked: set MCPGM_FLIPPER_ALLOW_TX=true or remove the environment variable`);
  }
}

/**
 * Get the maximum transmission duration in seconds
 */
export function txSecondsCap(): number {
  const n = Number(process.env.MCPGM_FLIPPER_TX_MAX_SECONDS ?? 10);
  return Number.isFinite(n) && n > 0 ? n : 10;
}

/**
 * Audit Logging
 */

/**
 * Log an audit event
 */
export function audit(action: string, meta: Record<string, unknown>): void {
  const logEntry: FlipperAuditLog = {
    timestamp: Date.now(),
    action,
    sessionId: meta.sessionId as string || 'unknown',
    deviceId: meta.deviceId as string || 'unknown',
    payload: meta.payload as any,
    metadata: sanitizeMetadata(meta)
  };
  
  // Use existing project logger if available, otherwise console
  if (typeof process !== 'undefined' && process.env.MCPGM_FLIPPER_LOG_STREAMS === 'true') {
    console.log(`[AUDIT flipper] ${action}`, sanitizeMetadata(meta));
  } else {
    // Minimal logging for production
    console.log(`[AUDIT flipper] ${action} session=${logEntry.sessionId} device=${logEntry.deviceId}`);
  }
}

/**
 * Sanitize metadata to remove sensitive information
 */
function sanitizeMetadata(obj: any): Record<string, unknown> {
  if (!obj || typeof obj !== 'object') return obj;
  
  const sanitized: Record<string, unknown> = {};
  
  for (const [key, value] of Object.entries(obj)) {
    if (key === 'payload' && value) {
      // Redact raw streams/large buffers
      if (typeof value === 'string') {
        sanitized[key] = `[len=${value.length}]`;
      } else if (value instanceof Uint8Array) {
        sanitized[key] = `[len=${value.length}]`;
      } else if (typeof value === 'object' && 'length' in value) {
        sanitized[key] = `[len=${(value as any).length}]`;
      } else {
        sanitized[key] = '[redacted]';
      }
    } else if (key === 'password' || key === 'token' || key === 'key') {
      sanitized[key] = '[redacted]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeMetadata(value);
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
}

/**
 * Get configuration from environment
 */
export function getConfig(): FlipperConfig {
  return {
    enabled: process.env.MCPGM_FLIPPER_ENABLED === 'true',
    usbEnabled: process.env.MCPGM_FLIPPER_USB_ENABLED === 'true',
    bleEnabled: process.env.MCPGM_FLIPPER_BLE_ENABLED === 'true',
    allowTx: process.env.MCPGM_FLIPPER_ALLOW_TX !== 'false', // Default to true unless explicitly disabled
    txMaxSeconds: txSecondsCap(),
    logStreams: process.env.MCPGM_FLIPPER_LOG_STREAMS === 'true',
    bridgeUrl: process.env.MCPGM_FLIPPER_BRIDGE_URL || undefined
  };
}

// Clean up expired sessions every 5 minutes
setInterval(cleanupExpiredSessions, 5 * 60 * 1000);
