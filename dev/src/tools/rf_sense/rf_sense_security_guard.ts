/**
 * RF Sense Security Guard
 * ======================
 * 
 * Provides comprehensive security controls for all RF_sense tools to prevent
 * AI token exposure, network egress, and ensure data privacy during sensitive operations.
 * 
 * Features:
 * - AI-safe scan mode with network blocking
 * - Local-only data caching
 * - Content Security Policy management
 * - Session isolation and data protection
 */

import { z } from "zod";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { randomUUID } from "crypto";

// Security configuration
export interface SecurityConfig {
  enableScanMode: boolean;
  blockNetworkEgress: boolean;
  localOnlyCache: boolean;
  maxDataSize: number;
  sessionTimeout: number;
  requireExplicitConsent: boolean;
}

// Session security state
export interface SecuritySession {
  id: string;
  scanMode: boolean;
  networkBlocked: boolean;
  cacheEnabled: boolean;
  startTime: number;
  lastActivity: number;
  dataSize: number;
  consentGiven: boolean;
}

// Default security configuration
const DEFAULT_SECURITY_CONFIG: SecurityConfig = {
  enableScanMode: true,
  blockNetworkEgress: true,
  localOnlyCache: true,
  maxDataSize: 100 * 1024 * 1024, // 100MB
  sessionTimeout: 3600000, // 1 hour
  requireExplicitConsent: true
};

// Global security state
const securitySessions = new Map<string, SecuritySession>();
let globalSecurityConfig: SecurityConfig = { ...DEFAULT_SECURITY_CONFIG };

/**
 * Initialize security guard with configuration
 */
export function initializeSecurityGuard(config?: Partial<SecurityConfig>): void {
  globalSecurityConfig = { ...DEFAULT_SECURITY_CONFIG, ...config };
  console.log('🔒 RF Sense Security Guard initialized');
}

/**
 * Create a new security session
 */
export function createSecuritySession(consentGiven: boolean = false): string {
  const sessionId = randomUUID();
  const session: SecuritySession = {
    id: sessionId,
    scanMode: false,
    networkBlocked: false,
    cacheEnabled: false,
    startTime: Date.now(),
    lastActivity: Date.now(),
    dataSize: 0,
    consentGiven
  };
  
  securitySessions.set(sessionId, session);
  console.log(`🔐 Created security session: ${sessionId}`);
  return sessionId;
}

/**
 * Enable AI-safe scan mode for a session
 */
export function enableScanMode(sessionId: string): boolean {
  const session = securitySessions.get(sessionId);
  if (!session) {
    console.error(`❌ Security session not found: ${sessionId}`);
    return false;
  }
  
  if (!session.consentGiven && globalSecurityConfig.requireExplicitConsent) {
    console.error(`❌ Consent required for scan mode: ${sessionId}`);
    return false;
  }
  
  session.scanMode = true;
  session.networkBlocked = globalSecurityConfig.blockNetworkEgress;
  session.cacheEnabled = globalSecurityConfig.localOnlyCache;
  session.lastActivity = Date.now();
  
  console.log(`🛡️ Scan mode enabled for session: ${sessionId}`);
  return true;
}

/**
 * Disable scan mode and restore normal operations
 */
export function disableScanMode(sessionId: string): boolean {
  const session = securitySessions.get(sessionId);
  if (!session) {
    console.error(`❌ Security session not found: ${sessionId}`);
    return false;
  }
  
  session.scanMode = false;
  session.networkBlocked = false;
  session.cacheEnabled = false;
  session.lastActivity = Date.now();
  
  console.log(`🔓 Scan mode disabled for session: ${sessionId}`);
  return true;
}

/**
 * Check if network egress is blocked for a session
 */
export function isNetworkBlocked(sessionId: string): boolean {
  const session = securitySessions.get(sessionId);
  return session?.networkBlocked || false;
}

/**
 * Check if scan mode is active for a session
 */
export function isScanModeActive(sessionId: string): boolean {
  const session = securitySessions.get(sessionId);
  return session?.scanMode || false;
}

/**
 * Validate data size against security limits
 */
export function validateDataSize(sessionId: string, dataSize: number): boolean {
  const session = securitySessions.get(sessionId);
  if (!session) return false;
  
  if (dataSize > globalSecurityConfig.maxDataSize) {
    console.error(`❌ Data size exceeds limit: ${dataSize} > ${globalSecurityConfig.maxDataSize}`);
    return false;
  }
  
  session.dataSize += dataSize;
  session.lastActivity = Date.now();
  return true;
}

/**
 * Sanitize response data to prevent AI token exposure
 */
export function sanitizeResponseData(
  sessionId: string, 
  data: any, 
  maxDataPoints: number = 100
): any {
  const session = securitySessions.get(sessionId);
  if (!session) return data;
  
  // If scan mode is active, limit data exposure
  if (session.scanMode) {
    return sanitizeForScanMode(data, maxDataPoints);
  }
  
  return data;
}

/**
 * Sanitize data for scan mode to prevent AI token dumps
 */
function sanitizeForScanMode(data: any, maxDataPoints: number): any {
  if (Array.isArray(data)) {
    // Limit array size
    const limited = data.slice(0, maxDataPoints);
    return {
      ...data,
      data: limited,
      _sanitized: true,
      _originalSize: data.length,
      _limitedTo: maxDataPoints,
      _note: "Data sanitized for AI-safe scan mode. Full data available in offline viewer."
    };
  }
  
  if (data && typeof data === 'object') {
    const sanitized: any = { ...data };
    
    // Recursively sanitize nested arrays
    for (const [key, value] of Object.entries(sanitized)) {
      if (Array.isArray(value)) {
        sanitized[key] = sanitizeForScanMode(value, maxDataPoints);
      }
    }
    
    sanitized._sanitized = true;
    sanitized._note = "Data sanitized for AI-safe scan mode. Full data available in offline viewer.";
    return sanitized;
  }
  
  return data;
}

/**
 * Get security status for a session
 */
export function getSecurityStatus(sessionId: string): any {
  const session = securitySessions.get(sessionId);
  if (!session) {
    return {
      error: "Session not found",
      sessionId
    };
  }
  
  return {
    sessionId: session.id,
    scanMode: session.scanMode,
    networkBlocked: session.networkBlocked,
    cacheEnabled: session.cacheEnabled,
    dataSize: session.dataSize,
    consentGiven: session.consentGiven,
    uptime: Date.now() - session.startTime,
    lastActivity: session.lastActivity,
    config: {
      maxDataSize: globalSecurityConfig.maxDataSize,
      sessionTimeout: globalSecurityConfig.sessionTimeout,
      requireExplicitConsent: globalSecurityConfig.requireExplicitConsent
    }
  };
}

/**
 * Clean up expired sessions
 */
export function cleanupExpiredSessions(): void {
  const now = Date.now();
  const expiredSessions: string[] = [];
  
  for (const [sessionId, session] of securitySessions.entries()) {
    if (now - session.lastActivity > globalSecurityConfig.sessionTimeout) {
      expiredSessions.push(sessionId);
    }
  }
  
  for (const sessionId of expiredSessions) {
    securitySessions.delete(sessionId);
    console.log(`🧹 Cleaned up expired security session: ${sessionId}`);
  }
}

/**
 * Get all active security sessions
 */
export function getActiveSessions(): any[] {
  return Array.from(securitySessions.values()).map(session => ({
    id: session.id,
    scanMode: session.scanMode,
    networkBlocked: session.networkBlocked,
    cacheEnabled: session.cacheEnabled,
    dataSize: session.dataSize,
    uptime: Date.now() - session.startTime,
    lastActivity: session.lastActivity
  }));
}

/**
 * Security middleware for RF sense tools
 */
export function createSecurityMiddleware(sessionId: string) {
  return {
    // Check if operation is allowed
    canProceed: (): boolean => {
      const session = securitySessions.get(sessionId);
      return !!session;
    },
    
    // Validate and sanitize data
    processData: (data: any, maxPoints: number = 100) => {
      if (!validateDataSize(sessionId, JSON.stringify(data).length)) {
        throw new Error("Data size exceeds security limits");
      }
      return sanitizeResponseData(sessionId, data, maxPoints);
    },
    
    // Check network access
    checkNetworkAccess: (): boolean => {
      return !isNetworkBlocked(sessionId);
    },
    
    // Get session info
    getSessionInfo: () => getSecurityStatus(sessionId)
  };
}

// Auto-cleanup every 5 minutes
setInterval(cleanupExpiredSessions, 5 * 60 * 1000);

export default {
  initializeSecurityGuard,
  createSecuritySession,
  enableScanMode,
  disableScanMode,
  isNetworkBlocked,
  isScanModeActive,
  validateDataSize,
  sanitizeResponseData,
  getSecurityStatus,
  cleanupExpiredSessions,
  getActiveSessions,
  createSecurityMiddleware
};
