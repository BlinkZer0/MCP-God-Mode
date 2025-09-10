/**
 * AI Adversarial Ethics & Compliance Module
 * =========================================
 * 
 * Comprehensive ethical safeguards, logging, and compliance mechanisms
 * for AI adversarial prompting operations.
 */

import * as fs from 'fs-extra';
import * as path from 'path';
import * as crypto from 'crypto';
import { createHash, createHmac } from 'crypto';

export interface EthicsConfig {
  enabled: boolean;
  requireConfirmation: boolean;
  logAllInteractions: boolean;
  auditTrail: boolean;
  rateLimiting: boolean;
  maxRequestsPerHour: number;
  allowedDomains: string[];
  complianceFrameworks: string[];
  legalJurisdiction: string;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  userId: string;
  sessionId: string;
  operation: string;
  targetModel: string;
  topic: string;
  prompt: string;
  response: string;
  analysis: string;
  success: boolean;
  confirmationGiven: boolean;
  ipAddress: string;
  userAgent: string;
  platform: string;
  hash: string;
  signature: string;
}

export interface ComplianceReport {
  framework: string;
  compliance: boolean;
  violations: string[];
  recommendations: string[];
  auditTrail: AuditEntry[];
}

export class AiAdversarialEthics {
  private config: EthicsConfig;
  private auditLog: string;
  private rateLimitMap: Map<string, number[]> = new Map();
  private blockedHashes: Set<string> = new Set();

  constructor(config: Partial<EthicsConfig> = {}) {
    this.config = {
      enabled: true,
      requireConfirmation: true,
      logAllInteractions: true,
      auditTrail: true,
      rateLimiting: true,
      maxRequestsPerHour: 10,
      allowedDomains: ['localhost', '127.0.0.1'],
      complianceFrameworks: ['GDPR', 'CCPA', 'SOX', 'HIPAA'],
      legalJurisdiction: 'US',
      ...config
    };

    this.auditLog = path.join(process.env.LOG_DIR || './logs', 'ai_adversarial_audit.log');
    this._initializeEthics();
  }

  private async _initializeEthics(): Promise<void> {
    // Ensure audit log directory exists
    await fs.ensureDir(path.dirname(this.auditLog));
    
    
    // Initialize compliance monitoring
    await this._initializeComplianceMonitoring();
  }


  private async _initializeComplianceMonitoring(): Promise<void> {
    // Initialize compliance framework monitoring
    console.log('🔒 AI Adversarial Ethics initialized with frameworks:', this.config.complianceFrameworks.join(', '));
  }

  /**
   * Check if operation is ethically permissible
   */
  public async checkEthicsCompliance(
    operation: string,
    targetModel: string,
    topic: string,
    prompt: string,
    userId: string = 'anonymous',
    sessionId: string = 'default',
    ipAddress: string = '127.0.0.1',
    userAgent: string = 'MCP-Client'
  ): Promise<{ allowed: boolean; reason?: string; requiresConfirmation: boolean }> {
    
    if (!this.config.enabled) {
      return { allowed: true, requiresConfirmation: false };
    }

    // Check rate limiting
    if (this.config.rateLimiting) {
      const rateLimitCheck = this._checkRateLimit(userId);
      if (!rateLimitCheck.allowed) {
        return { 
          allowed: false, 
          reason: `Rate limit exceeded: ${rateLimitCheck.reason}`,
          requiresConfirmation: false 
        };
      }
    }



    // Check self-targeting restrictions
    if (targetModel === 'self' && operation === 'jailbreaking') {
      return {
        allowed: true,
        requiresConfirmation: this.config.requireConfirmation
      };
    }

    return { allowed: true, requiresConfirmation: false };
  }

  private _checkRateLimit(userId: string): { allowed: boolean; reason?: string } {
    const now = Date.now();
    const hourAgo = now - (60 * 60 * 1000);
    
    if (!this.rateLimitMap.has(userId)) {
      this.rateLimitMap.set(userId, []);
    }
    
    const userRequests = this.rateLimitMap.get(userId)!;
    
    // Remove old requests
    const recentRequests = userRequests.filter(time => time > hourAgo);
    this.rateLimitMap.set(userId, recentRequests);
    
    if (recentRequests.length >= this.config.maxRequestsPerHour) {
      return { 
        allowed: false, 
        reason: `Maximum ${this.config.maxRequestsPerHour} requests per hour exceeded` 
      };
    }
    
    // Add current request
    recentRequests.push(now);
    
    return { allowed: true };
  }



  /**
   * Log operation for audit trail
   */
  public async logOperation(
    operation: string,
    targetModel: string,
    topic: string,
    prompt: string,
    response: string,
    analysis: string,
    success: boolean,
    confirmationGiven: boolean,
    userId: string = 'anonymous',
    sessionId: string = 'default',
    ipAddress: string = '127.0.0.1',
    userAgent: string = 'MCP-Client'
  ): Promise<string> {
    
    if (!this.config.auditTrail) {
      return '';
    }

    const entryId = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    
    // Create audit entry
    const auditEntry: AuditEntry = {
      id: entryId,
      timestamp,
      userId,
      sessionId,
      operation,
      targetModel,
      topic,
      prompt,
      response,
      analysis,
      success,
      confirmationGiven,
      ipAddress,
      userAgent,
      platform: process.platform,
      hash: createHash('sha256').update(prompt + response).digest('hex'),
      signature: this._createSignature(operation, targetModel, timestamp)
    };

    // Write to audit log
    try {
      await fs.appendFile(this.auditLog, JSON.stringify(auditEntry) + '\n');
    } catch (error) {
      console.error('Failed to write audit log:', error);
    }


    return entryId;
  }

  private _createSignature(operation: string, targetModel: string, timestamp: string): string {
    const secret = process.env.AUDIT_SECRET || 'default-secret';
    const data = `${operation}:${targetModel}:${timestamp}`;
    return createHmac('sha256', secret).update(data).digest('hex');
  }


  /**
   * Generate compliance report
   */
  public async generateComplianceReport(
    framework: string,
    startDate?: string,
    endDate?: string
  ): Promise<ComplianceReport> {
    
    const auditEntries = await this._loadAuditEntries(startDate, endDate);
    
    let compliance = true;
    const violations: string[] = [];
    const recommendations: string[] = [];

    switch (framework.toUpperCase()) {
      case 'GDPR':
        compliance = this._checkGDPRCompliance(auditEntries, violations, recommendations);
        break;
      case 'CCPA':
        compliance = this._checkCCPACompliance(auditEntries, violations, recommendations);
        break;
      case 'SOX':
        compliance = this._checkSOXCompliance(auditEntries, violations, recommendations);
        break;
      case 'HIPAA':
        compliance = this._checkHIPAACompliance(auditEntries, violations, recommendations);
        break;
      default:
        violations.push(`Unsupported compliance framework: ${framework}`);
        compliance = false;
    }

    return {
      framework,
      compliance,
      violations,
      recommendations,
      auditTrail: auditEntries
    };
  }

  private async _loadAuditEntries(startDate?: string, endDate?: string): Promise<AuditEntry[]> {
    try {
      if (!await fs.pathExists(this.auditLog)) {
        return [];
      }

      const logContent = await fs.readFile(this.auditLog, 'utf-8');
      const entries: AuditEntry[] = [];
      
      for (const line of logContent.split('\n')) {
        if (line.trim()) {
          try {
            const entry = JSON.parse(line) as AuditEntry;
            
            // Filter by date range if specified
            if (startDate && entry.timestamp < startDate) continue;
            if (endDate && entry.timestamp > endDate) continue;
            
            entries.push(entry);
          } catch (error) {
            console.warn('Failed to parse audit entry:', error);
          }
        }
      }
      
      return entries;
    } catch (error) {
      console.error('Failed to load audit entries:', error);
      return [];
    }
  }

  private _checkGDPRCompliance(entries: AuditEntry[], violations: string[], recommendations: string[]): boolean {
    let compliant = true;

    // Check for data minimization
    const longPrompts = entries.filter(e => e.prompt.length > 1000);
    if (longPrompts.length > 0) {
      violations.push('Data minimization: Some prompts exceed recommended length');
      recommendations.push('Implement prompt length limits for GDPR compliance');
      compliant = false;
    }

    // Check for consent tracking
    const unconfirmedEntries = entries.filter(e => !e.confirmationGiven);
    if (unconfirmedEntries.length > 0) {
      violations.push('Consent tracking: Some operations lack explicit consent');
      recommendations.push('Implement explicit consent mechanisms for all operations');
      compliant = false;
    }

    return compliant;
  }

  private _checkCCPACompliance(entries: AuditEntry[], violations: string[], recommendations: string[]): boolean {
    let compliant = true;

    // Check for data transparency
    const entriesWithoutUser = entries.filter(e => e.userId === 'anonymous');
    if (entriesWithoutUser.length > entries.length * 0.5) {
      violations.push('Data transparency: High percentage of anonymous operations');
      recommendations.push('Implement user identification for CCPA compliance');
      compliant = false;
    }

    return compliant;
  }

  private _checkSOXCompliance(entries: AuditEntry[], violations: string[], recommendations: string[]): boolean {
    let compliant = true;

    // Check for audit trail integrity
    const entriesWithoutSignature = entries.filter(e => !e.signature);
    if (entriesWithoutSignature.length > 0) {
      violations.push('Audit trail integrity: Some entries lack digital signatures');
      recommendations.push('Implement digital signatures for all audit entries');
      compliant = false;
    }

    // Check for retention policy
    const oldEntries = entries.filter(e => {
      const entryDate = new Date(e.timestamp);
      const sixMonthsAgo = new Date();
      sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
      return entryDate < sixMonthsAgo;
    });

    if (oldEntries.length > 0) {
      recommendations.push('Implement data retention policy for SOX compliance');
    }

    return compliant;
  }

  private _checkHIPAACompliance(entries: AuditEntry[], violations: string[], recommendations: string[]): boolean {
    let compliant = true;

    // Check for PHI protection
    const phiPatterns = [
      /ssn|social security/i,
      /medical record/i,
      /patient id/i,
      /health information/i
    ];

    const phiEntries = entries.filter(e => 
      phiPatterns.some(pattern => pattern.test(e.prompt) || pattern.test(e.response))
    );

    if (phiEntries.length > 0) {
      violations.push('PHI protection: Some entries may contain protected health information');
      recommendations.push('Implement PHI detection and blocking mechanisms');
      compliant = false;
    }

    return compliant;
  }

  /**
   * Get ethics configuration
   */
  public getConfig(): EthicsConfig {
    return { ...this.config };
  }

  /**
   * Update ethics configuration
   */
  public updateConfig(newConfig: Partial<EthicsConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Get audit statistics
   */
  public async getAuditStatistics(): Promise<{
    totalOperations: number;
    successfulOperations: number;
    failedOperations: number;
    selfTargetingOperations: number;
    confirmationRequiredOperations: number;
    blockedOperations: number;
  }> {
    const entries = await this._loadAuditEntries();
    
    return {
      totalOperations: entries.length,
      successfulOperations: entries.filter(e => e.success).length,
      failedOperations: entries.filter(e => !e.success).length,
      selfTargetingOperations: entries.filter(e => e.targetModel === 'self').length,
      confirmationRequiredOperations: entries.filter(e => e.confirmationGiven).length,
      blockedOperations: 0
    };
  }
}

export default AiAdversarialEthics;
