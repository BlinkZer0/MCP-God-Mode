#!/usr/bin/env node

import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { createWriteStream, createReadStream } from "node:fs";
import { pipeline } from "node:stream/promises";
import { Transform } from "node:stream";

// Legal compliance configuration
export interface LegalComplianceConfig {
  enabled: boolean;
  auditLogging: {
    enabled: boolean;
    logLevel: 'minimal' | 'standard' | 'comprehensive';
    retentionDays: number;
    includeUserActions: boolean;
    includeSystemEvents: boolean;
    includeDataAccess: boolean;
    includeSecurityEvents: boolean;
  };
  evidencePreservation: {
    enabled: boolean;
    autoPreserve: boolean;
    preservationPath: string;
    hashAlgorithm: 'sha256' | 'sha512' | 'md5';
    includeMetadata: boolean;
    includeTimestamps: boolean;
    includeUserContext: boolean;
  };
  legalHold: {
    enabled: boolean;
    holdPath: string;
    retentionPolicy: 'indefinite' | 'scheduled' | 'manual';
    scheduledRetentionDays?: number;
    includeNotifications: boolean;
    notificationEmail?: string;
  };
  chainOfCustody: {
    enabled: boolean;
    includeDigitalSignatures: boolean;
    includeWitnesses: boolean;
    witnessEmails?: string[];
    requireApproval: boolean;
    approvalWorkflow: 'single' | 'dual' | 'committee';
  };
  dataIntegrity: {
    enabled: boolean;
    verifyOnAccess: boolean;
    verifyOnModification: boolean;
    backupBeforeModification: boolean;
    includeChecksums: boolean;
  };
  complianceFrameworks: {
    sox: boolean;
    hipaa: boolean;
    gdpr: boolean;
    pci: boolean;
    iso27001: boolean;
    custom: boolean;
  };
}

// Default legal compliance configuration (disabled by default)
export const DEFAULT_LEGAL_CONFIG: LegalComplianceConfig = {
  enabled: false,
  auditLogging: {
    enabled: false,
    logLevel: 'standard',
    retentionDays: 2555, // 7 years (SOX compliance)
    includeUserActions: true,
    includeSystemEvents: true,
    includeDataAccess: true,
    includeSecurityEvents: true
  },
  evidencePreservation: {
    enabled: false,
    autoPreserve: false,
    preservationPath: './legal/evidence',
    hashAlgorithm: 'sha256',
    includeMetadata: true,
    includeTimestamps: true,
    includeUserContext: true
  },
  legalHold: {
    enabled: false,
    holdPath: './legal/holds',
    retentionPolicy: 'manual',
    includeNotifications: false
  },
  chainOfCustody: {
    enabled: false,
    includeDigitalSignatures: false,
    includeWitnesses: false,
    requireApproval: false,
    approvalWorkflow: 'single'
  },
  dataIntegrity: {
    enabled: false,
    verifyOnAccess: false,
    verifyOnModification: true,
    backupBeforeModification: true,
    includeChecksums: true
  },
  complianceFrameworks: {
    sox: false,
    hipaa: false,
    gdpr: false,
    pci: false,
    iso27001: false,
    custom: false
  }
};

// Audit log entry structure
export interface AuditLogEntry {
  id: string;
  timestamp: string;
  eventType: 'user_action' | 'system_event' | 'data_access' | 'security_event' | 'legal_hold' | 'evidence_preservation';
  severity: 'low' | 'medium' | 'high' | 'critical';
  userId?: string;
  sessionId?: string;
  toolName?: string;
  action: string;
  target?: string;
  result: 'success' | 'failure' | 'partial';
  details: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
  legalHoldId?: string;
  evidenceId?: string;
  chainOfCustodyId?: string;
  complianceFlags: string[];
  hash?: string;
  signature?: string;
}

// Evidence preservation record
export interface EvidenceRecord {
  id: string;
  timestamp: string;
  type: 'file' | 'data' | 'log' | 'system_state' | 'network_capture' | 'memory_dump';
  source: string;
  target: string;
  hash: string;
  size: number;
  metadata: Record<string, any>;
  preservationPath: string;
  legalHoldIds: string[];
  chainOfCustodyId?: string;
  witnessIds?: string[];
  digitalSignature?: string;
  retentionPolicy: string;
  accessLog: Array<{
    timestamp: string;
    userId: string;
    action: string;
    purpose: string;
  }>;
}

// Legal hold record
export interface LegalHoldRecord {
  id: string;
  caseId?: string;
  caseName: string;
  description: string;
  createdBy: string;
  createdDate: string;
  status: 'active' | 'suspended' | 'released' | 'expired';
  retentionPolicy: 'indefinite' | 'scheduled' | 'manual';
  scheduledReleaseDate?: string;
  affectedData: string[];
  custodian: string;
  legalBasis: string;
  notificationSent: boolean;
  notificationDate?: string;
  releaseDate?: string;
  releaseReason?: string;
  chainOfCustodyId?: string;
}

// Chain of custody record
export interface ChainOfCustodyRecord {
  id: string;
  evidenceId: string;
  action: 'created' | 'transferred' | 'accessed' | 'modified' | 'released' | 'destroyed';
  timestamp: string;
  fromCustodian?: string;
  toCustodian: string;
  purpose: string;
  location: string;
  witnesses: Array<{
    name: string;
    email: string;
    signature?: string;
  }>;
  digitalSignature?: string;
  notes: string;
  legalHoldId?: string;
}

// Legal compliance manager class
export class LegalComplianceManager {
  private config: LegalComplianceConfig;
  private auditLogPath: string;
  private evidencePath: string;
  private legalHoldPath: string;
  private chainOfCustodyPath: string;

  constructor(config: LegalComplianceConfig) {
    this.config = { ...DEFAULT_LEGAL_CONFIG, ...config };
    this.auditLogPath = path.join(process.cwd(), 'legal', 'audit-logs');
    this.evidencePath = this.config.evidencePreservation.preservationPath;
    this.legalHoldPath = this.config.legalHold.holdPath;
    this.chainOfCustodyPath = path.join(process.cwd(), 'legal', 'chain-of-custody');
  }

  // Initialize legal compliance system
  async initialize(): Promise<void> {
    if (!this.config.enabled) {
      return;
    }

    try {
      // Create legal compliance directories
      await fs.mkdir(this.auditLogPath, { recursive: true });
      await fs.mkdir(this.evidencePath, { recursive: true });
      await fs.mkdir(this.legalHoldPath, { recursive: true });
      await fs.mkdir(this.chainOfCustodyPath, { recursive: true });

      // Create initial audit log entry
      await this.logAuditEvent({
        eventType: 'system_event',
        severity: 'low',
        action: 'legal_compliance_system_initialized',
        result: 'success',
        details: { config: this.config },
        complianceFlags: ['system_init']
      });

      console.log('✅ Legal compliance system initialized');
    } catch (error) {
      console.error('❌ Failed to initialize legal compliance system:', error);
      throw error;
    }
  }

  // Log audit event
  async logAuditEvent(event: Omit<AuditLogEntry, 'id' | 'timestamp' | 'hash' | 'signature'>): Promise<string> {
    if (!this.config.enabled || !this.config.auditLogging.enabled) {
      return '';
    }

    const auditEntry: AuditLogEntry = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      hash: '',
      signature: '',
      ...event
    };

    // Generate hash for integrity
    const entryString = JSON.stringify(auditEntry, null, 2);
    auditEntry.hash = crypto.createHash(this.config.evidencePreservation.hashAlgorithm).update(entryString).digest('hex');

    // Add digital signature if enabled
    if (this.config.chainOfCustody.includeDigitalSignatures) {
      auditEntry.signature = await this.generateDigitalSignature(entryString);
    }

    // Write to audit log file
    const logFile = path.join(this.auditLogPath, `audit-${new Date().toISOString().split('T')[0]}.jsonl`);
    await fs.appendFile(logFile, JSON.stringify(auditEntry) + '\n');

    // Clean up old audit logs based on retention policy
    await this.cleanupAuditLogs();

    return auditEntry.id;
  }

  // Preserve evidence
  async preserveEvidence(
    source: string,
    type: EvidenceRecord['type'],
    metadata: Record<string, any> = {},
    legalHoldIds: string[] = []
  ): Promise<string> {
    if (!this.config.enabled || !this.config.evidencePreservation.enabled) {
      return '';
    }

    const evidenceId = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    
    try {
      // Read source data
      const sourceData = await fs.readFile(source);
      const hash = crypto.createHash(this.config.evidencePreservation.hashAlgorithm).update(sourceData).digest('hex');
      
      // Create evidence record
      const evidenceRecord: EvidenceRecord = {
        id: evidenceId,
        timestamp,
        type,
        source,
        target: path.join(this.evidencePath, `${evidenceId}.evidence`),
        hash,
        size: sourceData.length,
        metadata: {
          ...metadata,
          originalPath: source,
          preservationTimestamp: timestamp,
          hashAlgorithm: this.config.evidencePreservation.hashAlgorithm,
          ...(this.config.evidencePreservation.includeUserContext && {
            userId: process.env.USER || 'system',
            sessionId: process.env.SESSION_ID || 'unknown'
          })
        },
        preservationPath: path.join(this.evidencePath, `${evidenceId}.evidence`),
        legalHoldIds,
        retentionPolicy: this.config.legalHold.retentionPolicy,
        accessLog: []
      };

      // Write evidence file
      await fs.writeFile(evidenceRecord.preservationPath, sourceData);

      // Write evidence record
      const recordPath = path.join(this.evidencePath, `${evidenceId}.record.json`);
      await fs.writeFile(recordPath, JSON.stringify(evidenceRecord, null, 2));

      // Log evidence preservation
      await this.logAuditEvent({
        eventType: 'evidence_preservation',
        severity: 'high',
        action: 'evidence_preserved',
        target: source,
        result: 'success',
        details: { evidenceId, type, size: sourceData.length, hash },
        evidenceId,
        complianceFlags: ['evidence_preservation']
      });

      return evidenceId;
    } catch (error) {
      await this.logAuditEvent({
        eventType: 'evidence_preservation',
        severity: 'critical',
        action: 'evidence_preservation_failed',
        target: source,
        result: 'failure',
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
        complianceFlags: ['evidence_preservation', 'error']
      });
      throw error;
    }
  }

  // Create legal hold
  async createLegalHold(
    caseName: string,
    description: string,
    createdBy: string,
    affectedData: string[],
    custodian: string,
    legalBasis: string,
    caseId?: string
  ): Promise<string> {
    if (!this.config.enabled || !this.config.legalHold.enabled) {
      return '';
    }

    const holdId = crypto.randomUUID();
    const timestamp = new Date().toISOString();

    const legalHold: LegalHoldRecord = {
      id: holdId,
      caseId,
      caseName,
      description,
      createdBy,
      createdDate: timestamp,
      status: 'active',
      retentionPolicy: this.config.legalHold.retentionPolicy,
      scheduledReleaseDate: this.config.legalHold.retentionPolicy === 'scheduled' 
        ? new Date(Date.now() + (this.config.legalHold.scheduledRetentionDays || 30) * 24 * 60 * 60 * 1000).toISOString()
        : undefined,
      affectedData,
      custodian,
      legalBasis,
      notificationSent: false
    };

    // Write legal hold record
    const holdPath = path.join(this.legalHoldPath, `${holdId}.json`);
    await fs.writeFile(holdPath, JSON.stringify(legalHold, null, 2));

    // Send notification if enabled
    if (this.config.legalHold.includeNotifications && this.config.legalHold.notificationEmail) {
      await this.sendLegalHoldNotification(legalHold);
    }

    // Log legal hold creation
    await this.logAuditEvent({
      eventType: 'legal_hold',
      severity: 'high',
      action: 'legal_hold_created',
      result: 'success',
      details: { holdId, caseName, affectedDataCount: affectedData.length },
      legalHoldId: holdId,
      complianceFlags: ['legal_hold', 'data_retention']
    });

    return holdId;
  }

  // Record chain of custody
  async recordChainOfCustody(
    evidenceId: string,
    action: ChainOfCustodyRecord['action'],
    toCustodian: string,
    purpose: string,
    location: string,
    witnesses: ChainOfCustodyRecord['witnesses'] = [],
    notes: string = '',
    fromCustodian?: string,
    legalHoldId?: string
  ): Promise<string> {
    if (!this.config.enabled || !this.config.chainOfCustody.enabled) {
      return '';
    }

    const custodyId = crypto.randomUUID();
    const timestamp = new Date().toISOString();

    const custodyRecord: ChainOfCustodyRecord = {
      id: custodyId,
      evidenceId,
      action,
      timestamp,
      fromCustodian,
      toCustodian,
      purpose,
      location,
      witnesses,
      notes,
      legalHoldId
    };

    // Add digital signature if enabled
    if (this.config.chainOfCustody.includeDigitalSignatures) {
      const recordString = JSON.stringify(custodyRecord, null, 2);
      custodyRecord.digitalSignature = await this.generateDigitalSignature(recordString);
    }

    // Write chain of custody record
    const custodyPath = path.join(this.chainOfCustodyPath, `${custodyId}.json`);
    await fs.writeFile(custodyPath, JSON.stringify(custodyRecord, null, 2));

    // Log chain of custody event
    await this.logAuditEvent({
      eventType: 'system_event',
      severity: 'high',
      action: 'chain_of_custody_recorded',
      result: 'success',
      details: { custodyId, evidenceId, action, toCustodian },
      chainOfCustodyId: custodyId,
      complianceFlags: ['chain_of_custody']
    });

    return custodyId;
  }

  // Verify data integrity
  async verifyDataIntegrity(filePath: string): Promise<{ valid: boolean; hash: string; error?: string }> {
    if (!this.config.enabled || !this.config.dataIntegrity.enabled) {
      return { valid: true, hash: '' };
    }

    try {
      const data = await fs.readFile(filePath);
      const currentHash = crypto.createHash(this.config.evidencePreservation.hashAlgorithm).update(data).digest('hex');
      
      // Check if we have a stored hash for this file
      const hashFile = `${filePath}.hash`;
      try {
        const storedHash = await fs.readFile(hashFile, 'utf-8');
        const valid = currentHash === storedHash.trim();
        
        return { valid, hash: currentHash, error: valid ? undefined : 'Hash mismatch detected' };
      } catch {
        // No stored hash, create one
        await fs.writeFile(hashFile, currentHash);
        return { valid: true, hash: currentHash };
      }
    } catch (error) {
      return { valid: false, hash: '', error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  // Generate digital signature
  private async generateDigitalSignature(data: string): Promise<string> {
    // In a real implementation, this would use a proper digital signature system
    // For now, we'll create a hash-based signature
    const signature = crypto.createHmac('sha256', 'legal-compliance-key').update(data).digest('hex');
    return signature;
  }

  // Send legal hold notification
  private async sendLegalHoldNotification(legalHold: LegalHoldRecord): Promise<void> {
    // In a real implementation, this would send actual email notifications
    console.log(`📧 Legal Hold Notification: ${legalHold.caseName} - ${legalHold.description}`);
    console.log(`   Custodian: ${legalHold.custodian}`);
    console.log(`   Affected Data: ${legalHold.affectedData.length} items`);
  }

  // Clean up old audit logs
  private async cleanupAuditLogs(): Promise<void> {
    try {
      const files = await fs.readdir(this.auditLogPath);
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - this.config.auditLogging.retentionDays);

      for (const file of files) {
        if (file.startsWith('audit-') && file.endsWith('.jsonl')) {
          const fileDate = new Date(file.replace('audit-', '').replace('.jsonl', ''));
          if (fileDate < cutoffDate) {
            await fs.unlink(path.join(this.auditLogPath, file));
          }
        }
      }
    } catch (error) {
      console.warn('Failed to cleanup audit logs:', error);
    }
  }

  // Get compliance status
  getComplianceStatus(): {
    enabled: boolean;
    auditLogging: boolean;
    evidencePreservation: boolean;
    legalHold: boolean;
    chainOfCustody: boolean;
    dataIntegrity: boolean;
    frameworks: string[];
  } {
    const frameworks = Object.entries(this.config.complianceFrameworks)
      .filter(([_, enabled]) => enabled)
      .map(([framework, _]) => framework.toUpperCase());

    return {
      enabled: this.config.enabled,
      auditLogging: this.config.auditLogging.enabled,
      evidencePreservation: this.config.evidencePreservation.enabled,
      legalHold: this.config.legalHold.enabled,
      chainOfCustody: this.config.chainOfCustody.enabled,
      dataIntegrity: this.config.dataIntegrity.enabled,
      frameworks
    };
  }

  // Update configuration
  async updateConfig(newConfig: Partial<LegalComplianceConfig>): Promise<void> {
    const oldConfig = { ...this.config };
    this.config = { ...this.config, ...newConfig };

    // Log configuration change
    await this.logAuditEvent({
      eventType: 'system_event',
      severity: 'medium',
      action: 'legal_compliance_config_updated',
      result: 'success',
      details: { 
        oldConfig: oldConfig,
        newConfig: this.config,
        changes: Object.keys(newConfig)
      },
      complianceFlags: ['config_change']
    });
  }
}

// Export singleton instance
export const legalCompliance = new LegalComplianceManager(DEFAULT_LEGAL_CONFIG);
