import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { legalCompliance, LegalComplianceConfig, DEFAULT_LEGAL_CONFIG } from "../../utils/legal-compliance.js";
import { config } from "../../config/environment.js";

export function registerLegalComplianceManager(server: McpServer) {
  server.registerTool("legal_compliance_manager", {
    description: "Manage legal compliance, audit logging, evidence preservation, and legal hold capabilities",
    inputSchema: {
      action: z.enum([
        "enable_compliance",
        "disable_compliance", 
        "configure_compliance",
        "get_status",
        "create_legal_hold",
        "release_legal_hold",
        "preserve_evidence",
        "verify_integrity",
        "record_custody",
        "get_audit_logs",
        "get_evidence_records",
        "get_legal_holds",
        "get_chain_of_custody"
      ]).describe("Legal compliance action to perform"),
      // Configuration parameters
      enableAuditLogging: z.boolean().optional().describe("Enable audit logging"),
      enableEvidencePreservation: z.boolean().optional().describe("Enable evidence preservation"),
      enableLegalHold: z.boolean().optional().describe("Enable legal hold capabilities"),
      enableChainOfCustody: z.boolean().optional().describe("Enable chain of custody tracking"),
      enableDataIntegrity: z.boolean().optional().describe("Enable data integrity verification"),
      // Legal hold parameters
      caseName: z.string().optional().describe("Legal case name"),
      caseDescription: z.string().optional().describe("Legal case description"),
      createdBy: z.string().optional().describe("User creating the legal hold"),
      affectedData: z.array(z.string()).optional().describe("List of affected data paths"),
      custodian: z.string().optional().describe("Data custodian"),
      legalBasis: z.string().optional().describe("Legal basis for the hold"),
      caseId: z.string().optional().describe("External case ID"),
      // Evidence preservation parameters
      sourcePath: z.string().optional().describe("Source path for evidence preservation"),
      evidenceType: z.enum(["file", "data", "log", "system_state", "network_capture", "memory_dump"]).optional().describe("Type of evidence"),
      metadata: z.record(z.any()).optional().describe("Additional metadata for evidence"),
      legalHoldIds: z.array(z.string()).optional().describe("Associated legal hold IDs"),
      // Chain of custody parameters
      evidenceId: z.string().optional().describe("Evidence ID for chain of custody"),
      custodyAction: z.enum(["created", "transferred", "accessed", "modified", "released", "destroyed"]).optional().describe("Custody action"),
      toCustodian: z.string().optional().describe("Custodian receiving the evidence"),
      purpose: z.string().optional().describe("Purpose of the custody action"),
      location: z.string().optional().describe("Physical or logical location"),
      witnesses: z.array(z.object({
        name: z.string(),
        email: z.string(),
        signature: z.string().optional()
      })).optional().describe("Witnesses to the custody action"),
      notes: z.string().optional().describe("Additional notes"),
      fromCustodian: z.string().optional().describe("Custodian transferring the evidence"),
      // Compliance framework parameters
      complianceFrameworks: z.object({
        sox: z.boolean().optional(),
        hipaa: z.boolean().optional(),
        gdpr: z.boolean().optional(),
        pci: z.boolean().optional(),
        iso27001: z.boolean().optional(),
        custom: z.boolean().optional()
      }).optional().describe("Compliance frameworks to enable"),
      // Audit and retention parameters
      auditRetentionDays: z.number().optional().describe("Audit log retention period in days"),
      auditLogLevel: z.enum(["minimal", "standard", "comprehensive"]).optional().describe("Audit logging level"),
      // File integrity parameters
      filePath: z.string().optional().describe("File path for integrity verification"),
      // Query parameters
      startDate: z.string().optional().describe("Start date for query (ISO format)"),
      endDate: z.string().optional().describe("End date for query (ISO format)"),
      limit: z.number().optional().describe("Maximum number of records to return")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string(),
      result: z.any().optional(),
      complianceStatus: z.object({
        enabled: z.boolean(),
        auditLogging: z.boolean(),
        evidencePreservation: z.boolean(),
        legalHold: z.boolean(),
        chainOfCustody: z.boolean(),
        dataIntegrity: z.boolean(),
        frameworks: z.array(z.string())
      }).optional(),
      legalHoldId: z.string().optional(),
      custodyId: z.string().optional(),
      integrityResult: z.object({
        valid: z.boolean(),
        hash: z.string(),
        error: z.string().optional()
      }).optional()
    }
  }, async (args) => {
    const { 
      action, 
      enableAuditLogging, 
      enableEvidencePreservation, 
      enableLegalHold, 
      enableChainOfCustody, 
      enableDataIntegrity,
      caseName, 
      caseDescription, 
      createdBy, 
      affectedData, 
      custodian, 
      legalBasis, 
      caseId,
      sourcePath, 
      evidenceType, 
      metadata, 
      legalHoldIds,
      evidenceId,
      custodyAction, 
      toCustodian, 
      purpose, 
      location, 
      witnesses, 
      notes, 
      fromCustodian,
      complianceFrameworks,
      auditRetentionDays,
      auditLogLevel,
      filePath,
      startDate,
      endDate,
      limit
    } = args;
    try {
      switch (action) {
        case "enable_compliance":
          await legalCompliance.updateConfig({ enabled: true });
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                success: true,
                message: "Legal compliance system enabled",
                complianceStatus: legalCompliance.getComplianceStatus()
              }, null, 2)
            }]
          };

        case "disable_compliance":
          await legalCompliance.updateConfig({ enabled: false });
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                success: true,
                message: "Legal compliance system disabled",
                complianceStatus: legalCompliance.getComplianceStatus()
              }, null, 2)
            }]
          };

        case "configure_compliance":
          const configUpdate: Partial<LegalComplianceConfig> = {};
          
          if (enableAuditLogging !== undefined) {
            configUpdate.auditLogging = { ...DEFAULT_LEGAL_CONFIG.auditLogging, enabled: enableAuditLogging };
          }
          if (enableEvidencePreservation !== undefined) {
            configUpdate.evidencePreservation = { ...DEFAULT_LEGAL_CONFIG.evidencePreservation, enabled: enableEvidencePreservation };
          }
          if (enableLegalHold !== undefined) {
            configUpdate.legalHold = { ...DEFAULT_LEGAL_CONFIG.legalHold, enabled: enableLegalHold };
          }
          if (enableChainOfCustody !== undefined) {
            configUpdate.chainOfCustody = { ...DEFAULT_LEGAL_CONFIG.chainOfCustody, enabled: enableChainOfCustody };
          }
          if (enableDataIntegrity !== undefined) {
            configUpdate.dataIntegrity = { ...DEFAULT_LEGAL_CONFIG.dataIntegrity, enabled: enableDataIntegrity };
          }
          if (complianceFrameworks) {
            configUpdate.complianceFrameworks = { ...DEFAULT_LEGAL_CONFIG.complianceFrameworks, ...complianceFrameworks };
          }
          if (auditRetentionDays !== undefined) {
            configUpdate.auditLogging = { ...configUpdate.auditLogging || DEFAULT_LEGAL_CONFIG.auditLogging, retentionDays: auditRetentionDays };
          }
          if (auditLogLevel !== undefined) {
            configUpdate.auditLogging = { ...configUpdate.auditLogging || DEFAULT_LEGAL_CONFIG.auditLogging, logLevel: auditLogLevel };
          }

          await legalCompliance.updateConfig(configUpdate);
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                success: true,
                message: "Legal compliance configuration updated",
                complianceStatus: legalCompliance.getComplianceStatus()
              }, null, 2)
            }]
          };

        case "get_status":
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                success: true,
                message: "Legal compliance status retrieved",
                complianceStatus: legalCompliance.getComplianceStatus()
              }, null, 2)
            }]
          };

        case "create_legal_hold":
          if (!caseName || !caseDescription || !createdBy || !affectedData || !custodian || !legalBasis) {
            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  success: false,
                  message: "Missing required parameters for legal hold creation"
                }, null, 2)
              }]
            };
          }

          const legalHoldId = await legalCompliance.createLegalHold(
            caseName,
            caseDescription,
            createdBy,
            affectedData,
            custodian,
            legalBasis,
            caseId
          );

          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                success: true,
                message: `Legal hold created successfully`,
                legalHoldId
              }, null, 2)
            }]
          };

        case "preserve_evidence":
          if (!sourcePath || !evidenceType) {
            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  success: false,
                  message: "Missing required parameters for evidence preservation"
                }, null, 2)
              }]
            };
          }

          const evidenceId = await legalCompliance.preserveEvidence(
            sourcePath,
            evidenceType,
            metadata || {},
            legalHoldIds || []
          );

          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                success: true,
                message: `Evidence preserved successfully`,
                evidenceId
              }, null, 2)
            }]
          };

        case "verify_integrity":
          if (!filePath) {
            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  success: false,
                  message: "Missing file path for integrity verification"
                }, null, 2)
              }]
            };
          }

          const integrityResult = await legalCompliance.verifyDataIntegrity(filePath);

          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                success: true,
                message: "Data integrity verification completed",
                integrityResult
              }, null, 2)
            }]
          };

        case "record_custody":
          if (!custodyAction || !toCustodian || !purpose || !location) {
            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  success: false,
                  message: "Missing required parameters for chain of custody recording"
                }, null, 2)
              }]
            };
          }

          const evidenceIdValue = (args.evidenceId as string | undefined) || `EVIDENCE-${Date.now()}`;
          const custodyId = await legalCompliance.recordChainOfCustody(
            evidenceIdValue,
            custodyAction,
            toCustodian,
            purpose,
            location,
            (witnesses || []).map(w => ({ name: w.name || '', email: w.email || '', signature: w.signature })),
            notes || "",
            fromCustodian,
            legalHoldIds?.[0] // Use first legal hold ID if provided
          );

          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                success: true,
                message: `Chain of custody recorded successfully`,
                custodyId
              }, null, 2)
            }]
          };

        default:
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                success: false,
                message: `Unknown action: ${action}`
              }, null, 2)
            }]
          };
      }
    } catch (error) {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            message: `Legal compliance operation failed: ${error instanceof Error ? (error as Error).message : 'Unknown error'}`
          }, null, 2)
        }]
      };
    }
  });
}
