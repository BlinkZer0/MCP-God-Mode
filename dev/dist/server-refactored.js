#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { exec } from "node:child_process";
import { promisify } from "node:util";
// Import utility modules
import { PLATFORM, config } from "./config/environment.js";
import { logger, logServerStart } from "./utils/logger.js";
import { legalCompliance } from "./utils/legal-compliance.js";
// Import all tools from the comprehensive index
import * as allTools from "./tools/index.js";
// Import legal compliance tools
import { registerLegalComplianceManager } from "./tools/legal/legal_compliance_manager.js";
// Global variables for enhanced features
let browserInstance = null;
let webSocketServer = null;
let expressServer = null;
let cronJobs = new Map();
let fileWatchers = new Map();
let apiCache = new Map();
let webhookEndpoints = new Map();
const execAsync = promisify(exec);
// Log server startup
logServerStart(PLATFORM);
// Initialize legal compliance system
async function initializeLegalCompliance() {
    try {
        // Configure legal compliance from environment
        const legalConfig = {
            enabled: config.legalCompliance.enabled,
            auditLogging: config.legalCompliance.auditLogging,
            evidencePreservation: config.legalCompliance.evidencePreservation,
            legalHold: config.legalCompliance.legalHold,
            chainOfCustody: config.legalCompliance.chainOfCustody,
            dataIntegrity: config.legalCompliance.dataIntegrity,
            complianceFrameworks: config.legalCompliance.complianceFrameworks
        };
        await legalCompliance.updateConfig(legalConfig);
        await legalCompliance.initialize();
        if (legalConfig.enabled) {
            console.log("🔒 Legal compliance system initialized and enabled");
            console.log(`   📊 Audit Logging: ${legalConfig.auditLogging.enabled ? '✅' : '❌'}`);
            console.log(`   🗃️ Evidence Preservation: ${legalConfig.evidencePreservation.enabled ? '✅' : '❌'}`);
            console.log(`   ⚖️ Legal Hold: ${legalConfig.legalHold.enabled ? '✅' : '❌'}`);
            console.log(`   🔗 Chain of Custody: ${legalConfig.chainOfCustody.enabled ? '✅' : '❌'}`);
            console.log(`   🔐 Data Integrity: ${legalConfig.dataIntegrity.enabled ? '✅' : '❌'}`);
            const frameworks = Object.entries(legalConfig.complianceFrameworks)
                .filter(([_, enabled]) => enabled)
                .map(([framework, _]) => framework.toUpperCase());
            if (frameworks.length > 0) {
                console.log(`   📋 Compliance Frameworks: ${frameworks.join(', ')}`);
            }
        }
        else {
            console.log("🔓 Legal compliance system disabled (default)");
        }
    }
    catch (error) {
        console.warn("⚠️ Failed to initialize legal compliance system:", error);
    }
}
// ===========================================
// ADVANCED SECURITY & NETWORK ANALYSIS PLATFORM
// Comprehensive Tool Registration and Management
// ===========================================
const server = new McpServer({ name: "MCP God Mode - Advanced Security & Network Analysis Platform", version: "1.6.0" });
// Capture tool registrations dynamically to keep the list accurate
const registeredTools = new Set();
const _origRegisterTool = server.registerTool?.bind(server);
if (_origRegisterTool) {
    server.registerTool = (name, ...rest) => {
        try {
            registeredTools.add(name);
        }
        catch { }
        return _origRegisterTool(name, ...rest);
    };
}
// ===========================================
// REGISTER ALL TOOLS FROM COMPREHENSIVE INDEX
// ===========================================
// Get all tool registration functions from the comprehensive index
const toolFunctions = Object.values(allTools);
// Register all tools dynamically
toolFunctions.forEach((toolFunction) => {
    if (typeof toolFunction === 'function' && toolFunction.name.startsWith('register')) {
        try {
            toolFunction(server);
        }
        catch (error) {
            console.warn(`Warning: Failed to register tool ${toolFunction.name}:`, error);
        }
    }
});
// Register legal compliance manager
try {
    registerLegalComplianceManager(server);
    console.log("✅ Legal compliance manager registered");
}
catch (error) {
    console.warn("Warning: Failed to register legal compliance manager:", error);
}
console.log(`✅ Successfully registered ${toolFunctions.length} tool functions + legal compliance manager`);
// ===========================================
// START THE SERVER
// ===========================================
async function main() {
    // Initialize legal compliance system first
    await initializeLegalCompliance();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    logger.info("MCP God Mode - Advanced Security & Network Analysis Platform started successfully");
    console.log("🚀 **MCP GOD MODE - ADVANCED SECURITY & NETWORK ANALYSIS PLATFORM**");
    console.log(`📊 Total Tools Available: ${Array.from(registeredTools).length}`);
    console.log("");
    console.log("🔧 **COMPREHENSIVE PROFESSIONAL TOOL SUITE LOADED**");
    console.log("📁 File System Tools: Advanced file operations, search, compression, and metadata extraction");
    console.log("⚙️ Process Tools: Cross-platform process execution, monitoring, and elevated privilege management");
    console.log("🌐 Network Tools: Advanced network diagnostics, port scanning, traffic analysis, and geolocation");
    console.log("🔒 Security Tools: Professional penetration testing, vulnerability assessment, and security auditing");
    console.log("📡 Wireless Tools: Wi-Fi security assessment, Bluetooth analysis, and SDR signal processing");
    console.log("📧 Email Tools: Advanced email management, parsing, and security analysis");
    console.log("🎵 Media Tools: Professional audio/video editing, image processing, and OCR capabilities");
    console.log("🖥️ Web Tools: Advanced browser automation, web scraping, and form completion");
    console.log("📱 Mobile Tools: Comprehensive mobile device management, security analysis, and app testing");
    console.log("🖥️ Virtualization: Advanced VM and container management with security controls");
    console.log("🧮 Utility Tools: Mathematical computation, data analysis, and machine learning");
    console.log("🪟 Windows Tools: Windows-specific system management and service control");
    console.log("⚖️ Legal Tools: Legal compliance, audit logging, evidence preservation, and chain of custody");
    console.log("🔍 Forensics Tools: Digital forensics, malware analysis, and incident response");
    console.log("☁️ Cloud Tools: Multi-cloud security assessment and compliance validation");
    console.log("");
    console.log("🎯 **READY FOR PROFESSIONAL SECURITY OPERATIONS**");
}
main().catch((error) => {
    logger.error("Failed to start server:", error);
    process.exit(1);
});
