#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const node_child_process_1 = require("node:child_process");
const node_util_1 = require("node:util");
// Import utility modules
const environment_js_1 = require("./config/environment.js");
const logger_js_1 = require("./utils/logger.js");
// Import tool modules
const index_js_1 = require("./tools/core/index.js");
const index_js_2 = require("./tools/email/index.js");
const fs_list_js_1 = require("./tools/file_system/fs_list.js");
const index_js_3 = require("./tools/utilities/index.js");
const index_js_4 = require("./tools/security/index.js");
const index_js_5 = require("./tools/network/index.js");
// Global variables for enhanced features
let browserInstance = null;
let webSocketServer = null;
let expressServer = null;
let cronJobs = new Map();
let fileWatchers = new Map();
let apiCache = new Map();
let webhookEndpoints = new Map();
const execAsync = (0, node_util_1.promisify)(node_child_process_1.exec);
// Log server startup
(0, logger_js_1.logServerStart)(environment_js_1.PLATFORM);
// ===========================================
// MODULAR SERVER: Imported Tools
// ===========================================
const server = new mcp_js_1.McpServer({ name: "MCP God Mode - Modular", version: "1.4" });
// Register core tools
(0, index_js_1.registerHealth)(server);
(0, index_js_1.registerSystemInfo)(server);
// Register email tools
(0, index_js_2.registerSendEmail)(server);
(0, index_js_2.registerParseEmail)(server);
// Register file system tools
(0, fs_list_js_1.registerFsList)(server);
// Register utility tools
(0, index_js_3.registerDiceRolling)(server);
// ===========================================
// COMPREHENSIVE PENETRATION TESTING TOOLS
// ===========================================
// 
// 🚨 **SECURITY NOTICE**: These tools are designed for authorized corporate security testing ONLY.
// All WAN testing capabilities are strictly limited to personal networks and authorized corporate infrastructure.
// Unauthorized use may constitute cybercrime and result in legal consequences.
//
// 🔒 **AUTHORIZED USE CASES**:
// - Personal network security assessment
// - Corporate penetration testing with written authorization
// - Educational security research in controlled environments
// - Security professional development and training
//
// ❌ **PROHIBITED USE**:
// - Testing external networks without authorization
// - Scanning public internet infrastructure
// - Targeting systems you don't own or have permission to test
// - Any activities that could disrupt network services
//
// ===========================================
// Register security tools
(0, index_js_4.registerPortScanner)(server);
(0, index_js_4.registerVulnerabilityScanner)(server);
(0, index_js_4.registerPasswordCracker)(server);
(0, index_js_4.registerExploitFramework)(server);
// Register network tools
(0, index_js_5.registerPacketSniffer)(server);
// ===========================================
// START THE SERVER
// ===========================================
const transport = new stdio_js_1.StdioServerTransport();
server.connect(transport);
console.log("Modular MCP Server started with imported tools");
console.log("Available tools: health, system_info, send_email, parse_email, fs_list, dice_rolling, port_scanner, vulnerability_scanner, password_cracker, exploit_framework, packet_sniffer");
console.log("");
console.log("🔒 **COMPREHENSIVE PENETRATION TESTING SUITE LOADED**");
console.log("📡 Port Scanner: Advanced network reconnaissance and service enumeration");
console.log("🛡️ Vulnerability Scanner: Comprehensive security assessment and risk scoring");
console.log("🔐 Password Cracker: Authentication testing across multiple services");
console.log("⚡ Exploit Framework: Vulnerability testing with safe mode simulation");
console.log("📡 Packet Sniffer: Network traffic analysis and security monitoring");
console.log("");
console.log("⚠️  **SECURITY NOTICE**: All tools are for authorized testing ONLY");
console.log("🔒 Use only on networks you own or have explicit permission to test");
