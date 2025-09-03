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
const server = new mcp_js_1.McpServer({ name: "modular-mcp-server", version: "1.0.0" });
// Register core tools
(0, index_js_1.registerHealth)(server);
(0, index_js_1.registerSystemInfo)(server);
// Register email tools
(0, index_js_2.registerSendEmail)(server);
(0, index_js_2.registerParseEmail)(server);
// Register file system tools
(0, fs_list_js_1.registerFsList)(server);
// ===========================================
// START THE SERVER
// ===========================================
const transport = new stdio_js_1.StdioServerTransport();
server.connect(transport);
console.log("Modular MCP Server started with imported tools");
console.log("Available tools: health, system_info, send_email, parse_email, fs_list");
