#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as path from "node:path";
import * as os from "node:os";
import * as fs from "node:fs/promises";
import { spawn, exec } from "node:child_process";
import { promisify } from "node:util";
import simpleGit from "simple-git";
import { createWriteStream } from "node:fs";
import { pipeline } from "node:stream/promises";
import { Transform } from "node:stream";
import { createReadStream } from "node:fs";
import { Readable } from "node:stream";
import * as math from "mathjs";
import { ChartJSNodeCanvas } from "chartjs-node-canvas";
import * as crypto from "node:crypto";
import { createCanvas } from "canvas";

// Import utility modules
import { PLATFORM, IS_WINDOWS, IS_LINUX, IS_MACOS, IS_ANDROID, IS_IOS, IS_MOBILE, config, PROC_ALLOWLIST, MAX_BYTES, MOBILE_CONFIG, COMMAND_MAPPINGS } from "./config/environment.js";
import { ALLOWED_ROOTS_ARRAY, getPlatformCommand, getMobilePermissions, isMobileFeatureAvailable, getMobileDeviceInfo, getFileOperationCommand, getMobileProcessCommand, getMobileServiceCommand, getMobileNetworkCommand, getMobileStorageCommand, getMobileUserCommand } from "./utils/platform.js";
import { sanitizeCommand, isDangerousCommand, shouldPerformSecurityChecks } from "./utils/security.js";
import { ensureInsideRoot, limitString } from "./utils/fileSystem.js";
import { logger, logServerStart } from "./utils/logger.js";

// Import tool modules
import { registerHealth, registerSystemInfo } from "./tools/core/index.js";
import { registerSendEmail, registerParseEmail } from "./tools/email/index.js";
import { registerFsList } from "./tools/file_system/fs_list.js";
import { registerDiceRolling } from "./tools/utilities/index.js";

// Global variables for enhanced features
let browserInstance: any = null;
let webSocketServer: any = null;
let expressServer: any = null;
let cronJobs: Map<string, any> = new Map();
let fileWatchers: Map<string, any> = new Map();
let apiCache: Map<string, any> = new Map();
let webhookEndpoints: Map<string, any> = new Map();

const execAsync = promisify(exec);

// Log server startup
logServerStart(PLATFORM);

// ===========================================
// MODULAR SERVER: Imported Tools
// ===========================================

const server = new McpServer({ name: "MCP God Mode - Modular", version: "1.3" });

// Register core tools
registerHealth(server);
registerSystemInfo(server);

// Register email tools
registerSendEmail(server);
registerParseEmail(server);

// Register file system tools
registerFsList(server);

// Register utility tools
registerDiceRolling(server);

// ===========================================
// START THE SERVER
// ===========================================

const transport = new StdioServerTransport();
server.connect(transport);

console.log("Modular MCP Server started with imported tools");
console.log("Available tools: health, system_info, send_email, parse_email, fs_list, dice_rolling");
