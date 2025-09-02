"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
exports.logServerStart = logServerStart;
const node_fs_1 = require("node:fs");
const node_util_1 = require("node:util");
class MinimalLogger {
    logStream = null;
    constructor() {
        // Only create log file in development
        if (process.env.NODE_ENV !== 'production') {
            try {
                this.logStream = (0, node_fs_1.createWriteStream)('mcp-server.log', { flags: 'a' });
            }
            catch (error) {
                // Ignore log file creation errors
            }
        }
    }
    log(level, message, meta) {
        const entry = {
            level,
            message,
            timestamp: new Date().toISOString(),
            ...meta
        };
        const logLine = (0, node_util_1.format)('[%s] %s: %s %s', entry.timestamp, entry.level.toUpperCase(), entry.message, meta ? JSON.stringify(meta) : '');
        // Console output
        console.log(logLine);
        // File output (if available)
        if (this.logStream) {
            this.logStream.write(logLine + '\n');
        }
    }
    info(message, meta) {
        this.log('info', message, meta);
    }
    warn(message, meta) {
        this.log('warn', message, meta);
    }
    error(message, meta) {
        this.log('error', message, meta);
    }
    debug(message, meta) {
        if (process.env.NODE_ENV !== 'production') {
            this.log('debug', message, meta);
        }
    }
}
exports.logger = new MinimalLogger();
function logServerStart(platform) {
    exports.logger.info(`MCP Server starting on ${platform}`, {
        platform,
        nodeVersion: process.version,
        pid: process.pid,
        cwd: process.cwd()
    });
}
