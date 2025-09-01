"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
exports.logServerStart = logServerStart;
const winston = require("winston");
const environment_js_1 = require("../config/environment.js");
// Configure structured logging
exports.logger = winston.createLogger({
    level: environment_js_1.config.logLevel,
    format: winston.format.combine(winston.format.timestamp(), winston.format.errors({ stack: true }), winston.format.json()),
    transports: [
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});
function logServerStart(platform) {
    exports.logger.info("MCP Server starting", {
        platform,
        config: {
            allowedRoot: environment_js_1.config.allowedRoot ? "configured" : "unrestricted",
            webAllowlist: environment_js_1.config.webAllowlist ? "configured" : "unrestricted",
            procAllowlist: environment_js_1.config.procAllowlist ? "configured" : "unrestricted"
        }
    });
}
