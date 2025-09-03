import * as winston from "winston";
import { config } from "../config/environment.js";

// Configure structured logging
export const logger = winston.createLogger({
  level: config.logLevel,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

export function logServerStart(platform: string) {
  logger.info("MCP Server starting", { 
    platform,
    config: { 
      allowedRoot: config.allowedRoot ? "configured" : "unrestricted",
      webAllowlist: config.webAllowlist ? "configured" : "unrestricted",
      procAllowlist: config.procAllowlist ? "configured" : "unrestricted"
    } 
  });
}
