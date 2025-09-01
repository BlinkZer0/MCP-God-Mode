import { createWriteStream } from "node:fs";
import { format } from "node:util";

interface LogEntry {
  level: string;
  message: string;
  timestamp: string;
  [key: string]: any;
}

class MinimalLogger {
  private logStream: NodeJS.WritableStream | null = null;

  constructor() {
    // Only create log file in development
    if (process.env.NODE_ENV !== 'production') {
      try {
        this.logStream = createWriteStream('mcp-server.log', { flags: 'a' });
      } catch (error) {
        // Ignore log file creation errors
      }
    }
  }

  private log(level: string, message: string, meta?: any) {
    const entry: LogEntry = {
      level,
      message,
      timestamp: new Date().toISOString(),
      ...meta
    };

    const logLine = format('[%s] %s: %s %s', 
      entry.timestamp, 
      entry.level.toUpperCase(), 
      entry.message,
      meta ? JSON.stringify(meta) : ''
    );

    // Console output
    console.log(logLine);

    // File output (if available)
    if (this.logStream) {
      this.logStream.write(logLine + '\n');
    }
  }

  info(message: string, meta?: any) {
    this.log('info', message, meta);
  }

  warn(message: string, meta?: any) {
    this.log('warn', message, meta);
  }

  error(message: string, meta?: any) {
    this.log('error', message, meta);
  }

  debug(message: string, meta?: any) {
    if (process.env.NODE_ENV !== 'production') {
      this.log('debug', message, meta);
    }
  }
}

export const logger = new MinimalLogger();

export function logServerStart(platform: string) {
  logger.info(`MCP Server starting on ${platform}`, {
    platform,
    nodeVersion: process.version,
    pid: process.pid,
    cwd: process.cwd()
  });
}
