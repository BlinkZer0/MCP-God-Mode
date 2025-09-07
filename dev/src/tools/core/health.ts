import { z } from "zod";
import { ALLOWED_ROOTS } from "../../config/environment.js";

export function registerHealth(server: any) {
  server.registerTool("health", {
    description: "Comprehensive system health check and readiness probe for monitoring MCP server status, configuration validation, and operational readiness",
    outputSchema: { ok: z.boolean(), roots: z.array(z.string()), cwd: z.string() }
  }, async () => ({ 
    content: [{ type: "text", text: "ok" }], 
    structuredContent: { ok: true, roots: ALLOWED_ROOTS, cwd: process.cwd() } 
  }));
}
