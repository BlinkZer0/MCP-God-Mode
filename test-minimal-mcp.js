#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

console.log("🚀 Starting Minimal Test MCP Server...");

const server = new McpServer({ name: "Test MCP Server", version: "1.0.0" });

// Register a simple test tool
server.registerTool("test_tool", {
  description: "A simple test tool to verify MCP connection",
  inputSchema: { message: z.string().describe("Test message") },
  outputSchema: { success: z.boolean(), response: z.string() }
}, async ({ message }) => {
  console.log(`📝 Received test message: ${message}`);
  return {
    content: [],
    structuredContent: {
      success: true,
      response: `Echo: ${message}`
    }
  };
});

// Register a health check tool
server.registerTool("health", {
  description: "Health check for the test server",
  outputSchema: { ok: z.boolean(), message: z.string() }
}, async () => {
  return {
    content: [],
    structuredContent: {
      ok: true,
      message: "Test MCP Server is running!"
    }
  };
});

console.log("✅ Test tools registered");
console.log("🔌 Connecting to stdio transport...");

const transport = new StdioServerTransport();
server.connect(transport);

console.log("✅ Test MCP Server ready and connected!");
console.log("📋 Available tools: test_tool, health");
