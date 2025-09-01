#!/usr/bin/env node

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "node",
  args: ["dist/server.js"]
});

const client = new Client({
  name: "test-client",
  version: "1.0.0"
}, {
  capabilities: {}
});

await client.connect(transport);

console.log("Testing elevated execution tools...");

try {
  // Test proc_run_elevated
  console.log("Testing proc_run_elevated...");
  const result1 = await client.callTool({ 
    name: "proc_run_elevated", 
    arguments: { command: "echo", args: ["test_elevated"] } 
  });
  console.log("✓ proc_run_elevated: OK");
  console.log("  Platform:", result1.content[0]?.structuredContent?.platform);
  console.log("  Elevated:", result1.content[0]?.structuredContent?.elevated);
} catch (error) {
  console.log("✗ proc_run_elevated: FAILED -", error.message);
}

try {
  // Test unix_sudo_exec
  console.log("\nTesting unix_sudo_exec...");
  const result2 = await client.callTool({ 
    name: "unix_sudo_exec", 
    arguments: { command: "echo", args: ["test_sudo"], interactive: false } 
  });
  console.log("✓ unix_sudo_exec: OK");
  console.log("  Platform:", result2.content[0]?.structuredContent?.platform);
  console.log("  Sudo Used:", result2.content[0]?.structuredContent?.sudoUsed);
} catch (error) {
  console.log("✗ unix_sudo_exec: FAILED -", error.message);
}

try {
  // Test shell_exec_smart
  console.log("\nTesting shell_exec_smart...");
  const result3 = await client.callTool({ 
    name: "shell_exec_smart", 
    arguments: { command: "echo", args: ["test_smart"], autoElevate: false } 
  });
  console.log("✓ shell_exec_smart: OK");
  console.log("  Platform:", result3.content[0]?.structuredContent?.platform);
  console.log("  Elevation Used:", result3.content[0]?.structuredContent?.elevationUsed);
} catch (error) {
  console.log("✗ shell_exec_smart: FAILED -", error.message);
}

console.log("\nElevated execution tools testing complete!");

await client.close();
process.exit(0);
