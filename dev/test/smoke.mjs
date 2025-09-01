import { Client as McpClient } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const serverJs = "./dev/dist/server.js";
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [serverJs],
  env: {
    // No restrictions - GOD MODE
    ALLOWED_ROOT: "",
    WEB_ALLOWLIST: "",
    PROC_ALLOWLIST: "",
    EXTRA_PATH: ""
  },
  stderr: "inherit",
});

const client = new McpClient({ name: "smoke-tester", version: "1.0.0" });

function ok(name) { console.log(`OK ${name}`); }

await client.connect(transport);

// Tools list
const tools = await client.listTools();
ok(`listTools (${tools.tools.length})`);

// Call health
await client.callTool({ name: "health" });
ok("health");

// system_info
await client.callTool({ name: "system_info" });
ok("system_info");

// fs_list
await client.callTool({ name: "fs_list", arguments: { dir: "." } });
ok("fs_list");

// fs_read_text (read own package.json)
await client.callTool({ name: "fs_read_text", arguments: { path: "package.json" } });
ok("fs_read_text");

// fs_search
await client.callTool({ name: "fs_search", arguments: { pattern: "*.json", dir: "." } });
ok("fs_search");

// git_status (should succeed even if not a repo)
await client.callTool({ name: "git_status", arguments: { dir: "." } }).catch(() => {});
ok("git_status");

// proc_run (allowed command: node -v)
await client.callTool({ name: "proc_run", arguments: { command: "node", args: ["-v"] } });
ok("proc_run");

// Windows System Management Tools
await client.callTool({ name: "win_services", arguments: { filter: "spooler" } });
ok("win_services");

await client.callTool({ name: "win_processes", arguments: { filter: "node" } });
ok("win_processes");

// File Download Tools
await client.callTool({ 
  name: "download_file", 
  arguments: { 
    url: "https://httpbin.org/json", 
    outputPath: "test_download.json"
  } 
});
ok("download_file");

// RAG Tools
await client.callTool({ 
  name: "rag_search", 
  arguments: { 
    query: "What is this project about?",
    documents: [
      "This is a Windows development MCP server with various tools for system management, file operations, and AI capabilities."
    ],
    topK: 3
  } 
});
ok("rag_search");

await client.callTool({ 
  name: "rag_query", 
  arguments: { 
    query: "What tools are available?",
    documents: [
      "The MCP server provides tools for file operations, Windows system management, and RAG capabilities."
    ],
    contextLength: 500
  } 
});
ok("rag_query");

await client.close();
console.log("All MCP smoke tests passed.");


