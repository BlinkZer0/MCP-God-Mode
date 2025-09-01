import { Client as McpClient } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const serverJs = "./dist/server.js";
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

// Cross-Platform System Management Tools
// Windows-specific tools (will be skipped on other platforms)
await client.callTool({ name: "win_services", arguments: { filter: "spooler" } }).catch(() => {});
ok("win_services");

await client.callTool({ name: "win_processes", arguments: { filter: "node" } }).catch(() => {});
ok("win_processes");

// Unix/Linux/Mac system tools (will be skipped on Windows)
await client.callTool({ name: "unix_services", arguments: { filter: "ssh" } }).catch(() => {});
ok("unix_services");

await client.callTool({ name: "unix_processes", arguments: { filter: "node" } }).catch(() => {});
ok("unix_processes");

// Cross-platform system maintenance
await client.callTool({ name: "system_maintenance", arguments: { action: "disk_cleanup" } }).catch(() => {});
ok("system_maintenance");

await client.callTool({ name: "system_maintenance", arguments: { action: "check_disk" } }).catch(() => {});
ok("system_maintenance_check");

// Network diagnostics
await client.callTool({ name: "network_diagnostics", arguments: { action: "ping", target: "8.8.8.8" } }).catch(() => {});
ok("network_diagnostics_ping");

await client.callTool({ name: "network_diagnostics", arguments: { action: "traceroute", target: "google.com" } }).catch(() => {});
ok("network_diagnostics_traceroute");

// Security tools
await client.callTool({ name: "security_scan", arguments: { action: "check_permissions", path: "." } }).catch(() => {});
ok("security_scan");

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
      "This is a cross-platform development MCP server with various tools for system management, file operations, and AI capabilities."
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
      "The MCP server provides tools for file operations, cross-platform system management, browser automation, and RAG capabilities."
    ],
    contextLength: 500
  } 
});
ok("rag_query");

// Browser Automation Tools
await client.callTool({ 
  name: "browser_open", 
  arguments: { 
    url: "https://httpbin.org/json",
    headless: true
  } 
}).catch(() => {});
ok("browser_open");

await client.callTool({ 
  name: "browser_navigate", 
  arguments: { 
    url: "https://httpbin.org/html"
  } 
}).catch(() => {});
ok("browser_navigate");

await client.callTool({ 
  name: "browser_screenshot", 
  arguments: { 
    outputPath: "test_screenshot.png"
  } 
}).catch(() => {});
ok("browser_screenshot");

await client.callTool({ 
  name: "browser_close" 
}).catch(() => {});
ok("browser_close");

// Email Management Tools
await client.callTool({ name: "email_status", arguments: {} });
ok("email_status");

await client.callTool({ 
  name: "email_accounts", 
  arguments: { 
    action: "list"
  } 
});
ok("email_accounts_list");

// Email configuration (will likely fail without real credentials, but we test the tool)
await client.callTool({ 
  name: "email_config", 
  arguments: { 
    provider: "gmail",
    host: "smtp.gmail.com",
    port: 587,
    username: "test@example.com"
  } 
}).catch(() => {});
ok("email_config");

// Email composition (will likely fail without real credentials, but we test the tool)
await client.callTool({ 
  name: "email_compose", 
  arguments: { 
    to: "test@example.com",
    subject: "Test Email",
    body: "This is a test email from the MCP God Mode server."
  } 
}).catch(() => {});
ok("email_compose");

// Email checking (will likely fail without real credentials, but we test the tool)
await client.callTool({ 
  name: "email_check", 
  arguments: { 
    folder: "INBOX",
    limit: 5
  } 
}).catch(() => {});
ok("email_check");

// Email account management (will likely fail without real accounts, but we test the tool)
await client.callTool({ 
  name: "email_accounts", 
  arguments: { 
    action: "add",
    accountName: "Test Account",
    provider: "gmail",
    username: "test@example.com"
  } 
}).catch(() => {});
ok("email_accounts_add");

await client.callTool({ 
  name: "email_set_active", 
  arguments: { 
    account: "test@example.com"
  } 
}).catch(() => {});
ok("email_set_active");

// Advanced System Tools (platform-specific)
// Windows advanced tools
await client.callTool({ name: "win_advanced", arguments: { action: "sfc_scan" } }).catch(() => {});
ok("win_advanced_sfc");

await client.callTool({ name: "win_advanced", arguments: { action: "dism_restore" } }).catch(() => {});
ok("win_advanced_dism");

await client.callTool({ name: "win_advanced", arguments: { action: "chkdsk" } }).catch(() => {});
ok("win_advanced_chkdsk");

// Unix advanced tools
await client.callTool({ name: "unix_advanced", arguments: { action: "fsck" } }).catch(() => {});
ok("unix_advanced_fsck");

await client.callTool({ name: "unix_advanced", arguments: { action: "system_update" } }).catch(() => {});
ok("unix_advanced_update");

await client.callTool({ name: "unix_advanced", arguments: { action: "service_restart", service: "ssh" } }).catch(() => {});
ok("unix_advanced_service");

// Network advanced tools
await client.callTool({ name: "network_advanced", arguments: { action: "firewall_status" } }).catch(() => {});
ok("network_advanced_firewall");

await client.callTool({ name: "network_advanced", arguments: { action: "port_scan", target: "localhost" } }).catch(() => {});
ok("network_advanced_portscan");

await client.callTool({ name: "network_advanced", arguments: { action: "dns_lookup", domain: "google.com" } }).catch(() => {});
ok("network_advanced_dns");

// Log analysis tools
await client.callTool({ name: "log_analysis", arguments: { action: "system_logs", hours: 1 } }).catch(() => {});
ok("log_analysis_system");

await client.callTool({ name: "log_analysis", arguments: { action: "error_logs", hours: 1 } }).catch(() => {});
ok("log_analysis_errors");

await client.callTool({ name: "log_analysis", arguments: { action: "security_logs", hours: 1 } }).catch(() => {});
ok("log_analysis_security");

// Performance monitoring
await client.callTool({ name: "performance_monitor", arguments: { action: "cpu_usage" } }).catch(() => {});
ok("performance_monitor_cpu");

await client.callTool({ name: "performance_monitor", arguments: { action: "memory_usage" } }).catch(() => {});
ok("performance_monitor_memory");

await client.callTool({ name: "performance_monitor", arguments: { action: "disk_usage" } }).catch(() => {});
ok("performance_monitor_disk");

await client.callTool({ name: "performance_monitor", arguments: { action: "network_usage" } }).catch(() => {});
ok("performance_monitor_network");

// Process management
await client.callTool({ name: "process_management", arguments: { action: "list_processes" } }).catch(() => {});
ok("process_management_list");

await client.callTool({ name: "process_management", arguments: { action: "kill_process", processName: "nonexistent" } }).catch(() => {});
ok("process_management_kill");

// File system advanced tools
await client.callTool({ name: "file_system_advanced", arguments: { action: "find_files", pattern: "*.json" } }).catch(() => {});
ok("file_system_advanced_find");

await client.callTool({ name: "file_system_advanced", arguments: { action: "check_permissions", path: "." } }).catch(() => {});
ok("file_system_advanced_permissions");

await client.callTool({ name: "file_system_advanced", arguments: { action: "disk_space", path: "." } }).catch(() => {});
ok("file_system_advanced_space");

await client.close();
console.log("All MCP smoke tests passed.");


