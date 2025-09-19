#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Define schemas for more critical tools
const moreToolSchemas = {
  // File System Tools
  fs_list: [
    { name: "dir", type: "string", required: false, description: "The directory path to list files and folders from" }
  ],

  fs_read_text: [
    { name: "path", type: "string", required: true, description: "The file path to read from" }
  ],

  fs_write_text: [
    { name: "path", type: "string", required: true, description: "The file path to write to" },
    { name: "content", type: "string", required: true, description: "The text content to write to the file" }
  ],

  fs_search: [
    { name: "dir", type: "string", required: false, description: "The directory to search in" },
    { name: "pattern", type: "string", required: true, description: "The file name pattern to search for" }
  ],

  grep: [
    { name: "pattern", type: "string", required: true, description: "The search pattern" },
    { name: "path", type: "string", required: true, description: "The directory or file path to search in" },
    { name: "recursive", type: "boolean", required: false, description: "Search subdirectories recursively" },
    { name: "caseInsensitive", type: "boolean", required: false, description: "Case-insensitive search" },
    { name: "regex", type: "boolean", required: false, description: "Treat pattern as regex" }
  ],

  advanced_grep: [
    { name: "pattern", type: "string", required: true, description: "The search pattern" },
    { name: "path", type: "string", required: false, description: "The directory or file path to search in" },
    { name: "recursive", type: "boolean", required: false, description: "Search subdirectories recursively" },
    { name: "caseInsensitive", type: "boolean", required: false, description: "Case-insensitive search" },
    { name: "regex", type: "boolean", required: false, description: "Treat pattern as regex" },
    { name: "contextBefore", type: "number", required: false, description: "Number of lines to show before each match" },
    { name: "contextAfter", type: "number", required: false, description: "Number of lines to show after each match" },
    { name: "includePattern", type: "array[string]", required: false, description: "File patterns to include" },
    { name: "excludePattern", type: "array[string]", required: false, description: "File patterns to exclude" }
  ],

  // Process Tools
  proc_run: [
    { name: "command", type: "string", required: true, description: "Command to execute" },
    { name: "args", type: "array[string]", required: false, description: "Command line arguments" },
    { name: "working_dir", type: "string", required: false, description: "Working directory for execution" },
    { name: "timeout", type: "number", required: false, description: "Execution timeout in seconds" },
    { name: "capture_output", type: "boolean", required: false, description: "Capture command output" }
  ],

  proc_run_elevated: [
    { name: "command", type: "string", required: true, description: "Command to execute with elevated privileges" },
    { name: "args", type: "array[string]", required: false, description: "Command line arguments" },
    { name: "reason", type: "string", required: false, description: "Reason for requiring elevated privileges" },
    { name: "working_dir", type: "string", required: false, description: "Working directory for execution" },
    { name: "timeout", type: "number", required: false, description: "Execution timeout in seconds" }
  ],

  // Email Tools
  send_email: [
    { name: "to", type: "string", required: true, description: "Recipient email address" },
    { name: "subject", type: "string", required: true, description: "Email subject line" },
    { name: "body", type: "string", required: true, description: "Email body content" },
    { name: "from", type: "string", required: false, description: "Sender email address" },
    { name: "html", type: "boolean", required: false, description: "Send as HTML email" },
    { name: "attachments", type: "array[string]", required: false, description: "File paths to attach" }
  ],

  read_emails: [
    { name: "username", type: "string", required: true, description: "Email username" },
    { name: "password", type: "string", required: true, description: "Email password" },
    { name: "imap_server", type: "string", required: true, description: "IMAP server address" },
    { name: "folder", type: "string", required: false, description: "Email folder to read (default: INBOX)" },
    { name: "limit", type: "number", required: false, description: "Maximum number of emails to retrieve" },
    { name: "unread_only", type: "boolean", required: false, description: "Retrieve only unread emails" }
  ],

  // Screenshot Tool
  screenshot: [
    { name: "action", type: "enum[capture,capture_area,capture_window,capture_delay,capture_continuous]", required: true, description: "Screenshot action to perform" },
    { name: "output_path", type: "string", required: false, description: "Output file path for screenshot" },
    { name: "format", type: "enum[png,jpg,bmp]", required: false, description: "Output format" },
    { name: "delay", type: "number", required: false, description: "Delay before capture in seconds" },
    { name: "area", type: "object", required: false, description: "Area to capture (for capture_area)" }
  ],

  // OCR Tool
  ocr_tool: [
    { name: "image_path", type: "string", required: true, description: "Path to image file for OCR processing" },
    { name: "language", type: "string", required: false, description: "Language code for OCR processing" },
    { name: "output_format", type: "enum[text,json,xml,pdf]", required: false, description: "Output format for extracted text" },
    { name: "preprocess", type: "boolean", required: false, description: "Enable automatic image preprocessing" },
    { name: "confidence_threshold", type: "number", required: false, description: "Minimum confidence threshold for text recognition" }
  ],

  // Virtualization Tools
  vm_management: [
    { name: "action", type: "enum[list,start,stop,create,delete,status,snapshot]", required: true, description: "VM management action to perform" },
    { name: "vm_name", type: "string", required: false, description: "Name of the virtual machine" },
    { name: "vm_type", type: "enum[vmware,virtualbox,hyperv,kvm]", required: false, description: "Type of virtualization platform" },
    { name: "config", type: "object", required: false, description: "VM configuration parameters" }
  ],

  docker_management: [
    { name: "action", type: "enum[list_containers,list_images,start,stop,create,remove,logs,exec]", required: true, description: "Docker management action to perform" },
    { name: "container_name", type: "string", required: false, description: "Name or ID of the container" },
    { name: "image_name", type: "string", required: false, description: "Name of the Docker image" },
    { name: "command", type: "string", required: false, description: "Command to execute in container" },
    { name: "ports", type: "array[string]", required: false, description: "Port mappings" }
  ],

  // Windows Tools
  win_services: [
    { name: "action", type: "enum[list,start,stop,restart,status,config]", required: true, description: "Service management action to perform" },
    { name: "service_name", type: "string", required: false, description: "Name of the Windows service" },
    { name: "service_display_name", type: "string", required: false, description: "Display name of the service" },
    { name: "force", type: "boolean", required: false, description: "Force the operation" }
  ],

  win_processes: [
    { name: "action", type: "enum[list,kill,suspend,resume,info,tree]", required: true, description: "Process management action to perform" },
    { name: "process_name", type: "string", required: false, description: "Process name for operations" },
    { name: "process_id", type: "number", required: false, description: "Process ID for operations" },
    { name: "force", type: "boolean", required: false, description: "Force the operation" }
  ],

  // Network Tools
  network_diagnostics: [
    { name: "target", type: "string", required: true, description: "Target host or network to diagnose" },
    { name: "tests", type: "array[string]", required: false, description: "Network tests to perform" },
    { name: "timeout", type: "number", required: false, description: "Timeout for individual tests in seconds" },
    { name: "output_format", type: "string", required: false, description: "Output format for results" }
  ],

  download_file: [
    { name: "url", type: "string", required: true, description: "The URL of the file to download" },
    { name: "outputPath", type: "string", required: false, description: "Optional custom filename for the downloaded file" }
  ],

  // Utility Tools
  calculator: [
    { name: "operation", type: "enum[add,subtract,multiply,divide,power,sqrt,percentage]", required: true, description: "Mathematical operation to perform" },
    { name: "a", type: "number", required: true, description: "First number for calculation" },
    { name: "b", type: "number", required: false, description: "Second number for calculation" },
    { name: "precision", type: "number", required: false, description: "Decimal precision for result" }
  ],

  enhanced_calculator: [
    { name: "mode", type: "enum[basic,advanced,expression]", required: false, description: "Calculation mode" },
    { name: "operation", type: "enum[add,subtract,multiply,divide,power,sqrt,percentage,factorial,abs,round,floor,ceil]", required: false, description: "Mathematical operation to perform" },
    { name: "expression", type: "string", required: false, description: "Mathematical expression to evaluate" },
    { name: "a", type: "number", required: false, description: "First number for calculation" },
    { name: "b", type: "number", required: false, description: "Second number for calculation" },
    { name: "precision", type: "number", required: false, description: "Decimal precision for results" },
    { name: "variables", type: "object", required: false, description: "Variables to substitute in expression" }
  ]
};

function updateManifestWithMoreSchemas() {
  const manifestPath = path.join(__dirname, '..', 'tools.manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  
  let updatedCount = 0;
  
  // Update tools that have schemas defined
  Object.keys(moreToolSchemas).forEach(toolName => {
    const toolIndex = manifest.tools.findIndex(tool => tool.name === toolName);
    if (toolIndex !== -1) {
      const currentTool = manifest.tools[toolIndex];
      if (Array.isArray(currentTool.args) && currentTool.args.length === 0) {
        manifest.tools[toolIndex].args = moreToolSchemas[toolName];
        console.log(`✅ Updated ${toolName} with ${moreToolSchemas[toolName].length} parameters`);
        updatedCount++;
      } else {
        console.log(`⚠️  ${toolName} already has args, skipping`);
      }
    } else {
      console.log(`❌ Tool ${toolName} not found in manifest`);
    }
  });
  
  if (updatedCount > 0) {
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
    console.log(`\n✅ Updated ${updatedCount} tools with proper schemas`);
    console.log(`📁 Manifest saved to ${manifestPath}`);
  } else {
    console.log('\n⚠️  No tools were updated');
  }
  
  return updatedCount;
}

if (require.main === module) {
  console.log('🔧 Adding More Tool Schemas to Manifest\n');
  updateManifestWithMoreSchemas();
}

module.exports = { moreToolSchemas, updateManifestWithMoreSchemas };
