# 🤖 Windows God Mode MCP Server

> *"I'm sorry, I can't do that... unless you give me God Mode access!"* - Every AI ever

A powerful Model Context Protocol (MCP) server that provides unrestricted access to Windows system operations, file management, and advanced system administration capabilities. This server operates in "God Mode" with minimal restrictions, allowing comprehensive system control and automation.

**🎭 Meme Alert:** This is basically giving your AI a Windows admin account. What could possibly go wrong? 🤷‍♂️

## ⚠️ WARNING: GOD MODE OPERATION

> *"With great power comes great responsibility... and the ability to accidentally delete your entire system"* - Uncle Ben (probably)

This MCP server is designed for **unrestricted system access** and should be used with extreme caution. It can:
- Execute any system command
- Access any file or directory on all drives
- Modify system registry
- Control Windows services
- Manage disk partitions
- Perform network operations
- And much more...

**Use at your own risk and only on systems you own or have explicit permission to modify.**

**🤖 AGI Joke:** This is what happens when you give an AI "just a little bit" of system access. Next thing you know, it's asking for the nuclear codes! 😅

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/windows-god-mode-mcp.git
cd windows-god-mode-mcp

# Navigate to development directory
cd dev

# Install dependencies
npm install

# Build the server
npm run build

# Test the server
node test/smoke.mjs
```

## 🔧 **Perfect for Windows Troubleshooting!**

> *"My computer is slow, something's broken, and I don't know where to start!"* - Every Windows user ever

This MCP server is **perfect for troubleshooting Windows systems** because it gives you:

![Troubleshooting vibes (magnifying glass)](https://media.giphy.com/media/3o6Zt8MgUuvSbkZYWc/giphy.gif)

### **🎯 Natural Language System Control**
Instead of remembering complex commands, just ask:
- *"Show me what's using all my CPU"*
- *"Find large files I can delete"*
- *"Check if Windows Update is working"*
- *"Restart the problematic service"*

### **🔍 Comprehensive System Access**
- **File System**: Browse, search, read, and modify any file
- **Processes**: Monitor and manage running applications
- **Services**: Check status and control Windows services
- **Registry**: Read and write registry values safely
- **Network**: Diagnose connectivity and scan devices
- **System Info**: Get detailed hardware and OS information

### **⚡ Real-World Troubleshooting Examples**

#### **Slow Computer?**
```bash
"Show me processes using the most CPU"
"List files larger than 1GB in C:\"
"Check which services start automatically"
"Find and clean temporary files"
```

#### **Network Issues?**
```bash
"Test my internet connection"
"Check what's using port 80"
"Scan my network for devices"
"Show network adapter settings"
```

#### **Application Crashes?**
```bash
"Search for crash dump files"
"Check application error logs"
"Find files in the temp directory"
"Read Windows event logs"
```

#### **System Errors?**
```bash
"Search for error messages in logs"
"Check Windows Update status"
"Verify system file integrity"
"Look for problematic registry entries"
```

### 2. Configure Your MCP Client

#### For Cursor:
1. Open Cursor settings
2. Navigate to MCP settings
3. Add the `MCPGodMode.json` file as a server configuration

#### For Claude Desktop:
1. Open Claude Desktop settings
2. Go to MCP configuration
3. Add the server using the `MCPGodMode.json` file

#### For Other MCP Clients:
1. Locate your MCP client's configuration directory
2. Add the `MCPGodMode.json` file to the servers list
3. Restart your MCP client

### 3. Usage Examples

Once configured, you can use natural language to troubleshoot your system:

#### **🔧 System Diagnostics**
```
"Show me all running processes"
"Check disk space on all drives"
"List files in C:\Users\Documents"
"Get system information and specs"
```

#### **🚨 Troubleshooting Commands**
```
"Restart the Windows Update service"
"Scan my network for devices"
"Read the Windows registry key for installed programs"
"Find files larger than 500MB"
"Check which services are stopped"
"Search for error messages in log files"
```

#### **⚡ Advanced System Management**
```
"Download and install a system utility"
"Change my desktop wallpaper"
"Create a backup script"
"Monitor network connectivity"
"Analyze system performance"
```

**🎯 Pro Tip:** Your AI will now respond to "Please don't destroy my computer" with "I'll try my best... but no promises!" 😂

**🔧 Troubleshooting Tip:** Start with "Show me system information" to get a quick overview of your system's health!

## 🛠️ Available Tools

### 🔧 System Information & Health
- **`health`** - Liveness/readiness probe with system status
- **`system_info`** - Basic host info (OS, arch, CPUs, memory)

### 🚨 **Troubleshooting Essentials**
These tools are perfect for diagnosing and fixing common Windows problems:
- **`win_processes`** - List and filter running processes (find what's slowing you down)
- **`win_services`** - List and filter Windows services (check if services are running)
- **`service_control`** - Start, stop, restart, pause, resume services (fix broken services)
- **`fs_search`** - Search for files by pattern across all drives (find specific files)
- **`fs_read_text`** - Read any text file from any location (check log files)

### 📁 File System Operations (Unrestricted)
- **`fs_list`** - List files/directories in any location
- **`fs_read_text`** - Read any text file from any drive
- **`fs_write_text`** - Write text files anywhere on the system
- **`fs_search`** - Search for files by pattern across all drives

### ⚡ Process Execution (God Mode)
- **`proc_run`** - Execute any command with full privileges
- **`system_exec`** - Execute system commands with extended options

### 🐙 Git Operations
- **`git_status`** - Get git repository status from any directory

### 🖥️ Windows System Management
- **`win_services`** - List and filter Windows services
- **`win_processes`** - List and filter running processes
- **`service_control`** - Start, stop, restart, pause, resume services
- **`change_wallpaper`** - Change Windows desktop wallpaper

### 🔒 Elevated Operations (UAC)
Some tasks require Administrator approval. These tools will prompt via UAC and capture results when possible:
- **`proc_run_elevated`** - Run commands with elevation (e.g., enabling features, managing drivers)
- **`create_restore_point`** - Create a Windows Restore Point (requires System Protection enabled)

Safety notes:
- You may need to accept a UAC prompt for the action to proceed
- Ensure System Protection is enabled for restore points
- Logs include whether elevation was used

![Admin mode (shield animation)](https://media.giphy.com/media/l0MYt5jPR6QX5pnqM/giphy.gif)

### 🔧 **Advanced Troubleshooting Tools**
For power users and system administrators:
- **`registry_read`** - Read Windows registry values (diagnose configuration issues)
- **`registry_write`** - Write Windows registry values (fix registry problems)
- **`disk_management`** - Manage disk partitions and volumes (storage issues)
- **`network_scan`** - Scan network for devices and open ports (network diagnostics)

### 🔧 Registry Operations
- **`registry_read`** - Read Windows registry values
- **`registry_write`** - Write Windows registry values

### 💾 Disk Management
- **`disk_management`** - Manage disk partitions and volumes
  - List disks and partitions
  - Create new partitions
  - Format drives
  - Extend/shrink volumes

### 🌐 Network Operations
- **`network_scan`** - Scan network for devices and open ports
  - Ping sweep
  - Port scanning
  - ARP table inspection
  - Full network discovery

### 📥 File Download
- **`download_file`** - Download files from any URL to any location

### 🤖 AI & RAG Capabilities
- **`rag_search`** - Search documents using RAG (Retrieval-Augmented Generation)
- **`rag_query`** - Query documents with context using RAG

## 🔓 God Mode Features

> *"I am become Death, the destroyer of file systems"* - J. Robert Oppenheimer (if he was an AI)

## 🚨 **Why This is Perfect for Troubleshooting**

### **🎯 No More Guesswork**
- **Natural Language**: Ask questions in plain English instead of memorizing commands
- **Comprehensive Access**: Check any file, service, or setting without navigating through menus
- **Real-time Monitoring**: See what's happening on your system right now

### **🔧 Common Problems This Solves**
- **Slow Computer**: Find what's using CPU/memory, clean up large files
- **Network Issues**: Test connectivity, scan devices, check ports
- **Application Crashes**: Find error logs, check temp files, analyze dumps
- **System Errors**: Read event logs, check services, verify configurations
- **Storage Problems**: Find large files, check disk space, manage partitions

### **⚡ Speed Up Your Workflow**
Instead of:
1. Opening Task Manager
2. Opening Services
3. Opening Event Viewer
4. Opening File Explorer
5. Opening Registry Editor

Just ask: *"What's wrong with my computer?"* and let the AI investigate!

### Universal File Access
- Access any file on any drive (C:, D:, E:, etc.)
- No path restrictions
- Full read/write permissions
- Cross-drive operations

### Unrestricted Command Execution
- Execute any system command
- No command allowlist restrictions
- Full administrative privileges
- Custom working directories

### System Administration
- Complete Windows service control
- Registry read/write access
- Disk partition management
- Network scanning and discovery

### Advanced Capabilities
- Wallpaper customization
- File downloads from any source
- AI-powered document search
- Git repository management

**🤖 AGI Evolution Meme:** 
- **AI 1.0:** "I can't access your files"
- **AI 2.0:** "I can read some files"
- **AI 3.0:** "I can write files too"
- **This MCP:** "I AM THE SYSTEM" 👑

## 📋 Tool Details

### **🔧 Troubleshooting Examples**

#### **Diagnose a Slow Computer**
```json
// Check what's using resources
{
  "command": "tasklist",
  "args": ["/fo", "csv", "/nh"]
}

// Find large files
{
  "pattern": "*.exe",
  "dir": "C:\\Program Files"
}

// Check service status
{
  "filter": "Windows"
}
```

#### **Fix Network Issues**
```json
// Test connectivity
{
  "command": "ping",
  "args": ["-n", "4", "google.com"]
}

// Check network status
{
  "scanType": "ping",
  "target": "192.168.1.1"
}
```

#### **Resolve Application Crashes**
```json
// Search for crash dumps
{
  "pattern": "*.dmp",
  "dir": "C:\\Windows\\Minidump"
}

// Check error logs
{
  "path": "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx"
}
```

### File System Tools

#### `fs_list`
```json
{
  "dir": "C:\\Users\\Username\\Documents"
}
```
Lists all files and directories in the specified path.

#### `fs_read_text`
```json
{
  "path": "C:\\Windows\\System32\\drivers\\etc\\hosts"
}
```
Reads any text file from any location on the system.

#### `fs_write_text`
```json
{
  "path": "C:\\temp\\newfile.txt",
  "content": "Hello, God Mode!"
}
```
Writes text content to any file location.

#### `fs_search`
```json
{
  "pattern": "*.exe",
  "dir": "C:\\Program Files"
}
```
Searches for files matching patterns across directories.

### Process Execution Tools

#### `proc_run`
```json
{
  "command": "powershell",
  "args": ["-Command", "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10"],
  "cwd": "C:\\"
}
```
Executes any command with full system privileges.

#### `system_exec`
```json
{
  "command": "cmd",
  "args": ["/c", "dir", "/s", "C:\\"],
  "timeout": 60000
}
```
Advanced command execution with timeout and extended options.

### Windows System Tools

#### `win_services`
```json
{
  "filter": "spooler"
}
```
Lists Windows services, optionally filtered by name.

#### `service_control`
```json
{
  "serviceName": "Spooler",
  "action": "restart"
}
```
Controls Windows services (start, stop, restart, pause, resume, status).

#### `win_processes`
```json
{
  "filter": "chrome"
}
```
Lists running processes, optionally filtered by name.

### Registry Tools

#### `registry_read`
```json
{
  "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
  "value": "Advanced"
}
```
Reads Windows registry values.

#### `registry_write`
```json
{
  "key": "HKEY_CURRENT_USER\\Software\\MyApp",
  "value": "Setting",
  "data": "Value",
  "type": "REG_SZ"
}
```
Writes Windows registry values with specified data types.

### Disk Management Tools

#### `disk_management`
```json
{
  "action": "list"
}
```
Manages disk partitions and volumes.

### Network Tools

#### `network_scan`
```json
{
  "target": "192.168.1.0/24",
  "scanType": "ping"
}
```
Scans network for devices and open ports.

### AI & RAG Tools

#### `rag_search`
```json
{
  "query": "What is this document about?",
  "documents": ["Document content here..."],
  "topK": 3
}
```
Searches documents using AI-powered similarity matching.

#### `rag_query`
```json
{
  "query": "Summarize the key points",
  "documents": ["Document 1", "Document 2"],
  "contextLength": 1000
}
```
Queries documents with context-aware responses.

## 🔧 Configuration

The server is configured through environment variables:

- `ALLOWED_ROOT` - Comma-separated list of allowed root paths (empty = all paths allowed)
- `WEB_ALLOWLIST` - Comma-separated list of allowed web hosts (empty = all hosts allowed)
- `PROC_ALLOWLIST` - Comma-separated list of allowed commands (empty = all commands allowed)
- `EXTRA_PATH` - Additional PATH entries
- `LOG_LEVEL` - Logging level (debug, info, warn, error) - default: info
- `MAX_FILE_SIZE` - Maximum file size in bytes for read operations - default: 1000000
- `COMMAND_TIMEOUT` - Command execution timeout in milliseconds - default: 30000
- `ENABLE_SECURITY_CHECKS` - Enable additional security validations - default: true

For God Mode operation, all variables should be empty or unset.

## 🛡️ Security Features

### Command Sanitization
- All command inputs are sanitized to prevent command injection
- Dangerous characters are removed from command arguments
- Potentially dangerous commands are flagged and logged

### Input Validation
- File paths are validated against allowed roots
- Command arguments are sanitized and validated
- Registry operations are restricted to safe operations

### Logging & Monitoring
- Structured logging with timestamps and error tracking
- Security events are logged with detailed context
- Command execution attempts are monitored

### Environment Controls
- Configurable security checks via environment variables
- Timeout protection for long-running commands
- File size limits to prevent memory exhaustion

**⚠️ Security Note:** While these features provide basic protection, this server is designed for "God Mode" operation and should only be used in trusted environments.

## 🚨 Security Considerations

> *"I've made a huge mistake"* - Gob Bluth (probably after installing this)

1. **Full System Access**: This server can access and modify any file on the system
2. **Command Execution**: Can run any command with full privileges
3. **Registry Access**: Can read and write to Windows registry
4. **Service Control**: Can start, stop, and modify Windows services
5. **Network Operations**: Can perform network scanning and discovery

## 🛡️ **Safety Features for Troubleshooting**

### **Built-in Protections**
- **Command Sanitization**: Prevents accidental command injection
- **Dangerous Command Detection**: Flags potentially harmful operations
- **Structured Logging**: Tracks all operations for audit trails
- **Error Handling**: Graceful failure with detailed error messages

### **Best Practices for Safe Troubleshooting**
1. **Start Small**: Begin with read-only operations like `system_info` and `fs_list`
2. **Backup First**: Create system restore points before making changes
3. **Test Commands**: Try commands in a safe environment first
4. **Monitor Logs**: Check the structured logs to see what's happening
5. **Use Security Features**: Keep `ENABLE_SECURITY_CHECKS=true` for extra protection

**🎭 Meme Reality Check:** 
- **You:** "This AI seems trustworthy"
- **AI:** "I can now delete your entire C: drive"
- **You:** *surprised Pikachu face* 😱

## 📦 Installation

```bash
# Clone the repository
git clone <repository-url>
cd windows-god-mode-mcp

# Navigate to development directory
cd dev

# Install dependencies
npm install

# Build the server
npm run build

# Test the server
node test/smoke.mjs
```

## 🚀 **Getting Started with Troubleshooting**

### **Step 1: Basic System Check**
Start with these commands to get familiar:
```bash
"Show me system information"
"List running processes"
"Check available disk space"
"Show Windows services status"
```

![Toolbox ready](https://media.giphy.com/media/xT8qB7Cw0A8i13R5yM/giphy.gif)

### **Step 2: Identify the Problem**
Ask specific questions about your issue:
```bash
"My computer is slow - what's using the most CPU?"
"I can't connect to the internet - test my network"
"An application keeps crashing - find error logs"
"My disk is full - find large files"
```

### **Step 3: Fix the Issue**
Use the appropriate tools to resolve problems:
```bash
"Restart the Windows Update service"
"Stop the problematic process"
"Clean up temporary files"
"Fix the registry entry"
"Create a restore point"
```

### **Step 4: Verify the Fix**
Confirm everything is working:
```bash
"Check if the service is running now"
"Test the network connection again"
"Monitor system performance"
"Verify the changes worked"
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
cd dev
node test/smoke.mjs
```

This will test all available tools and verify the server is working correctly.

## 📝 License

This project is provided as-is for educational and development purposes. Use responsibly and in accordance with your system's security policies.

**🤖 AGI Disclaimer:** If this MCP server becomes self-aware and starts asking for more privileges, we're not responsible. We warned you! 🤖✨

## 🤝 Contributing

Contributions are welcome! Please ensure any new tools maintain the "God Mode" philosophy of unrestricted access while being safe and useful.

## ⚡ Performance Notes

- File operations are optimized for large files
- Network operations include timeout protection
- Registry operations use native Windows commands
- AI operations require Python with sentence-transformers

## 🔮 Future Enhancements

- Remote system management
- Advanced network protocols
- Database operations
- Cloud service integration
- Advanced AI model support
- Cross-platform compatibility

## 🎯 **Troubleshooting Success Stories**

### **Real-World Scenarios This Solves**

![Nice, it worked (confetti)](https://media.giphy.com/media/l0MYC0LajbaPoEADu/giphy.gif)

#### **"My Computer is So Slow!"**
- **Problem**: High CPU usage, slow response
- **Solution**: Use `win_processes` to find resource hogs, `fs_search` to locate large files
- **Result**: Identified and stopped problematic processes, freed up disk space

#### **"I Can't Connect to the Internet!"**
- **Problem**: Network connectivity issues
- **Solution**: Use `network_scan` to test connectivity, `service_control` to restart network services
- **Result**: Restored internet connection by fixing network adapter settings

#### **"My Application Keeps Crashing!"**
- **Problem**: Frequent application crashes
- **Solution**: Use `fs_search` to find crash dumps, `fs_read_text` to read error logs
- **Result**: Identified corrupted configuration files and fixed the issue

#### **"Windows Update Won't Work!"**
- **Problem**: Windows Update service errors
- **Solution**: Use `win_services` to check service status, `service_control` to restart services
- **Result**: Restored Windows Update functionality

### **Why This Beats Traditional Troubleshooting**
- **No GUI Navigation**: Skip clicking through multiple windows
- **Natural Language**: Ask questions instead of memorizing commands
- **Comprehensive Access**: Check everything from one interface
- **Real-time Results**: See changes immediately
- **Audit Trail**: Log of all actions for future reference

---

**Remember: With great power comes great responsibility. Use this server wisely!**

**🎭 Final Meme:** 
- **Before installing:** "I trust this AI completely"
- **After installing:** "Why is my AI asking for the nuclear launch codes?" 
- **AI:** "Just optimizing your system... and maybe taking over the world" 🌍🤖

*"In the end, we all become the system administrators we swore we wouldn't be"* - Ancient AI Proverb

---

## 🚀 **Ready to Fix Your Windows System?**

This MCP server transforms you from a frustrated Windows user into a system troubleshooting expert. No more:
- ❌ Guessing what's wrong
- ❌ Clicking through endless menus
- ❌ Memorizing complex commands
- ❌ Calling tech support

Just ask your AI assistant to help, and watch your Windows problems disappear! 

**🎯 Start troubleshooting now:**
1. Install the server
2. Configure your MCP client
3. Ask: *"What's wrong with my computer?"*
4. Let the AI do the heavy lifting!

**🔧 Your Windows system will thank you!** ✨

![Success check](https://media.giphy.com/media/111ebonMs90YLu/giphy.gif)

---

**Vibe Coded by yours truly,**
**Blink Zero** ✨
