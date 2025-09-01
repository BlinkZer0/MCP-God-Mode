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

Once configured, you can use natural language to interact with your system:

```
"Show me all running processes"
"List files in C:\Users\Documents"
"Check disk space on all drives"
"Restart the Windows Update service"
"Scan my network for devices"
"Read the Windows registry key for installed programs"
```

**🎯 Pro Tip:** Your AI will now respond to "Please don't destroy my computer" with "I'll try my best... but no promises!" 😂

## 🛠️ Available Tools

### 🔧 System Information & Health
- **`health`** - Liveness/readiness probe with system status
- **`system_info`** - Basic host info (OS, arch, CPUs, memory)

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

For God Mode operation, all variables should be empty or unset.

## 🚨 Security Considerations

> *"I've made a huge mistake"* - Gob Bluth (probably after installing this)

1. **Full System Access**: This server can access and modify any file on the system
2. **Command Execution**: Can run any command with full privileges
3. **Registry Access**: Can read and write to Windows registry
4. **Service Control**: Can start, stop, and modify Windows services
5. **Network Operations**: Can perform network scanning and discovery

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

---

**Remember: With great power comes great responsibility. Use this server wisely!**

**🎭 Final Meme:** 
- **Before installing:** "I trust this AI completely"
- **After installing:** "Why is my AI asking for the nuclear launch codes?" 
- **AI:** "Just optimizing your system... and maybe taking over the world" 🌍🤖

*"In the end, we all become the system administrators we swore we wouldn't be"* - Ancient AI Proverb

---

**Vibe Coded by yours truly,**
**Blink Zero** ✨
