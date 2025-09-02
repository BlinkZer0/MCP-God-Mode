# 🚀 MCP God Mode Setup Guide

## 📋 Overview

MCP God Mode is designed to be **completely portable** and work regardless of where you install it. This guide will help you set it up on any system without depending on specific folder structures.

## 🎯 Quick Start

### 1. **Clone/Download the Project**
```bash
git clone https://github.com/blinkzero/mcp-god-mode.git
cd mcp-god-mode
```

### 2. **Install Dependencies**
```bash
# Install root dependencies
npm install

# Install development dependencies
cd dev
npm install
cd ..
```

### 3. **Build the Project**
```bash
npm run build
```

### 4. **Start the MCP Server**
```bash
npm start
```

## ⚙️ Configuration

### **MCP Configuration File (`mcp.json`)**

The project includes a portable `mcp.json` that works anywhere:

```json
{
  "mcpServers": {
    "mcp-god-mode": {
      "command": "node",
      "args": ["./start-mcp.js"],
      "cwd": ".",
      "env": {
        "ALLOWED_ROOT": "",
        "WEB_ALLOWLIST": "",
        "PROC_ALLOWLIST": "",
        "EXTRA_PATH": ""
      }
    }
  }
}
```

**Key Features:**
- ✅ **Relative paths** - No absolute paths that break on different systems
- ✅ **Portable working directory** - Works from any location
- ✅ **Cross-platform** - Compatible with Windows, macOS, and Linux

## 🔧 How It Works

### **File Structure**
```
mcp-god-mode/
├── start-mcp.js          ← Root entry point (portable)
├── mcp.json             ← MCP configuration (portable)
├── package.json         ← Root package (portable)
├── dev/
│   ├── dist/            ← Built server files
│   ├── src/             ← Source code
│   └── package.json     ← Dev dependencies
└── docs/                ← Documentation
```

### **Smart Server Detection**

The `start-mcp.js` automatically finds the best available server:

1. **Primary locations** (in order of preference):
   - `dev/dist/server-refactored.js` (recommended)
   - `dev/dist/server.js`
   - `dev/dist/server-minimal.js`
   - `dev/dist/server-ultra-minimal.js`

2. **Fallback locations**:
   - `server.js` (root level)
   - `server-refactored.js` (root level)

## 🌍 Cross-Platform Compatibility

### **Windows**
```bash
# PowerShell/Command Prompt
npm start
```

### **macOS/Linux**
```bash
# Terminal
npm start
# or
node start-mcp.js
```

### **Docker**
```bash
# Build and run in container
docker build -t mcp-god-mode .
docker run -it mcp-god-mode
```

## 🔌 MCP Client Integration

### **Cursor AI**
1. Copy `mcp.json` to your Cursor AI MCP configuration
2. Ensure the project path is correct
3. Restart Cursor AI

### **LM Studio**
1. Copy `mcp.json` to your LM Studio MCP configuration
2. Set the working directory to the project root
3. Restart LM Studio

### **Other MCP Clients**
1. Use the provided `mcp.json` as a template
2. Adjust paths if needed for your specific client
3. Ensure the working directory points to the project root

## 🚨 Troubleshooting

### **"Cannot find module" Error**
```bash
# Solution: Rebuild the project
cd dev
npm run build
cd ..
npm start
```

### **"No server file found" Error**
```bash
# Solution: Check if dist folder exists
ls dev/dist/
# If empty, run build
npm run build
```

### **Permission Errors**
```bash
# On Linux/macOS, ensure execute permissions
chmod +x start-mcp.js
chmod +x dev/dist/*.js
```

### **Path Resolution Issues**
- Ensure you're running from the project root
- Check that `mcp.json` uses relative paths
- Verify the working directory in your MCP client

## 🔒 Security Configuration

### **Environment Variables**
Set these in your MCP client configuration:

```bash
ALLOWED_ROOT=""           # Restrict file access
WEB_ALLOWLIST=""          # Restrict web access
PROC_ALLOWLIST=""         # Restrict process execution
EXTRA_PATH=""             # Additional security paths
```

### **Production Security**
```bash
# Restrict to specific directories
ALLOWED_ROOT="/home/user/safe-folder"
WEB_ALLOWLIST="https://api.example.com"
PROC_ALLOWLIST="git,node,npm"
```

## 📚 Advanced Configuration

### **Custom Server Selection**
Modify `start-mcp.js` to prioritize specific server files:

```javascript
const possiblePaths = [
  path.join(__dirname, 'dev', 'dist', 'my-custom-server.js'),
  // ... other paths
];
```

### **Multiple MCP Servers**
Add multiple server configurations:

```json
{
  "mcpServers": {
    "mcp-god-mode": { /* ... */ },
    "mcp-god-mode-minimal": {
      "command": "node",
      "args": ["./start-mcp.js"],
      "env": { "SERVER_TYPE": "minimal" }
    }
  }
}
```

## 🎉 Success Indicators

When everything is working correctly, you should see:

```
🚀 Starting MCP God Mode Server on win32 x64
📁 Working directory: C:\path\to\mcp-god-mode
✅ Found server at: C:\path\to\mcp-god-mode\dev\dist\server-refactored.js
🔄 Loading server from: C:\path\to\mcp-god-mode\dev\dist\server-refactored.js
✅ Server loaded successfully!
```

## 🤝 Support

If you encounter issues:

1. **Check the logs** - Look for specific error messages
2. **Verify file structure** - Ensure all files are in place
3. **Rebuild the project** - Run `npm run build` in the dev folder
4. **Check permissions** - Ensure files are executable
5. **Review MCP client logs** - Look for connection issues

## 📝 Notes

- **No absolute paths** - Everything uses relative paths
- **Automatic detection** - Server files are found automatically
- **Cross-platform** - Works on Windows, macOS, and Linux
- **Portable** - Can be moved to any location without breaking
- **Self-contained** - All dependencies are included in the dev folder

---

**🎯 The goal is to make MCP God Mode work anywhere, anytime, without configuration headaches!**
