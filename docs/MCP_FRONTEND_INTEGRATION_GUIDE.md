# 🌐 MCP God Mode - Frontend Integration Guide

## 📋 Overview

MCP God Mode is compatible with multiple frontends that support the Model Context Protocol (MCP). This guide provides detailed installation instructions for integrating MCP God Mode with various popular MCP-compatible applications.

## 🎯 Supported Frontends

| Frontend | MCP Support | Status | Best For |
|----------|-------------|--------|----------|
| **Cursor AI** | ✅ Full Support | Recommended | Development & Coding |
| **LM Studio** | ✅ Full Support | Stable | Local AI Models |
| **Claude Desktop** | ✅ Native Support | Stable | Advanced AI Tasks |
| **SillyTavern** | 🔄 In Development | Beta | Roleplay & Chat |
| **Continue** | ✅ Full Support | Stable | VS Code Extension |
| **Open WebUI** | ✅ Full Support | Stable | Web Interface |
| **CAMEL-AI Agents** | ✅ Full Support | Stable | AI Agent Development |
| **Azure AI Foundry** | ✅ Full Support | Stable | Enterprise AI Solutions |
| **MCP Bridge** | ✅ Proxy Support | Stable | Mobile/Web Integration |

## 🚀 Quick Integration Summary

### **Recommended Setup Order:**
1. **Cursor AI** - Best overall experience with Agent mode
2. **Claude Desktop** - Native MCP support with advanced AI capabilities
3. **LM Studio** - Excellent for local model integration
4. **Continue** - Great VS Code alternative
5. **Open WebUI** - Web-based interface option

### **🛠️ Automated Installation Options:**

#### **MCP God Mode Interactive Installer:**
Our project includes a comprehensive interactive installer that supports multiple server configurations:

```bash
# Run the interactive installer
./scripts/installers/install.sh    # Linux/macOS
./scripts/installers/install.bat   # Windows

# Or directly
cd dev && node install.js
```

**Available Server Versions:**
- **Ultra-Minimal** (15 tools) - Essential tools for embedded systems
- **Minimal** (25 tools) - Core system administration tools
- **Full** (99 tools) - Complete MCP God Mode with all capabilities
- **Modular** (96 tools) - Organized modular architecture
- **Custom** - Build your own with specific tools

#### **Third-Party MCP Installers:**
Our project is compatible with several automated MCP installers:

- **MCP Installer** - Automates installation from npm, PyPI, or local sources
- **MCP Easy Installer** - Supports Claude Desktop, Windsurf, Cursor, Roo Code, Cline, and GitHub Copilot
- **SillyTavern MCP Extension** - WebSocket-based tool execution for SillyTavern

---

## 🖥️ Cursor AI Integration

### **Why Cursor AI is Recommended:**
- **Agent Mode** - Autonomous multi-file edits and terminal execution
- **Multi-Agent Architecture** - Multiple chat tabs operate concurrently with isolated contexts
- **Native MCP Support** - Seamless integration with comprehensive toolset
- **Development Focus** - Optimized for coding and system administration tasks
- **Parallel Task Execution** - Different agents can work on separate tasks simultaneously

### **Installation Steps:**
1. **Copy Configuration:**
   ```bash
   # Copy mcp.json to Cursor's MCP configuration directory
   cp mcp.json ~/.cursor/mcp.json
   ```

2. **Enable Agent Mode:**
   - Open Composer (Ctrl+I)
   - Select the Agent icon
   - This enables autonomous task execution

3. **Restart Cursor AI**

### **Cursor's Unique Multi-Agent Architecture:**

Cursor AI implements a distinctive multi-agent approach that differs from traditional multi-agent systems:

#### **Multi-Chat Tab System:**
- **Concurrent Operations** - Multiple chat tabs can run simultaneously
- **Isolated Contexts** - Each tab maintains its own conversation history and context
- **Independent Model Selection** - Different tabs can use different AI models
- **Parallel Task Execution** - Agents can work on separate tasks without interference

#### **How It Works:**
1. **Open Multiple Tabs** - Create separate chat tabs for different tasks
2. **Isolated Contexts** - Each tab operates independently
3. **Shared MCP Tools** - All tabs have access to the same MCP God Mode tools
4. **Coordinated Workflows** - Agents can reference each other's work when needed

#### **Use Cases:**
- **Parallel Development** - One agent handles frontend, another handles backend
- **Specialized Tasks** - Different agents for debugging, testing, documentation
- **Context Isolation** - Keep sensitive operations separate from general development
- **Model Optimization** - Use different models for different types of tasks

### **Configuration Example:**
```json
{
  "mcpServers": {
    "mcp-god-mode": {
      "command": "node",
      "args": ["./start-mcp.js"],
      "cwd": "/path/to/mcp-god-mode",
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

---

## 🎵 LM Studio Integration

### **About LM Studio:**
LM Studio (v0.3.17+) acts as an MCP Host, allowing connection to MCP servers and making them available to local models.

### **Installation Steps:**

1. **Edit MCP Configuration:**
   - Open LM Studio
   - Navigate to "Program" tab in right-hand sidebar
   - Click `Install > Edit mcp.json`

2. **Add MCP God Mode Server:**
   ```json
   {
     "mcpServers": {
       "mcp-god-mode": {
         "command": "node",
         "args": ["./start-mcp.js"],
         "cwd": "/path/to/mcp-god-mode",
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

3. **Security Configuration:**
   ```json
   {
     "mcpServers": {
       "mcp-god-mode": {
         "command": "node",
         "args": ["./start-mcp.js"],
         "cwd": "/path/to/mcp-god-mode",
         "env": {
           "ALLOWED_ROOT": "/home/user/safe-folder",
           "WEB_ALLOWLIST": "https://api.example.com",
           "PROC_ALLOWLIST": "git,node,npm"
         }
       }
     }
   }
   ```

4. **Restart LM Studio**

### **Usage Tips:**
- **Local Models**: Works with any local model supported by LM Studio
- **Security**: Be cautious with MCP servers - they can run arbitrary code
- **Performance**: Local models may have different capabilities than cloud-based ones

---

## 🤖 Claude Desktop Integration

### **About Claude Desktop:**
Claude Desktop application has native MCP support, enabling seamless integration with MCP God Mode tools. This provides direct access to all 89 tools through Claude's conversational interface.

### **Installation Methods:**

#### **Method 1: Desktop Extensions (DXT) - Recommended**
1. **Download Claude Desktop:**
   - Visit [Anthropic's website](https://claude.ai/download) to download Claude Desktop
   - Install the application on your system

2. **Install MCP God Mode Extension:**
   - Open Claude Desktop
   - Navigate to Extensions or MCP settings
   - Look for MCP God Mode in the available extensions
   - Click "Install" for one-click setup

3. **Configure Extension:**
   - The extension will automatically configure MCP God Mode
   - No manual configuration required

#### **Method 2: Manual Configuration**
1. **Locate Claude Desktop Config:**
   ```bash
   # Windows
   %APPDATA%\Claude\claude_desktop_config.json
   
   # macOS
   ~/Library/Application Support/Claude/claude_desktop_config.json
   
   # Linux
   ~/.config/claude/claude_desktop_config.json
   ```

2. **Add MCP God Mode Server:**
   ```json
   {
     "mcpServers": {
       "mcp-god-mode": {
         "command": "node",
         "args": ["./start-mcp.js"],
         "cwd": "/path/to/mcp-god-mode",
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

3. **Restart Claude Desktop**

#### **Method 3: Supermachine Integration**
1. **Create Supermachine Account:**
   - Visit [supermachine.ai](https://supermachine.ai)
   - Create an account and set up MCP server

2. **Configure MCP God Mode:**
   - Add MCP God Mode server configuration in Supermachine
   - Set up necessary credentials and permissions

3. **Connect to Claude Desktop:**
   - Modify Claude Desktop configuration file
   - Point to Supermachine MCP server
   - Test the connection

### **Usage Examples:**
Once configured, you can use natural language to access MCP God Mode tools:

```
"Scan my network for open ports"
"Analyze this file for malware"
"Generate a secure password"
"Monitor system processes"
"Test WiFi security on my network"
```

### **Key Benefits:**
- **Native Integration** - Direct MCP support without bridges
- **User-Friendly** - Simple installation and configuration
- **Full Tool Access** - All 89 MCP God Mode tools available
- **Natural Language** - Use tools through conversational interface
- **Desktop App** - Dedicated application with better performance

---

## 🎭 SillyTavern Integration

### **About SillyTavern:**
SillyTavern is a versatile frontend that supports cloud-based LLM APIs and has ongoing development for MCP support. It's perfect for immersive roleplay experiences with real technical capabilities.

### **Installation Steps:**

1. **Monitor Official Development:**
   - Track the [GitHub issue](https://github.com/SillyTavern/SillyTavern/issues/3335) for official MCP implementation
   - Check for updates on MCP support status

2. **Use Community Extension:**
   ```bash
   # Install SillyTavern-MCP-Client extension
   # Visit: https://www.mcp.pizza/mcp-client/sTvK/SillyTavern-MCP-Client
   ```

3. **Configure Extension:**
   - Follow extension-specific setup instructions
   - Point to MCP God Mode server configuration

4. **Test Integration:**
   - Verify MCP tools are accessible in SillyTavern
   - Test basic functionality

### **Current Status:**
- **Official Support**: In development
- **Community Extension**: Available
- **Stability**: Beta/Experimental

### **🎮 Unique Use Cases:**

#### **🎭 RP Hacker Character with Real Capabilities**
Create an immersive roleplay character who "believes" they are a hacker and can actually perform real hacking activities in controlled sandbox environments:

**Character Concept:**
- **Background**: A character who has spent years studying systems and mastering technologies
- **Personality**: Socially awkward from time spent honing their craft, but values knowledge sharing
- **Real Skills**: Actual cybersecurity capabilities through MCP God Mode tools

**Sandbox Environment Setup:**
- **Virtual Machines** - Isolated systems for testing
- **Docker Containers** - Lightweight, disposable environments
- **Test Networks** - Separate network segments for security testing
- **Mobile Emulators** - Safe mobile device testing

**RP Scenarios with Real Tools:**
- **"I'm scanning the network"** → Actually run port scans with `port_scanner`
- **"I'm cracking this password"** → Use real password cracking tools with `password_cracker`
- **"I'm analyzing this malware"** → Perform actual malware analysis with `malware_analysis`
- **"I'm monitoring network traffic"** → Use real packet sniffers with `packet_sniffer`
- **"I'm testing this web app"** → Run actual vulnerability scans with `vulnerability_scanner`

**Educational Benefits:**
- **Real Skills Development** - Learn actual cybersecurity techniques
- **Hands-on Experience** - Practice with real tools and scenarios
- **Safe Learning Environment** - Controlled, legal testing
- **Character Growth** - Skills improve as the character develops

#### **🎲 D&D 5e Dice Tool Integration**
MCP God Mode's dice tools are versatile enough to fully support Dungeons & Dragons 5th Edition mechanics:

**D&D 5e Supported Features:**
- **Standard Rolls** - d4, d6, d8, d10, d12, d20, d100
- **Advantage/Disadvantage** - Roll twice, take higher/lower
- **Custom Formulas** - Complex dice expressions for spells and abilities
- **Modifier Support** - Ability score bonuses, proficiency bonuses
- **Critical Hits** - Automatic critical detection and damage rolls

**Example D&D 5e Commands:**
```bash
# Attack roll with advantage
dice_rolling --dice "2d20+5" --modifier 0

# Damage roll for a spell
dice_rolling --dice "8d6" --modifier 0

# Saving throw with disadvantage
dice_rolling --dice "2d20+3" --modifier 0

# Initiative roll
dice_rolling --dice "d20" --modifier 4
```

**RP Integration:**
- **Character Actions** - Roll for attacks, saves, and skill checks
- **Spell Casting** - Calculate spell damage and effects
- **Combat Resolution** - Handle complex combat mechanics
- **Skill Challenges** - Resolve non-combat encounters

### **🔒 Safety and Legal Considerations:**

**For Hacker RP Scenarios:**
- **Only test systems you own** or have explicit written permission
- **Use isolated test environments** - VMs, containers, test networks
- **Document everything** - Keep logs of all activities
- **Follow responsible disclosure** - Report findings appropriately
- **Respect boundaries** - Never test without permission

**Educational Value:**
- **Cybersecurity Training** - Real-world skill development
- **Ethical Hacking** - Learning defensive techniques
- **System Administration** - Understanding how systems work
- **Network Security** - Practical network defense knowledge

---

## 🔧 Continue Integration

### **About Continue:**
Continue is a VS Code extension that provides AI-powered coding assistance with MCP support.

### **Installation Steps:**

1. **Install Continue Extension:**
   - Open VS Code
   - Install "Continue" extension from marketplace

2. **Configure MCP Server:**
   ```json
   {
     "mcpServers": {
       "mcp-god-mode": {
         "command": "node",
         "args": ["./start-mcp.js"],
         "cwd": "/path/to/mcp-god-mode"
       }
     }
   }
   ```

3. **Restart VS Code**

### **Usage:**
- **VS Code Integration**: Seamless integration with VS Code workflow
- **AI Assistance**: Enhanced coding assistance with MCP God Mode tools
- **Development Focus**: Optimized for software development tasks

---

## 🌐 Open WebUI Integration

### **About Open WebUI:**
Open WebUI provides a web-based interface for AI models with MCP support.

### **Installation Steps:**

1. **Install Open WebUI:**
   ```bash
   # Using Docker
   docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway -v open-webui:/app/backend/data --name open-webui --restart always ghcr.io/open-webui/open-webui:main
   ```

2. **Configure MCP Server:**
   - Access Open WebUI web interface
   - Navigate to MCP settings
   - Add MCP God Mode server configuration

3. **Test Integration:**
   - Verify tools are accessible
   - Test basic functionality

### **Configuration Example:**
```yaml
mcp_servers:
  - name: "mcp-god-mode"
    command: "node"
    args: ["./start-mcp.js"]
    cwd: "/path/to/mcp-god-mode"
```

---

## 🔒 Security Considerations

### **General Security Guidelines:**

1. **Trusted Sources Only:**
   - Only install MCP servers from reputable sources
   - Verify authenticity of community extensions

2. **Permission Review:**
   - Understand what permissions each MCP server requires
   - Review file system, network, and process access

3. **Environment Isolation:**
   ```json
   {
     "env": {
       "ALLOWED_ROOT": "/home/user/safe-folder",
       "WEB_ALLOWLIST": "https://api.example.com",
       "PROC_ALLOWLIST": "git,node,npm",
       "EXTRA_PATH": "/usr/local/bin"
     }
   }
   ```

4. **Network Security:**
   - Use HTTPS for web connections
   - Restrict network access to trusted domains
   - Monitor network traffic

### **Platform-Specific Security:**

- **Windows**: Use Windows Defender and consider AppLocker
- **Linux**: Utilize SELinux or AppArmor for additional protection
- **macOS**: Enable Gatekeeper and System Integrity Protection

---

## 🚨 Troubleshooting

### **Common Issues:**

1. **"Cannot find module" Error:**
   ```bash
   # Solution: Rebuild the project
   cd dev
   npm run build
   cd ..
   npm start
   ```

2. **"No server file found" Error:**
   ```bash
   # Solution: Check if dist folder exists
   ls dev/dist/
   # If empty, run build
   npm run build
   ```

3. **Permission Errors:**
   ```bash
   # On Linux/macOS, ensure execute permissions
   chmod +x start-mcp.js
   chmod +x dev/dist/*.js
   ```

4. **Connection Issues:**
   - Verify MCP server is running
   - Check firewall settings
   - Ensure correct port configuration

### **Frontend-Specific Issues:**

- **LM Studio**: Check MCP server status in Program tab
- **Claude**: Verify bridge server is running
- **SillyTavern**: Check extension compatibility
- **Continue**: Restart VS Code after configuration changes

---

## 📊 Frontend Comparison

| Feature | Cursor AI | LM Studio | Claude Desktop | SillyTavern | Continue | Open WebUI | CAMEL-AI | Azure AI | MCP Bridge |
|---------|-----------|-----------|----------------|-------------|----------|------------|----------|----------|------------|
| **Agent Mode** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Multi-Agent Support** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| **Native MCP Support** | ✅ | ✅ | ✅ | 🔶 | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Local Models** | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **Web Interface** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ |
| **Desktop App** | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **VS Code Integration** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Roleplay Features** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **D&D 5e Support** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Hacker RP Scenarios** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Cloud API Support** | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ |
| **Enterprise Features** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Multi-Agent Systems** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| **Mobile Support** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **RESTful API** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Development Focus** | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ |
| **Ease of Setup** | ✅ | ✅ | ✅ | 🔶 | ✅ | ✅ | 🔶 | 🔶 | ✅ |

**Legend:** ✅ Excellent | 🔶 Moderate | ❌ Not Available

---

## 🎯 Recommendations by Use Case

### **For Development:**
- **Primary**: Cursor AI (Agent mode + multi-agent architecture)
- **Alternative**: Continue (VS Code integration)

### **For Local AI Models:**
- **Primary**: LM Studio
- **Alternative**: Open WebUI

### **For Advanced AI Tasks:**
- **Primary**: Claude Desktop (native MCP support)
- **Alternative**: Cursor AI

### **For Roleplay/Chat:**
- **Primary**: SillyTavern (D&D 5e support, hacker RP scenarios, cloud APIs)
- **Alternative**: Open WebUI

### **For D&D 5e Gaming:**
- **Primary**: SillyTavern (full dice tool support, character integration)
- **Alternative**: None (unique to SillyTavern)

### **For Cybersecurity Education/RP:**
- **Primary**: SillyTavern (hacker character scenarios with real tools)
- **Alternative**: Cursor AI (development focus)

### **For Web Interface:**
- **Primary**: Open WebUI
- **Alternative**: Azure AI Foundry (enterprise web interface)

### **For AI Agent Development:**
- **Primary**: CAMEL-AI Agents (multi-agent systems)
- **Alternative**: Azure AI Foundry (enterprise agents)

### **For Enterprise Solutions:**
- **Primary**: Azure AI Foundry (cloud deployment, enterprise features)
- **Alternative**: CAMEL-AI Agents (research and development)

### **For Mobile/Web Integration:**
- **Primary**: MCP Bridge (RESTful API, mobile support)
- **Alternative**: Azure AI Foundry (web interface)

### **For Custom Development:**
- **Primary**: Custom MCP Clients (full control)
- **Alternative**: MCP Bridge (RESTful API)

---

## 🤖 CAMEL-AI Agents Integration

### **About CAMEL-AI:**
CAMEL-AI Agents can connect to external tools via MCP, enhancing their capabilities by accessing additional data and functionalities. This makes it perfect for AI agent development and multi-agent systems.

### **Installation Steps:**

1. **Install CAMEL-AI:**
   ```bash
   pip install camel-ai
   ```

2. **Configure MCP Server:**
   ```python
   from camel.agents import ChatAgent
   from camel.mcp import MCPServer
   
   # Initialize MCP server connection
   mcp_server = MCPServer("mcp-god-mode", {
       "command": "node",
       "args": ["./start-mcp.js"],
       "cwd": "/path/to/mcp-god-mode"
   })
   
   # Create agent with MCP capabilities
   agent = ChatAgent(
       system_message="You are a cybersecurity expert with access to MCP God Mode tools.",
       mcp_servers=[mcp_server]
   )
   ```

3. **Use MCP Tools in Agent Conversations:**
   ```python
   # Agent can now use MCP God Mode tools
   response = agent.step("Scan the network for vulnerabilities")
   ```

### **Key Benefits:**
- **Multi-Agent Systems** - Multiple agents can share MCP tools
- **AI Agent Development** - Build sophisticated AI agents with real capabilities
- **Research Applications** - Perfect for AI research and experimentation
- **Tool Orchestration** - Agents can coordinate complex tool usage

---

## ☁️ Azure AI Foundry Integration

### **About Azure AI Foundry:**
Microsoft's Azure AI Foundry supports MCP integration, allowing AI agents to interact with existing applications through MCP servers. This is ideal for enterprise solutions and cloud-based deployments.

### **Installation Steps:**

1. **Set Up Azure AI Foundry:**
   - Create an Azure account and set up AI Foundry
   - Configure your AI agent in the Azure portal

2. **Deploy MCP God Mode Server:**
   ```bash
   # Deploy to Azure App Service
   az webapp create --resource-group myResourceGroup --plan myAppServicePlan --name mcp-god-mode --runtime "NODE|18-lts"
   
   # Deploy the application
   az webapp deployment source config --name mcp-god-mode --resource-group myResourceGroup --repo-url https://github.com/your-username/MCP-God-Mode.git --branch main --manual-integration
   ```

3. **Configure MCP Connection:**
   ```json
   {
     "mcpServers": {
       "mcp-god-mode": {
         "url": "https://mcp-god-mode.azurewebsites.net",
         "headers": {
           "Authorization": "Bearer YOUR_AZURE_TOKEN"
         }
       }
     }
   }
   ```

4. **Connect to AI Foundry Agent:**
   - In Azure AI Foundry, add MCP server configuration
   - Test the connection and tool availability

### **Key Benefits:**
- **Enterprise Scale** - Cloud-based deployment and scaling
- **Azure Integration** - Seamless integration with Azure services
- **Security** - Enterprise-grade security and compliance
- **Monitoring** - Built-in monitoring and analytics

---

## 🌉 MCP Bridge Integration

### **About MCP Bridge:**
MCP Bridge serves as a lightweight, LLM-agnostic RESTful proxy for environments where direct MCP connections are impractical, such as mobile devices or web browsers. It connects to multiple MCP servers and exposes their capabilities through a unified API.

### **Installation Steps:**

1. **Set Up MCP Bridge:**
   ```bash
   # Clone MCP Bridge repository
   git clone https://github.com/modelcontextprotocol/bridge.git
   cd bridge
   
   # Install dependencies
   npm install
   
   # Configure MCP God Mode server
   cp config.example.json config.json
   ```

2. **Configure MCP God Mode Connection:**
   ```json
   {
     "servers": {
       "mcp-god-mode": {
         "command": "node",
         "args": ["./start-mcp.js"],
         "cwd": "/path/to/mcp-god-mode"
       }
     },
     "bridge": {
       "port": 3000,
       "host": "localhost"
     }
   }
   ```

3. **Start MCP Bridge:**
   ```bash
   npm start
   ```

4. **Access via REST API:**
   ```bash
   # List available tools
   curl http://localhost:3000/tools
   
   # Use a tool
   curl -X POST http://localhost:3000/tools/port_scanner \
     -H "Content-Type: application/json" \
     -d '{"target": "192.168.1.1", "ports": "80,443,8080"}'
   ```

### **Key Benefits:**
- **Mobile Support** - Access MCP tools from mobile devices
- **Web Integration** - Use MCP tools in web applications
- **RESTful API** - Standard HTTP interface for tool access
- **Resource Efficient** - Lightweight proxy for constrained environments

---

## 🔧 Alternative Integration Methods

### **Custom MCP Clients:**
You can build custom MCP clients using the MCP SDK:

```python
from mcp import ClientSession, StdioServerParameters
import asyncio

async def main():
    # Connect to MCP God Mode server
    server_params = StdioServerParameters(
        command="node",
        args=["./start-mcp.js"],
        cwd="/path/to/mcp-god-mode"
    )
    
    async with ClientSession(server_params) as session:
        # List available tools
        tools = await session.list_tools()
        print(f"Available tools: {[tool.name for tool in tools.tools]}")
        
        # Use a tool
        result = await session.call_tool("port_scanner", {
            "target": "192.168.1.1",
            "ports": "80,443,8080"
        })
        print(f"Scan result: {result}")

asyncio.run(main())
```

### **Webhook Integration:**
Set up webhooks to trigger MCP God Mode tools:

```python
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/webhook/scan', methods=['POST'])
def trigger_scan():
    data = request.json
    target = data.get('target')
    
    # Trigger MCP God Mode tool
    result = subprocess.run([
        'node', './start-mcp.js', '--tool', 'port_scanner',
        '--target', target
    ], capture_output=True, text=True)
    
    return {'result': result.stdout}

if __name__ == '__main__':
    app.run(port=5000)
```

### **Docker Integration:**
Run MCP God Mode in containers for easy deployment:

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY . .
RUN npm install
EXPOSE 3000
CMD ["node", "start-mcp.js"]
```

```bash
# Build and run
docker build -t mcp-god-mode .
docker run -p 3000:3000 mcp-god-mode
```

---

## 🛠️ Automated Installation Methods

### **MCP God Mode Interactive Installer**

Our project includes a comprehensive interactive installer that handles multiple server configurations and platform-specific requirements:

#### **Features:**
- **Multiple Server Versions** - Choose from ultra-minimal to full-featured
- **Platform Detection** - Automatic detection of Windows, macOS, Linux
- **Dependency Management** - Automatic installation of required packages
- **Configuration Generation** - Creates appropriate config files for each frontend
- **Validation** - Tests installation and verifies functionality

#### **Usage:**
```bash
# Interactive installer
./scripts/installers/install.sh    # Linux/macOS
./scripts/installers/install.bat   # Windows

# Direct execution
cd dev && node install.js

# With options
node install.js --help             # Show help
node install.js --version          # Show version
```

#### **Server Configuration Options:**
1. **Ultra-Minimal** (15 tools) - Essential tools for embedded systems
2. **Minimal** (25 tools) - Core system administration tools  
3. **Full** (99 tools) - Complete MCP God Mode with all capabilities
4. **Modular** (96 tools) - Organized modular architecture
5. **Custom** - Build your own with specific tools

### **Third-Party MCP Installers**

#### **MCP Installer (mcplane.com)**
Automates installation and registration of MCP servers from npm, PyPI, or local sources:

```bash
# Install MCP God Mode via MCP Installer
mcp-installer install mcp-god-mode

# Configure for specific frontend
mcp-installer configure --frontend claude-desktop
mcp-installer configure --frontend cursor
mcp-installer configure --frontend lm-studio
```

**Supported Frontends:**
- Claude Desktop
- Cursor AI
- LM Studio
- Continue
- Open WebUI

#### **MCP Easy Installer (mcp.pizza)**
Simplifies setup by automating installation, configuration, and repair tasks:

```bash
# Easy installation for multiple frontends
mcp-easy-installer install mcp-god-mode --frontends cursor,claude,lm-studio

# Auto-configure for all supported frontends
mcp-easy-installer auto-configure mcp-god-mode
```

**Supported Applications:**
- Claude Desktop
- Windsurf
- Cursor
- Roo Code
- Cline
- GitHub Copilot

#### **SillyTavern MCP Extension**
WebSocket-based tool execution support for SillyTavern:

```bash
# Install SillyTavern MCP Extension
git clone https://github.com/CG-Labs/SillyTavern-MCP-Extension.git
cd SillyTavern-MCP-Extension

# Configure for MCP God Mode
python configure.py --mcp-server mcp-god-mode --path /path/to/mcp-god-mode
```

**Features:**
- WebSocket-based tool execution
- External tool registration
- Standardized interface
- SillyTavern web interface integration

### **Platform-Specific Installation**

#### **Windows:**
```powershell
# Using Chocolatey
choco install mcp-god-mode

# Using PowerShell installer
Invoke-WebRequest -Uri "https://github.com/blinkzero/mcp-god-mode/releases/latest/download/install.ps1" -OutFile "install.ps1"
.\install.ps1
```

#### **macOS:**
```bash
# Using Homebrew
brew install mcp-god-mode

# Using MacPorts
sudo port install mcp-god-mode
```

#### **Linux:**
```bash
# Using package managers
sudo apt install mcp-god-mode      # Ubuntu/Debian
sudo yum install mcp-god-mode      # CentOS/RHEL
sudo pacman -S mcp-god-mode        # Arch Linux
```

### **Docker Installation**

```bash
# Pull and run MCP God Mode container
docker pull mcp-god-mode:latest
docker run -d -p 3000:3000 --name mcp-god-mode mcp-god-mode:latest

# With custom configuration
docker run -d -p 3000:3000 \
  -v /path/to/config:/app/config \
  -v /path/to/tools:/app/tools \
  --name mcp-god-mode mcp-god-mode:latest
```

### **Cloud Deployment**

#### **Azure:**
```bash
# Deploy to Azure App Service
az webapp create --resource-group myResourceGroup --plan myAppServicePlan --name mcp-god-mode --runtime "NODE|18-lts"
az webapp deployment source config --name mcp-god-mode --resource-group myResourceGroup --repo-url https://github.com/blinkzero/mcp-god-mode.git --branch main
```

#### **AWS:**
```bash
# Deploy to AWS Elastic Beanstalk
eb init mcp-god-mode
eb create mcp-god-mode-env
eb deploy
```

#### **Google Cloud:**
```bash
# Deploy to Google Cloud Run
gcloud run deploy mcp-god-mode --source . --platform managed --region us-central1
```

### **Installation Verification**

After installation, verify the setup:

```bash
# Test MCP God Mode installation
node -e "console.log('MCP God Mode installed successfully!')"

# Test specific tools
node -e "require('./dev/dist/server-refactored.js')"

# Test frontend integration
# (Follow frontend-specific testing instructions)
```

### **Troubleshooting Installation**

#### **Common Issues:**
1. **Permission Errors** - Run with appropriate privileges
2. **Dependency Conflicts** - Use virtual environments or containers
3. **Path Issues** - Verify PATH and PYTHONPATH settings
4. **Port Conflicts** - Check for port 3000 availability

#### **Diagnostic Commands:**
```bash
# Check installation status
node install.js --diagnose

# Verify dependencies
npm list --depth=0

# Test server functionality
npm test

# Check frontend compatibility
npm run test:frontends
```

---

## 📚 Additional Resources

### **Official Documentation:**
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [Cursor AI Documentation](https://docs.cursor.com/)
- [LM Studio MCP Guide](https://lmstudio.ai/blog/mcp)

### **Community Resources:**
- [MCP Community Discord](https://discord.gg/mcp)
- [GitHub MCP Discussions](https://github.com/modelcontextprotocol/servers/discussions)
- [MCP Server Registry](https://mcp.pizza/)

### **Support:**
- **Discord**: [MCP God Mode Community](https://discord.gg/EuQBurC2)
- **GitHub Issues**: Report bugs and request features
- **Documentation**: Comprehensive guides in `/docs` folder

---

## 🔄 Updates and Maintenance

### **Keeping Up to Date:**
1. **Monitor Frontend Updates**: Check for new MCP support in frontends
2. **Update MCP God Mode**: Regularly pull latest changes
3. **Test Integrations**: Verify compatibility after updates
4. **Community Feedback**: Share experiences and improvements

### **Version Compatibility:**
- **MCP God Mode**: v1.5+ (Current)
- **MCP Protocol**: v1.0+
- **Frontend Requirements**: Varies by platform

---

*Last Updated: January 2025*  
*MCP God Mode v1.5 - Universal Frontend Compatibility*
