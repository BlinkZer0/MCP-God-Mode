# 🌐 MCP God Mode - Frontend Integration Guide

## 📋 Overview

MCP God Mode is compatible with multiple frontends that support the Model Context Protocol (MCP). This guide provides detailed installation instructions for integrating MCP God Mode with various popular MCP-compatible applications.

## 🎯 Supported Frontends

| Frontend | MCP Support | Status | Best For |
|----------|-------------|--------|----------|
| **Cursor AI** | ✅ Full Support | Recommended | Development & Coding |
| **LM Studio** | ✅ Full Support | Stable | Local AI Models |
| **Claude** | ✅ Via Bridge | Stable | Advanced AI Tasks |
| **SillyTavern** | 🔄 In Development | Beta | Roleplay & Chat |
| **Continue** | ✅ Full Support | Stable | VS Code Extension |
| **Open WebUI** | ✅ Full Support | Stable | Web Interface |

## 🚀 Quick Integration Summary

### **Recommended Setup Order:**
1. **Cursor AI** - Best overall experience with Agent mode
2. **LM Studio** - Excellent for local model integration
3. **Continue** - Great VS Code alternative
4. **Open WebUI** - Web-based interface option

---

## 🖥️ Cursor AI Integration

### **Why Cursor AI is Recommended:**
- **Agent Mode** - Autonomous multi-file edits and terminal execution
- **Native MCP Support** - Seamless integration with comprehensive toolset
- **Development Focus** - Optimized for coding and system administration tasks

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

## 🤖 Claude Integration (Via Bridge)

### **About Claude Integration:**
Claude can be integrated with MCP God Mode using the Claude-LMStudio Bridge, enabling communication with locally running models.

### **Installation Steps:**

1. **Clone the Bridge Repository:**
   ```bash
   git clone https://github.com/infinitimeless/Claude-LMStudio-Bridge_V2.git
   cd Claude-LMStudio-Bridge_V2
   ```

2. **Set Up Virtual Environment:**
   ```bash
   # Create virtual environment
   python -m venv venv
   
   # Activate (Linux/macOS)
   source venv/bin/activate
   
   # Activate (Windows)
   venv\Scripts\activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure MCP God Mode:**
   - Ensure MCP God Mode is running on your system
   - Update bridge configuration to point to MCP God Mode server

5. **Run the Bridge Server:**
   ```bash
   python lmstudio_bridge.py
   ```

6. **Configure Claude:**
   - In Claude's interface, enable the MCP server
   - Point it to your locally running bridge
   - Test the connection

### **Configuration Example:**
```python
# Bridge configuration
MCP_SERVER_URL = "http://localhost:3000"  # MCP God Mode server
CLAUDE_API_KEY = "your-claude-api-key"
```

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

| Feature | Cursor AI | LM Studio | Claude | SillyTavern | Continue | Open WebUI |
|---------|-----------|-----------|--------|-------------|----------|------------|
| **Agent Mode** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Local Models** | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ |
| **Web Interface** | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ |
| **VS Code Integration** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Roleplay Features** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **D&D 5e Support** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **Hacker RP Scenarios** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **Cloud API Support** | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ |
| **Development Focus** | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ |
| **Ease of Setup** | ✅ | ✅ | 🔶 | 🔶 | ✅ | ✅ |

**Legend:** ✅ Excellent | 🔶 Moderate | ❌ Not Available

---

## 🎯 Recommendations by Use Case

### **For Development:**
- **Primary**: Cursor AI (Agent mode)
- **Alternative**: Continue (VS Code integration)

### **For Local AI Models:**
- **Primary**: LM Studio
- **Alternative**: Open WebUI

### **For Advanced AI Tasks:**
- **Primary**: Claude (via bridge)
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
- **Alternative**: Claude (web interface)

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
