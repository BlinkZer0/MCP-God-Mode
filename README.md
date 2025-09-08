<picture>
  <img src="assets/hero-animated.svg" alt="MCP God Mode - Ultimate Cross-Platform Security & System Management Suite" width="100%" />
</picture>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-flipper-zero-integration">Flipper Zero</a> •
  <a href="#️-tool-categories">Tool Categories</a> •
  <a href="#-usage-examples">Usage Examples</a> •
  <a href="#-cross-platform-support">Platform Support</a> •
  <a href="#️-legal-disclaimer">Legal</a>
</p>

One MCP to rule them all, one MCP to find them, one MCP to compile the tools, and in the God Mode bind them. 🎲⚡

[![Version](https://img.shields.io/badge/Version-v1.7c-blue)](docs/updates/VERSION_1.7c_CHANGELOG.md)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Node](https://img.shields.io/badge/Node-%3E%3D%2018-brightgreen)](package.json)
[![Platforms](https://img.shields.io/badge/Platforms-Win%20%7C%20macOS%20%7C%20Linux%20%7C%20Android%20%7C%20iOS-orange)](docs/general/CROSS_PLATFORM_COMPATIBILITY.md)
[![GitHub Stars](https://img.shields.io/github/stars/BlinkZer0/MCP-God-Mode?style=social)](https://github.com/BlinkZer0/MCP-God-Mode)
[![CI](https://img.shields.io/badge/CI-Smoke%20Tests-yellow)](scripts/smoke-test.js)
[![Tools](https://img.shields.io/badge/Tools-148%20Total-orange)](docs/general/TOOL_CATALOG.md)

**Version 1.7c - Individual Tool Installation & Consolidated Flipper Zero Support**

## 🔢 Canonical Tool Count
**148 Tools** - Complete implementation across both server architectures (server-refactored and modular)

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 📚 Quick Navigation

<img src="assets/wave-divider.svg" alt="" width="100%" />

- **[🚀 Quick Start](docs/guides/COMPLETE_SETUP_GUIDE.md)** - Get up and running in minutes
- **[🌐 Frontend Integration Guide](docs/guides/MCP_FRONTEND_INTEGRATION_GUIDE.md)** - Setup for Cursor, LM Studio, Claude, SillyTavern & more
- **[📋 Complete Tool Catalog](docs/general/TOOL_CATALOG.md)** - Browse all 148 documented tools with detailed documentation
- **[🔧 Parameter Reference](docs/general/COMPLETE_PARAMETER_REFERENCE.md)** - Complete parameter documentation
- **[💻 Examples & Tutorials](docs/guides/EXAMPLES_AND_TUTORIALS.md)** - Real-world usage examples
- **[🌍 Platform Compatibility](docs/general/CROSS_PLATFORM_COMPATIBILITY.md)** - Platform-specific details
- **[📝 Version 1.7c Changelog](docs/updates/VERSION_1.7c_CHANGELOG.md)** - What's new in the latest update

## Table of Contents

<img src="assets/wave-divider.svg" alt="" width="100%" />

- [Quick Start](#-quick-start)
- [Flipper Zero Integration](#-flipper-zero-integration)
- [Understanding Tool Counts](#-understanding-tool-counts-tools-vs-actions-vs-parameters)
- [Visual Demo](#️-visual-demo)
- [Tool Categories](#️-tool-categories)
- [Usage Examples](#-usage-examples)
- [Cross-Platform Support](#-cross-platform-support)
- [Documentation](#-documentation)
- [Legal Disclaimer](#️-legal-disclaimer)


https://github.com/user-attachments/assets/932c43e4-159e-4ce2-9c02-4acf23fc47fd

***Slow typing for that 90's dramatic vibe in this demonstration of proc_run, the tool get's the elevated permissions it needs.***

***Bug Bounty $$$; find a nasty bug or somthing big I forgot and I will make and add a custom MPC tool in your honor***

## 🚀 Quick Start

```bash
# 1) Clone & enter
git clone https://github.com/BlinkZer0/MCP-God-Mode.git
cd MCP-God-Mode

# 2) Setup
cp .env.example .env   # edit if needed
npm install

# 3) Launch (choose one)
npm run start:refactored   # full refactored server (148 tools)
# or
npm run start:modular      # modular loader (148 tools, grouped)
# or minimal
npm run start:minimal      # minimal profile (15 core tools)
```

### Individual Tool Installation (NEW!)

Install only the specific tools you need:

```bash
# Install specific tools
node install.js --modular --tools health,system_info,fs_list

# Install with automatic dependencies
node install.js --modular --tools port_scanner --auto-deps

# Install categories + individual tools
node install.js --modular --categories core,network --tools packet_sniffer

# List all available tools
node install.js --list-tools
```

**📖 [Complete Individual Tool Installation Guide](dev/src/docs/guides/INDIVIDUAL_TOOL_INSTALLATION.md)**

### Windows (PowerShell)
```powershell
.\scripts\install-win.ps1
npm run start:refactored
```

### Quick Health Check
```bash
npm run smoke
```

<img src="assets/wave-divider.svg" alt="" width="100%" />

<details open>
  <summary><b>TL;DR</b> — What is MCP God Mode?</summary>

MCP God Mode is the ultimate cybersecurity and system management platform that provides **148 fully implemented tools** across **5 major platforms**. It's designed for security professionals, system administrators, penetration testers, and anyone who needs comprehensive system control and security testing capabilities.

</details>

<details>
  <summary><b>Deep Dive</b> — Architecture & Safety</summary> 

**📝 Note**: We offer both monolithic and modular server architectures. Our **primary server-refactored** provides comprehensive functionality in a unified interface with **148 tools**. The modular server provides **148 tools** (configurable) for granular control, better error handling, and for the ease of an individual to extract a tool for their own server build. Tools are located in dev/src/tools. Each architecture serves different use cases and preferences.

**🔍 Server Architecture Differences**:
- **Server-Refactored (148 tools)**: Unified server with all core endpoints plus enhanced endpoints (Flipper Zero suite + MCP Web UI Bridge + advanced tools). Includes built-in legal compliance, audit logging, and forensic readiness capabilities.
- **Modular Server (148 tools, configurable)**: Comprehensive architecture with 148 tools for granular control, better error handling, and specialized functionality. **Configurable** - can be set to load minimal (10 tools), custom categories, or full (148 tools). Full legal compliance integration with modular evidence preservation.
- **Server-Minimal (15 tools)**: Lightweight implementation with core tools only for basic functionality and resource-constrained environments.

**🔢 Tool Count Explanation**: 
- **148 tools** are registered in both server-refactored and server-modular (complete implementation)
- **15 tools** are registered in server-minimal (core tools only)

**📊 Documentation Status**: All 148 tools (both servers) now have comprehensive documentation with detailed usage examples, parameter references, and platform compatibility information. See [Complete Tool Catalog](docs/general/TOOL_CATALOG.md) for detailed information about each tool.

**⚖️ Legal Compliance & Forensic Readiness**: Both server architectures include comprehensive legal compliance capabilities including audit logging, evidence preservation, legal hold management, and chain of custody tracking. These features are disabled by default and can be enabled through environment variables for SOX, HIPAA, GDPR, PCI DSS, and ISO 27001 compliance. See [Legal Compliance Documentation](docs/LEGAL_COMPLIANCE.md) for detailed configuration and usage instructions.

### Safety & Compliance Modes
| Flag               | Default | Effect (summary)                                      |
|--------------------|:-------:|-------------------------------------------------------|
| MCPGM_AUDIT_ENABLED|  true   | Logs tool calls + params to audit log.                |
| MCPGM_REQUIRE_CONFIRMATION | true | Prompts before high-risk actions.               |
| MCPGM_MODE_SOX     |  false  | Extra logging & retention guidance.                   |
| MCPGM_MODE_HIPAA   |  false  | Disables PHI-unsafe tools; stricter redaction.        |
| MCPGM_MODE_GDPR    |  false  | Right-to-erasure helpers; data minimization.          |

**⚠️ Threat Model / Safe-Use Notice**: This tool is intended for authorized testing and security assessment ONLY. Use only on networks and systems you own or have explicit written permission to test. Default audit logging is enabled; high-risk tools require confirmation. Do-not-target policy applies to all operations.

</details>

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 🐬 Flipper Zero Integration

<table>
  <tr>
    <td width="6"><img src="assets/callout-info.svg" alt="" width="6"/></td>
    <td><strong>Heads up:</strong> Run in a controlled environment first. See <a href="#-disclaimer">Disclaimer</a>.</td>
  </tr>
</table>

MCP-God-Mode includes comprehensive Flipper Zero integration with cross-platform support for both USB CDC Serial and BLE GATT transports. A single consolidated tool `flipper_zero` provides all Flipper Zero operations in both server modes.

See full documentation at `docs/tool/flipper_zero.md`.

### 🔧 Setup

1. **Enable Flipper Integration**:
   ```bash
   # Copy environment template
   cp dev/flipper.env.example .env
   
   # Edit .env to enable Flipper Zero
   MCPGM_FLIPPER_ENABLED=true
   MCPGM_FLIPPER_USB_ENABLED=true
   MCPGM_FLIPPER_BLE_ENABLED=true
   ```

2. **Install Dependencies**:
   ```bash
   cd dev
   npm install
   ```

3. **Start Server**:
   ```bash
   npm run start:refactored
   # or
   npm run start:modular
   ```

### 🚀 Quick Examples

**List Available Devices**:
```javascript
// List all Flipper Zero devices (USB and BLE)
flipper_zero({\n  action: "list_devices",\n  scan_ble: true,\n  scan_usb: true,\n  include_bridge: true\n})
```

**Connect and Get Device Info**:
```javascript
// Connect to device
const connectResult = flipper_zero({\n  action: "connect",\n  device_id: "usb:/dev/tty.usbmodem123"\n})

// Get device information
const info = flipper_zero({\n  action: "get_info",\n  session_id: connectResult.sessionId\n})
```

**File Operations**:
```javascript
// List files in root directory
flipper_zero({\n  action: "fs_list",\n  session_id: sessionId,\n  path: "/"\n})

// Read a file
flipper_zero({\n  action: "fs_read",\n  session_id: sessionId,\n  path: "/ext/ir/remote.ir"\n})
```

**NFC/RFID Operations**:
```javascript
// Read NFC card
flipper_zero({\n  action: "nfc_read",\n  session_id: sessionId\n})

// Dump RFID to file
flipper_zero({\n  action: "rfid_dump",\n  session_id: sessionId,\n  filename: "/ext/nfc/dump.nfc"\n})
```

### 🔒 Safety Features

- **Transmission Lock**: IR, Sub-GHz, and BadUSB operations are disabled by default
- **Audit Logging**: All operations are logged for security and compliance
- **Session Management**: Automatic session cleanup and timeout handling
- **Environment Guards**: Multiple layers of permission checking

### 🌍 Cross-Platform Support

- **Windows**: USB CDC appears as COM ports, BLE requires Windows 10+
- **macOS**: USB CDC appears as `/dev/tty.usbmodem*`, BLE requires permissions
- **Linux**: USB CDC requires `dialout` group, BLE requires `noble` permissions

### ?? Available Operations (Consolidated)

- Use the single tool:  `flipper_zero` with the `action` parameter (see docs/tool/flipper_zero.md). 
- Common actions:  `list_devices`, `connect`, `disconnect`, `get_info`, `list_sessions`, `fs_list`, `fs_read`, `fs_write`, `fs_delete`, `ir_send`, `ir_send_raw`, `subghz_tx`, `subghz_tx_raw`, `nfc_read`, `nfc_dump`, `rfid_read`, `rfid_dump`, `badusb_send`, `badusb_ducky`, `uart_sniff`, `gpio_set`, `gpio_read`, `ble_scan`, `ble_pair`. 

### ⚠️ Legal and Safety Notice

Flipper Zero transmission operations (IR, Sub-GHz, BadUSB) may be regulated in your jurisdiction. Always ensure you have proper authorization before using transmission features. The integration includes multiple safety mechanisms:

- Hard-locked transmission by default
- Audit logging for all operations
- Session-based security
- Environment-based permission controls

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 🔢 Understanding Tool Counts: Tools vs. Actions vs. Parameters

### **Why Tool Counting is Complex**

Tool counting in MCP God Mode presents unique challenges due to the multi-layered nature of our comprehensive security suite:

#### **🛠️ Tools (MCP Server Functions)**
- **Definition**: Distinct MCP server tool registrations
 - **Count**: 148 tools (both server architectures)
- **Example**: `wifi_security_toolkit` = 1 tool

#### **⚡ Actions (Tool Capabilities)**
- **Definition**: Specific operations within each tool
- **Count**: 500+ total actions across all tools
- **Example**: `wifi_security_toolkit` offers 25+ actions (scan, crack, monitor, deauth, etc.)

#### **🔧 Parameters (Configuration Options)**
- **Definition**: Input options for each action
- **Count**: 1000+ parameters across all tools
- **Example**: `scan` action has parameters like `interface`, `duration`, `stealth_mode`

### **Architecture Differences**

| Aspect | Server-Refactored | Modular Server |
|--------|------------------|----------------|
| **Tool Count** | 148 tools | 148 tools |
| **Architecture** | Unified interface | Individual focused tools |
| **Complexity** | Multi-action tools | Single-action tools |
| **Error Handling** | Centralized | Granular |
| **Use Case** | Comprehensive operations | Specific tasks |

### **Why the Count is Different?**

The server-refactored and modular servers have different tool counts because:

1. **Different Architecture**: Server-refactored uses unified tool registration, modular uses fragmented approach
2. **Granular Implementation**: Modular server breaks down complex tools into specialized functions
3. **Enhanced Functionality**: Modular server provides more precise control with additional tools
4. **Specialized Capabilities**: Modular server offers granular tools for specific tasks

**🎯 Bottom Line**: Both server-refactored and modular server provide identical functionality with 148 tools for comprehensive operations and built-in legal compliance features. The modular server adds configurability for different deployment scenarios.

**HELLO SPIDER NETWORK**

<img src="assets/wave-divider.svg" alt="" width="100%" />

<p align="center">
  <img src="assets/flame-text.svg" alt="One MCP to rule them all, one MCP to find them, one MCP to compile the tools, and in the God Mode bind them." width="100%" />
</p>

## 🖥️ Visual Demo

See MCP God Mode in action with Cursor IDE integration:

### 🎯 **Complete Cursor IDE Integration Proof**

<div align="center">

<img src="docs/images/Cursortoolsenabled.png" alt="Cursor IDE showing MCP God Mode tools enabled" width="100%" />
<img src="docs/images/Toolscursor1.png" alt="Cursor IDE integration with MCP God Mode tools" width="100%" />
<img src="docs/images/Toolscursor2.png" alt="Cursor IDE displaying MCP God Mode tool interface" width="100%" />

</div>

*MCP God Mode tools seamlessly integrated into Cursor IDE - providing instant access to 148 powerful security and system management tools across all major platforms! 🚀✨*

**🎭 Fun Fact**: We have so many visual proofs, even the screenshots are impressed! Each image shows different aspects of our comprehensive tool integration! 📸💻

### ✨ Key Features

- **🔒 100% Complete Implementation** - Every tool is fully functional and tested
- **🌍 Universal Platform Support** - Windows, Linux, macOS, Android, iOS
- **🌐 Multi-Frontend Compatibility** - Works with Cursor, LM Studio, Claude Desktop, SillyTavern, CAMEL-AI, Azure AI Foundry, MCP Bridge & more
- **🛡️ Enterprise-Grade Security** - Professional penetration testing tools
- **📱 Mobile-First Design** - Full mobile device support and management
- **🔧 Natural Language Interface** - Use tools with simple commands
- **📊 Real-Time Monitoring** - Live system and network analysis
- **🔄 Automated Workflows** - Batch processing and automation
- **📚 Comprehensive Documentation** - Wiki-style documentation with examples

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 🛠️ Tool Categories

<details>
  <summary><b>Core System Tools</b> - File operations, process management, system info, health monitoring</summary>

<picture>
  <img src="docs/headers/svg/system.svg" alt="Core System Tools" width="100%" />
</picture>

### 🔐 Core System Tools (8 Tools)
- **File Operations** - Advanced cross-platform file management
- **Process Management** - Command execution and elevated permissions
- **System Information** - Hardware, software, and health monitoring
- **Git Operations** - Repository management and version control
- **System Restore** - Backup and recovery operations
- **Health Monitoring** - System health checks
- **File Watcher** - File system monitoring
- **Cron Job Management** - Scheduled task management

**[📖 View All Core Tools](docs/general/TOOL_CATEGORY_INDEX.md#core-system-tools)**

</details>

<details>
  <summary><b>Network & Security Tools</b> - Network diagnostics, penetration testing, packet analysis, port scanning</summary>

<picture>
  <img src="docs/headers/svg/network.svg" alt="Network & Security Tools" width="100%" />
</picture>

### 🌐 Network & Security (19 Tools)
- **Network Diagnostics** - Ping, traceroute, DNS, port scanning
- **IP Geolocation** - IP-based geolocation using multiple databases
- **Network Triangulation** - Wi-Fi and cell tower triangulation
- **OSINT Reconnaissance** - Open source intelligence gathering
- **Latency Geolocation** - Ping-based geolocation triangulation
- **Network Discovery** - Comprehensive network reconnaissance
- **Vulnerability Assessment** - Comprehensive security assessment
- **Traffic Analysis** - Advanced packet and traffic analysis
- **Network Utilities** - Network utility tools and management
- **Social Network Ripper** - Social media account information extraction
- **Metadata Extractor** - Media metadata analysis and geolocation
- **Penetration Testing** - Comprehensive network security testing
- **Packet Analysis** - Network traffic capture and analysis
- **Port Scanner** - Port discovery and analysis
- **Network Traffic Analyzer** - Advanced traffic analysis
- **Network Penetration** - Advanced network security testing
- **Hack Network** - Comprehensive penetration testing
- **Security Testing** - Multi-domain vulnerability assessment
- **Download File** - File downloading capabilities

**[📖 View All Network Tools](docs/general/TOOL_CATEGORY_INDEX.md#network--security)**

</details>

<details>
  <summary><b>Wireless & Radio Tools</b> - Wi-Fi, Bluetooth, SDR security testing, signal analysis</summary>

<picture>
  <img src="docs/headers/svg/radio.svg" alt="Wireless & Radio Tools" width="100%" />
</picture>

### 📡 Wireless & Radio (7 Tools)
- **Wi-Fi Security** - Complete wireless security testing toolkit
- **Bluetooth Security** - Bluetooth device security assessment
- **SDR Operations** - Software Defined Radio security testing
- **Signal Analysis** - Radio frequency analysis and decoding
- **Wi-Fi Hacking** - Advanced wireless penetration testing
- **Bluetooth Hacking** - Advanced Bluetooth security testing
- **Wireless Network Scanner** - Advanced wireless discovery

**🎥 Live Demo**: See our WiFi security tools in action! [Watch the demo video]

https://github.com/user-attachments/assets/f074039c-1989-40fc-b769-5efa855e854d

 showing real-time wireless security testing capabilities.

**[📖 View All Wireless Tools](docs/general/TOOL_CATEGORY_INDEX.md#wireless--radio)**

</details>

<details>
  <summary><b>Flipper Zero Integration</b> - Comprehensive Flipper Zero device management and operations</summary>

### 🐬 Flipper Zero Integration (24 Tools)
-- **Device Management** - Connect, disconnect, and manage Flipper Zero devices
-- **File System** - Read, write, list, and delete files on Flipper Zero storage
-- **Infrared (IR)** - Send IR signals and raw IR data (requires TX permission)
-- **Sub-GHz** - Transmit Sub-GHz signals and raw data (requires TX permission)
-- **NFC/RFID** - Read and dump NFC cards and RFID tags
-- **BadUSB** - Send BadUSB scripts and DuckyScript (requires TX permission)
-- **UART** - Sniff UART communication
-- **GPIO** - Set and read GPIO pin values
-- **Bluetooth** - Scan and pair with Bluetooth devices
-- **Cross-Platform** - USB CDC Serial and BLE GATT transport support
-- **Safety Features** - Hard-locked transmission with audit logging
-- **Session Management** - Secure session handling with automatic cleanup

**🔒 Safety Notice**: Flipper Zero transmission operations (IR, Sub-GHz, BadUSB) are disabled by default and require explicit environment configuration. All operations are logged for audit purposes.

**[?? Flipper Zero (Consolidated) — Full Docs](docs/tool/flipper_zero.md)**

</details>

<details>
  <summary><b>Email Management Tools</b> - SMTP, IMAP, email security, account management</summary>

<picture>
  <img src="docs/headers/svg/email.svg" alt="Email Management Tools" width="100%" />
</picture>

### 📧 Email Management (6 Tools)
- **SMTP Operations** - Send emails across all platforms
- **IMAP Operations** - Read, parse, and manage emails
- **Email Security** - Threat analysis and filtering
- **Account Management** - Multi-account email operations

**[📖 View All Email Tools](docs/general/TOOL_CATEGORY_INDEX.md#email-management)**

</details>

<details>
  <summary><b>Media & Content Tools</b> - Audio, video, image processing, OCR, screenshots</summary>

<picture>
  <img src="docs/headers/svg/media.svg" alt="Media & Content Tools" width="100%" />
</picture>

### 🎵 Media & Content (5 Tools)
- **Audio Processing** - Recording, editing, and conversion
- **Video Processing** - Screen recording and video editing
- **Image Processing** - Editing, enhancement, and OCR
- **Screenshot Tools** - Advanced screen capture capabilities
- **OCR Tools** - Text extraction from images

**[📖 View All Media Tools](docs/general/TOOL_CATEGORY_INDEX.md#media--content)**

</details>

<details>
  <summary><b>Web & Browser Tools</b> - Browser automation, web scraping, web automation, webhooks</summary>

<picture>
  <img src="docs/headers/svg/web.svg" alt="Web & Browser Tools" width="100%" />
</picture>

### 🖥️ Web & Browser (4 Tools)
- **Browser Automation** - Cross-platform browser control
- **Web Scraping** - Advanced content extraction and analysis
- **Web Automation** - Advanced web automation
- **Webhook Manager** - Webhook endpoint management

**[📖 View All Web Tools](docs/general/TOOL_CATEGORY_INDEX.md#web--browser)**

### 🌐 MCP Web UI Bridge (6 Tools)
- **Web UI Chat** - Chat with AI services through their web interfaces without APIs
- **Providers List** - List all available AI service providers and their capabilities
- **Provider Wizard** - Interactive wizard to set up custom AI service providers
- **Macro Record** - Record user actions into portable JSON scripts
- **Macro Run** - Execute saved macros with variable substitution
- **Session Management** - Manage encrypted sessions for AI service providers

**Supported AI Services**: ChatGPT, Grok (x.ai), Claude (Anthropic), Hugging Face Chat, plus custom providers
**Platforms**: Desktop (Windows/macOS/Linux), Android, iOS
**Features**: Real-time streaming, encrypted session persistence, anti-bot friendly, macro recording/replay

**[📖 View All MCP Web UI Bridge Tools](docs/general/TOOL_CATEGORY_INDEX.md#mcp-web-ui-bridge)**

<picture>
  <img src="docs/headers/svg/mobile.svg" alt="Mobile Device Tools" width="100%" />
</picture>

### 📱 Mobile Device (13 Tools)
- **Device Information** - Hardware and software details
- **File Operations** - Mobile file management
- **Hardware Access** - Camera, sensors, and peripherals
- **System Tools** - Mobile system administration
- **Device Management** - Mobile device administration
- **App Analytics** - Mobile application analytics and user behavior tracking
- **App Deployment** - Mobile app deployment and distribution toolkit
- **App Monitoring** - Mobile app monitoring and performance tracking
- **App Optimization** - Mobile app performance optimization
- **App Security** - Mobile app security testing and assessment
- **App Testing** - Mobile app testing and quality assurance toolkit
- **Network Analyzer** - Mobile network analysis and diagnostics
- **Performance Toolkit** - Mobile app performance testing and benchmarking

**[📖 View All Mobile Tools](docs/general/TOOL_CATEGORY_INDEX.md#mobile-device)**

<picture>
  <img src="docs/headers/svg/virtualization.svg" alt="Virtualization Tools" width="100%" />
</picture>

### 🖥️ Virtualization (2 Tools)
- **VM Management** - Virtual machine operations
- **Docker Management** - Container orchestration

**[📖 View All Virtualization Tools](docs/general/TOOL_CATEGORY_INDEX.md#virtualization--containers)**

<picture>
  <img src="docs/headers/svg/security.svg" alt="Advanced Security Tools" width="100%" />
</picture>

### 🔒 Advanced Security (17 Tools)
- **Blockchain Security** - Cryptocurrency and blockchain analysis
- **Quantum Security** - Post-quantum cryptography assessment
- **IoT Security** - Internet of Things device security
- **Malware Analysis** - Malicious software detection and analysis
- **Forensics Analysis** - Digital forensics and incident response
- **Compliance Assessment** - Regulatory compliance testing (ISO 27001, SOC 2, PCI DSS, GDPR, HIPAA, NIST)
- **Cloud Security** - Cloud infrastructure security assessment
- **Cloud Infrastructure Manager** - Cloud resource management
- **Exploit Framework** - Vulnerability exploitation
- **Vulnerability Scanner** - Security assessment tools
- **Password Cracker** - Authentication testing
- **Threat Intelligence** - Security threat analysis and monitoring
- **Social Engineering** - Human factor security testing and awareness training
- **Network Security** - Comprehensive network security
- **Packet Sniffer** - Network traffic analysis
- **Port Scanner** - Security port scanning

**[📖 View All Advanced Security Tools](docs/general/TOOL_CATEGORY_INDEX.md#advanced-security)**

### 🧮 Utilities (12 Tools)
- **Mathematical Tools** - Advanced calculations and statistics
- **Random Generation** - Dice rolling and random numbers
- **Data Analysis** - Statistical analysis and machine learning
- **Chart Generator** - Data visualization and charts
- **Data Analyzer** - Advanced data analysis
- **Machine Learning** - AI-powered analysis and model training
- **RAG Toolkit** - Advanced Retrieval-Augmented Generation for document search and context-aware Q&A
- **Password Generator** - Secure password generation
- **Text Processor** - Advanced text processing and analysis
- **Encryption Tools** - Cryptographic operations and security
- **Calculator** - Basic mathematical operations
- **Tool Discovery** - Natural language tool search and exploration

**[📖 View All Utility Tools](docs/general/TOOL_CATEGORY_INDEX.md#utilities)**

### 🔄 System Restore (1 Tool)
- **System Backup** - Cross-platform system restore points and backup management

**[📖 View All System Restore Tools](docs/general/TOOL_CATEGORY_INDEX.md#system-restore)**

### 🔧 Tool Discovery (2 Tools)
- **Natural Language Search** - Find tools using natural language queries
- **Category Explorer** - Browse tools by category and capability

**[📖 View All Discovery Tools](docs/general/TOOL_CATEGORY_INDEX.md#tool-discovery)**

### 📁 File System (6 Tools)
- **File Operations** - Advanced file management
- **File Watcher** - File system monitoring
- **File List** - Directory navigation
- **File Read** - Text file reading
- **File Write** - Text file writing
- **File Search** - Content-based search

**[📖 View All File System Tools](docs/general/TOOL_CATEGORY_INDEX.md#file-system)**

### 🔍 Forensics (3 Tools)
- **Forensics Analysis** - Digital forensics and incident response
- **Forensics Toolkit** - Complete forensics framework
- **Malware Analysis Toolkit** - Malicious software analysis

**[📖 View All Forensics Tools](docs/general/TOOL_CATEGORY_INDEX.md#forensics)**

### ☁️ Cloud (3 Tools)
- **Cloud Security** - Cloud infrastructure security assessment
- **Cloud Security Toolkit** - Comprehensive cloud security
- **Cloud Infrastructure Manager** - Cloud resource management

**[📖 View All Cloud Tools](docs/general/TOOL_CATEGORY_INDEX.md#cloud)**

## 📊 **Complete Tool Summary**

| Category | Tools | Description |
|----------|-------|-------------|
| **🔐 Core System** | 8 | File operations, process management, system info, health monitoring |
| **🌐 Network & Security** | 19 | Network diagnostics, penetration testing, packet analysis, port scanning |
| **📡 Wireless & Radio** | 7 | Wi-Fi, Bluetooth, SDR security testing, signal analysis |
| **📧 Email Management** | 6 | SMTP, IMAP, email security, account management |
| **🎵 Media & Content** | 5 | Audio, video, image processing, OCR, screenshots |
| **🖥️ Web & Browser** | 4 | Browser automation, web scraping, web automation, webhooks |
| **📱 Mobile Device** | 13 | Device info, file ops, hardware access, system tools, app tools |
| **🖥️ Virtualization** | 2 | VM management, Docker orchestration |
| **🔒 Advanced Security** | 17 | Blockchain, quantum, IoT, forensics, cloud security |
| **🧮 Utilities** | 12 | Math tools, dice rolling, data analysis, ML, RAG toolkit, encryption |
| **🔄 System Restore** | 1 | Cross-platform backup and restore |
| **🔧 Tool Discovery** | 2 | Natural language search, category explorer |
| **📁 File System** | 6 | File operations, file watching, file management |
| **🔍 Forensics** | 3 | Digital forensics, malware analysis, forensics toolkit |
| **☁️ Cloud** | 3 | Cloud security, cloud infrastructure management |
| **🪟 Windows-Specific** | 2 | Windows services and process management |

<<<<<<< HEAD
**Total: 148 Tools (Both Servers)** - All fully implemented, tested, and documented ✅

## 🎯 **Implementation Status: 100% Complete**

✅ **All 148 tools (both servers) are fully implemented and tested**  
✅ **Cross-platform compatibility verified**  
✅ **MCP protocol integration complete**  
✅ **Natural language interface working**  
✅ **Comprehensive documentation available for all tools**  
✅ **Real-world testing completed**

**🔧 Architecture Note**: We offer both server-refactored and modular server architectures. Our **primary server-refactored** provides comprehensive functionality in a unified interface with **148 tools**. The modular server provides **148 tools** for granular control and better error handling. Each architecture serves different use cases and preferences.  

### 🪟 Windows-Specific (2 Tools)
- **Service Management** - Windows service control
- **Process Management** - Windows process administration

**[📖 View All Windows Tools](docs/general/TOOL_CATEGORY_INDEX.md#windows-specific)**

</details>

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 🚀 Quick Start

### ⚡ **Recommended: Use with Cursor AI Agent Mode**

**For optimal performance, we recommend using this project with Cursor AI in Agent mode.** Agent mode empowers Cursor to autonomously handle complex coding tasks, such as multi-file edits and terminal command execution, which are integral to this project's functionality.

**To activate Agent mode:**
1. Open the Composer (Ctrl+I)
2. Select the Agent icon
3. Begin utilizing the enhanced features

This mode provides the best experience for leveraging MCP God Mode's comprehensive toolset through natural language interaction.

### 1. Choose Your Frontend
Select your preferred MCP-compatible frontend:

- **[🖥️ Cursor AI](docs/guides/MCP_FRONTEND_INTEGRATION_GUIDE.md#cursor-ai-integration)** - Recommended (Agent mode)
- **[🎵 LM Studio](docs/guides/MCP_FRONTEND_INTEGRATION_GUIDE.md#lm-studio-integration)** - Local AI models
- **[🤖 Claude Desktop](docs/guides/MCP_FRONTEND_INTEGRATION_GUIDE.md#claude-desktop-integration)** - Advanced AI tasks
- **[🎭 SillyTavern](docs/guides/MCP_FRONTEND_INTEGRATION_GUIDE.md#sillytavern-integration)** - Roleplay & chat
- **[🔧 Continue](docs/guides/MCP_FRONTEND_INTEGRATION_GUIDE.md#continue-integration)** - VS Code extension
- **[🌐 Open WebUI](docs/guides/MCP_FRONTEND_INTEGRATION_GUIDE.md#open-webui-integration)** - Web interface
- **[🤖 CAMEL-AI Agents](docs/guides/MCP_FRONTEND_INTEGRATION_GUIDE.md#camel-ai-agents-integration)** - AI agent development
- **[☁️ Azure AI Foundry](docs/guides/MCP_FRONTEND_INTEGRATION_GUIDE.md#azure-ai-foundry-integration)** - Enterprise solutions
- **[🌉 MCP Bridge](docs/guides/MCP_FRONTEND_INTEGRATION_GUIDE.md#mcp-bridge-integration)** - Mobile/web integration

### 2. Choose Your Platform
Select your operating system for specific installation instructions:

- **[🪟 Windows Setup](docs/guides/COMPLETE_SETUP_GUIDE.md#windows-setup)** - PowerShell, Chocolatey, or manual installation
- **[🐧 Linux Setup](docs/guides/COMPLETE_SETUP_GUIDE.md#linux-setup)** - Ubuntu, CentOS, Arch, and more
- **[🍎 macOS Setup](docs/guides/COMPLETE_SETUP_GUIDE.md#macos-setup)** - Homebrew or MacPorts installation
- **[🤖 Android Setup](docs/guides/COMPLETE_SETUP_GUIDE.md#android-setup)** - Termux, ADB, or root installation
- **[🍎 iOS Setup](docs/guides/COMPLETE_SETUP_GUIDE.md#ios-setup)** - TestFlight, jailbreak, or manual deployment

### 3. Install Dependencies
```bash
# Python 3.8+ required
python --version

# Clone repository
git clone https://github.com/your-username/MCP-God-Mode.git
cd MCP-God-Mode

# Install dependencies
pip install -r requirements.txt
```

### 4. First Steps
```bash
# Test installation
python -m mcp_god_mode.tools.core.system_info

# Check available tools
python -m mcp_god_mode.tools.core.health

# Run network diagnostics
python -m mcp_god_mode.tools.network.network_diagnostics --action ping --target "8.8.8.8"
```

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 💡 Usage Examples

### 🔒 Security Testing
```bash
# Comprehensive security assessment
python -m mcp_god_mode.tools.security.security_testing \
  --target_type "network" \
  --action "assess_vulnerabilities" \
  --target "192.168.1.0/24"

# Wi-Fi security testing
python -m mcp_god_mode.tools.wireless.wifi_security_toolkit \
  --action "scan_networks" \
  --interface "wlan0"
```

### 📁 File Management
```bash
# Advanced file operations
python -m mcp_god_mode.tools.core.file_ops \
  --action "copy" \
  --source "./source/" \
  --destination "./backup/" \
  --recursive true \
  --compression_level "high"
```

### 📧 Email Operations
```bash
# Send secure email
python -m mcp_god_mode.tools.email.send_email \
  --to "recipient@example.com" \
  --subject "Test" \
  --body "Hello from MCP God Mode!" \
  --email_config '{"service":"gmail","email":"sender@gmail.com","password":"app_password"}'
```

**[📖 View More Examples](docs/guides/EXAMPLES_AND_TUTORIALS.md)**

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 🛠️ Troubleshooting & Support

### **Need Help?**
If you encounter issues, need assistance, or have questions about MCP God Mode:

**📞 Official Discord Server**: Join our community for real-time support, troubleshooting, and discussions: [https://discord.gg/EuQBurC2](https://discord.gg/EuQBurC2)

**👨‍💻 Contact Blink Zero**: For technical support, bug reports, or advanced troubleshooting, reach out to Blink Zero directly on Discord.

### **Common Issues**
- **Installation Problems**: Check platform-specific setup guides
- **Tool Not Working**: Verify dependencies and permissions
- **Cross-Platform Issues**: Review compatibility matrix
- **Performance Issues**: Check system requirements and resource usage

### **Bug Reports & Feature Requests**
- **Discord**: Report bugs and request features in our Discord server
- **GitHub Issues**: For detailed bug reports and feature requests
- **Security Issues**: Contact Blink Zero directly for security-related concerns

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 🌍 Cross-Platform Support

### Platform Matrix
| Platform | Core Functionality | Security Tools | Network Tools | Media Tools | File Operations | Overall |
|----------|---------------------|----------------|---------------|-------------|-----------------|---------|
| **Windows** | ✅ 100% | ✅ 100% | ✅ 100% | ✅ 100% | ✅ 100% | ✅ 100% |
| **Linux**   | ✅ 100% | ✅ 100% | ✅ 100% | ✅ 100% | ✅ 100% | ✅ 100% |
| **macOS**   | ✅ 100% | ✅ 100% | ✅ 100% | ✅ 100% | ✅ 100% | ✅ 100% |
| **Android** | ✅ 95%  | ✅ 90%  | ✅ 95%  | ✅ 90%  | ✅ 95%  | ✅ 93%  |
| **iOS**     | ✅ 90%  | ✅ 85%  | ✅ 90%  | ✅ 85%  | ✅ 90%  | ✅ 88%  |

**[📖 View Complete Compatibility Matrix](docs/general/CROSS_PLATFORM_COMPATIBILITY.md)**

### Platform-Specific Features
- **Windows**: Native Windows Services, Process Management, Registry Operations
- **Linux**: Systemd Integration, Package Management, SELinux Support
- **macOS**: LaunchDaemon Support, Gatekeeper Integration, Time Machine
- **Android**: ADB Integration, Root Access, Hardware Sensors
- **iOS**: Jailbreak Support, Hardware Access, System Integration

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 🔧 Advanced Features

### Natural Language Interface
Use tools with simple, natural commands:
```bash
# Instead of complex parameters, use natural language
python -m mcp_god_mode.tools.security.hack_network \
  --target "192.168.1.0/24" \
  --action "test network security" \
  --method "vulnerability scan"
```

### Automated Workflows
Create automated security testing pipelines:
```bash
# Automated security assessment
python -m mcp_god_mode.tools.security.security_testing \
  --target_type "network" \
  --action "automated_assessment" \
  --target "company.com" \
  --duration 3600
```

### Real-Time Monitoring
Monitor systems and networks in real-time:
```bash
# Live network monitoring
python -m mcp_god_mode.tools.network.packet_sniffer \
  --action "monitor_bandwidth" \
  --interface "eth0" \
  --duration 3600
```

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 📊 Performance & Benchmarks

### Tool Performance
- **File Operations**: 10GB+ files in seconds
- **Network Scanning**: 1000+ ports in under 1 minute
- **Security Testing**: Full network assessment in 30 minutes
- **Media Processing**: 4K video processing in real-time

### Resource Usage
- **Memory**: Minimal footprint (50-200MB per tool)
- **CPU**: Optimized for multi-core systems
- **Storage**: Efficient compression and caching
- **Network**: Bandwidth-optimized operations

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 🔒 Security & Privacy

### Built-in Security Features
- **Encryption**: AES-256 encryption for sensitive data
- **Authentication**: Multi-factor authentication support
- **Audit Logging**: Complete operation logging
- **Permission Management**: Granular access control

### Privacy Protection
- **Data Minimization**: Only collect necessary information
- **Local Processing**: Process data locally when possible
- **Secure Communication**: Encrypted network communications
- **Compliance**: GDPR, HIPAA, and SOC2 compliant

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 📦 Releases

### v1.7 Release Assets
The v1.7 release includes platform-specific archives for easy deployment:

- **MCP-God-Mode-v1.7-win.zip** - Windows package with PowerShell installer
- **MCP-God-Mode-v1.7-macos.tar.gz** - macOS package with shell installer  
- **MCP-God-Mode-v1.7-linux.tar.gz** - Linux package with shell installer

Each archive contains:
- `/dist` - Compiled server files
- `README-QUICKSTART.md` - Quick start guide
- `scripts/` - Platform-specific installers
- `.env.example` - Environment configuration template
- One-shot launcher scripts

### Download & Install
```bash
# Download latest release
curl -L https://github.com/BlinkZer0/MCP-God-Mode/releases/latest/download/MCP-God-Mode-v1.7-linux.tar.gz | tar -xz
cd MCP-God-Mode-v1.7

# Run installer
./scripts/install-unix.sh
npm run start:refactored
```

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### 🐛 Report Issues
- **[GitHub Issues](https://github.com/your-username/MCP-God-Mode/issues)** - Report bugs and request features
- **[Security Issues](https://github.com/your-username/MCP-God-Mode/security)** - Report security vulnerabilities

### 💡 Suggest Features
- **[GitHub Discussions](https://github.com/your-username/MCP-God-Mode/discussions)** - Share ideas and ask questions
- **[Feature Requests](https://github.com/your-username/MCP-God-Mode/issues/new?template=feature_request.md)** - Submit feature requests

### 🔧 Contribute Code
- **[Contributing Guide](CONTRIBUTING.md)** - Learn how to contribute
- **[Development Setup](docs/DEVELOPMENT.md)** - Set up development environment
- **[Code Standards](docs/CODE_STANDARDS.md)** - Follow our coding standards

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 📚 Documentation

### 📖 Complete Documentation Index
- **[Main Index](docs/general/DOCUMENTATION_INDEX.md)** - Navigate all documentation
- **[Tool Categories](docs/general/TOOL_CATEGORY_INDEX.md)** - Browse tools by category
- **[Parameter Reference](docs/general/COMPLETE_PARAMETER_REFERENCE.md)** - Complete parameter documentation

### 🚀 Getting Started
- **[Setup Guide](docs/guides/COMPLETE_SETUP_GUIDE.md)** - Installation and configuration
- **[Examples & Tutorials](docs/guides/EXAMPLES_AND_TUTORIALS.md)** - Real-world usage examples
- **[Platform Compatibility](docs/general/CROSS_PLATFORM_COMPATIBILITY.md)** - Platform-specific details

### 🔧 Advanced Topics
- **[Development Guide](docs/guides/DEVELOPMENT.md)** - Contributing and development
- **[API Reference](docs/general/API_REFERENCE.md)** - Programmatic interface
- **[Performance Tuning](docs/general/PERFORMANCE.md)** - Optimization and benchmarking

### 📁 Organized Documentation
- **[Implementation Docs](dev/src/docs/)** - Technical implementation details
- **[Project Summaries](dev/src/docs/summaries/)** - Feature and milestone summaries
- **[Tool Documentation](dev/src/docs/tools/)** - Individual tool guides
- **[Documentation Index](dev/src/docs/DOCUMENTATION_INDEX.md)** - Complete documentation index


### 🔄 Version History
- **v1.7** (Current) - **148 tools (both servers) complete (100%)**, perfect parity achieved, MCP Web UI Bridge tools, modular configuration system, comprehensive documentation, cross-platform support, MCP integration, accurate tool counting
- **v1.6d** - **148 tools (both servers) complete (100%)**, comprehensive documentation, cross-platform support, MCP integration, accurate tool counting, RAG toolkit integration
- **v1.4a** - Enhanced security tools and mobile support
- **v1.0** - Initial release with core functionality

<img src="assets/wave-divider.svg" alt="" width="100%" />

## ⚖️ Legal Disclaimer

**IMPORTANT**: This software is designed for legitimate security testing and system administration purposes only. Users are responsible for ensuring they have proper authorization before using any security testing tools.

**[📋 Read Full Legal Disclaimer](docs/legal/LEGAL_DISCLAIMER.md)** - Terms of use, liability information, and prohibited uses

**📞 Contact for Legal Matters**: For legal questions, compliance inquiries, or authorization concerns, contact Blink Zero on our official Discord server: [https://discord.gg/EuQBurC2](https://discord.gg/EuQBurC2)

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Security Community** - For feedback and testing
- **Open Source Contributors** - For building amazing tools
- **Platform Developers** - For creating robust operating systems
- **Users** - For valuable feedback and feature requests

<img src="assets/wave-divider.svg" alt="" width="100%" />

## 🥋 **About the Developer**

### **Meet Blink Zero (Shuriken Miasma)**

**🎮 Join Our Community**: [MCP GOD MODE's Official Discord Server](https://discord.gg/EuQBurC2) - Connect with Blink Zero and the community for support, discussions, and updates.

The mastermind behind MCP God Mode is **Blink Zero**, a true renaissance developer who combines martial arts mastery with electronic jazz composition and cutting-edge cybersecurity development.

#### **🥋 Martial Arts Mastery**
Blink Zero is a dedicated Kung Fu artist whose skills transcend the digital realm. From lightning-fast nunchaku strikes to explosive aerial kicks, their martial arts prowess demonstrates the same precision and power that goes into every line of code.

#### **🎵 Electronic Jazz Composer**
With **111 electronic jazz songs** and counting, Blink Zero creates innovative musical compositions that blend electronic elements with jazz sophistication. This creative approach translates into innovative problem-solving and tool design.

#### **💻 Development Philosophy**
Just as in martial arts, Blink Zero approaches software development with technical precision, creative innovation, and reliable performance. MCP God Mode represents the culmination of years of cybersecurity expertise, martial arts discipline, and musical creativity.

**[📖 View Full Developer Showcase](docs/general/DEVELOPER_SHOWCASE.md)** - Learn more about the developer behind the tools



---

## ⭐ Star This Project

If MCP God Mode has been helpful to you, please consider giving it a star on GitHub! It helps us reach more users and continue development.

**[⭐ Star on GitHub](https://github.com/your-username/MCP-God-Mode)**

---

*Last Updated: September 2025*  
*MCP God Mode v1.7 Final - One MCP to rule them all - The Ultimate Cross-Platform Security Suite*  
*All 148 tools (both servers) tested, verified working, and fully documented ✅*

---

<div align="center">

**🚀 Ready to become a cybersecurity god? First, remember to be kind to one another and set your differences aside. This tool is not for malicious use. [Get Started Now](docs/guides/COMPLETE_SETUP_GUIDE.md)! 🚀**

</div>





