# Explore Categories Tool

## Overview
The Explore Categories tool provides comprehensive browsing and exploration of tools organized by functional categories. It helps users understand the full scope of available tools and discover new capabilities within specific domains.

## Features
- **Category Browsing**: Explore tools by functional categories
- **Hierarchical Organization**: Navigate through category hierarchies
- **Tool Counts**: See how many tools are available in each category
- **Capability Overview**: Understand what each category offers
- **Cross-References**: Find related tools across categories

## Parameters

### Required Parameters
- **category** (string): Category to explore (optional for full overview)

### Optional Parameters
- **depth** (number): Exploration depth (1-3 levels)
- **include_examples** (boolean): Include usage examples
- **platform_filter** (string): Filter by platform compatibility

## Usage Examples

### Full Category Overview
```bash
# Get complete category overview
python -m mcp_god_mode.tools.discovery.explore_categories
```

### Explore Specific Category
```bash
# Explore network and security tools
python -m mcp_god_mode.tools.discovery.explore_categories \
  --category "network_security"

# Explore mobile device tools
python -m mcp_god_mode.tools.discovery.explore_categories \
  --category "mobile_device"
```

### Deep Category Exploration
```bash
# Deep exploration with examples
python -m mcp_god_mode.tools.discovery.explore_categories \
  --category "security" \
  --depth 3 \
  --include_examples true
```

### Platform-Specific Exploration
```bash
# Explore tools for specific platform
python -m mcp_god_mode.tools.discovery.explore_categories \
  --category "wireless" \
  --platform_filter "android"
```

## Output Format

The tool returns structured results including:
- **success** (boolean): Operation success status
- **message** (string): Exploration results summary
- **categories** (array): List of categories with details
  - **name** (string): Category name
  - **description** (string): Category description
  - **tool_count** (number): Number of tools in category
  - **tools** (array): List of tools in category
  - **subcategories** (array): Subcategories if applicable
  - **capabilities** (array): Key capabilities of category

## Available Categories

### Core System (8 Tools)
- **File Operations**: Advanced cross-platform file management
- **Process Management**: Command execution and elevated permissions
- **System Information**: Hardware, software, and health monitoring
- **Git Operations**: Repository management and version control
- **System Restore**: Backup and recovery operations
- **Health Monitoring**: System health checks
- **File Watcher**: File system monitoring
- **Cron Job Management**: Scheduled task management

### Network & Security (11 Tools)
- **Network Diagnostics**: Ping, traceroute, DNS, port scanning
- **Penetration Testing**: Comprehensive network security testing
- **Packet Analysis**: Network traffic capture and analysis
- **Port Scanner**: Port discovery and analysis
- **Network Traffic Analyzer**: Advanced traffic analysis
- **Network Penetration**: Advanced network security testing
- **Hack Network**: Comprehensive penetration testing
- **Security Testing**: Multi-domain vulnerability assessment
- **Penetration Testing Toolkit**: Complete PT framework
- **Social Engineering**: Human factor security testing
- **Download File**: File downloading capabilities

### Wireless & Radio (7 Tools)
- **Wi-Fi Security**: Complete wireless security testing toolkit
- **Bluetooth Security**: Bluetooth device security assessment
- **SDR Operations**: Software Defined Radio security testing
- **Signal Analysis**: Radio frequency analysis and decoding
- **Wi-Fi Hacking**: Advanced wireless penetration testing
- **Bluetooth Hacking**: Advanced Bluetooth security testing
- **Wireless Network Scanner**: Advanced wireless discovery

### Email Management (6 Tools)
- **SMTP Operations**: Send emails across all platforms
- **IMAP Operations**: Read, parse, and manage emails
- **Email Security**: Threat analysis and filtering
- **Account Management**: Multi-account email operations
- **Email Sorting**: Organize and categorize emails
- **Email Deletion**: Secure email removal

### Media & Content (5 Tools)
- **Audio Processing**: Recording, editing, and conversion
- **Video Processing**: Screen recording and video editing
- **Image Processing**: Editing, enhancement, and OCR
- **Screenshot Tools**: Advanced screen capture capabilities
- **OCR Tools**: Text extraction from images

### Web & Browser (4 Tools)
- **Browser Automation**: Cross-platform browser control
- **Web Scraping**: Advanced content extraction and analysis
- **Web Automation**: Advanced web automation
- **Webhook Manager**: Webhook endpoint management

### Mobile Device (13 Tools)
- **Device Information**: Hardware and software details
- **File Operations**: Mobile file management
- **Hardware Access**: Camera, sensors, and peripherals
- **System Tools**: Mobile system administration
- **Device Management**: Mobile device administration
- **App Analytics**: Mobile application analytics
- **App Deployment**: Mobile app deployment toolkit
- **App Monitoring**: Mobile app monitoring
- **App Optimization**: Mobile app performance optimization
- **App Security**: Mobile app security testing
- **App Testing**: Mobile app testing toolkit
- **Network Analyzer**: Mobile network analysis
- **Performance Toolkit**: Mobile app performance tools

### Virtualization (2 Tools)
- **VM Management**: Virtual machine operations
- **Docker Management**: Container orchestration

### Advanced Security (17 Tools)
- **Blockchain Security**: Cryptocurrency and blockchain analysis
- **Quantum Security**: Post-quantum cryptography assessment
- **IoT Security**: Internet of Things device security
- **Malware Analysis**: Malicious software detection and analysis
- **Forensics Analysis**: Digital forensics and incident response
- **Compliance Assessment**: Regulatory compliance testing
- **Cloud Security**: Cloud infrastructure security assessment
- **Cloud Infrastructure Manager**: Cloud resource management
- **Exploit Framework**: Vulnerability exploitation
- **Vulnerability Scanner**: Security assessment tools
- **Password Cracker**: Authentication testing
- **Threat Intelligence**: Security threat analysis
- **Network Security**: Comprehensive network security
- **Packet Sniffer**: Network traffic analysis
- **Port Scanner**: Security port scanning

### Utilities (11 Tools)
- **Mathematical Tools**: Advanced calculations and statistics
- **Random Generation**: Dice rolling and random numbers
- **Data Analysis**: Statistical analysis and machine learning
- **Chart Generator**: Data visualization and charts
- **Data Analyzer**: Advanced data analysis
- **Machine Learning**: AI-powered analysis
- **Password Generator**: Secure password generation
- **Text Processor**: Advanced text processing
- **Encryption Tools**: Cryptographic operations
- **Calculator**: Basic mathematical operations

## Platform Support
- ✅ **Windows**: Full category exploration support
- ✅ **Linux**: Complete tool categorization
- ✅ **macOS**: Native category browsing
- ✅ **Android**: Mobile-optimized category exploration
- ✅ **iOS**: iOS-specific tool categories

## Use Cases
- **Tool Discovery**: Find tools within specific domains
- **Capability Assessment**: Understand available functionality
- **Workflow Planning**: Plan multi-tool workflows
- **Learning**: Explore tool capabilities systematically
- **Documentation**: Get organized tool information

## Best Practices
1. **Start Broad**: Begin with general categories
2. **Use Depth**: Explore subcategories for detailed views
3. **Check Examples**: Review examples for practical usage
4. **Cross-Reference**: Look for related tools in other categories
5. **Platform Filter**: Use platform filters for specific environments

## Related Tools
- [Tool Discovery Tool](tool_discovery.md) - Natural language tool search
- [System Info Tool](system_info.md) - System information
- [Health Tool](health.md) - System health check

## Troubleshooting
- **Empty Categories**: Check if tools are available for your platform
- **Missing Subcategories**: Use depth parameter for detailed exploration
- **Platform Issues**: Verify platform compatibility for specific tools
- **Navigation Problems**: Use category names exactly as shown
