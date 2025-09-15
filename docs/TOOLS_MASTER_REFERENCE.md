# MCP God Mode - Master Tool Reference

## 📚 Documentation Structure

1. [Core Tools](#core-tools)
2. [Security Tools](#security-tools)
3. [AI & Automation](#ai--automation)
4. [System & Network](#system--network)
5. [Forensics & Analysis](#forensics--analysis)
6. [Specialized Tools](#specialized-tools)

## Core Tools

### Enhanced Calculator
- **Description**: Advanced mathematical operations with scientific computing
- **Category**: Utilities
- **Parameters**:
  - `expression`: Mathematical expression to evaluate
  - `precision`: Decimal precision (default: 10)
  - `output_format`: Result format (number, scientific, fraction)

### Enhanced Data Analysis
- **Description**: Statistical analysis and data visualization
- **Category**: Analytics
- **Parameters**:
  - `data_source`: Input data file or JSON string
  - `analysis_type`: Type of analysis (statistical, trend, correlation)
  - `output_format`: Output format (chart, table, json)

## Security Tools

### Advanced Security Assessment
- **Description**: Comprehensive security evaluation with threat modeling
- **Category**: Security
- **Parameters**:
  - `assessment_type`: Type of assessment (threat_modeling, risk_analysis)
  - `target`: System or component to assess
  - `report_format`: Output format (pdf, html, json)

### Session Management
- **Description**: Manage encrypted AI service sessions
- **Category**: Security
- **Parameters**:
  - `action`: Action to perform (list, clear, cleanup)
  - `session_id`: Specific session to manage (optional)

## AI & Automation

### Web UI Chat
- **Description**: Chat with AI services through web interfaces
- **Category**: AI
- **Parameters**:
  - `provider`: AI service provider (chatgpt, claude, etc.)
  - `prompt`: Message to send
  - `session_id`: Continue existing session (optional)

### Browser Automation
- **Description**: Advanced web automation with Playwright
- **Category**: Automation
- **Parameters**:
  - `action`: Action to perform (navigate, click, fill, extract)
  - `url`: Target URL
  - `selector`: Element selector (for click/fill)

## System & Network

### Network Scanner
- **Description**: Advanced network scanning and host discovery
- **Category**: Network
- **Parameters**:
  - `target`: IP range or host to scan
  - `scan_type`: Type of scan (quick, full, stealth)
  - `ports`: Ports to scan (default: common ports)

### System Information
- **Description**: Detailed system and hardware information
- **Category**: System
- **Parameters**:
  - `detail_level`: Level of detail (basic, detailed, full)
  - `output_format`: Output format (json, text, table)

## Forensics & Analysis

### Memory Forensics
- **Description**: Advanced memory analysis and forensics
- **Category**: Forensics
- **Parameters**:
  - `action`: Analysis action (dump, analyze, search)
  - `target`: Process ID or memory dump file
  - `search_terms`: Terms to search for in memory

### Network Forensics
- **Description**: Network traffic capture and analysis
- **Category**: Forensics
- **Parameters**:
  - `interface`: Network interface to capture from
  - `filter`: BPF filter expression
  - `output_file`: Save capture to file (optional)

## Specialized Tools

### Flipper Zero Integration
- **Description**: Interface with Flipper Zero devices
- **Category**: Hardware
- **Parameters**:
  - `action`: Action to perform (list, read, write)
  - `device_path`: Path to Flipper device
  - `data`: Data to write (for write actions)

### Drone Control
- **Description**: Autonomous drone control and automation
- **Category**: Hardware
- **Parameters**:
  - `command`: Drone command (takeoff, land, move)
  - `coordinates`: Target coordinates (for move)
  - `altitude`: Flight altitude (meters)

## Usage Examples

### Running a Security Scan
```bash
mcp-god-mode run security_assessment --target=webapp.example.com --type=web
```

### Starting an AI Chat
```bash
mcp-god-mode run web_ui_chat --provider=chatgpt --prompt="Hello, how are you?"
```

### Network Analysis
```bash
mcp-god-mode run network_scan --target=192.168.1.0/24 --scan_type=quick
```

## Tool Development

### Adding a New Tool
1. Create implementation in `dev/src/tools/`
2. Add entry to `tools.manifest.json`
3. Write smoke test in `scripts/smoke/`
4. Update documentation in `docs/TOOLS_MASTER_REFERENCE.md`

### Tool Categories
- **Security**: Security assessment, testing, and analysis
- **AI**: Artificial intelligence and machine learning
- **Network**: Network analysis and scanning
- **System**: System information and management
- **Forensics**: Digital forensics and analysis
- **Hardware**: Physical device integration

## Troubleshooting

### Common Issues
1. **Permission Denied**: Ensure you have necessary permissions
2. **Tool Not Found**: Verify tool name in manifest
3. **Connection Issues**: Check network and service status

### Getting Help
- Use `--help` flag with any tool
- Check logs in `logs/` directory
- Open an issue on GitHub for bugs or feature requests
