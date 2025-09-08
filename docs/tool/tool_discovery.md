# Tool Discovery Tool

## Overview
The Tool Discovery tool provides natural language search capabilities to find and explore available tools in the MCP God Mode suite. It helps users discover the right tool for their specific needs through intelligent search and categorization.

## Features
- **Natural Language Search**: Find tools using conversational queries
- **Category Exploration**: Browse tools by functional categories
- **Capability Matching**: Match tools to specific use cases
- **Parameter Discovery**: Learn about tool parameters and options
- **Usage Examples**: Get practical examples for each tool

## Parameters

### Required Parameters
- **search_term** (string): Natural language search query or specific tool name

### Optional Parameters
- **category** (string): Filter results by tool category
- **capability** (string): Filter by specific capability or function


## Natural Language Access
Users can request tool discovery operations using natural language:
- "Discover available tools"
- "Find relevant tools"
- "Search tool capabilities"
- "Explore tool options"
- "Identify useful tools"
## Usage Examples

### Natural Language Search
```bash
# Search for network security tools
python -m mcp_god_mode.tools.discovery.tool_discovery \
  --search_term "tools for testing network security"

# Find file management tools
python -m mcp_god_mode.tools.discovery.tool_discovery \
  --search_term "how to manage files and directories"
```

### Category-Based Search
```bash
# Find all mobile device tools
python -m mcp_god_mode.tools.discovery.tool_discovery \
  --search_term "mobile" \
  --category "mobile_device"

# Search for penetration testing tools
python -m mcp_god_mode.tools.discovery.tool_discovery \
  --search_term "penetration testing" \
  --category "security"
```

### Capability-Based Search
```bash
# Find tools that can scan ports
python -m mcp_god_mode.tools.discovery.tool_discovery \
  --search_term "port scanning" \
  --capability "network_scanning"

# Discover encryption tools
python -m mcp_god_mode.tools.discovery.tool_discovery \
  --search_term "encryption" \
  --capability "cryptography"
```

## Output Format

The tool returns structured results including:
- **success** (boolean): Operation success status
- **message** (string): Search results summary
- **tools_found** (array): List of matching tools with details
  - **name** (string): Tool name
  - **description** (string): Tool description
  - **category** (string): Tool category
  - **capabilities** (array): List of capabilities
  - **parameters** (object): Tool parameters
  - **examples** (array): Usage examples

## Platform Support
- ✅ **Windows**: Full search and discovery support
- ✅ **Linux**: Complete tool exploration capabilities
- ✅ **macOS**: Native search functionality
- ✅ **Android**: Mobile-optimized tool discovery
- ✅ **iOS**: iOS-specific tool search and discovery

## Search Capabilities

### Natural Language Queries
- **Intent Recognition**: Understands user intent from natural language
- **Synonym Matching**: Finds tools using alternative terms
- **Context Awareness**: Considers context for better results
- **Fuzzy Matching**: Handles typos and variations

### Category Filtering
- **Core System**: File operations, process management, system info
- **Network & Security**: Network diagnostics, penetration testing
- **Wireless & Radio**: Wi-Fi, Bluetooth, SDR security
- **Email Management**: SMTP, IMAP, email security
- **Media & Content**: Audio, video, image processing
- **Web & Browser**: Browser automation, web scraping
- **Mobile Device**: Mobile device management and security
- **Virtualization**: VM and container management
- **Advanced Security**: Blockchain, quantum, IoT security
- **Utilities**: Math tools, data analysis, encryption

### Capability Matching
- **Network Operations**: Scanning, monitoring, analysis
- **Security Testing**: Penetration testing, vulnerability assessment
- **File Management**: Operations, monitoring, search
- **Process Control**: Execution, monitoring, management
- **Data Processing**: Analysis, transformation, visualization
- **Communication**: Email, web, API interactions
- **System Administration**: Configuration, monitoring, maintenance

## Use Cases
- **Tool Discovery**: Find the right tool for specific tasks
- **Learning**: Explore available capabilities and features
- **Documentation**: Get detailed information about tools
- **Workflow Planning**: Discover tools for complex workflows
- **Training**: Learn about tool capabilities and usage

## Best Practices
1. **Specific Queries**: Use specific terms for better results
2. **Category Filtering**: Use categories to narrow down results
3. **Capability Focus**: Search by capability for functional matches
4. **Example Usage**: Review examples for practical implementation
5. **Parameter Study**: Understand tool parameters before use

## Related Tools
- [Explore Categories Tool](explore_categories.md) - Browse tools by category
- [System Info Tool](system_info.md) - Get system information
- [Health Tool](health.md) - Check system health

## Troubleshooting
- **No Results**: Try broader search terms or different categories
- **Too Many Results**: Use more specific terms or add category filters
- **Unclear Results**: Review tool descriptions and examples
- **Missing Tools**: Check if tool is available in your platform
