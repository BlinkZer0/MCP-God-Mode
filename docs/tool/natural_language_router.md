# Natural Language Router Tool

## Overview
Route natural language requests to appropriate tools with intelligent matching. This tool analyzes user queries in natural language and suggests the most appropriate tools and actions based on the detected intent and context.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | Natural language query to route to appropriate tools |
| `context` | string | No | Additional context about the request |
| `user_intent` | string | No | User's intended goal or objective |

## Usage Examples

### Security Testing Query
```json
{
  "query": "I want to test the security of my Wi-Fi network",
  "context": "Home network security assessment",
  "user_intent": "security_testing"
}
```

### Network Analysis Query
```json
{
  "query": "How can I analyze network traffic on my system?",
  "context": "Network troubleshooting",
  "user_intent": "analysis"
}
```

### System Management Query
```json
{
  "query": "I need to manage files on my mobile device",
  "context": "Mobile device administration",
  "user_intent": "management"
}
```

## Output Structure

### Success Response
```json
{
  "suggested_tools": [
    "wifi_security_toolkit",
    "network_diagnostics",
    "packet_sniffer"
  ],
  "confidence": 0.85,
  "reasoning": "Query contains security testing keywords and Wi-Fi network context",
  "alternative_tools": [
    "bluetooth_security_toolkit",
    "network_security"
  ],
  "recommended_actions": [
    "Scan for nearby Wi-Fi networks",
    "Test network security vulnerabilities",
    "Capture WPA handshakes for analysis",
    "Perform penetration testing"
  ],
  "query_analysis": {
    "detected_intent": "security_testing",
    "key_terms": ["test", "security", "wifi", "network"],
    "suggested_category": "security"
  }
}
```

## Intent Detection

### Supported Intents
- **security_testing**: Security assessment and penetration testing
- **analysis**: Data analysis and investigation
- **monitoring**: System and network monitoring
- **management**: System and device management
- **testing**: General testing and validation
- **general**: General purpose queries

### Intent Detection Patterns
- **Security Testing**: Keywords like "hack", "break", "penetrate", "test security"
- **Analysis**: Keywords like "analyze", "examine", "investigate", "check"
- **Monitoring**: Keywords like "monitor", "watch", "track", "observe"
- **Management**: Keywords like "manage", "control", "administer", "configure"
- **Testing**: Keywords like "test", "check", "verify", "validate"

## Category Suggestions

### Tool Categories
- **security**: Security testing and assessment tools
- **network**: Network analysis and management tools
- **file_system**: File and directory management tools
- **mobile**: Mobile device management tools
- **web**: Web automation and scraping tools
- **media**: Media editing and processing tools
- **general**: General purpose tools

### Category Detection Logic
- **Security**: Keywords related to security, vulnerability, penetration, hacking
- **Network**: Keywords related to network, Wi-Fi, Bluetooth, radio, packet
- **File System**: Keywords related to file, directory, folder, storage
- **Mobile**: Keywords related to mobile, Android, iOS, device
- **Web**: Keywords related to web, browser, scrape, automation
- **Media**: Keywords related to video, audio, image, media, edit

## Tool Recommendations

### Security Tools
- `wifi_security_toolkit` - Wi-Fi security testing
- `bluetooth_security_toolkit` - Bluetooth security testing
- `sdr_security_toolkit` - Software Defined Radio security
- `network_security` - General network security
- `penetration_testing_toolkit` - Penetration testing

### Network Tools
- `network_diagnostics` - Network troubleshooting
- `packet_sniffer` - Network traffic analysis
- `port_scanner` - Port scanning
- `network_discovery` - Network discovery
- `traffic_analysis` - Traffic analysis

### System Tools
- `system_info` - System information
- `file_ops` - File operations
- `process_management` - Process management
- `system_monitor` - System monitoring

## Recommended Actions

### Wi-Fi Security Toolkit
- Scan for nearby Wi-Fi networks
- Test network security vulnerabilities
- Capture WPA handshakes for analysis
- Perform penetration testing

### Bluetooth Security Toolkit
- Scan for Bluetooth devices
- Test Bluetooth security
- Analyze device vulnerabilities
- Perform pairing security tests

### SDR Security Toolkit
- Detect SDR hardware
- Scan radio frequencies
- Analyze radio signals
- Decode radio protocols

### Network Diagnostics
- Test network connectivity
- Run ping tests
- Perform traceroute analysis
- Check DNS resolution

### System Info
- Get system information
- Check hardware details
- View system specifications
- Display system configuration

## Confidence Scoring

### Confidence Levels
- **0.9-1.0**: Very high confidence - Clear intent and context
- **0.7-0.9**: High confidence - Good intent detection
- **0.5-0.7**: Medium confidence - Some ambiguity
- **0.3-0.5**: Low confidence - Unclear intent
- **0.0-0.3**: Very low confidence - Ambiguous query

### Confidence Factors
- **Keyword Matching**: Presence of relevant keywords
- **Context Clarity**: Clear context and intent
- **Tool Availability**: Availability of suggested tools
- **Query Specificity**: Specificity of the request

## Cross-Platform Support
- **Windows**: Full support
- **Linux**: Full support
- **macOS**: Full support
- **Android**: Full support
- **iOS**: Full support

## Best Practices
1. **Clear Queries**: Use clear and specific language
2. **Context**: Provide relevant context when available
3. **Intent**: Specify user intent when known
4. **Follow-up**: Use suggested tools and actions
5. **Feedback**: Provide feedback on tool effectiveness

## Related Tools
- [Tool Discovery](tool_discovery.md)
- [Explore Categories](explore_categories.md)
- [Security Testing](security_testing.md)
- [Network Diagnostics](network_diagnostics.md)
