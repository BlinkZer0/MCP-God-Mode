# Cellular Triangulation Tool

## Overview

The Cellular Triangulation Tool (`cellular_triangulate`) is a location estimation system that uses cellular tower signals to determine device position without GPS. This tool leverages signal strength (RSSI) and time difference of arrival (TDOA) from multiple cell towers to perform triangulation, making it ideal for indoor positioning, low-power scenarios, and GPS-denied environments.

## Key Features

### 📡 **Protocol-Aware Triangulation**
- Uses cellular network protocols (GSM/CDMA/LTE) for signal analysis
- Supports both RSSI and TDOA triangulation methods
- Integrates with OpenCellID API for tower location lookup
- Provides location estimates with error radius calculations

### 🔧 **Multiple Triangulation Modes**
- **RSSI Mode**: Signal strength-based location estimation using free-space path loss models
- **TDOA Mode**: Time difference of arrival for higher accuracy (when supported by modem)
- **Hybrid Mode**: Combines multiple signals for improved accuracy

### 🌐 **Cross-Platform Support**
- **Linux**: Full support via mmcli and pyphonecontrol
- **Windows**: Mobile Broadband API integration
- **macOS**: External modem support via AT commands
- **Android**: Telephony API via Termux (root required)
- **iOS**: CoreTelephony integration (jailbreak required for full access)

## Installation & Setup

### Prerequisites

```bash
# Python dependencies
pip install requests pyphonecontrol

# Linux - ModemManager
sudo apt install modemmanager

# Windows - Npcap
# Download and install Npcap from https://nmap.org/npcap/

# Android - Termux + Root
# Install Termux and ensure root access
```

### API Key Setup

1. **OpenCellID API** (Recommended)
   - Sign up at [OpenCellID.org](https://opencellid.org)
   - Get your free API key
   - Configure in tool parameters

2. **Google Geolocation API** (Alternative)
   - Enable Google Geolocation API
   - Get API key from Google Cloud Console
   - Configure for tower location queries

## Usage Examples

### Basic Triangulation

```bash
# Natural Language
"Triangulate my location using cell towers"

# API Call
{
  "action": "triangulate_location",
  "modem": "wwan0",
  "mode": "rssi",
  "api_key": "your_opencellid_key"
}
```

### Advanced Configuration

```bash
# TDOA Mode with Custom Tower List
{
  "action": "triangulate_location",
  "modem": "wwan0",
  "mode": "tdoa",
  "towers": "1234:5678:310:410:-70,1235:5679:310:410:-75",
  "max_towers": 5,
  "api_key": "your_opencellid_key"
}
```

### Tower Scanning

```bash
# Scan Available Towers
{
  "action": "scan_towers",
  "modem": "wwan0",
  "max_towers": 10
}
```

## Parameters Reference

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `action` | string | Yes | - | Action to perform: `triangulate_location`, `scan_towers`, `query_tower_location`, `parse_nl_command` |
| `modem` | string | No | `wwan0` | Cellular modem interface (e.g., `wwan0`, `Modem0`) |
| `mode` | string | No | `rssi` | Triangulation mode: `rssi` or `tdoa` |
| `towers` | string | No | `auto` | Comma-separated Cell IDs or `auto` for scanning |
| `api_key` | string | No | - | OpenCellID or Google Geolocation API key |
| `max_towers` | number | No | `3` | Maximum towers to use (minimum 3 for triangulation) |
| `nl_command` | string | No | - | Natural language command to parse |
| `auto_confirm` | boolean | No | `false` | Skip confirmation prompt |

## Output Format

### Successful Triangulation

```json
{
  "success": true,
  "cellular_triangulate_data": {
    "action": "triangulate_location",
    "mode": "rssi",
    "modem": "wwan0",
    "towers_used": 3,
    "location": {
      "lat": 43.0731,
      "lon": -89.4012,
      "error_radius_m": 200
    },
    "status": "success",
    "details": "Location estimated using rssi mode with 3 towers.",
    "platform_info": {
      "os": "linux",
      "is_mobile": false,
      "requests_available": true,
      "ppc_available": true
    }
  }
}
```

### Error Response

```json
{
  "success": false,
  "error": "Insufficient tower data: 2 towers (minimum 3 required)"
}
```

## Platform-Specific Notes

### Linux
- **Requirements**: ModemManager, mmcli
- **Setup**: `sudo apt install modemmanager`
- **Usage**: `mmcli -m 0 --location-get`
- **Advantages**: Full API access, real-time tower data

### Windows
- **Requirements**: Npcap, Mobile Broadband drivers
- **Setup**: Install Npcap and compatible modem drivers
- **Usage**: Windows Mobile Broadband API
- **Limitations**: Limited tower data access

### macOS
- **Requirements**: External USB modem
- **Setup**: Install modem drivers and AT command tools
- **Usage**: AT commands via serial interface
- **Limitations**: No built-in cellular support

### Android
- **Requirements**: Termux, root access
- **Setup**: Install Termux and ensure root permissions
- **Usage**: `su -c 'mmcli -m 0'`
- **Advantages**: Full telephony API access

### iOS
- **Requirements**: Jailbreak for full access
- **Setup**: Install CoreTelephony tools
- **Usage**: Limited to API-based triangulation
- **Limitations**: Sandboxing restrictions

## Natural Language Interface

The tool supports natural language commands for intuitive operation:

### Supported Commands

- **"Find my location with cell towers"**
- **"Triangulate location using cellular signals"**
- **"Locate device using cell tower triangulation"**
- **"Scan for nearby cellular towers"**
- **"Estimate location with RSSI signals"**

### Command Parsing

The tool automatically extracts parameters from natural language:

```python
# Input: "Find my location with cell towers on wlan0 using 5 towers"
# Parsed: {
#   "mode": "rssi",
#   "modem": "wlan0", 
#   "max_towers": 5,
#   "towers": "auto"
# }
```

## Integration with Mobile Security Toolkit

The cellular triangulation tool is integrated into the Mobile Security Toolkit for comprehensive mobile device analysis:

### Mobile Security Actions

- **`cellular_triangulation`**: Location estimation using cell towers
- **`location_tracking`**: Continuous location monitoring
- **`cellular_analysis`**: Cellular network analysis
- **`penetration_test`**: Comprehensive security testing including location services

### Example Integration

```bash
# Mobile Security Toolkit with Cellular Triangulation
{
  "action": "cellular_triangulation",
  "device_id": "android_device_001",
  "platform": "android",
  "cellular_modem": "wwan0",
  "api_key": "your_opencellid_key",
  "test_depth": "comprehensive"
}
```

## Security & Privacy Considerations

### Legal Compliance
- **Authorization Required**: Use only on devices you own or have explicit permission to test
- **Regulatory Compliance**: Cellular tower data access may be regulated in your jurisdiction
- **Data Protection**: Do not store sensitive tower information beyond session requirements

### Privacy Protection
- **No Data Storage**: Tower IDs and location data are not permanently stored
- **Session-Only**: All data is cleared after operation completion
- **API Key Security**: Store API keys securely and rotate regularly

### Ethical Guidelines
- **Authorized Testing Only**: Use for legitimate security testing and research
- **Emergency Services**: Appropriate for emergency location services
- **Educational Use**: Suitable for learning and research purposes

## Troubleshooting

### Common Issues

1. **"No cellular modem found"**
   - Ensure modem is connected and drivers are installed
   - Check modem interface name (try `wwan0`, `Modem0`, etc.)
   - Verify ModemManager is running (Linux)

2. **"Insufficient tower data"**
   - Ensure you're in an area with multiple cell towers
   - Check signal strength and modem connectivity
   - Try increasing `max_towers` parameter

3. **"API key invalid"**
   - Verify OpenCellID API key is correct
   - Check API key permissions and quota
   - Ensure internet connectivity for API calls

4. **"Platform not supported"**
   - Check platform-specific requirements
   - Install necessary dependencies
   - Verify modem compatibility

### Debug Mode

Enable debug output for troubleshooting:

```bash
# Python script with debug
python3 cellular_triangulate.py --modem wwan0 --mode rssi --debug

# TypeScript with verbose logging
MCPGM_DEBUG=true node cellular_triangulate.js
```

## Performance Optimization

### Accuracy Improvements
- **Use TDOA Mode**: When available, TDOA provides better accuracy than RSSI
- **Increase Tower Count**: More towers generally improve accuracy
- **API Integration**: Real tower locations provide better results than simulated data
- **Signal Quality**: Ensure good signal strength for reliable measurements

### Speed Optimization
- **Cache Tower Data**: Store frequently used tower locations locally
- **Parallel Processing**: Query multiple towers simultaneously
- **Connection Pooling**: Reuse API connections for multiple requests

## Advanced Features

### Custom Tower Database
- **Local Database**: Store tower locations locally for offline operation
- **Database Integration**: Connect to custom tower databases
- **Data Import**: Import tower data from various sources

### Machine Learning Integration
- **Signal Prediction**: Use ML models for signal strength prediction
- **Location Refinement**: Apply ML algorithms for location accuracy improvement
- **Pattern Recognition**: Identify location patterns and anomalies

### Real-Time Monitoring
- **Continuous Tracking**: Monitor location changes over time
- **Alert System**: Set up alerts for location changes
- **Historical Analysis**: Track location history and patterns

## API Reference

### Python API

```python
from cellular_triangulate import CellularTriangulateTool

# Initialize tool
tool = CellularTriangulateTool()

# Basic triangulation
result = tool.execute(
    modem='wwan0',
    mode='rssi',
    api_key='your_key'
)

# Advanced configuration
result = tool.execute(
    modem='wwan0',
    mode='tdoa',
    towers='1234:5678:310:410:-70',
    max_towers=5,
    api_key='your_key'
)
```

### TypeScript API

```typescript
import { registerCellularTriangulate } from './cellular_triangulate';

// Register tool
registerCellularTriangulate(server);

// Use in MCP server
const result = await cellularTriangulate.execute({
  modem: 'wwan0',
  mode: 'rssi',
  api_key: 'your_key'
});
```

## Contributing

### Development Setup

1. **Clone Repository**: Get the latest code
2. **Install Dependencies**: Set up Python and Node.js environments
3. **Configure API Keys**: Set up OpenCellID API access
4. **Test on Platform**: Verify functionality on your platform

### Testing

```bash
# Python tests
python3 -m pytest tests/cellular_triangulate_test.py

# TypeScript tests
npm test -- cellular_triangulate.test.ts

# Integration tests
npm run test:integration
```

### Code Style

- **Python**: Follow PEP 8 guidelines
- **TypeScript**: Use ESLint configuration
- **Documentation**: Update docs for new features
- **Tests**: Add tests for new functionality

## License & Legal

This tool is provided for educational and authorized testing purposes only. Users are responsible for ensuring compliance with local laws and regulations regarding cellular network access and location services.

### Disclaimer

- **No Warranty**: Tool provided as-is without warranty
- **Use at Own Risk**: Users assume all risks and responsibilities
- **Legal Compliance**: Ensure compliance with applicable laws
- **Authorization Required**: Use only with proper authorization

## Support & Community

### Getting Help

- **Documentation**: Check this documentation first
- **Issues**: Report bugs and feature requests via GitHub
- **Community**: Join discussions in community forums
- **Professional Support**: Contact for commercial support

### Resources

- **OpenCellID**: [opencellid.org](https://opencellid.org)
- **ModemManager**: [freedesktop.org/wiki/Software/ModemManager](https://freedesktop.org/wiki/Software/ModemManager)
- **Cellular Networks**: Learn about cellular network protocols
- **Location Services**: Understanding GPS and cellular positioning

---

*Last updated: December 2024*
*Version: 1.0.0*
