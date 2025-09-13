# Cellular Triangulation Tool

## Overview
The **Cellular Triangulation Tool** is a comprehensive cellular location estimation utility that provides advanced cellular tower signal analysis, location triangulation, and GPS-free location services. It offers cross-platform support and enterprise-grade cellular location capabilities.

## Features
- **Cellular Triangulation**: Advanced cellular tower signal triangulation
- **Location Estimation**: GPS-free location estimation using cellular signals
- **Tower Analysis**: Cellular tower location and signal analysis
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Multiple Methods**: RSSI, TDOA, GPS, and SS7 triangulation methods
- **API Integration**: Integration with cellular location APIs

## Usage

### Cellular Triangulation
```bash
# Triangulate location
{
  "action": "triangulate_location",
  "modem": "wwan0",
  "mode": "rssi"
}

# Scan towers
{
  "action": "scan_towers",
  "modem": "wwan0"
}

# Query tower location
{
  "action": "query_tower_location",
  "towers": "auto"
}
```

### Location Methods
```bash
# RSSI triangulation
{
  "action": "triangulate_location",
  "mode": "rssi",
  "towers": "auto"
}

# TDOA triangulation
{
  "action": "triangulate_location",
  "mode": "tdoa",
  "towers": "auto"
}

# GPS coordinates
{
  "action": "triangulate_location",
  "mode": "gps",
  "gps_data": {
    "lat": 40.7128,
    "lon": -74.0060
  }
}
```

### Advanced Features
```bash
# SS7 queries
{
  "action": "triangulate_location",
  "mode": "ss7",
  "ss7_pc": "12345",
  "ss7_gt": "1234567890"
}

# Natural language commands
{
  "action": "parse_nl_command",
  "nl_command": "Find my location with cell towers"
}

# Phone number pinging
{
  "action": "ping_phone_number",
  "phone_number": "+1234567890"
}
```

## Parameters

### Triangulation Parameters
- **action**: Cellular triangulation operation to perform
- **modem**: Cellular modem interface (e.g., 'wwan0', 'Modem0')
- **mode**: Triangulation mode (rssi, tdoa, gps, ss7)
- **towers**: Comma-separated Cell IDs or 'auto' for scanning

### Location Parameters
- **api_key**: OpenCellID or Google Geolocation API key
- **max_towers**: Maximum towers to use for triangulation (minimum 3)
- **phone_number**: Target phone number for SMS triggering
- **tower_data**: Remote tower data from target device

### Advanced Parameters
- **ss7_pc**: SS7 Point Code (e.g., '12345')
- **ss7_gt**: SS7 Global Title (e.g., '1234567890')
- **ss7_hlr**: HLR address for SS7 queries
- **nl_command**: Natural language command to parse

## Output Format
```json
{
  "success": true,
  "action": "triangulate_location",
  "result": {
    "location": {
      "latitude": 40.7128,
      "longitude": -74.0060,
      "accuracy": 100,
      "method": "rssi"
    },
    "towers_used": 3,
    "confidence": 0.85
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows cellular devices
- **Linux**: Complete functionality with Linux cellular devices
- **macOS**: Full feature support with macOS cellular devices
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Basic Triangulation
```bash
# Triangulate location
{
  "action": "triangulate_location",
  "modem": "wwan0",
  "mode": "rssi"
}

# Result
{
  "success": true,
  "result": {
    "location": {
      "latitude": 40.7128,
      "longitude": -74.0060,
      "accuracy": 100
    },
    "method": "rssi"
  }
}
```

### Example 2: Tower Scanning
```bash
# Scan towers
{
  "action": "scan_towers",
  "modem": "wwan0"
}

# Result
{
  "success": true,
  "result": {
    "towers": [
      {
        "cid": "12345",
        "lac": "67890",
        "rssi": -50
      }
    ],
    "total_towers": 1
  }
}
```

### Example 3: GPS Integration
```bash
# GPS coordinates
{
  "action": "triangulate_location",
  "mode": "gps",
  "gps_data": {
    "lat": 40.7128,
    "lon": -74.0060
  }
}

# Result
{
  "success": true,
  "result": {
    "location": {
      "latitude": 40.7128,
      "longitude": -74.0060,
      "accuracy": 5
    },
    "method": "gps"
  }
}
```

## Error Handling
- **Modem Errors**: Proper handling of cellular modem access issues
- **Signal Errors**: Secure handling of cellular signal failures
- **API Errors**: Robust error handling for API communication failures
- **Location Errors**: Safe handling of location estimation problems

## Related Tools
- **Geolocation**: IP-based geolocation tools
- **Network Analysis**: Network analysis and monitoring tools
- **Mobile Device**: Mobile device management tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Cellular Triangulation Tool, please refer to the main MCP God Mode documentation or contact the development team.
