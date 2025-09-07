# flipper_ble_scan

Scan for Bluetooth Low Energy devices using Flipper Zero.

## Description

Scans for nearby Bluetooth Low Energy (BLE) devices using the Flipper Zero's Bluetooth interface. This tool discovers BLE devices in range, providing information about device names, addresses, signal strength, and available services. Useful for Bluetooth device discovery and analysis.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `duration` | number | No | Scan duration in seconds (default: 10) |

## Usage Examples

### Basic BLE Scan (10 seconds)
```javascript
flipper_ble_scan({
  session_id: "session_123"
})
```

### Extended BLE Scan (30 seconds)
```javascript
flipper_ble_scan({
  session_id: "session_123",
  duration: 30
})
```

### Quick BLE Scan (5 seconds)
```javascript
flipper_ble_scan({
  session_id: "session_123",
  duration: 5
})
```

## Response Format

```json
{
  "success": true,
  "data": {
    "duration": 10,
    "devices_found": 3,
    "devices": [
      {
        "address": "AA:BB:CC:DD:EE:FF",
        "name": "iPhone",
        "rssi": -45,
        "services": ["180F", "180A"],
        "manufacturer": "Apple Inc.",
        "device_type": "smartphone"
      },
      {
        "address": "11:22:33:44:55:66",
        "name": "Fitness Tracker",
        "rssi": -67,
        "services": ["180D", "180F"],
        "manufacturer": "Unknown",
        "device_type": "wearable"
      }
    ],
    "timestamp": "2025-01-07T16:33:00Z"
  }
}
```

## BLE Device Information

### Device Properties
- **Address**: MAC address of the BLE device
- **Name**: Device name (if advertised)
- **RSSI**: Signal strength indicator (dBm)
- **Services**: List of advertised service UUIDs
- **Manufacturer**: Device manufacturer (if available)
- **Device Type**: Classified device type

### Common BLE Services
- **180F**: Battery Service
- **180A**: Device Information Service
- **180D**: Heart Rate Service
- **180E**: HID Service
- **1800**: Generic Access Service
- **1801**: Generic Attribute Service

## Error Handling

- **No Devices Found**: Returns empty devices list if no BLE devices detected
- **Session Invalid**: Returns error if session_id is not found
- **Hardware Error**: Returns error if BLE scanning fails
- **Timeout**: Returns partial results if scan duration exceeds available time

## Use Cases

### Device Discovery
- Find nearby BLE devices
- Identify unknown devices
- Monitor device presence
- Track device movement

### Security Analysis
- Identify vulnerable BLE devices
- Analyze BLE traffic
- Test BLE security
- Monitor BLE communications

### Development
- Test BLE applications
- Debug BLE connections
- Analyze BLE protocols
- Develop BLE tools

## Safety Notes

⚠️ **Privacy Warning**: BLE scanning can detect nearby devices and may reveal information about people in the area. Only use in appropriate environments and respect privacy.

## Related Tools

- `flipper_ble_pair` - Pair with BLE devices
- `flipper_connect` - Establish device connection
- `flipper_info` - Get device information

## Platform Support

- ✅ Windows (USB CDC)
- ✅ macOS (USB CDC)
- ✅ Linux (USB CDC)
- ✅ All platforms (BLE GATT)

## Requirements

- Flipper Zero device connected
- Active session established
- BLE interface enabled on device
- BLE scanning permissions granted

## BLE Scanning Tips

### Optimal Scanning
- Use longer durations for comprehensive scans
- Move device around to detect more devices
- Scan in different environments
- Repeat scans to detect intermittent devices

### Signal Strength
- RSSI values closer to 0 indicate stronger signals
- Typical range: -30 dBm (very close) to -100 dBm (far)
- Signal strength varies with distance and obstacles
