# flipper_subghz_tx_raw

Transmit raw Sub-GHz signal data to Flipper Zero device (requires transmission permission).

## Description

Transmits raw Sub-GHz radio frequency signals with custom frequency, protocol, and data parameters. This tool provides direct control over Sub-GHz transmission parameters for advanced users and custom protocols. **Requires `MCPGM_FLIPPER_ALLOW_TX=true` in environment configuration.**

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `frequency` | number | Yes | Frequency in Hz (e.g., 433920000 for 433.92 MHz) |
| `protocol` | string | Yes | Sub-GHz protocol name (e.g., "Princeton", "KeeLoq", "Security+") |
| `data` | string | Yes | Raw Sub-GHz data in hexadecimal format |

## Usage Examples

### Transmit Princeton Protocol at 433.92 MHz
```javascript
flipper_subghz_tx_raw({
  session_id: "session_123",
  frequency: 433920000,
  protocol: "Princeton", 
  data: "A1B2C3D4E5F6"
})
```

### Transmit KeeLoq Protocol at 315 MHz
```javascript
flipper_subghz_tx_raw({
  session_id: "session_123",
  frequency: 315000000,
  protocol: "KeeLoq",
  data: "1234567890ABCDEF"
})
```

### Transmit Custom Frequency and Data
```javascript
flipper_subghz_tx_raw({
  session_id: "session_123",
  frequency: 868350000,
  protocol: "Custom",
  data: "FF00FF00FF00"
})
```

## Response Format

```json
{
  "success": true,
  "data": {
    "frequency": 433920000,
    "protocol": "Princeton",
    "data": "A1B2C3D4E5F6",
    "transmitted": true,
    "duration": 1.2,
    "power": 7,
    "timestamp": "2025-01-07T16:33:00Z"
  }
}
```

## Error Handling

- **Transmission Disabled**: Returns error if `MCPGM_FLIPPER_ALLOW_TX=false`
- **Invalid Frequency**: Returns error for frequencies outside supported range
- **Invalid Protocol**: Returns error for unsupported Sub-GHz protocols
- **Invalid Data**: Returns error for malformed hexadecimal data
- **Session Invalid**: Returns error if session_id is not found
- **Hardware Error**: Returns error if Sub-GHz transmitter fails

## Safety Notes

⚠️ **Legal Warning**: Sub-GHz transmission may interfere with nearby devices and may be regulated in your jurisdiction. Always ensure you have proper authorization before using transmission features.

## Related Tools

- `flipper_subghz_tx` - Send Sub-GHz signals from files
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
- `MCPGM_FLIPPER_ALLOW_TX=true` environment setting
- Sub-GHz transmitter enabled on device

## Frequency Ranges

Common Sub-GHz frequencies:
- **315 MHz**: North American garage doors, car keys
- **433.92 MHz**: European garage doors, weather stations
- **868.35 MHz**: European ISM band devices
- **915 MHz**: North American ISM band devices
