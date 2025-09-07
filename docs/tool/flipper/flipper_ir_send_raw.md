# flipper_ir_send_raw

Send raw IR signal to Flipper Zero device (requires transmission permission).

## Description

Transmits raw infrared signals using the Flipper Zero's IR transmitter. This tool allows you to send custom IR protocols and data directly to the device. **Requires `MCPGM_FLIPPER_ALLOW_TX=true` in environment configuration.**

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `protocol` | string | Yes | IR protocol name (e.g., "NEC", "RC5", "Samsung") |
| `data` | string | Yes | Raw IR data in hexadecimal format |

## Usage Examples

### Send NEC Protocol IR Signal
```javascript
flipper_ir_send_raw({
  session_id: "session_123",
  protocol: "NEC",
  data: "20DF10EF"
})
```

### Send Samsung TV Power Command
```javascript
flipper_ir_send_raw({
  session_id: "session_123", 
  protocol: "Samsung32",
  data: "E0E040BF"
})
```

## Response Format

```json
{
  "success": true,
  "data": {
    "protocol": "NEC",
    "data": "20DF10EF",
    "transmitted": true,
    "timestamp": "2025-01-07T16:33:00Z"
  }
}
```

## Error Handling

- **Transmission Disabled**: Returns error if `MCPGM_FLIPPER_ALLOW_TX=false`
- **Invalid Protocol**: Returns error for unsupported IR protocols
- **Invalid Data**: Returns error for malformed hexadecimal data
- **Session Invalid**: Returns error if session_id is not found

## Safety Notes

⚠️ **Legal Warning**: IR transmission may interfere with nearby devices. Only use on devices you own or have explicit permission to control.

## Related Tools

- `flipper_ir_send` - Send IR signals from files
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
- IR transmitter enabled on device
