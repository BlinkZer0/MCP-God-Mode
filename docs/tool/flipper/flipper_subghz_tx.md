# flipper_subghz_tx

Transmit Sub-GHz signal from file on Flipper Zero device (requires transmission permission).

## Description

Transmits Sub-GHz radio frequency signals using pre-recorded files stored on the Flipper Zero device. This tool allows you to send various Sub-GHz protocols like garage door openers, car keys, and other RF devices. **Requires `MCPGM_FLIPPER_ALLOW_TX=true` in environment configuration.**

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `file` | string | Yes | Sub-GHz file path on Flipper Zero (e.g., "/ext/subghz/garage.sub") |

## Usage Examples

### Transmit Garage Door Opener
```javascript
flipper_subghz_tx({
  session_id: "session_123",
  file: "/ext/subghz/garage.sub"
})
```

### Transmit Car Key Signal
```javascript
flipper_subghz_tx({
  session_id: "session_123",
  file: "/ext/subghz/car_key.sub"
})
```

### Transmit Custom Sub-GHz File
```javascript
flipper_subghz_tx({
  session_id: "session_123", 
  file: "/ext/subghz/custom_signal.sub"
})
```

## Response Format

```json
{
  "success": true,
  "data": {
    "file": "/ext/subghz/garage.sub",
    "transmitted": true,
    "duration": 2.5,
    "frequency": 433920000,
    "protocol": "Princeton",
    "timestamp": "2025-01-07T16:33:00Z"
  }
}
```

## Error Handling

- **Transmission Disabled**: Returns error if `MCPGM_FLIPPER_ALLOW_TX=false`
- **File Not Found**: Returns error if Sub-GHz file doesn't exist
- **Invalid File Format**: Returns error for corrupted or invalid Sub-GHz files
- **Session Invalid**: Returns error if session_id is not found
- **Hardware Error**: Returns error if Sub-GHz transmitter fails

## Safety Notes

⚠️ **Legal Warning**: Sub-GHz transmission may interfere with nearby devices and may be regulated in your jurisdiction. Only use on devices you own or have explicit written permission to test.

## Related Tools

- `flipper_subghz_tx_raw` - Send raw Sub-GHz data
- `flipper_fs_list` - List available Sub-GHz files
- `flipper_fs_read` - Read Sub-GHz file contents
- `flipper_connect` - Establish device connection

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
- Valid Sub-GHz file on device storage
