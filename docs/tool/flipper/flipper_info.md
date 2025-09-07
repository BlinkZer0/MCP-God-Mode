# Flipper Info

## Overview

Retrieves comprehensive device information from a connected Flipper Zero device, including firmware version, hardware details, battery status, and system configuration.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from `flipper_connect` |

## Usage Examples

### Basic Device Information
```javascript
// Get device information
const info = await flipper_info({
  session_id: "session_1234567890"
});
```

### Complete Workflow
```javascript
// Connect and get info
const session = await flipper_connect({
  device_id: "usb:/dev/tty.usbmodem123"
});

const info = await flipper_info({
  session_id: session.data.sessionId
});

console.log(`Firmware: ${info.data.firmware.version}`);
console.log(`Battery: ${info.data.battery.level}%`);
```

## Response Format

```json
{
  "success": true,
  "data": {
    "device": {
      "name": "Flipper Zero",
      "model": "Flipper Zero",
      "serial": "ABC123456789",
      "hardware": {
        "version": "1.0",
        "revision": "A",
        "manufacturer": "Flipper Devices Inc."
      }
    },
    "firmware": {
      "version": "0.95.0",
      "build": "2024-01-15",
      "commit": "abc123def456",
      "branch": "dev"
    },
    "battery": {
      "level": 85,
      "voltage": 3.7,
      "charging": false,
      "temperature": 25
    },
    "storage": {
      "internal": {
        "total": 1048576,
        "used": 524288,
        "free": 524288
      },
      "external": {
        "total": 8388608,
        "used": 4194304,
        "free": 4194304
      }
    },
    "system": {
      "uptime": 3600,
      "cpu_usage": 15,
      "memory_usage": 45,
      "temperature": 30
    },
    "features": {
      "nfc": true,
      "rfid": true,
      "ir": true,
      "subghz": true,
      "badusb": true,
      "gpio": true,
      "uart": true,
      "ble": true
    }
  }
}
```

## Device Information Fields

### Device Details
- **Name**: Device model name
- **Model**: Hardware model identifier
- **Serial**: Unique device serial number
- **Hardware**: Hardware version and revision information

### Firmware Information
- **Version**: Firmware version number
- **Build**: Build date and time
- **Commit**: Git commit hash
- **Branch**: Firmware branch (dev, release, etc.)

### Battery Status
- **Level**: Battery charge percentage (0-100)
- **Voltage**: Current battery voltage
- **Charging**: Whether device is currently charging
- **Temperature**: Battery temperature in Celsius

### Storage Information
- **Internal**: Internal flash storage usage
- **External**: External SD card storage usage
- **Total/Used/Free**: Storage space in bytes

### System Status
- **Uptime**: Device uptime in seconds
- **CPU Usage**: Current CPU utilization percentage
- **Memory Usage**: Current memory utilization percentage
- **Temperature**: System temperature in Celsius

### Feature Availability
- **NFC**: NFC functionality available
- **RFID**: RFID functionality available
- **IR**: Infrared functionality available
- **Sub-GHz**: Sub-GHz radio functionality available
- **BadUSB**: BadUSB functionality available
- **GPIO**: GPIO control available
- **UART**: UART communication available
- **BLE**: Bluetooth Low Energy available

## Use Cases

### Device Verification
```javascript
// Verify device capabilities before operations
const info = await flipper_info({ session_id: sessionId });

if (!info.data.features.nfc) {
  throw new Error("NFC not available on this device");
}

if (info.data.battery.level < 20) {
  console.warn("Low battery warning");
}
```

### System Monitoring
```javascript
// Monitor device health
const info = await flipper_info({ session_id: sessionId });

console.log(`System Status:
  Battery: ${info.data.battery.level}%
  Temperature: ${info.data.system.temperature}°C
  CPU Usage: ${info.data.system.cpu_usage}%
  Memory Usage: ${info.data.system.memory_usage}%`);
```

### Storage Management
```javascript
// Check available storage
const info = await flipper_info({ session_id: sessionId });

const freeSpace = info.data.storage.external.free;
const freeSpaceMB = Math.round(freeSpace / 1024 / 1024);

console.log(`Available storage: ${freeSpaceMB} MB`);
```

## Error Handling

### Common Errors
- **Invalid Session**: Session ID doesn't exist or has expired
- **Device Disconnected**: Device is no longer connected
- **Communication Error**: Failed to communicate with device
- **Timeout**: Device didn't respond within timeout period

### Troubleshooting
1. **Check Session**: Verify session ID is valid and active
2. **Reconnect**: Try reconnecting to the device
3. **Check Connection**: Ensure device is still connected
4. **Restart Device**: Power cycle the Flipper Zero if needed

## Performance Notes

### Response Time
- **USB**: Typically 100-500ms response time
- **BLE**: Typically 500-2000ms response time
- **Caching**: Some information may be cached for faster subsequent calls

### Data Size
- **Response Size**: Typically 1-2KB of JSON data
- **Network Impact**: Minimal impact on BLE bandwidth
- **Memory Usage**: Low memory footprint for response parsing

## Security Considerations

### Information Disclosure
- **Serial Numbers**: Device serial numbers are included
- **Firmware Version**: Firmware version information is exposed
- **System Status**: Current system state is visible
- **Logging**: Device information is logged for audit purposes

### Privacy
- **No Personal Data**: No personal or sensitive data is exposed
- **System Only**: Only system and hardware information is returned
- **Sanitized Logs**: Sensitive information is sanitized in logs

## Related Tools

- `flipper_connect` - Establish device connection
- `flipper_list_devices` - Discover available devices
- `flipper_fs_list` - List device files
- `flipper_list_sessions` - List active sessions
