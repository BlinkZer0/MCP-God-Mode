# Flipper Connect

## Overview

Establishes a connection to a Flipper Zero device using either USB CDC Serial or Bluetooth Low Energy (BLE) transport. This tool creates a secure session for subsequent operations and handles connection initialization.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `device_id` | string | Yes | Device ID from `flipper_list_devices` (format: `transport:path`) |

## Device ID Format

The `device_id` parameter uses the format `transport:path`:

- **USB**: `usb:/dev/tty.usbmodem123` or `usb:COM3`
- **BLE**: `ble:AA:BB:CC:DD:EE:FF`

## Usage Examples

### Connect via USB
```javascript
// Connect to USB device
const session = await flipper_connect({
  device_id: "usb:/dev/tty.usbmodem123"
});
```

### Connect via BLE
```javascript
// Connect to BLE device
const session = await flipper_connect({
  device_id: "ble:AA:BB:CC:DD:EE:FF"
});
```

### Dynamic Connection
```javascript
// First discover devices, then connect
const devices = await flipper_list_devices();
const usbDevice = devices.data.devices.find(d => d.transport === 'usb');

if (usbDevice) {
  const session = await flipper_connect({
    device_id: usbDevice.id
  });
}
```

## Response Format

```json
{
  "success": true,
  "data": {
    "sessionId": "session_1234567890",
    "deviceId": "usb:/dev/tty.usbmodem123",
    "transportKind": "usb"
  }
}
```

## Session Management

### Session ID Usage
The returned `sessionId` is required for all subsequent operations:

```javascript
const session = await flipper_connect({ device_id: "usb:/dev/tty.usbmodem123" });
const sessionId = session.data.sessionId;

// Use sessionId for other operations
const info = await flipper_info({ session_id: sessionId });
```

### Session Lifecycle
- **Creation**: Session created on successful connection
- **Usage**: Session ID used for all device operations
- **Cleanup**: Session automatically cleaned up on disconnect or timeout

## Transport Types

### USB CDC Serial
- **Protocol**: USB Communication Device Class
- **Speed**: High-speed data transfer
- **Reliability**: Reliable connection with error detection
- **Platform Support**: Windows, macOS, Linux

### Bluetooth Low Energy (BLE)
- **Protocol**: BLE GATT services
- **Range**: Limited by Bluetooth range (~10m)
- **Power**: Low power consumption
- **Platform Support**: Windows 10+, macOS, Linux

## Connection Process

### USB Connection
1. **Device Detection**: Verify device is available
2. **Port Opening**: Open serial communication port
3. **Handshake**: Establish communication protocol
4. **Session Creation**: Create secure session instance

### BLE Connection
1. **Device Discovery**: Find BLE device by address
2. **Pairing**: Establish BLE connection
3. **Service Discovery**: Discover GATT services
4. **Session Creation**: Create secure session instance

## Error Handling

### Common Errors
- **Device Not Found**: Device ID doesn't match available devices
- **Permission Denied**: Insufficient permissions for device access
- **Device Busy**: Device is in use by another application
- **Connection Timeout**: Device doesn't respond within timeout period
- **Transport Error**: Communication protocol error

### Troubleshooting
1. **Verify Device ID**: Ensure device ID matches format from `flipper_list_devices`
2. **Check Permissions**: Verify user has access to the device
3. **Close Other Apps**: Ensure no other applications are using the device
4. **Check Connection**: Verify device is powered on and in range (BLE)

## Security Features

### Session Security
- **Unique Session IDs**: Each connection gets a unique session identifier
- **Automatic Cleanup**: Sessions are automatically cleaned up on disconnect
- **Timeout Handling**: Sessions timeout after inactivity
- **Audit Logging**: All connections are logged for security

### Transport Security
- **Encrypted BLE**: BLE connections use encrypted communication
- **USB Isolation**: USB connections are isolated from other system resources
- **Permission Validation**: Multiple layers of permission checking

## Platform-Specific Notes

### Windows
- **USB**: Requires COM port access permissions
- **BLE**: Requires Windows 10+ with Bluetooth support
- **Drivers**: May require Flipper Zero drivers installation

### macOS
- **USB**: May require Gatekeeper approval for first connection
- **BLE**: Requires Bluetooth permissions in System Preferences
- **Security**: macOS may prompt for device access approval

### Linux
- **USB**: User must be in `dialout` group
- **BLE**: Requires `noble` package and Bluetooth permissions
- **Permissions**: May require udev rules for USB device access

## Best Practices

### Connection Management
- **Single Connection**: Only one connection per device at a time
- **Proper Cleanup**: Always disconnect when done
- **Error Handling**: Implement proper error handling for connection failures
- **Session Tracking**: Keep track of active sessions

### Performance
- **USB Preferred**: USB connections are generally faster and more reliable
- **BLE for Remote**: Use BLE when physical USB connection isn't possible
- **Connection Pooling**: Reuse connections when possible

## Related Tools

- `flipper_list_devices` - Discover available devices
- `flipper_disconnect` - Close device connection
- `flipper_info` - Get device information
- `flipper_list_sessions` - List active sessions
