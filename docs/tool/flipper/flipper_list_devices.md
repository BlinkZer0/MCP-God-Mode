# Flipper List Devices

## Overview

Discovers and lists available Flipper Zero devices on both USB and Bluetooth Low Energy (BLE) connections. This tool provides comprehensive device discovery with detailed information about each detected device.

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `scan_ble` | boolean | No | `true` | Whether to scan for BLE devices |
| `scan_usb` | boolean | No | `true` | Whether to scan for USB devices |

## Usage Examples

### Basic Device Discovery
```javascript
// Scan for all available devices
const devices = await flipper_list_devices({
  scan_ble: true,
  scan_usb: true
});
```

### USB-Only Discovery
```javascript
// Only scan for USB devices
const usbDevices = await flipper_list_devices({
  scan_ble: false,
  scan_usb: true
});
```

### BLE-Only Discovery
```javascript
// Only scan for BLE devices
const bleDevices = await flipper_list_devices({
  scan_ble: true,
  scan_usb: false
});
```

## Response Format

```json
{
  "success": true,
  "data": {
    "devices": [
      {
        "id": "usb:/dev/tty.usbmodem123",
        "name": "Flipper Zero (USB)",
        "transport": "usb",
        "path": "/dev/tty.usbmodem123",
        "manufacturer": "Flipper Devices Inc.",
        "serialNumber": "ABC123",
        "connected": false
      },
      {
        "id": "ble:AA:BB:CC:DD:EE:FF",
        "name": "Flipper Zero",
        "transport": "ble",
        "address": "AA:BB:CC:DD:EE:FF",
        "rssi": -45,
        "connected": false
      }
    ],
    "config": {
      "enabled": true,
      "usbEnabled": true,
      "bleEnabled": true,
      "allowTx": false
    }
  }
}
```

## Device Information

### USB Devices
- **ID Format**: `usb:device_path`
- **Path**: Serial device path (e.g., `/dev/tty.usbmodem123`, `COM3`)
- **Manufacturer**: Device manufacturer information
- **Serial Number**: Unique device serial number

### BLE Devices
- **ID Format**: `ble:mac_address`
- **Address**: Bluetooth MAC address
- **RSSI**: Signal strength indicator
- **Name**: Device advertising name

## Platform-Specific Notes

### Windows
- USB devices appear as COM ports (e.g., `COM3`, `COM4`)
- BLE requires Windows 10+ with Bluetooth support
- Administrator privileges may be required for USB access

### macOS
- USB devices appear as `/dev/tty.usbmodem*` paths
- BLE requires Bluetooth permissions
- Gatekeeper may require approval for USB access

### Linux
- USB devices appear as `/dev/ttyUSB*` or `/dev/ttyACM*` paths
- User must be in `dialout` group for USB access
- BLE requires `noble` package and permissions

## Error Handling

### Common Errors
- **Permission Denied**: Insufficient permissions for device access
- **Device Busy**: Device is in use by another application
- **Driver Issues**: Missing or incorrect device drivers
- **BLE Unavailable**: Bluetooth not available or disabled

### Troubleshooting
1. **Check Permissions**: Ensure proper user permissions for device access
2. **Verify Drivers**: Install required device drivers for your platform
3. **Close Other Apps**: Ensure no other applications are using the device
4. **Check Bluetooth**: Verify Bluetooth is enabled for BLE scanning

## Security Considerations

- Device discovery is read-only and safe
- No sensitive data is transmitted during discovery
- Device information is sanitized in logs
- BLE scanning respects privacy settings

## Related Tools

- `flipper_connect` - Connect to a discovered device
- `flipper_info` - Get detailed device information
- `flipper_list_sessions` - List active connections
