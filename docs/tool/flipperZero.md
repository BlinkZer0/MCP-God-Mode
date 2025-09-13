# Flipper Zero Tool

## Overview
The **Flipper Zero Tool** is a comprehensive Flipper Zero device management and operations utility that provides advanced Flipper Zero device control, file operations, and hardware interaction capabilities. It offers cross-platform support and enterprise-grade Flipper Zero features.

## Features
- **Device Management**: Advanced Flipper Zero device management and control
- **File Operations**: Comprehensive file operations and management
- **Hardware Interaction**: Advanced hardware interaction and control
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **IR/Sub-GHz Operations**: IR and Sub-GHz transmission and control
- **NFC/RFID Operations**: NFC and RFID operations and management

## Usage

### Device Management
```bash
# List devices
{
  "action": "list_devices",
  "scan_ble": true,
  "scan_usb": true,
  "include_bridge": true
}

# Connect to device
{
  "action": "connect",
  "device_id": "device_001"
}

# Disconnect from device
{
  "action": "disconnect",
  "device_id": "device_001"
}
```

### File Operations
```bash
# List files
{
  "action": "fs_list",
  "path": "/ext"
}

# Read file
{
  "action": "fs_read",
  "path": "/ext/readme.txt"
}

# Write file
{
  "action": "fs_write",
  "path": "/ext/data.txt",
  "content": "Hello, Flipper Zero!"
}

# Delete file
{
  "action": "fs_delete",
  "path": "/ext/old_file.txt"
}
```

### Hardware Operations
```bash
# IR transmission
{
  "action": "ir_send",
  "file": "/ext/ir_signals/tv_power.ir"
}

# Sub-GHz transmission
{
  "action": "subghz_tx",
  "frequency": 433920000,
  "data": "0101010101010101"
}

# NFC operations
{
  "action": "nfc_read"
}

# RFID operations
{
  "action": "rfid_read"
}
```

## Parameters

### Device Parameters
- **action**: Flipper Zero operation to perform
- **device_id**: Device ID from list_devices
- **session_id**: Session ID from connect
- **scan_ble**: Whether to scan for BLE devices
- **scan_usb**: Whether to scan for USB devices

### File Parameters
- **path**: File or directory path
- **content**: File content to write
- **file**: IR file path on Flipper Zero

### Hardware Parameters
- **frequency**: Frequency in Hz for Sub-GHz operations
- **data**: Raw data for transmission
- **duration**: Sniff duration in seconds
- **pin**: GPIO pin number
- **value**: Pin value (true=high, false=low)

## Output Format
```json
{
  "success": true,
  "action": "list_devices",
  "result": {
    "devices": [
      {
        "device_id": "device_001",
        "name": "Flipper Zero",
        "type": "usb",
        "status": "available"
      }
    ],
    "total_devices": 1
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows Flipper Zero operations
- **Linux**: Complete functionality with Linux Flipper Zero operations
- **macOS**: Full feature support with macOS Flipper Zero operations
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: List Devices
```bash
# List devices
{
  "action": "list_devices",
  "scan_ble": true,
  "scan_usb": true
}

# Result
{
  "success": true,
  "result": {
    "devices": [
      {
        "device_id": "device_001",
        "name": "Flipper Zero",
        "type": "usb",
        "status": "available"
      }
    ],
    "total_devices": 1
  }
}
```

### Example 2: Connect to Device
```bash
# Connect to device
{
  "action": "connect",
  "device_id": "device_001"
}

# Result
{
  "success": true,
  "result": {
    "device_id": "device_001",
    "session_id": "session_001",
    "status": "connected"
  }
}
```

### Example 3: IR Transmission
```bash
# IR transmission
{
  "action": "ir_send",
  "file": "/ext/ir_signals/tv_power.ir"
}

# Result
{
  "success": true,
  "result": {
    "action": "ir_send",
    "file": "/ext/ir_signals/tv_power.ir",
    "status": "transmitted"
  }
}
```

## Error Handling
- **Device Errors**: Proper handling of Flipper Zero device communication issues
- **File Errors**: Secure handling of file operation failures
- **Hardware Errors**: Robust error handling for hardware interaction failures
- **Connection Errors**: Safe handling of device connection problems

## Related Tools
- **Hardware Interface**: Hardware interface and control tools
- **File Management**: File management and operations tools
- **Device Management**: Device management and control tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Flipper Zero Tool, please refer to the main MCP God Mode documentation or contact the development team.
