# Flipper Zero Consolidated Tool

## Overview
The **Flipper Zero Consolidated Tool** is a comprehensive Flipper Zero device management and operations toolkit that provides device discovery, connection management, file operations, IR/Sub-GHz transmission, NFC/RFID operations, BadUSB scripting, UART sniffing, GPIO control, and Bluetooth management.

## Features
- **Device Management**: Device discovery, connection, and information retrieval
- **File Operations**: File system management and operations
- **IR Operations**: Infrared signal transmission and control
- **Sub-GHz Operations**: Sub-GHz frequency transmission and control
- **NFC/RFID Operations**: NFC and RFID card operations
- **BadUSB**: BadUSB scripting and execution
- **UART Sniffing**: UART communication monitoring and analysis
- **GPIO Control**: General purpose input/output control
- **Bluetooth Management**: Bluetooth device scanning and pairing

## Usage

### Device Management
```bash
# List available devices
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

# Get device information
{
  "action": "get_info",
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
  "path": "/ext/config.txt",
  "content": "config_data_here"
}
```

### IR Operations
```bash
# Send IR signal
{
  "action": "ir_send",
  "file": "/ext/infrared/tv_power.ir"
}

# Send raw IR data
{
  "action": "ir_send_raw",
  "protocol": "NEC",
  "data": "0x20DF10EF"
}
```

### Sub-GHz Operations
```bash
# Transmit Sub-GHz signal
{
  "action": "subghz_tx",
  "file": "/ext/subghz/door_opener.sub"
}

# Transmit raw Sub-GHz data
{
  "action": "subghz_tx_raw",
  "frequency": 433920000,
  "data": "raw_data_here"
}
```

### NFC/RFID Operations
```bash
# Read NFC card
{
  "action": "nfc_read"
}

# Dump NFC card
{
  "action": "nfc_dump",
  "filename": "card_dump.nfc"
}

# Read RFID card
{
  "action": "rfid_read"
}
```

### BadUSB Operations
```bash
# Send BadUSB script
{
  "action": "badusb_send",
  "script": "DELAY 1000\nSTRING Hello World\nENTER"
}

# Send DuckyScript
{
  "action": "badusb_ducky",
  "script": "DELAY 1000\nSTRING Hello World\nENTER"
}
```

### UART Operations
```bash
# Sniff UART communication
{
  "action": "uart_sniff",
  "duration": 30
}
```

### GPIO Operations
```bash
# Set GPIO pin
{
  "action": "gpio_set",
  "pin": 1,
  "value": true
}

# Read GPIO pin
{
  "action": "gpio_read",
  "pin": 1
}
```

### Bluetooth Operations
```bash
# Scan for BLE devices
{
  "action": "ble_scan"
}

# Pair with Bluetooth device
{
  "action": "ble_pair",
  "address": "AA:BB:CC:DD:EE:FF"
}
```

## Parameters

### Device Management
- **action**: Device operation to perform
- **device_id**: Device identifier
- **scan_ble**: Whether to scan for BLE devices
- **scan_usb**: Whether to scan for USB devices
- **include_bridge**: Whether to include bridge endpoint

### File Operations
- **path**: File or directory path
- **content**: File content to write

### IR Operations
- **file**: IR file path on Flipper Zero
- **protocol**: IR protocol name
- **data**: Raw IR data

### Sub-GHz Operations
- **frequency**: Frequency in Hz
- **data**: Raw Sub-GHz data

### NFC/RFID Operations
- **filename**: Optional filename to save dump

### BadUSB Operations
- **script**: BadUSB or DuckyScript content

### UART Operations
- **duration**: Sniff duration in seconds

### GPIO Operations
- **pin**: GPIO pin number
- **value**: Pin value (true=high, false=low)

### Bluetooth Operations
- **address**: Bluetooth device address

## Output Format
```json
{
  "success": true,
  "action": "list_devices",
  "result": {
    "devices": [
      {
        "id": "device_001",
        "name": "Flipper Zero",
        "type": "usb",
        "connected": false,
        "capabilities": ["ir", "subghz", "nfc", "rfid", "badusb", "uart", "gpio", "ble"]
      }
    ],
    "totalDevices": 1
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with native integration
- **Linux**: Complete functionality
- **macOS**: Full feature support
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Device Discovery
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
  "devices": [
    {
      "id": "device_001",
      "name": "Flipper Zero",
      "type": "usb",
      "connected": false
    }
  ]
}
```

### Example 2: IR Signal Transmission
```bash
# Send IR signal
{
  "action": "ir_send",
  "file": "/ext/infrared/tv_power.ir"
}

# Result
{
  "success": true,
  "message": "IR signal sent successfully",
  "file": "/ext/infrared/tv_power.ir"
}
```

## Error Handling
- **Invalid Commands**: Clear error messages for invalid inputs
- **Device Errors**: Proper handling of device connection issues
- **File Errors**: Secure handling of file operations
- **Communication Errors**: Robust error handling for device communication

## Related Tools
- **Device Management**: Device management tools
- **File Operations**: File system tools
- **Network Tools**: Network communication tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Flipper Zero Consolidated Tool, please refer to the main MCP God Mode documentation or contact the development team.
