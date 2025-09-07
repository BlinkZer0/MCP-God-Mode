# 🔌 Flipper Zero Comprehensive Tool

## Overview
The `flipper_zero` tool is a comprehensive, consolidated interface for all Flipper Zero device operations. It replaces 24 individual Flipper Zero tools with a single, action-based interface that provides complete device management and operation capabilities.

## Features
- **Device Management**: Discovery, connection, and session management
- **File System Operations**: List, read, write, and delete files on Flipper Zero storage
- **Infrared Operations**: Send IR signals from files or raw data
- **Sub-GHz Operations**: Transmit Sub-GHz signals for radio frequency operations
- **NFC/RFID Operations**: Read and dump NFC/RFID cards
- **BadUSB Operations**: Execute BadUSB scripts and DuckyScript
- **UART Operations**: Sniff UART communication
- **GPIO Operations**: Control and read GPIO pins
- **Bluetooth Operations**: Scan and pair with Bluetooth devices

## Actions

### Device Management
- `list_devices` - List available Flipper Zero devices (USB, BLE, Bridge)
- `connect` - Connect to a Flipper Zero device
- `disconnect` - Disconnect from a Flipper Zero device
- `get_info` - Get device information from connected Flipper Zero
- `list_sessions` - List active Flipper Zero sessions

### File System Operations
- `fs_list` - List files in Flipper Zero storage
- `fs_read` - Read file from Flipper Zero storage
- `fs_write` - Write file to Flipper Zero storage
- `fs_delete` - Delete file from Flipper Zero storage

### Infrared Operations
- `ir_send` - Send IR signal from file (requires MCPGM_FLIPPER_ALLOW_TX=true)
- `ir_send_raw` - Send raw IR signal (requires MCPGM_FLIPPER_ALLOW_TX=true)

### Sub-GHz Operations
- `subghz_tx` - Transmit Sub-GHz signal from file (requires MCPGM_FLIPPER_ALLOW_TX=true)
- `subghz_tx_raw` - Transmit raw Sub-GHz signal (requires MCPGM_FLIPPER_ALLOW_TX=true)

### NFC Operations
- `nfc_read` - Read NFC card
- `nfc_dump` - Dump NFC card to file

### RFID Operations
- `rfid_read` - Read RFID card
- `rfid_dump` - Dump RFID card to file

### BadUSB Operations
- `badusb_send` - Send BadUSB script (requires MCPGM_FLIPPER_ALLOW_TX=true)
- `badusb_ducky` - Send DuckyScript (requires MCPGM_FLIPPER_ALLOW_TX=true)

### UART Operations
- `uart_sniff` - Sniff UART communication

### GPIO Operations
- `gpio_set` - Set GPIO pin value
- `gpio_read` - Read GPIO pin value

### Bluetooth Operations
- `ble_scan` - Scan for Bluetooth devices
- `ble_pair` - Pair with Bluetooth device

## Parameters

### Common Parameters
- `action` (required) - The operation to perform
- `device_id` - Device ID from list_devices (required for connect)
- `session_id` - Session ID from connect (required for most operations)

### Device Discovery Parameters
- `scan_ble` - Whether to scan for BLE devices (default: true)
- `scan_usb` - Whether to scan for USB devices (default: true)
- `include_bridge` - Whether to include bridge endpoint (default: true)

### File System Parameters
- `path` - File or directory path
- `content` - File content to write

### IR Parameters
- `file` - IR file path on Flipper Zero
- `protocol` - IR protocol name
- `data` - Raw IR data

### Sub-GHz Parameters
- `frequency` - Frequency in Hz

### NFC/RFID Parameters
- `filename` - Optional filename to save dump

### BadUSB Parameters
- `script` - BadUSB or DuckyScript content

### UART Parameters
- `duration` - Sniff duration in seconds (default: 10)

### GPIO Parameters
- `pin` - GPIO pin number
- `value` - Pin value (true=high, false=low)

### Bluetooth Parameters
- `address` - Bluetooth device address

## Environment Configuration

The tool respects the following environment variables:
- `MCPGM_FLIPPER_ENABLED` - Enable/disable Flipper Zero integration (default: true)
- `MCPGM_FLIPPER_USB_ENABLED` - Enable USB transport (default: true)
- `MCPGM_FLIPPER_BLE_ENABLED` - Enable BLE transport (default: true)
- `MCPGM_FLIPPER_ALLOW_TX` - Allow transmission operations (default: false)
- `MCPGM_FLIPPER_BRIDGE_URL` - WebSocket bridge URL for mobile/remote access

## Examples

### List Available Devices
```json
{
  "action": "list_devices",
  "scan_usb": true,
  "scan_ble": true,
  "include_bridge": true
}
```

### Connect to USB Device
```json
{
  "action": "connect",
  "device_id": "usb:COM3"
}
```

### List Files on Device
```json
{
  "action": "fs_list",
  "session_id": "session_123",
  "path": "/"
}
```

### Send IR Signal
```json
{
  "action": "ir_send",
  "session_id": "session_123",
  "file": "/ext/infrared/tv_power.ir"
}
```

### Read NFC Card
```json
{
  "action": "nfc_read",
  "session_id": "session_123"
}
```

## Migration from Individual Tools

This consolidated tool replaces the following 24 individual tools:
- `flipper_list_devices`
- `flipper_connect`
- `flipper_disconnect`
- `flipper_info`
- `flipper_fs_list`
- `flipper_fs_read`
- `flipper_fs_write`
- `flipper_fs_delete`
- `flipper_ir_send`
- `flipper_ir_send_raw`
- `flipper_subghz_tx`
- `flipper_subghz_tx_raw`
- `flipper_nfc_read`
- `flipper_nfc_dump`
- `flipper_rfid_read`
- `flipper_rfid_dump`
- `flipper_badusb_send`
- `flipper_badusb_ducky`
- `flipper_uart_sniff`
- `flipper_gpio_set`
- `flipper_gpio_read`
- `flipper_ble_scan`
- `flipper_ble_pair`
- `flipper_list_sessions`

## Benefits of Consolidation

1. **Simplified Interface**: Single tool with action-based parameters instead of 24 separate tools
2. **Better Organization**: All Flipper Zero operations in one place
3. **Reduced Tool Count**: Decreased from 170 to 147 total tools
4. **Consistent Parameters**: Unified parameter structure across all operations
5. **Easier Discovery**: Users can see all available Flipper operations in one tool
6. **Backward Compatibility**: Legacy function names still work for existing integrations

## Security Considerations

- Transmission operations (IR, Sub-GHz, BadUSB) require `MCPGM_FLIPPER_ALLOW_TX=true`
- All operations are logged for audit purposes when legal compliance is enabled
- Device connections are session-based and automatically cleaned up
- Bridge connections support mobile/remote access with proper authentication
