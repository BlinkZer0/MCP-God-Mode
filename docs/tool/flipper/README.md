# Note: The Flipper Zero toolset has been consolidated into a single action-based tool:  `flipper_zero`. This page remains for historical reference. For current usage, see `../flipper_zero.md`. 

# 🐬 Flipper Zero Security Toolkit (Legacy)

## Overview

The Flipper Zero Security Toolkit provides comprehensive integration with Flipper Zero devices through MCP-God-Mode, enabling advanced security testing, hardware interaction, and penetration testing capabilities. This toolkit includes **24 specialized tools** for device management, file operations, wireless communication, and security assessment.

## ⚠️ Legal and Safety Notice

**IMPORTANT**: This toolkit is designed for authorized security testing and educational purposes only. Users must comply with all applicable laws and regulations in their jurisdiction. Transmission operations (IR, Sub-GHz, BadUSB) are disabled by default and require explicit configuration.

## 🔧 Features

### Device Management
- **Multi-transport Support**: USB CDC Serial and Bluetooth Low Energy (BLE) connectivity
- **Cross-platform Compatibility**: Windows, macOS, and Linux support
- **Session Management**: Secure connection handling with automatic cleanup
- **Device Discovery**: Automatic detection of Flipper Zero devices

### Security Operations
- **NFC/RFID Operations**: Card reading, dumping, and analysis
- **Infrared Control**: IR signal transmission and recording
- **Sub-GHz Operations**: Radio frequency transmission and analysis
- **BadUSB Scripts**: USB HID attack simulation
- **Bluetooth Management**: Device scanning and pairing
- **UART Monitoring**: Serial communication analysis
- **GPIO Control**: Hardware pin manipulation

### File System Operations
- **File Management**: Read, write, delete, and list files
- **Storage Access**: Full access to Flipper Zero internal storage
- **Data Transfer**: Efficient file transfer between host and device

## 🛠️ Available Tools (24 Total)

### Device Management (3 tools)
- [`flipper_list_devices`](flipper_list_devices.md) - Discover available Flipper Zero devices
- [`flipper_connect`](flipper_connect.md) - Establish connection to device
- [`flipper_disconnect`](flipper_disconnect.md) - Close device connection

### Device Information (2 tools)
- [`flipper_info`](flipper_info.md) - Get device information and status
- [`flipper_list_sessions`](flipper_list_sessions.md) - List active sessions

### File System Operations (4 tools)
- [`flipper_fs_list`](flipper_fs_list.md) - List files and directories
- [`flipper_fs_read`](flipper_fs_read.md) - Read file contents
- [`flipper_fs_write`](flipper_fs_write.md) - Write data to files
- [`flipper_fs_delete`](flipper_fs_delete.md) - Delete files

### Infrared Operations (2 tools)
- [`flipper_ir_send`](flipper_ir_send.md) - Send IR signals from files
- [`flipper_ir_send_raw`](flipper_ir_send_raw.md) - Send raw IR data

### Sub-GHz Operations (2 tools)
- [`flipper_subghz_tx`](flipper_subghz_tx.md) - Transmit Sub-GHz signals
- [`flipper_subghz_tx_raw`](flipper_subghz_tx_raw.md) - Send raw Sub-GHz data

### NFC/RFID Operations (4 tools)
- [`flipper_nfc_read`](flipper_nfc_read.md) - Read NFC cards
- [`flipper_nfc_dump`](flipper_nfc_dump.md) - Dump NFC data to files
- [`flipper_rfid_read`](flipper_rfid_read.md) - Read RFID cards
- [`flipper_rfid_dump`](flipper_rfid_dump.md) - Dump RFID data to files

### BadUSB Operations (2 tools)
- [`flipper_badusb_send`](flipper_badusb_send.md) - Execute BadUSB scripts
- [`flipper_badusb_ducky`](flipper_badusb_ducky.md) - Run DuckyScript commands

### Hardware Operations (3 tools)
- [`flipper_uart_sniff`](flipper_uart_sniff.md) - Monitor UART communication
- [`flipper_gpio_set`](flipper_gpio_set.md) - Set GPIO pin values
- [`flipper_gpio_read`](flipper_gpio_read.md) - Read GPIO pin states

### Bluetooth Operations (2 tools)
- [`flipper_ble_scan`](flipper_ble_scan.md) - Scan for Bluetooth devices
- [`flipper_ble_pair`](flipper_ble_pair.md) - Pair with Bluetooth devices

## 🚀 Quick Start

### 1. Environment Configuration

Copy the environment template and configure your settings:

```bash
cp dev/flipper.env.example .env
```

Edit `.env` with your preferred settings:

```env
# Enable Flipper Zero integration
MCPGM_FLIPPER_ENABLED=true

# Enable USB transport
MCPGM_FLIPPER_USB_ENABLED=true

# Enable BLE transport
MCPGM_FLIPPER_BLE_ENABLED=true

# WARNING: Only enable transmission if you understand legal implications
MCPGM_FLIPPER_ALLOW_TX=false
```

### 2. Basic Usage

```javascript
// List available devices
const devices = await flipper_list_devices({
  scan_ble: true,
  scan_usb: true
});

// Connect to a device
const session = await flipper_connect({
  device_id: "usb:/dev/tty.usbmodem123"
});

// Get device information
const info = await flipper_info({
  session_id: session.data.sessionId
});

// List files on device
const files = await flipper_fs_list({
  session_id: session.data.sessionId,
  path: "/"
});
```

### 3. Advanced Operations

```javascript
// Read NFC card
const nfcData = await flipper_nfc_read({
  session_id: sessionId
});

// Dump RFID card
const rfidDump = await flipper_rfid_dump({
  session_id: sessionId,
  filename: "/ext/nfc/dump.nfc"
});

// Scan for Bluetooth devices
const bleDevices = await flipper_ble_scan({
  session_id: sessionId,
  duration: 10
});
```

## 🔒 Security Features

### Transmission Lock
- **Default State**: All transmission operations (IR, Sub-GHz, BadUSB) are disabled
- **Enabling**: Requires explicit `MCPGM_FLIPPER_ALLOW_TX=true` configuration
- **Safety**: Multiple confirmation layers for high-risk operations

### Audit Logging
- **Comprehensive Logging**: All operations logged with sanitized metadata
- **Session Tracking**: Complete session lifecycle monitoring
- **Security Events**: Transmission attempts and permission changes logged

### Environment Guards
- **Feature Toggles**: Granular control over available functionality
- **Permission Validation**: Multiple layers of permission checking
- **Configuration Validation**: Environment-based feature validation

## 🌍 Cross-Platform Support

### Windows
- **USB**: COM port detection and connection
- **BLE**: Windows 10+ Bluetooth support
- **Permissions**: Administrator privileges may be required

### macOS
- **USB**: `/dev/tty.usbmodem*` device detection
- **BLE**: Bluetooth permissions required
- **Security**: Gatekeeper may require approval

### Linux
- **USB**: Requires `dialout` group membership
- **BLE**: `noble` package permissions
- **Permissions**: User group configuration required

## 📋 Use Cases

### Security Testing
- **NFC/RFID Analysis**: Card cloning and security assessment
- **Wireless Testing**: Sub-GHz and IR signal analysis
- **Hardware Hacking**: GPIO and UART manipulation
- **Bluetooth Security**: Device discovery and pairing analysis

### Educational Purposes
- **Hardware Learning**: Understanding embedded systems
- **Security Research**: Wireless protocol analysis
- **Penetration Testing**: Authorized security assessments
- **IoT Security**: Internet of Things device testing

### Development
- **Firmware Development**: Custom Flipper Zero applications
- **Script Development**: BadUSB and automation scripts
- **Data Analysis**: Wireless signal analysis and processing
- **Tool Integration**: Custom security tool development

## ⚙️ Configuration Options

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCPGM_FLIPPER_ENABLED` | `false` | Enable Flipper Zero integration |
| `MCPGM_FLIPPER_USB_ENABLED` | `true` | Enable USB CDC transport |
| `MCPGM_FLIPPER_BLE_ENABLED` | `true` | Enable BLE GATT transport |
| `MCPGM_FLIPPER_ALLOW_TX` | `false` | Allow transmission operations |
| `MCPGM_FLIPPER_TX_MAX_SECONDS` | `10` | Maximum transmission duration |
| `MCPGM_FLIPPER_LOG_STREAMS` | `false` | Enable detailed stream logging |

### Safety Configurations

#### Read-Only Mode (Recommended for beginners)
```env
MCPGM_FLIPPER_ENABLED=true
MCPGM_FLIPPER_USB_ENABLED=true
MCPGM_FLIPPER_BLE_ENABLED=true
MCPGM_FLIPPER_ALLOW_TX=false
```

#### Full Access Mode (Advanced users only)
```env
MCPGM_FLIPPER_ENABLED=true
MCPGM_FLIPPER_USB_ENABLED=true
MCPGM_FLIPPER_BLE_ENABLED=true
MCPGM_FLIPPER_ALLOW_TX=true
MCPGM_FLIPPER_TX_MAX_SECONDS=5
```

## 🔧 Troubleshooting

### Common Issues

#### Device Not Detected
- **USB**: Check device permissions and drivers
- **BLE**: Verify Bluetooth is enabled and permissions granted
- **Platform**: Ensure platform-specific requirements are met

#### Connection Failures
- **USB**: Verify device is not in use by other applications
- **BLE**: Check device pairing status and proximity
- **Session**: Ensure previous sessions are properly closed

#### Permission Errors
- **Transmission**: Verify `MCPGM_FLIPPER_ALLOW_TX=true` is set
- **File Access**: Check file system permissions
- **Hardware**: Ensure required hardware permissions are granted

### Debug Mode

Enable detailed logging for troubleshooting:

```env
MCPGM_FLIPPER_LOG_STREAMS=true
```

## 📚 Additional Resources

- **[Flipper Zero Official Documentation](https://docs.flipperzero.one/)**
- **[MCP-God-Mode Setup Guide](../../guides/COMPLETE_SETUP_GUIDE.md)**
- **[Security Testing Guidelines](../../legal/LEGAL_COMPLIANCE.md)**
- **[Cross-Platform Compatibility](../../general/CROSS_PLATFORM_COMPATIBILITY.md)**

## 🆘 Support

For technical support and questions:
- **Documentation**: Check the complete tool documentation in this directory
- **Issues**: Report bugs and feature requests through the project repository
- **Community**: Join the MCP-God-Mode community for discussions

---

*This toolkit is part of MCP-God-Mode v1.7 and provides comprehensive Flipper Zero integration for authorized security testing and educational purposes.*
