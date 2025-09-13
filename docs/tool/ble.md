# BLE Tool

## Overview
The **BLE Tool** is a comprehensive Bluetooth Low Energy (BLE) communication utility that provides BLE device management, communication, and monitoring capabilities. It offers cross-platform support and advanced BLE communication features.

## Features
- **BLE Device Management**: Discover, connect, and manage BLE devices
- **BLE Communication**: Send and receive data over BLE connections
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Device Monitoring**: Real-time device monitoring and status tracking
- **Data Logging**: BLE data logging and analysis
- **Protocol Support**: Support for various BLE protocols

## Usage

### Device Management
```bash
# List BLE devices
{
  "action": "list_devices"
}

# Get device info
{
  "action": "get_device_info",
  "device_id": "device_001"
}

# Configure device
{
  "action": "configure_device",
  "device_id": "device_001",
  "configuration": {
    "connection_timeout": 10000,
    "scan_timeout": 5000,
    "auto_connect": true
  }
}
```

### BLE Communication
```bash
# Connect to device
{
  "action": "connect_device",
  "device_id": "device_001"
}

# Disconnect from device
{
  "action": "disconnect_device",
  "device_id": "device_001"
}

# Send data
{
  "action": "send_data",
  "device_id": "device_001",
  "service_uuid": "12345678-1234-1234-1234-123456789abc",
  "characteristic_uuid": "87654321-4321-4321-4321-cba987654321",
  "data": "Hello, BLE!"
}

# Receive data
{
  "action": "receive_data",
  "device_id": "device_001",
  "service_uuid": "12345678-1234-1234-1234-123456789abc",
  "characteristic_uuid": "87654321-4321-4321-4321-cba987654321",
  "timeout": 5000
}
```

### Device Control
```bash
# Start device
{
  "action": "start_device",
  "device_id": "device_001"
}

# Stop device
{
  "action": "stop_device",
  "device_id": "device_001"
}

# Pause device
{
  "action": "pause_device",
  "device_id": "device_001"
}

# Resume device
{
  "action": "resume_device",
  "device_id": "device_001"
}
```

### Data Monitoring
```bash
# Monitor devices
{
  "action": "monitor_devices",
  "duration": 60000
}

# Log device data
{
  "action": "log_device_data",
  "device_id": "device_001",
  "log_file": "./ble_log.txt",
  "duration": 300000
}

# Analyze device data
{
  "action": "analyze_device_data",
  "device_id": "device_001",
  "analysis_type": "hex"
}
```

## Parameters

### Device Parameters
- **action**: BLE operation to perform
- **device_id**: ID of the BLE device
- **configuration**: Device configuration object

### Communication Parameters
- **service_uuid**: UUID of the BLE service
- **characteristic_uuid**: UUID of the BLE characteristic
- **data**: Data to send over BLE
- **timeout**: Timeout for operations in milliseconds
- **duration**: Duration for monitoring operations

### Configuration Parameters
- **connection_timeout**: Connection timeout in milliseconds
- **scan_timeout**: Scan timeout in milliseconds
- **auto_connect**: Whether to auto-connect to devices

## Output Format
```json
{
  "success": true,
  "action": "list_devices",
  "result": {
    "devices": [
      {
        "device_id": "device_001",
        "name": "BLE Device",
        "address": "AA:BB:CC:DD:EE:FF",
        "rssi": -50,
        "status": "available"
      }
    ],
    "total_devices": 1
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows BLE devices
- **Linux**: Complete functionality with Linux BLE devices
- **macOS**: Full feature support with macOS BLE devices
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Device Discovery
```bash
# List devices
{
  "action": "list_devices"
}

# Result
{
  "success": true,
  "result": {
    "devices": [
      {
        "device_id": "device_001",
        "name": "BLE Device",
        "address": "AA:BB:CC:DD:EE:FF",
        "status": "available"
      }
    ],
    "total_devices": 1
  }
}
```

### Example 2: Device Communication
```bash
# Send data
{
  "action": "send_data",
  "device_id": "device_001",
  "service_uuid": "12345678-1234-1234-1234-123456789abc",
  "characteristic_uuid": "87654321-4321-4321-4321-cba987654321",
  "data": "Hello, BLE!"
}

# Result
{
  "success": true,
  "result": {
    "device_id": "device_001",
    "data_sent": "Hello, BLE!",
    "bytes_sent": 12,
    "status": "sent"
  }
}
```

### Example 3: Data Reception
```bash
# Receive data
{
  "action": "receive_data",
  "device_id": "device_001",
  "service_uuid": "12345678-1234-1234-1234-123456789abc",
  "characteristic_uuid": "87654321-4321-4321-4321-cba987654321",
  "timeout": 5000
}

# Result
{
  "success": true,
  "result": {
    "device_id": "device_001",
    "data_received": "Response from device",
    "bytes_received": 19,
    "status": "received"
  }
}
```

## Error Handling
- **Device Errors**: Proper handling of device access and communication issues
- **Communication Errors**: Secure handling of BLE communication failures
- **Timeout Errors**: Robust error handling for operation timeouts
- **Configuration Errors**: Safe handling of device configuration problems

## Related Tools
- **Hardware Interface**: Hardware interface tools
- **Communication**: Communication tools
- **Monitoring**: BLE monitoring and logging tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the BLE Tool, please refer to the main MCP God Mode documentation or contact the development team.
