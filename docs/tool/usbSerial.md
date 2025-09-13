# USB Serial Tool

## Overview
The **USB Serial Tool** is a comprehensive USB serial communication utility that provides serial port management, communication, and monitoring capabilities. It offers cross-platform support and advanced serial communication features.

## Features
- **Serial Port Management**: Discover, configure, and manage serial ports
- **Serial Communication**: Send and receive data over serial connections
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Port Monitoring**: Real-time port monitoring and status tracking
- **Data Logging**: Serial data logging and analysis
- **Protocol Support**: Support for various serial protocols

## Usage

### Port Management
```bash
# List serial ports
{
  "action": "list_ports"
}

# Get port info
{
  "action": "get_port_info",
  "port_name": "COM3"
}

# Configure port
{
  "action": "configure_port",
  "port_name": "COM3",
  "configuration": {
    "baud_rate": 9600,
    "data_bits": 8,
    "stop_bits": 1,
    "parity": "none"
  }
}
```

### Serial Communication
```bash
# Open port
{
  "action": "open_port",
  "port_name": "COM3",
  "configuration": {
    "baud_rate": 9600,
    "data_bits": 8,
    "stop_bits": 1,
    "parity": "none"
  }
}

# Send data
{
  "action": "send_data",
  "port_name": "COM3",
  "data": "Hello, Serial!"
}

# Receive data
{
  "action": "receive_data",
  "port_name": "COM3",
  "timeout": 5000
}
```

### Port Control
```bash
# Close port
{
  "action": "close_port",
  "port_name": "COM3"
}

# Flush port
{
  "action": "flush_port",
  "port_name": "COM3"
}

# Set port options
{
  "action": "set_port_options",
  "port_name": "COM3",
  "options": {
    "rts": true,
    "dtr": true,
    "cts": false,
    "dsr": false
  }
}
```

### Data Monitoring
```bash
# Monitor port
{
  "action": "monitor_port",
  "port_name": "COM3",
  "duration": 60000
}

# Log data
{
  "action": "log_data",
  "port_name": "COM3",
  "log_file": "./serial_log.txt",
  "duration": 300000
}

# Analyze data
{
  "action": "analyze_data",
  "port_name": "COM3",
  "analysis_type": "hex"
}
```

## Parameters

### Port Parameters
- **action**: Serial operation to perform
- **port_name**: Name of the serial port
- **configuration**: Port configuration object

### Communication Parameters
- **data**: Data to send over serial
- **timeout**: Timeout for operations in milliseconds
- **duration**: Duration for monitoring operations

### Configuration Parameters
- **baud_rate**: Baud rate for serial communication
- **data_bits**: Number of data bits
- **stop_bits**: Number of stop bits
- **parity**: Parity setting (none, even, odd)

### Options Parameters
- **rts**: Request to send control
- **dtr**: Data terminal ready control
- **cts**: Clear to send status
- **dsr**: Data set ready status

## Output Format
```json
{
  "success": true,
  "action": "list_ports",
  "result": {
    "ports": [
      {
        "name": "COM3",
        "description": "USB Serial Port",
        "manufacturer": "FTDI",
        "product_id": "6001",
        "vendor_id": "0403",
        "status": "available"
      }
    ],
    "total_ports": 1
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows COM ports
- **Linux**: Complete functionality with Linux tty devices
- **macOS**: Full feature support with macOS serial ports
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Port Discovery
```bash
# List ports
{
  "action": "list_ports"
}

# Result
{
  "success": true,
  "result": {
    "ports": [
      {
        "name": "COM3",
        "description": "USB Serial Port",
        "status": "available"
      }
    ],
    "total_ports": 1
  }
}
```

### Example 2: Serial Communication
```bash
# Send data
{
  "action": "send_data",
  "port_name": "COM3",
  "data": "Hello, Serial!"
}

# Result
{
  "success": true,
  "result": {
    "port_name": "COM3",
    "data_sent": "Hello, Serial!",
    "bytes_sent": 14,
    "status": "sent"
  }
}
```

### Example 3: Data Reception
```bash
# Receive data
{
  "action": "receive_data",
  "port_name": "COM3",
  "timeout": 5000
}

# Result
{
  "success": true,
  "result": {
    "port_name": "COM3",
    "data_received": "Response from device",
    "bytes_received": 19,
    "status": "received"
  }
}
```

## Error Handling
- **Port Errors**: Proper handling of port access and configuration issues
- **Communication Errors**: Secure handling of serial communication failures
- **Timeout Errors**: Robust error handling for operation timeouts
- **Configuration Errors**: Safe handling of port configuration problems

## Related Tools
- **Hardware Interface**: Hardware interface tools
- **Communication**: Communication tools
- **Monitoring**: Serial monitoring and logging tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the USB Serial Tool, please refer to the main MCP God Mode documentation or contact the development team.
