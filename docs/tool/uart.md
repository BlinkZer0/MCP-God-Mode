# UART Tool

## Overview
The **UART Tool** is a comprehensive UART (Universal Asynchronous Receiver-Transmitter) communication utility that provides UART port management, communication, and monitoring capabilities. It offers cross-platform support and advanced UART communication features.

## Features
- **UART Port Management**: Discover, configure, and manage UART ports
- **UART Communication**: Send and receive data over UART connections
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Port Monitoring**: Real-time port monitoring and status tracking
- **Data Logging**: UART data logging and analysis
- **Protocol Support**: Support for various UART protocols

## Usage

### Port Management
```bash
# List UART ports
{
  "action": "list_ports"
}

# Get port info
{
  "action": "get_port_info",
  "port_name": "/dev/ttyUSB0"
}

# Configure port
{
  "action": "configure_port",
  "port_name": "/dev/ttyUSB0",
  "configuration": {
    "baud_rate": 115200,
    "data_bits": 8,
    "stop_bits": 1,
    "parity": "none",
    "flow_control": "none"
  }
}
```

### UART Communication
```bash
# Open port
{
  "action": "open_port",
  "port_name": "/dev/ttyUSB0",
  "configuration": {
    "baud_rate": 115200,
    "data_bits": 8,
    "stop_bits": 1,
    "parity": "none"
  }
}

# Send data
{
  "action": "send_data",
  "port_name": "/dev/ttyUSB0",
  "data": "AT+COMMAND\r\n"
}

# Receive data
{
  "action": "receive_data",
  "port_name": "/dev/ttyUSB0",
  "timeout": 5000
}
```

### Port Control
```bash
# Close port
{
  "action": "close_port",
  "port_name": "/dev/ttyUSB0"
}

# Flush port
{
  "action": "flush_port",
  "port_name": "/dev/ttyUSB0"
}

# Set port options
{
  "action": "set_port_options",
  "port_name": "/dev/ttyUSB0",
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
  "port_name": "/dev/ttyUSB0",
  "duration": 60000
}

# Log data
{
  "action": "log_data",
  "port_name": "/dev/ttyUSB0",
  "log_file": "./uart_log.txt",
  "duration": 300000
}

# Analyze data
{
  "action": "analyze_data",
  "port_name": "/dev/ttyUSB0",
  "analysis_type": "hex"
}
```

## Parameters

### Port Parameters
- **action**: UART operation to perform
- **port_name**: Name of the UART port
- **configuration**: Port configuration object

### Communication Parameters
- **data**: Data to send over UART
- **timeout**: Timeout for operations in milliseconds
- **duration**: Duration for monitoring operations

### Configuration Parameters
- **baud_rate**: Baud rate for UART communication
- **data_bits**: Number of data bits
- **stop_bits**: Number of stop bits
- **parity**: Parity setting (none, even, odd)
- **flow_control**: Flow control setting (none, rts_cts, xon_xoff)

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
        "name": "/dev/ttyUSB0",
        "description": "USB UART Port",
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
        "name": "/dev/ttyUSB0",
        "description": "USB UART Port",
        "status": "available"
      }
    ],
    "total_ports": 1
  }
}
```

### Example 2: UART Communication
```bash
# Send data
{
  "action": "send_data",
  "port_name": "/dev/ttyUSB0",
  "data": "AT+COMMAND\r\n"
}

# Result
{
  "success": true,
  "result": {
    "port_name": "/dev/ttyUSB0",
    "data_sent": "AT+COMMAND\r\n",
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
  "port_name": "/dev/ttyUSB0",
  "timeout": 5000
}

# Result
{
  "success": true,
  "result": {
    "port_name": "/dev/ttyUSB0",
    "data_received": "OK\r\n",
    "bytes_received": 4,
    "status": "received"
  }
}
```

## Error Handling
- **Port Errors**: Proper handling of port access and configuration issues
- **Communication Errors**: Secure handling of UART communication failures
- **Timeout Errors**: Robust error handling for operation timeouts
- **Configuration Errors**: Safe handling of port configuration problems

## Related Tools
- **Hardware Interface**: Hardware interface tools
- **Communication**: Communication tools
- **Monitoring**: UART monitoring and logging tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the UART Tool, please refer to the main MCP God Mode documentation or contact the development team.
