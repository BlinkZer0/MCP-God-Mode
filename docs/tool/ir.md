# IR Tool

## Overview
The **IR Tool** is a comprehensive Infrared (IR) communication utility that provides IR signal management, communication, and monitoring capabilities. It offers cross-platform support and advanced IR communication features.

## Features
- **IR Signal Management**: Discover, configure, and manage IR signals
- **IR Communication**: Send and receive data over IR connections
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Signal Monitoring**: Real-time signal monitoring and status tracking
- **Data Logging**: IR data logging and analysis
- **Protocol Support**: Support for various IR protocols

## Usage

### Signal Management
```bash
# List IR signals
{
  "action": "list_signals"
}

# Get signal info
{
  "action": "get_signal_info",
  "signal_id": "signal_001"
}

# Configure signal
{
  "action": "configure_signal",
  "signal_id": "signal_001",
  "configuration": {
    "frequency": "38",
    "protocol": "NEC",
    "power": "high"
  }
}
```

### IR Communication
```bash
# Send signal
{
  "action": "send_signal",
  "signal_id": "signal_001",
  "data": "Hello, IR!"
}

# Receive signal
{
  "action": "receive_signal",
  "signal_id": "signal_001",
  "timeout": 5000
}

# Transmit signal
{
  "action": "transmit_signal",
  "signal_id": "signal_001",
  "frequency": "38",
  "data": "raw_signal_data"
}
```

### Signal Control
```bash
# Start signal
{
  "action": "start_signal",
  "signal_id": "signal_001"
}

# Stop signal
{
  "action": "stop_signal",
  "signal_id": "signal_001"
}

# Pause signal
{
  "action": "pause_signal",
  "signal_id": "signal_001"
}

# Resume signal
{
  "action": "resume_signal",
  "signal_id": "signal_001"
}
```

### Data Monitoring
```bash
# Monitor signals
{
  "action": "monitor_signals",
  "duration": 60000
}

# Log signal data
{
  "action": "log_signal_data",
  "signal_id": "signal_001",
  "log_file": "./ir_log.txt",
  "duration": 300000
}

# Analyze signal data
{
  "action": "analyze_signal_data",
  "signal_id": "signal_001",
  "analysis_type": "hex"
}
```

## Parameters

### Signal Parameters
- **action**: IR operation to perform
- **signal_id**: ID of the IR signal
- **configuration**: Signal configuration object

### Communication Parameters
- **data**: Data to send over IR
- **timeout**: Timeout for operations in milliseconds
- **duration**: Duration for monitoring operations

### Configuration Parameters
- **frequency**: IR frequency (38, 36, 40)
- **protocol**: IR protocol (NEC, RC5, RC6, SONY)
- **power**: Power level (low, medium, high)

## Output Format
```json
{
  "success": true,
  "action": "list_signals",
  "result": {
    "signals": [
      {
        "signal_id": "signal_001",
        "frequency": "38",
        "protocol": "NEC",
        "power": "high",
        "status": "available"
      }
    ],
    "total_signals": 1
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows IR devices
- **Linux**: Complete functionality with Linux IR devices
- **macOS**: Full feature support with macOS IR devices
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Signal Discovery
```bash
# List signals
{
  "action": "list_signals"
}

# Result
{
  "success": true,
  "result": {
    "signals": [
      {
        "signal_id": "signal_001",
        "frequency": "38",
        "protocol": "NEC",
        "status": "available"
      }
    ],
    "total_signals": 1
  }
}
```

### Example 2: Signal Transmission
```bash
# Send signal
{
  "action": "send_signal",
  "signal_id": "signal_001",
  "data": "Hello, IR!"
}

# Result
{
  "success": true,
  "result": {
    "signal_id": "signal_001",
    "data_sent": "Hello, IR!",
    "bytes_sent": 10,
    "status": "sent"
  }
}
```

### Example 3: Signal Reception
```bash
# Receive signal
{
  "action": "receive_signal",
  "signal_id": "signal_001",
  "timeout": 5000
}

# Result
{
  "success": true,
  "result": {
    "signal_id": "signal_001",
    "data_received": "Response from device",
    "bytes_received": 19,
    "status": "received"
  }
}
```

## Error Handling
- **Signal Errors**: Proper handling of signal access and communication issues
- **Communication Errors**: Secure handling of IR communication failures
- **Timeout Errors**: Robust error handling for operation timeouts
- **Configuration Errors**: Safe handling of signal configuration problems

## Related Tools
- **Hardware Interface**: Hardware interface tools
- **Communication**: Communication tools
- **Monitoring**: IR monitoring and logging tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the IR Tool, please refer to the main MCP God Mode documentation or contact the development team.
