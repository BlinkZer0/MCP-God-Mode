# Sub-GHz Tool

## Overview
The **Sub-GHz Tool** is a comprehensive Sub-GHz frequency communication utility that provides Sub-GHz signal management, communication, and monitoring capabilities. It offers cross-platform support and advanced Sub-GHz communication features.

## Features
- **Sub-GHz Signal Management**: Discover, configure, and manage Sub-GHz signals
- **Sub-GHz Communication**: Send and receive data over Sub-GHz connections
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Signal Monitoring**: Real-time signal monitoring and status tracking
- **Data Logging**: Sub-GHz data logging and analysis
- **Protocol Support**: Support for various Sub-GHz protocols

## Usage

### Signal Management
```bash
# List Sub-GHz signals
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
    "frequency": "433.92",
    "modulation": "ASK",
    "power": "high"
  }
}
```

### Sub-GHz Communication
```bash
# Send signal
{
  "action": "send_signal",
  "signal_id": "signal_001",
  "data": "Hello, Sub-GHz!"
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
  "frequency": "433.92",
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
  "log_file": "./subghz_log.txt",
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
- **action**: Sub-GHz operation to perform
- **signal_id**: ID of the Sub-GHz signal
- **configuration**: Signal configuration object

### Communication Parameters
- **data**: Data to send over Sub-GHz
- **timeout**: Timeout for operations in milliseconds
- **duration**: Duration for monitoring operations

### Configuration Parameters
- **frequency**: Sub-GHz frequency (433.92, 868.35, 915.0)
- **modulation**: Modulation type (ASK, FSK, PSK)
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
        "frequency": "433.92",
        "modulation": "ASK",
        "power": "high",
        "status": "available"
      }
    ],
    "total_signals": 1
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows Sub-GHz devices
- **Linux**: Complete functionality with Linux Sub-GHz devices
- **macOS**: Full feature support with macOS Sub-GHz devices
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
        "frequency": "433.92",
        "modulation": "ASK",
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
  "data": "Hello, Sub-GHz!"
}

# Result
{
  "success": true,
  "result": {
    "signal_id": "signal_001",
    "data_sent": "Hello, Sub-GHz!",
    "bytes_sent": 15,
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
- **Communication Errors**: Secure handling of Sub-GHz communication failures
- **Timeout Errors**: Robust error handling for operation timeouts
- **Configuration Errors**: Safe handling of signal configuration problems

## Related Tools
- **Hardware Interface**: Hardware interface tools
- **Communication**: Communication tools
- **Monitoring**: Sub-GHz monitoring and logging tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Sub-GHz Tool, please refer to the main MCP God Mode documentation or contact the development team.
