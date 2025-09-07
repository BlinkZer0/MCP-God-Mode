# flipper_uart_sniff

Sniff UART communication on Flipper Zero device.

## Description

Monitors and captures UART (Universal Asynchronous Receiver-Transmitter) communication data using the Flipper Zero's UART interface. This tool is useful for analyzing serial communication protocols, debugging embedded systems, and reverse engineering devices that use UART communication.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `duration` | number | No | Sniff duration in seconds (default: 10) |

## Usage Examples

### Basic UART Sniffing (10 seconds)
```javascript
flipper_uart_sniff({
  session_id: "session_123"
})
```

### Extended UART Sniffing (60 seconds)
```javascript
flipper_uart_sniff({
  session_id: "session_123",
  duration: 60
})
```

### Short UART Sniffing (5 seconds)
```javascript
flipper_uart_sniff({
  session_id: "session_123",
  duration: 5
})
```

## Response Format

```json
{
  "success": true,
  "data": {
    "duration": 10,
    "baud_rate": 9600,
    "data_bits": 8,
    "stop_bits": 1,
    "parity": "none",
    "captured_data": "48656C6C6F20576F726C64",
    "data_hex": "48656C6C6F20576F726C64",
    "data_ascii": "Hello World",
    "packet_count": 1,
    "timestamp": "2025-01-07T16:33:00Z"
  }
}
```

## UART Configuration

The Flipper Zero UART interface supports various configurations:

### Baud Rates
- 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600

### Data Bits
- 5, 6, 7, 8 bits

### Stop Bits
- 1, 2 stop bits

### Parity
- None, Even, Odd

## Error Handling

- **No UART Activity**: Returns empty data if no UART communication detected
- **Session Invalid**: Returns error if session_id is not found
- **Hardware Error**: Returns error if UART interface fails
- **Timeout**: Returns partial data if duration exceeds available data

## Use Cases

### Embedded System Debugging
- Monitor microcontroller communication
- Analyze sensor data transmission
- Debug protocol implementations

### Reverse Engineering
- Capture device communication protocols
- Analyze proprietary serial protocols
- Understand device behavior

### Security Testing
- Monitor authentication exchanges
- Analyze encrypted communication
- Test device security

## Safety Notes

⚠️ **Legal Warning**: Only sniff UART communication on devices you own or have explicit permission to monitor. Unauthorized monitoring may violate laws and regulations.

## Related Tools

- `flipper_connect` - Establish device connection
- `flipper_info` - Get device information
- `flipper_fs_write` - Save captured data to file

## Platform Support

- ✅ Windows (USB CDC)
- ✅ macOS (USB CDC)
- ✅ Linux (USB CDC)
- ✅ All platforms (BLE GATT)

## Requirements

- Flipper Zero device connected
- Active session established
- UART interface enabled on device
- Target device connected to UART pins

## Hardware Connections

Connect target device to Flipper Zero UART pins:
- **TX** (Transmit) - Connect to target device RX
- **RX** (Receive) - Connect to target device TX
- **GND** (Ground) - Connect to target device ground
- **VCC** (Power) - Optional, for powering target device
