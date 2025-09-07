# flipper_gpio_set

Set GPIO pin value on Flipper Zero device.

## Description

Controls GPIO (General Purpose Input/Output) pins on the Flipper Zero device, allowing you to set digital output pins to high or low states. This tool is useful for controlling external hardware, testing circuits, and interfacing with other devices.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `pin` | number | Yes | GPIO pin number to control |
| `value` | boolean | Yes | Pin value (true=high/3.3V, false=low/0V) |

## Usage Examples

### Set GPIO Pin High
```javascript
flipper_gpio_set({
  session_id: "session_123",
  pin: 2,
  value: true
})
```

### Set GPIO Pin Low
```javascript
flipper_gpio_set({
  session_id: "session_123",
  pin: 2,
  value: false
})
```

### Control Multiple GPIO Pins
```javascript
// Set pin 2 high
flipper_gpio_set({
  session_id: "session_123",
  pin: 2,
  value: true
})

// Set pin 3 low
flipper_gpio_set({
  session_id: "session_123",
  pin: 3,
  value: false
})
```

## Response Format

```json
{
  "success": true,
  "data": {
    "pin": 2,
    "value": true,
    "voltage": 3.3,
    "state": "high",
    "timestamp": "2025-01-07T16:33:00Z"
  }
}
```

## Available GPIO Pins

The Flipper Zero provides several GPIO pins for external connections:

### Digital Output Pins
- **Pin 2**: GPIO output (3.3V logic)
- **Pin 3**: GPIO output (3.3V logic)
- **Pin 4**: GPIO output (3.3V logic)
- **Pin 5**: GPIO output (3.3V logic)
- **Pin 6**: GPIO output (3.3V logic)
- **Pin 7**: GPIO output (3.3V logic)

### Special Pins
- **Pin 1**: 5V power output
- **Pin 8**: 3.3V power output
- **Pin 9**: Ground (GND)

## Error Handling

- **Invalid Pin**: Returns error for unsupported GPIO pin numbers
- **Session Invalid**: Returns error if session_id is not found
- **Hardware Error**: Returns error if GPIO control fails
- **Pin Conflict**: Returns error if pin is already in use

## Use Cases

### Hardware Control
- Control LEDs and indicators
- Drive relays and switches
- Interface with external circuits
- Test hardware components

### Prototyping
- Build custom circuits
- Test sensor interfaces
- Develop embedded projects
- Create automation systems

### Educational
- Learn GPIO programming
- Understand digital electronics
- Practice circuit design
- Experiment with hardware

## Safety Notes

⚠️ **Hardware Warning**: 
- GPIO pins output 3.3V logic levels
- Maximum current per pin: 20mA
- Do not exceed voltage/current limits
- Use appropriate protection circuits
- Ensure proper grounding

## Related Tools

- `flipper_gpio_read` - Read GPIO pin values
- `flipper_connect` - Establish device connection
- `flipper_info` - Get device information

## Platform Support

- ✅ Windows (USB CDC)
- ✅ macOS (USB CDC)
- ✅ Linux (USB CDC)
- ✅ All platforms (BLE GATT)

## Requirements

- Flipper Zero device connected
- Active session established
- GPIO interface enabled on device
- External hardware connected (optional)

## Hardware Connections

Connect external devices to GPIO pins:
- **GPIO Pin** - Connect to device input
- **Ground (GND)** - Connect to device ground
- **Power (3.3V/5V)** - Connect to device power if needed
