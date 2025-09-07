# flipper_gpio_read

Read GPIO pin value from Flipper Zero device.

## Description

Reads the current state of GPIO (General Purpose Input/Output) pins on the Flipper Zero device, allowing you to monitor digital input signals from external hardware. This tool is useful for reading sensor data, monitoring switches, and interfacing with external devices.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `pin` | number | Yes | GPIO pin number to read |

## Usage Examples

### Read Single GPIO Pin
```javascript
flipper_gpio_read({
  session_id: "session_123",
  pin: 2
})
```

### Read Multiple GPIO Pins
```javascript
// Read pin 2
const pin2 = flipper_gpio_read({
  session_id: "session_123",
  pin: 2
})

// Read pin 3
const pin3 = flipper_gpio_read({
  session_id: "session_123",
  pin: 3
})
```

### Monitor GPIO Pin State
```javascript
// Read pin state
const state = flipper_gpio_read({
  session_id: "session_123",
  pin: 2
})

console.log(`Pin 2 is ${state.data.value ? 'HIGH' : 'LOW'}`)
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

### Digital Input Pins
- **Pin 2**: GPIO input/output (3.3V logic)
- **Pin 3**: GPIO input/output (3.3V logic)
- **Pin 4**: GPIO input/output (3.3V logic)
- **Pin 5**: GPIO input/output (3.3V logic)
- **Pin 6**: GPIO input/output (3.3V logic)
- **Pin 7**: GPIO input/output (3.3V logic)

### Special Pins
- **Pin 1**: 5V power output
- **Pin 8**: 3.3V power output
- **Pin 9**: Ground (GND)

## Error Handling

- **Invalid Pin**: Returns error for unsupported GPIO pin numbers
- **Session Invalid**: Returns error if session_id is not found
- **Hardware Error**: Returns error if GPIO read fails
- **Pin Not Configured**: Returns error if pin is not set as input

## Use Cases

### Sensor Reading
- Read digital sensor outputs
- Monitor switch states
- Detect button presses
- Read encoder signals

### Hardware Monitoring
- Monitor external device status
- Read configuration switches
- Detect power states
- Monitor communication signals

### Prototyping
- Test circuit connections
- Debug hardware interfaces
- Verify signal levels
- Develop embedded projects

## Safety Notes

⚠️ **Hardware Warning**: 
- GPIO pins accept 3.3V logic levels
- Maximum input voltage: 3.3V
- Do not exceed voltage limits
- Use appropriate level shifters for 5V signals
- Ensure proper grounding

## Related Tools

- `flipper_gpio_set` - Set GPIO pin values
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
- **GPIO Pin** - Connect to device output
- **Ground (GND)** - Connect to device ground
- **Power (3.3V/5V)** - Connect to device power if needed

## Input Characteristics

- **Logic High**: 2.0V - 3.3V
- **Logic Low**: 0V - 0.8V
- **Input Impedance**: High impedance
- **Pull-up/Pull-down**: Configurable
