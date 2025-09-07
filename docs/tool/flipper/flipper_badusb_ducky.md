# flipper_badusb_ducky

Send DuckyScript commands to Flipper Zero device (requires transmission permission).

## Description

Executes DuckyScript commands on the Flipper Zero device, providing a standardized scripting language for USB HID attacks. DuckyScript is a simple scripting language designed for USB Rubber Ducky devices and is widely supported. **Requires `MCPGM_FLIPPER_ALLOW_TX=true` in environment configuration.**

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `script` | string | Yes | DuckyScript content |

## Usage Examples

### Simple DuckyScript
```javascript
flipper_badusb_ducky({
  session_id: "session_123",
  script: "STRING Hello World!\nENTER"
})
```

### Complex DuckyScript with Delays
```javascript
flipper_badusb_ducky({
  session_id: "session_123",
  script: "DELAY 1000\nGUI r\nDELAY 500\nSTRING notepad\nENTER\nDELAY 1000\nSTRING Hello from DuckyScript!\nCTRL s\nSTRING test.txt\nENTER"
})
```

### DuckyScript with Loops
```javascript
flipper_badusb_ducky({
  session_id: "session_123",
  script: "REPEAT 5\nSTRING Hello!\nENTER\nDELAY 1000\nREPEAT_END"
})
```

## Response Format

```json
{
  "success": true,
  "data": {
    "script": "STRING Hello World!\nENTER",
    "executed": true,
    "duration": 1.2,
    "commands": 2,
    "timestamp": "2025-01-07T16:33:00Z"
  }
}
```

## DuckyScript Commands

### Basic Commands
- `STRING text` - Type text
- `ENTER` - Press Enter key
- `SPACE` - Press Space key
- `TAB` - Press Tab key
- `ESC` - Press Escape key

### Modifier Keys
- `CTRL` - Control key
- `ALT` - Alt key
- `SHIFT` - Shift key
- `GUI` - Windows/Command key

### Special Keys
- `UP`, `DOWN`, `LEFT`, `RIGHT` - Arrow keys
- `HOME`, `END` - Home/End keys
- `PAGEUP`, `PAGEDOWN` - Page Up/Down
- `F1-F12` - Function keys
- `DELETE`, `BACKSPACE` - Delete/Backspace

### Timing Commands
- `DELAY ms` - Wait specified milliseconds
- `DEFAULTDELAY ms` - Set default delay between commands
- `DEFAULTCHARDELAY ms` - Set default delay between characters

### Control Flow
- `REPEAT n` - Start repeat block
- `REPEAT_END` - End repeat block
- `REM comment` - Comment (ignored)

### Combinations
- `CTRL-ALT-DELETE` - Three-key combination
- `GUI-r` - Windows Run dialog
- `ALT-F4` - Close window

## Error Handling

- **Transmission Disabled**: Returns error if `MCPGM_FLIPPER_ALLOW_TX=false`
- **Invalid Script**: Returns error for malformed DuckyScript
- **Session Invalid**: Returns error if session_id is not found
- **Hardware Error**: Returns error if DuckyScript execution fails

## Safety Notes

⚠️ **Legal Warning**: DuckyScript can control connected computers and may be used maliciously. Only use on computers you own or have explicit permission to control. Unauthorized use may violate laws and regulations.

## Related Tools

- `flipper_badusb_send` - Send BadUSB scripts
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
- `MCPGM_FLIPPER_ALLOW_TX=true` environment setting
- BadUSB functionality enabled on device
- Target computer connected via USB

## DuckyScript Resources

- [Official DuckyScript Documentation](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Duckyscript)
- [DuckyScript Payloads](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Payloads)
