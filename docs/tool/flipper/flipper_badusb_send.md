# flipper_badusb_send

Send BadUSB script to Flipper Zero device (requires transmission permission).

## Description

Executes BadUSB scripts on the Flipper Zero device, allowing it to act as a USB Human Interface Device (HID) keyboard. This tool can send keystrokes, text, and keyboard shortcuts to connected computers. **Requires `MCPGM_FLIPPER_ALLOW_TX=true` in environment configuration.**

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `script` | string | Yes | BadUSB script content (keyboard commands) |

## Usage Examples

### Send Simple Text
```javascript
flipper_badusb_send({
  session_id: "session_123",
  script: "Hello World!"
})
```

### Send Keyboard Shortcuts
```javascript
flipper_badusb_send({
  session_id: "session_123",
  script: "CTRL+ALT+DEL"
})
```

### Send Complex Script
```javascript
flipper_badusb_send({
  session_id: "session_123",
  script: "GUI+r\nnotepad\nENTER\nHello from Flipper Zero!\nCTRL+s\ntest.txt\nENTER"
})
```

## Response Format

```json
{
  "success": true,
  "data": {
    "script": "Hello World!",
    "executed": true,
    "duration": 0.5,
    "keystrokes": 12,
    "timestamp": "2025-01-07T16:33:00Z"
  }
}
```

## BadUSB Script Commands

### Basic Keys
- `A-Z`, `0-9` - Letters and numbers
- `SPACE` - Space bar
- `ENTER` - Enter key
- `TAB` - Tab key
- `ESC` - Escape key

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

### Combinations
- `CTRL+c` - Copy
- `CTRL+v` - Paste
- `ALT+F4` - Close window
- `GUI+r` - Run dialog

## Error Handling

- **Transmission Disabled**: Returns error if `MCPGM_FLIPPER_ALLOW_TX=false`
- **Invalid Script**: Returns error for malformed BadUSB script
- **Session Invalid**: Returns error if session_id is not found
- **Hardware Error**: Returns error if BadUSB execution fails

## Safety Notes

⚠️ **Legal Warning**: BadUSB scripts can control connected computers and may be used maliciously. Only use on computers you own or have explicit permission to control. Unauthorized use may violate laws and regulations.

## Related Tools

- `flipper_badusb_ducky` - Send DuckyScript commands
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
