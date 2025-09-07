# flipper_list_sessions

List active Flipper Zero sessions.

## Description

Lists all currently active Flipper Zero sessions, providing information about connected devices, session IDs, and connection status. This tool is useful for managing multiple device connections and monitoring active sessions.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| None | - | - | No parameters required |

## Usage Examples

### List All Active Sessions
```javascript
flipper_list_sessions({})
```

### Check Session Status
```javascript
const sessions = flipper_list_sessions({})
console.log(`Active sessions: ${sessions.data.count}`)

sessions.data.sessions.forEach(session => {
  console.log(`Session ${session.id}: ${session.deviceId} (${session.transportKind})`)
})
```

### Monitor Session Activity
```javascript
// List sessions before operation
const beforeSessions = flipper_list_sessions({})

// Perform some operation...

// List sessions after operation
const afterSessions = flipper_list_sessions({})
console.log(`Sessions changed: ${beforeSessions.data.count !== afterSessions.data.count}`)
```

## Response Format

```json
{
  "success": true,
  "data": {
    "sessions": [
      {
        "id": "session_123",
        "deviceId": "usb:/dev/tty.usbmodem123",
        "transportKind": "usb",
        "connected": true,
        "created": "2025-01-07T16:30:00Z",
        "lastActivity": "2025-01-07T16:33:00Z"
      },
      {
        "id": "session_456",
        "deviceId": "ble:AA:BB:CC:DD:EE:FF",
        "transportKind": "ble",
        "connected": true,
        "created": "2025-01-07T16:31:00Z",
        "lastActivity": "2025-01-07T16:32:00Z"
      }
    ],
    "count": 2
  }
}
```

## Session Information

### Session Properties
- **id**: Unique session identifier
- **deviceId**: Device identifier (USB path or BLE address)
- **transportKind**: Connection type ("usb" or "ble")
- **connected**: Current connection status
- **created**: Session creation timestamp
- **lastActivity**: Last activity timestamp

### Session States
- **Active**: Session is connected and ready for operations
- **Disconnected**: Session exists but device is not connected
- **Error**: Session encountered an error
- **Timeout**: Session timed out due to inactivity

## Error Handling

- **No Sessions**: Returns empty sessions list if no active sessions
- **System Error**: Returns error if session management fails
- **Memory Error**: Returns error if session data cannot be retrieved

## Use Cases

### Session Management
- Monitor active connections
- Track device usage
- Manage multiple devices
- Debug connection issues

### Resource Monitoring
- Check session count
- Monitor connection status
- Track session activity
- Identify idle sessions

### Development
- Debug session handling
- Test connection management
- Monitor session lifecycle
- Develop session tools

## Safety Notes

⚠️ **Session Management**: Active sessions consume system resources. Ensure proper session cleanup to prevent resource leaks and maintain system performance.

## Related Tools

- `flipper_connect` - Create new sessions
- `flipper_disconnect` - Close sessions
- `flipper_info` - Get device information

## Platform Support

- ✅ Windows (USB CDC)
- ✅ macOS (USB CDC)
- ✅ Linux (USB CDC)
- ✅ All platforms (BLE GATT)

## Requirements

- Flipper Zero integration enabled
- No active session required
- System session management available

## Session Management Tips

### Best Practices
- Monitor session count regularly
- Close unused sessions promptly
- Check session status before operations
- Handle session errors gracefully

### Troubleshooting
- Verify session IDs are valid
- Check device connection status
- Monitor session activity timestamps
- Clean up orphaned sessions
