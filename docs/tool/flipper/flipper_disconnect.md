# Flipper Disconnect Tool

## Overview

The `flipper_disconnect` tool allows you to properly close a connection to a Flipper Zero device and clean up the session resources.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |

## Usage Examples

### Basic Disconnect
```javascript
// Disconnect from a Flipper Zero device
const result = await flipper_disconnect({
  session_id: "session_12345"
});
```

### Disconnect with Error Handling
```javascript
try {
  const result = await flipper_disconnect({
    session_id: sessionId
  });
  
  if (result.success) {
    console.log("Successfully disconnected from Flipper Zero");
  }
} catch (error) {
  console.error("Failed to disconnect:", error.message);
}
```

## Response Format

```json
{
  "success": true,
  "data": {
    "sessionId": "session_12345",
    "closed": true,
    "cleanup": "completed"
  }
}
```

## Error Handling

The tool may return errors in the following scenarios:

- **Invalid Session ID**: The provided session ID doesn't exist
- **Connection Error**: Unable to properly close the connection
- **Cleanup Failure**: Session cleanup failed

## Best Practices

1. **Always Disconnect**: Always call disconnect when done with a session
2. **Error Handling**: Wrap disconnect calls in try-catch blocks
3. **Session Management**: Keep track of active sessions to avoid resource leaks
4. **Timeout Handling**: Set appropriate timeouts for disconnect operations

## Security Considerations

- **Session Cleanup**: Ensures all session data is properly cleared
- **Resource Management**: Prevents resource leaks from abandoned sessions
- **Connection Security**: Properly closes secure connections

## Related Tools

- `flipper_connect` - Establish connection to device
- `flipper_list_sessions` - List active sessions
- `flipper_info` - Get device information

## Troubleshooting

### Common Issues

1. **Session Not Found**
   - Verify the session ID is correct
   - Check if the session was already closed

2. **Connection Timeout**
   - Ensure the device is still connected
   - Try increasing the timeout value

3. **Cleanup Errors**
   - Check device status
   - Verify no other processes are using the connection

## Cross-Platform Notes

- **Windows**: Uses COM port cleanup
- **macOS**: Handles USB CDC cleanup
- **Linux**: Manages serial port resources

## Legal Compliance

This tool is designed for authorized security testing and educational purposes only. Users must comply with all applicable laws and regulations in their jurisdiction.
