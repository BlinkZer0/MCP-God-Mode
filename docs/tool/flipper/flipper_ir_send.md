# Flipper IR Send Tool

## Overview

The `flipper_ir_send` tool allows you to send infrared signals from files stored on the Flipper Zero device. This tool requires transmission permissions to be enabled in the environment configuration.

## ⚠️ Important Notice

**Transmission Operations**: This tool requires `MCPGM_FLIPPER_ALLOW_TX=true` in your environment configuration. Transmission operations are disabled by default for safety and legal compliance.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `file` | string | Yes | IR file path on Flipper Zero |

## Usage Examples

### Send IR Signal from File
```javascript
// Send an IR signal from a stored file
const result = await flipper_ir_send({
  session_id: "session_12345",
  file: "/ext/ir/tv_power.ir"
});
```

### Send with Error Handling
```javascript
try {
  const result = await flipper_ir_send({
    session_id: sessionId,
    file: "/ext/ir/air_conditioner.ir"
  });
  
  if (result.success) {
    console.log("IR signal sent successfully");
    console.log("Protocol:", result.data.protocol);
    console.log("Duration:", result.data.duration, "ms");
  }
} catch (error) {
  console.error("Failed to send IR signal:", error.message);
}
```

### Send Multiple Signals
```javascript
// Send multiple IR signals in sequence
const irFiles = [
  "/ext/ir/tv_power.ir",
  "/ext/ir/tv_volume_up.ir",
  "/ext/ir/tv_channel_up.ir"
];

for (const file of irFiles) {
  try {
    const result = await flipper_ir_send({
      session_id: sessionId,
      file: file
    });
    
    if (result.success) {
      console.log(`Sent: ${file}`);
      // Add delay between signals
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  } catch (error) {
    console.error(`Failed to send ${file}:`, error.message);
  }
}
```

## Response Format

```json
{
  "success": true,
  "data": {
    "file": "/ext/ir/tv_power.ir",
    "protocol": "NEC",
    "signal": "0x20DF10EF",
    "duration": 67,
    "transmitted": true,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

## Supported IR Protocols

| Protocol | Description | Common Use |
|----------|-------------|------------|
| NEC | Most common protocol | TVs, set-top boxes |
| RC5 | Philips protocol | Audio equipment |
| RC6 | Philips extended | Modern devices |
| Sony | Sony devices | TVs, audio |
| Samsung | Samsung devices | TVs, appliances |
| LG | LG devices | TVs, air conditioners |
| Panasonic | Panasonic devices | TVs, appliances |
| JVC | JVC devices | Audio equipment |

## IR File Format

IR files on the Flipper Zero are stored in a specific format:

```json
{
  "protocol": "NEC",
  "address": "0x20DF",
  "command": "0x10EF",
  "frequency": 38000,
  "duty_cycle": 0.33
}
```

## Error Handling

The tool may return errors in the following scenarios:

- **Transmission Disabled**: `MCPGM_FLIPPER_ALLOW_TX` is not set to true
- **File Not Found**: The specified IR file doesn't exist
- **Invalid File Format**: The IR file format is invalid
- **Invalid Session**: Session ID doesn't exist or is expired
- **Device Error**: Hardware or communication error
- **Protocol Error**: Unsupported IR protocol

## Best Practices

1. **File Validation**: Verify the IR file exists before sending
2. **Protocol Compatibility**: Ensure the protocol is supported
3. **Timing**: Add delays between multiple signals
4. **Error Handling**: Always implement proper error handling
5. **Testing**: Test signals in a safe environment first
6. **Documentation**: Keep track of what each IR file does

## Security Considerations

- **Transmission Control**: Requires explicit permission to enable
- **Legal Compliance**: Only use for authorized testing
- **Device Safety**: Ensure proper device operation
- **Signal Validation**: Validate signals before transmission

## Related Tools

- `flipper_ir_send_raw` - Send raw IR data
- `flipper_fs_list` - List IR files
- `flipper_fs_read` - Read IR file contents
- `flipper_fs_write` - Write IR files to device

## Troubleshooting

### Common Issues

1. **Transmission Disabled**
   - Set `MCPGM_FLIPPER_ALLOW_TX=true` in environment
   - Restart the application
   - Check configuration file

2. **File Not Found**
   - Verify the file path is correct
   - Check if the file exists using `flipper_fs_list`
   - Ensure proper file permissions

3. **Invalid Protocol**
   - Check IR file format
   - Verify protocol support
   - Use supported protocols only

4. **Device Not Responding**
   - Check device connection
   - Verify session is active
   - Restart device if necessary

## Legal Compliance

**IMPORTANT**: This tool is designed for authorized security testing and educational purposes only. Users must:

- Comply with all applicable laws and regulations
- Only use on devices they own or have explicit permission to test
- Not interfere with other people's devices
- Respect privacy and property rights

## Cross-Platform Notes

- **IR Hardware**: Works with Flipper Zero's built-in IR transmitter
- **File System**: Uses device's internal file system
- **Protocols**: Supports standard IR protocols across platforms
- **Timing**: Handles timing-sensitive IR transmission

## Safety Guidelines

1. **Authorized Use Only**: Only use on devices you own or have permission to test
2. **Safe Environment**: Test in a controlled environment
3. **Device Compatibility**: Ensure target devices can handle the signals
4. **Power Management**: Be aware of device battery usage
5. **Interference**: Avoid interfering with other devices
