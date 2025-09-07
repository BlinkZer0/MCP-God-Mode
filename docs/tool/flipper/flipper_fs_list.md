# Flipper File System List Tool

## Overview

The `flipper_fs_list` tool allows you to list files and directories in the Flipper Zero device's internal storage, providing detailed information about the file system structure.

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | string | Yes | - | Session ID from flipper_connect |
| `path` | string | No | "/" | Directory path to list |

## Usage Examples

### List Root Directory
```javascript
// List files in the root directory
const result = await flipper_fs_list({
  session_id: "session_12345"
});
```

### List Specific Directory
```javascript
// List files in a specific directory
const result = await flipper_fs_list({
  session_id: "session_12345",
  path: "/ext/nfc"
});
```

### List with Error Handling
```javascript
try {
  const result = await flipper_fs_list({
    session_id: sessionId,
    path: "/ext/ir"
  });
  
  if (result.success) {
    console.log("Files found:", result.data.files.length);
    result.data.files.forEach(file => {
      console.log(`${file.type === 'directory' ? '📁' : '📄'} ${file.name}`);
    });
  }
} catch (error) {
  console.error("Failed to list files:", error.message);
}
```

## Response Format

```json
{
  "success": true,
  "data": {
    "path": "/ext/nfc",
    "files": [
      {
        "name": "card.nfc",
        "type": "file",
        "size": 1024,
        "modified": "2024-01-15T10:30:00Z"
      },
      {
        "name": "backup",
        "type": "directory",
        "size": 0,
        "modified": "2024-01-15T09:15:00Z"
      }
    ],
    "totalFiles": 1,
    "totalDirectories": 1,
    "totalSize": 1024
  }
}
```

## File Types

The tool can identify the following file types:

- **File**: Regular files (NFC, IR, Sub-GHz, etc.)
- **Directory**: Folders containing other files
- **System File**: Internal system files
- **Backup**: Backup files created by the device

## Common Directories

| Directory | Description |
|-----------|-------------|
| `/ext/nfc` | NFC card dumps and files |
| `/ext/ir` | Infrared signal files |
| `/ext/subghz` | Sub-GHz signal files |
| `/ext/badusb` | BadUSB script files |
| `/ext/rfid` | RFID card dumps |
| `/ext/bt` | Bluetooth related files |
| `/ext/apps` | Custom applications |
| `/ext/toolbox` | Toolbox files |

## Error Handling

The tool may return errors in the following scenarios:

- **Invalid Session**: Session ID doesn't exist or is expired
- **Path Not Found**: The specified directory doesn't exist
- **Permission Denied**: Insufficient permissions to access the directory
- **Device Error**: Hardware or communication error

## Best Practices

1. **Path Validation**: Always validate paths before listing
2. **Error Handling**: Implement proper error handling for file operations
3. **Large Directories**: Be aware that some directories may contain many files
4. **File Types**: Check file types before performing operations

## Security Considerations

- **File Access**: Only lists files, doesn't read content
- **Path Traversal**: Validates paths to prevent directory traversal
- **Session Security**: Requires valid session for access

## Related Tools

- `flipper_fs_read` - Read file contents
- `flipper_fs_write` - Write files to device
- `flipper_fs_delete` - Delete files from device
- `flipper_connect` - Establish device connection

## Troubleshooting

### Common Issues

1. **Empty Directory List**
   - Verify the path exists
   - Check if the directory is empty
   - Ensure proper permissions

2. **Path Not Found**
   - Use absolute paths starting with "/"
   - Check directory spelling
   - Verify the directory exists on the device

3. **Session Errors**
   - Ensure the session is still active
   - Reconnect if necessary
   - Check device connection

## Cross-Platform Notes

- **File System**: Works with Flipper Zero's internal file system
- **Path Format**: Uses Unix-style paths with forward slashes
- **Case Sensitivity**: File names are case-sensitive

## Legal Compliance

This tool is designed for authorized security testing and educational purposes only. Users must comply with all applicable laws and regulations in their jurisdiction.
