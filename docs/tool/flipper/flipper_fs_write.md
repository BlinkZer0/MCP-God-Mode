# Flipper File System Write Tool

## Overview

The `flipper_fs_write` tool allows you to write data to files on the Flipper Zero device's internal storage, supporting various file formats including NFC, IR, Sub-GHz, and text files.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `path` | string | Yes | File path to write |
| `content` | string | Yes | File content to write |

## Usage Examples

### Write NFC File
```javascript
// Write an NFC card dump file
const result = await flipper_fs_write({
  session_id: "session_12345",
  path: "/ext/nfc/card.nfc",
  content: "NFC card data content"
});
```

### Write IR Signal File
```javascript
// Write an infrared signal file
const result = await flipper_fs_write({
  session_id: "session_12345",
  path: "/ext/ir/tv_power.ir",
  content: JSON.stringify({
    protocol: "NEC",
    data: "0x20DF10EF"
  })
});
```

### Write with Error Handling
```javascript
try {
  const result = await flipper_fs_write({
    session_id: sessionId,
    path: "/ext/subghz/signal.sub",
    content: "Sub-GHz signal data"
  });
  
  if (result.success) {
    console.log("File written successfully");
    console.log("File size:", result.data.size, "bytes");
    console.log("File path:", result.data.path);
  }
} catch (error) {
  console.error("Failed to write file:", error.message);
}
```

## Response Format

```json
{
  "success": true,
  "data": {
    "path": "/ext/nfc/card.nfc",
    "size": 1024,
    "written": true,
    "modified": "2024-01-15T10:30:00Z"
  }
}
```

## Supported File Types

| File Type | Extension | Description | Content Format |
|-----------|-----------|-------------|----------------|
| NFC | .nfc | NFC card dumps | Binary/Base64 |
| IR | .ir | Infrared signals | Text/JSON |
| Sub-GHz | .sub | Sub-GHz signals | Binary/Base64 |
| RFID | .rfid | RFID card dumps | Binary/Base64 |
| BadUSB | .txt | BadUSB scripts | Text |
| Text | .txt | Text files | UTF-8 text |
| JSON | .json | JSON data | JSON format |

## Content Handling

The tool automatically handles different content types:

- **Text Content**: UTF-8 encoding
- **Binary Content**: Base64 decoding
- **JSON Content**: Validation and formatting
- **Signal Data**: Protocol-specific formatting

## File Path Guidelines

### Recommended Paths
- `/ext/nfc/` - NFC card files
- `/ext/ir/` - Infrared signal files
- `/ext/subghz/` - Sub-GHz signal files
- `/ext/badusb/` - BadUSB script files
- `/ext/rfid/` - RFID card files
- `/ext/bt/` - Bluetooth files
- `/ext/apps/` - Custom applications

### File Naming
- Use descriptive names
- Avoid special characters
- Keep names under 64 characters
- Use appropriate file extensions

## Error Handling

The tool may return errors in the following scenarios:

- **Invalid Path**: The specified path is invalid
- **Permission Denied**: Insufficient permissions to write the file
- **Invalid Session**: Session ID doesn't exist or is expired
- **Storage Full**: Device storage is full
- **Invalid Content**: Content format is invalid for the file type
- **Path Too Long**: File path exceeds maximum length

## Best Practices

1. **Path Validation**: Use proper directory paths
2. **Content Validation**: Validate content before writing
3. **Error Handling**: Always implement proper error handling
4. **File Size**: Be aware of storage limitations
5. **Backup**: Consider backing up important files
6. **Permissions**: Ensure proper file permissions

## Security Considerations

- **File Overwrite**: Existing files will be overwritten
- **Path Validation**: Validates file paths to prevent directory traversal
- **Session Security**: Requires valid session for access
- **Content Sanitization**: Sanitizes file content before writing

## Related Tools

- `flipper_fs_list` - List files in directory
- `flipper_fs_read` - Read files from device
- `flipper_fs_delete` - Delete files from device
- `flipper_nfc_dump` - Dump NFC cards to files
- `flipper_ir_send` - Send IR signals from files

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Check file path permissions
   - Ensure proper directory structure
   - Verify session permissions

2. **Storage Full**
   - Check available storage space
   - Delete unnecessary files
   - Use smaller file sizes

3. **Invalid Content**
   - Validate content format
   - Check file type compatibility
   - Ensure proper encoding

4. **Path Errors**
   - Use absolute paths starting with "/"
   - Check directory existence
   - Verify path format

## Cross-Platform Notes

- **File System**: Works with Flipper Zero's internal file system
- **Path Format**: Uses Unix-style paths with forward slashes
- **Encoding**: Handles platform-specific encoding issues
- **Binary Files**: Properly handles binary data across platforms

## Legal Compliance

This tool is designed for authorized security testing and educational purposes only. Users must comply with all applicable laws and regulations in their jurisdiction.
