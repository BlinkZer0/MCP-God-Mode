# Flipper File System Read Tool

## Overview

The `flipper_fs_read` tool allows you to read the contents of files stored on the Flipper Zero device's internal storage, supporting various file formats including NFC, IR, Sub-GHz, and text files.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `path` | string | Yes | File path to read |

## Usage Examples

### Read NFC File
```javascript
// Read an NFC card dump file
const result = await flipper_fs_read({
  session_id: "session_12345",
  path: "/ext/nfc/card.nfc"
});
```

### Read IR Signal File
```javascript
// Read an infrared signal file
const result = await flipper_fs_read({
  session_id: "session_12345",
  path: "/ext/ir/tv_power.ir"
});
```

### Read with Error Handling
```javascript
try {
  const result = await flipper_fs_read({
    session_id: sessionId,
    path: "/ext/subghz/signal.sub"
  });
  
  if (result.success) {
    console.log("File content:", result.data.content);
    console.log("File size:", result.data.size, "bytes");
    console.log("File type:", result.data.type);
  }
} catch (error) {
  console.error("Failed to read file:", error.message);
}
```

## Response Format

```json
{
  "success": true,
  "data": {
    "path": "/ext/nfc/card.nfc",
    "content": "File content as string or base64",
    "size": 1024,
    "type": "nfc",
    "format": "raw",
    "modified": "2024-01-15T10:30:00Z",
    "encoding": "utf8"
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

## Content Encoding

The tool automatically detects and handles different content encodings:

- **Text Files**: UTF-8 encoding
- **Binary Files**: Base64 encoding
- **JSON Files**: Parsed JSON objects
- **Signal Files**: Protocol-specific formats

## Error Handling

The tool may return errors in the following scenarios:

- **File Not Found**: The specified file doesn't exist
- **Permission Denied**: Insufficient permissions to read the file
- **Invalid Session**: Session ID doesn't exist or is expired
- **File Too Large**: File exceeds maximum read size
- **Corrupted File**: File is corrupted or unreadable

## Best Practices

1. **File Validation**: Check if the file exists before reading
2. **Size Limits**: Be aware of file size limits for large files
3. **Error Handling**: Always implement proper error handling
4. **Content Type**: Handle different content types appropriately
5. **Memory Management**: Consider memory usage for large files

## Security Considerations

- **File Access**: Only reads files, doesn't modify them
- **Path Validation**: Validates file paths to prevent directory traversal
- **Session Security**: Requires valid session for access
- **Content Sanitization**: Sanitizes file content in responses

## Related Tools

- `flipper_fs_list` - List files in directory
- `flipper_fs_write` - Write files to device
- `flipper_fs_delete` - Delete files from device
- `flipper_nfc_read` - Read NFC cards directly
- `flipper_ir_send` - Send IR signals from files

## Troubleshooting

### Common Issues

1. **File Not Found**
   - Verify the file path is correct
   - Check if the file exists using `flipper_fs_list`
   - Ensure proper file permissions

2. **Encoding Issues**
   - Check file encoding for text files
   - Verify binary file format
   - Handle different content types appropriately

3. **Large Files**
   - Consider file size before reading
   - Use streaming for very large files
   - Monitor memory usage

4. **Session Errors**
   - Ensure the session is still active
   - Reconnect if necessary
   - Check device connection

## Cross-Platform Notes

- **File System**: Works with Flipper Zero's internal file system
- **Path Format**: Uses Unix-style paths with forward slashes
- **Encoding**: Handles platform-specific encoding issues
- **Binary Files**: Properly handles binary data across platforms

## Legal Compliance

This tool is designed for authorized security testing and educational purposes only. Users must comply with all applicable laws and regulations in their jurisdiction.
