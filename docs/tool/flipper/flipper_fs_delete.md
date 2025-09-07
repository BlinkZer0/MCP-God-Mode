# Flipper File System Delete Tool

## Overview

The `flipper_fs_delete` tool allows you to delete files from the Flipper Zero device's internal storage, providing a safe way to remove unwanted files and free up storage space.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `path` | string | Yes | File path to delete |

## Usage Examples

### Delete Single File
```javascript
// Delete a specific file
const result = await flipper_fs_delete({
  session_id: "session_12345",
  path: "/ext/nfc/old_card.nfc"
});
```

### Delete with Error Handling
```javascript
try {
  const result = await flipper_fs_delete({
    session_id: sessionId,
    path: "/ext/ir/unused_signal.ir"
  });
  
  if (result.success) {
    console.log("File deleted successfully");
    console.log("Freed space:", result.data.freedSpace, "bytes");
  }
} catch (error) {
  console.error("Failed to delete file:", error.message);
}
```

### Batch Delete with Validation
```javascript
// Delete multiple files with validation
const filesToDelete = [
  "/ext/nfc/temp1.nfc",
  "/ext/nfc/temp2.nfc",
  "/ext/ir/old_signal.ir"
];

for (const filePath of filesToDelete) {
  try {
    const result = await flipper_fs_delete({
      session_id: sessionId,
      path: filePath
    });
    
    if (result.success) {
      console.log(`Deleted: ${filePath}`);
    }
  } catch (error) {
    console.warn(`Failed to delete ${filePath}:`, error.message);
  }
}
```

## Response Format

```json
{
  "success": true,
  "data": {
    "path": "/ext/nfc/old_card.nfc",
    "deleted": true,
    "freedSpace": 1024,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

## File Types That Can Be Deleted

| File Type | Extension | Description |
|-----------|-----------|-------------|
| NFC | .nfc | NFC card dumps |
| IR | .ir | Infrared signal files |
| Sub-GHz | .sub | Sub-GHz signal files |
| RFID | .rfid | RFID card dumps |
| BadUSB | .txt | BadUSB script files |
| Text | .txt | Text files |
| JSON | .json | JSON data files |
| Custom | * | Any user-created files |

## Safety Features

### Protected Files
The tool will not delete:
- System files
- Core application files
- Firmware files
- Critical configuration files

### Confirmation
- Validates file existence before deletion
- Checks file permissions
- Provides detailed error messages

## Error Handling

The tool may return errors in the following scenarios:

- **File Not Found**: The specified file doesn't exist
- **Permission Denied**: Insufficient permissions to delete the file
- **Invalid Session**: Session ID doesn't exist or is expired
- **Protected File**: Attempting to delete a protected system file
- **Directory Not Empty**: Attempting to delete a non-empty directory
- **Device Error**: Hardware or communication error

## Best Practices

1. **File Validation**: Always verify the file exists before deletion
2. **Backup Important Files**: Backup important files before deletion
3. **Error Handling**: Implement proper error handling
4. **Batch Operations**: Use batch operations for multiple files
5. **Storage Management**: Regularly clean up temporary files
6. **Path Validation**: Use absolute paths for safety

## Security Considerations

- **File Protection**: System files are protected from deletion
- **Path Validation**: Validates file paths to prevent directory traversal
- **Session Security**: Requires valid session for access
- **Permission Checks**: Verifies delete permissions before operation

## Related Tools

- `flipper_fs_list` - List files in directory
- `flipper_fs_read` - Read files from device
- `flipper_fs_write` - Write files to device
- `flipper_info` - Get device storage information

## Troubleshooting

### Common Issues

1. **File Not Found**
   - Verify the file path is correct
   - Check if the file exists using `flipper_fs_list`
   - Ensure proper file permissions

2. **Permission Denied**
   - Check file permissions
   - Verify session permissions
   - Ensure the file is not protected

3. **Protected File**
   - Cannot delete system files
   - Use appropriate file paths
   - Check file type restrictions

4. **Session Errors**
   - Ensure the session is still active
   - Reconnect if necessary
   - Check device connection

## Storage Management

### Freeing Space
- Delete unused NFC dumps
- Remove old IR signals
- Clean up temporary files
- Remove duplicate files

### Storage Monitoring
- Check available space regularly
- Monitor file sizes
- Use `flipper_info` to check storage status

## Cross-Platform Notes

- **File System**: Works with Flipper Zero's internal file system
- **Path Format**: Uses Unix-style paths with forward slashes
- **Permissions**: Handles platform-specific permission systems
- **File Types**: Properly handles different file types across platforms

## Legal Compliance

This tool is designed for authorized security testing and educational purposes only. Users must comply with all applicable laws and regulations in their jurisdiction.
