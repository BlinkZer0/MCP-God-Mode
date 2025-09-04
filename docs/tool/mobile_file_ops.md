# Mobile File Operations Tool

## Overview
Advanced mobile file operations with comprehensive Android and iOS support. Perform file management, data transfer, compression, and search operations on mobile devices. Supports both rooted/jailbroken and standard devices with appropriate permission handling.

## Description
Advanced mobile file operations with comprehensive Android and iOS support. Perform file management, data transfer, compression, and search operations on mobile devices. Supports both rooted/jailbroken and standard devices with appropriate permission handling.

## Input Schema
- **action** (required): File operation to perform. 'list' shows directory contents, 'copy'/'move' transfer files, 'delete' removes files/folders, 'create' makes new files/directories, 'get_info' provides file details, 'search' finds files by pattern/content, 'compress'/'decompress' handle archives.
- **source** (required): Source file or directory path for operations. Examples: '/sdcard/Documents/', '/var/mobile/Documents/', './photos/', 'C:\\Users\\Mobile\\Downloads\\'.
- **destination** (optional): Destination path for copy/move operations. Examples: '/sdcard/backup/', '/var/mobile/backup/', './backup/'. Should include filename for file operations.
- **content** (optional): Content to write when creating files. Can be text, JSON, XML, or binary data. Examples: 'Hello World', '{"config": "value"}', '<xml>data</xml>'.
- **recursive** (optional): Perform operation recursively on directories. Set to true for directory operations, false for single files. Required for copying/deleting folders.
- **pattern** (optional): Search pattern for file operations. Supports wildcards and regex. Examples: '*.jpg' for images, '*.log' for logs, 'backup*' for files starting with backup.
- **search_text** (optional): Text content to search for within files. Examples: 'password', 'API_KEY', 'error', 'TODO'. Used with search action to find files containing specific text.

## Output Schema
Returns operation results with success status, file information, and operation details.

## Natural Language Access
Users can request mobile file operations using natural language:
- "List files on my Android device"
- "Copy photos from my iPhone to backup folder"
- "Search for documents containing 'project' on my mobile device"
- "Create a new folder on my Android phone"
- "Compress my mobile photos into a zip file"
- "Delete old log files from my mobile device"

## Usage Examples

### List Directory Contents
```javascript
// List files in mobile documents folder
const result = await mobile_file_ops({
  action: "list",
  source: "/sdcard/Documents/",
  recursive: false
});
```

### Copy Files
```javascript
// Copy photos to backup folder
const result = await mobile_file_ops({
  action: "copy",
  source: "/sdcard/DCIM/Camera/",
  destination: "/sdcard/backup/photos/",
  recursive: true
});
```

### Search Files
```javascript
// Search for documents containing specific text
const result = await mobile_file_ops({
  action: "search",
  source: "/sdcard/Documents/",
  search_text: "project",
  pattern: "*.txt"
});
```

### Create Files
```javascript
// Create a new configuration file
const result = await mobile_file_ops({
  action: "create",
  source: "/sdcard/config/settings.json",
  content: '{"theme": "dark", "notifications": true}'
});
```

## Platform Support
- **Android**: Full support with ADB, Termux, and system commands
- **iOS**: Limited support through Files app and system APIs
- **Windows**: Android emulator and device support
- **Linux**: Full Android and iOS device support
- **macOS**: Full iOS device support, Android via ADB

## Security Features
- Permission validation for file operations
- Sandboxed file access on iOS
- Root privilege escalation when needed
- Secure file transfer protocols
- Content validation and sanitization

## Error Handling
- Permission denied errors with guidance
- File not found with recovery suggestions
- Insufficient storage space detection
- Network connectivity issues for cloud operations
- Device compatibility warnings

## Related Tools
- `mobile_device_info` - Get device information and capabilities
- `mobile_system_tools` - System-level mobile operations
- `mobile_hardware` - Hardware access and sensor data
- `file_ops` - Desktop file operations
- `fs_list` - Basic file listing

## Use Cases
- **Data Backup**: Transfer files between mobile devices and computers
- **File Management**: Organize and manage mobile file systems
- **Content Search**: Find specific files or content on mobile devices
- **Data Recovery**: Recover deleted or corrupted files
- **Storage Optimization**: Compress and organize mobile storage
- **Cross-Platform Sync**: Synchronize files between different mobile platforms
