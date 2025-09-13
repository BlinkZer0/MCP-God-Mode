# File System Tool

## Overview
The **File System Tool** is a comprehensive file system management utility that provides advanced directory listing, file operations, and path validation capabilities with cross-platform support.

## Features
- **Directory Listing**: Advanced directory enumeration with metadata
- **File Operations**: Comprehensive file system operations
- **Path Validation**: Secure path validation and sanitization
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Metadata Extraction**: File and directory metadata extraction
- **Security**: Path traversal protection and security checks
- **Performance**: Optimized for large directory structures

## Usage

### Directory Listing
```bash
# List current directory
{
  "action": "list",
  "path": "."
}

# List specific directory
{
  "action": "list",
  "path": "./documents"
}

# List with detailed information
{
  "action": "list",
  "path": "./src",
  "detailed": true
}
```

### File Operations
```bash
# Read file
{
  "action": "read",
  "path": "./config.txt"
}

# Write file
{
  "action": "write",
  "path": "./output.txt",
  "content": "Hello, World!"
}

# Delete file
{
  "action": "delete",
  "path": "./temp.txt"
}

# Copy file
{
  "action": "copy",
  "source": "./source.txt",
  "destination": "./destination.txt"
}

# Move file
{
  "action": "move",
  "source": "./old_name.txt",
  "destination": "./new_name.txt"
}
```

### Directory Operations
```bash
# Create directory
{
  "action": "create_dir",
  "path": "./new_directory"
}

# Delete directory
{
  "action": "delete",
  "path": "./old_directory",
  "recursive": true
}

# Copy directory
{
  "action": "copy",
  "source": "./source_dir",
  "destination": "./destination_dir",
  "recursive": true
}
```

## Parameters

### Common Parameters
- **action**: File system operation to perform
- **path**: File or directory path
- **source**: Source path for copy/move operations
- **destination**: Destination path for copy/move operations

### File Parameters
- **content**: Content to write to file
- **recursive**: Perform operation recursively for directories

### Directory Parameters
- **detailed**: Get detailed information about files and directories

## Output Format
```json
{
  "success": true,
  "action": "list",
  "result": {
    "path": "./documents",
    "files": [
      {
        "name": "document1.txt",
        "type": "file",
        "size": 1024,
        "modified": "2025-01-15T10:30:00Z",
        "permissions": "rw-r--r--"
      }
    ],
    "directories": [
      {
        "name": "subdirectory",
        "type": "directory",
        "modified": "2025-01-15T10:30:00Z",
        "permissions": "rwxr-xr-x"
      }
    ],
    "total_files": 1,
    "total_directories": 1
  }
}
```

## Error Handling
- **Path Errors**: Clear error messages for invalid paths
- **Permission Errors**: Proper handling of permission issues
- **File Errors**: Robust error handling for file operations
- **Directory Errors**: Safe handling of directory operations

## Cross-Platform Support
- **Windows**: Full support with Windows-style paths
- **Linux**: Complete functionality with Unix-style paths
- **macOS**: Full feature support with macOS integration
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Directory Listing
```bash
# List directory
{
  "action": "list",
  "path": "./src"
}

# Result
{
  "success": true,
  "result": {
    "path": "./src",
    "files": [
      {
        "name": "main.js",
        "type": "file",
        "size": 2048
      }
    ],
    "total_files": 1
  }
}
```

### Example 2: File Operations
```bash
# Write file
{
  "action": "write",
  "path": "./config.txt",
  "content": "debug=true\nport=3000"
}

# Result
{
  "success": true,
  "result": {
    "path": "./config.txt",
    "size": 20,
    "status": "created"
  }
}
```

### Example 3: Directory Operations
```bash
# Create directory
{
  "action": "create_dir",
  "path": "./new_project"
}

# Result
{
  "success": true,
  "result": {
    "path": "./new_project",
    "status": "created"
  }
}
```

## Security Features
- **Path Validation**: Ensures paths are valid and secure
- **Traversal Protection**: Prevents directory traversal attacks
- **Permission Checks**: Validates file and directory permissions
- **Input Sanitization**: Sanitizes input paths and content

## Related Tools
- **File Operations**: Other file system tools
- **Download File**: File download tools
- **Text Processing**: Text file processing tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the File System Tool, please refer to the main MCP God Mode documentation or contact the development team.
