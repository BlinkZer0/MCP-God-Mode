# 📁 File Operations Tool - MCP God Mode

## Overview
The **File Operations Tool** (`mcp_mcp-god-mode_file_ops`) is a comprehensive file system management utility that provides cross-platform file operations across Windows, Linux, macOS, Android, and iOS platforms. It supports file copying, moving, deletion, creation, compression, permissions management, and professional file system operations with comprehensive security features and monitoring capabilities.

## Functionality
- **File Management**: Copy, move, delete, and create files and directories
- **Directory Operations**: Directory creation, listing, and management
- **Compression Support**: File compression and decompression
- **Permissions Management**: File and directory permission control
- **Cross-Platform Support**: Native implementation across all supported operating systems
- **Advanced Features**: File watching, hard linking, and advanced file operations

## Technical Details

### Tool Identifier
- **MCP Tool Name**: `mcp_mcp-god-mode_file_ops`
- **Category**: File System & Management
- **Platform Support**: Windows, Linux, macOS, Android, iOS
- **Elevated Permissions**: Required for system-level file operations

### Input Parameters
```typescript
{
  action: "copy" | "move" | "delete" | "create_dir" | "create_file" | "get_info" | "list_recursive" | "find_by_content" | "compress" | "decompress" | "chmod" | "chown" | "symlink" | "hardlink" | "watch" | "unwatch" | "get_size" | "get_permissions" | "set_permissions" | "compare_files",
  source: string,           // Source file or directory path
  destination?: string,     // Destination path for operations
  content?: string,         // Content to write when creating files
  recursive?: boolean,      // Whether to perform operation recursively
  overwrite?: boolean,      // Whether to overwrite existing files
  permissions?: string,     // Unix-style file permissions
  owner?: string,           // Username to set as owner
  group?: string,           // Group name to set
  pattern?: string,         // File pattern for search operations
  search_text?: string,     // Text content to search for
  compression_type?: "zip" | "tar" | "gzip" | "bzip2" // Compression format
}
```

### Output Response
```typescript
{
  action: string,           // Action performed
  source: string,           // Source path used
  destination?: string,     // Destination path used
  status: "success" | "error" | "partial",
  timestamp: string,        // Operation timestamp
  results?: {
    // File Operation Results
    files_processed?: number,    // Number of files processed
    directories_processed?: number, // Number of directories processed
    total_size?: number,         // Total size of processed items
    operation_time?: number,     // Operation duration in milliseconds
    
    // File Information Results
    file_info?: {
      name: string,              // File name
      path: string,              // Full file path
      size: number,              // File size in bytes
      type: string,              // File type
      permissions: string,       // File permissions
      owner: string,             // File owner
      group: string,             // File group
      created: string,           // Creation timestamp
      modified: string,          // Last modified timestamp
      accessed: string           // Last accessed timestamp
    },
    
    // Directory Listing Results
    directory_listing?: Array<{
      name: string,              // Item name
      type: "file" | "directory" | "symlink",
      size: number,              // Size in bytes
      permissions: string,       // Permissions
      owner: string,             // Owner
      group: string,             // Group
      modified: string           // Last modified
    }>,
    
    // Search Results
    search_results?: Array<{
      file_path: string,         // File path
      line_number: number,       // Line number where text found
      context: string,           // Context around found text
      match_count: number        // Number of matches in file
    }>,
    
    // Compression Results
    compression?: {
      original_size: number,     // Original size
      compressed_size: number,   // Compressed size
      compression_ratio: number, // Compression ratio
      format: string             // Compression format used
    }
  },
  error?: string,            // Error message if operation failed
  warnings?: string[],       // Warning messages
  execution_time?: number    // Total execution time in milliseconds
}
```


## Natural Language Access
Users can request file ops operations using natural language:
- "Manage files and folders"
- "Copy or move files"
- "Organize file system"
- "Backup files"
- "Sync file operations"
## Usage Examples

### Basic File Copy
```typescript
const copyResult = await file_ops({
  action: "copy",
  source: "./source.txt",
  destination: "./backup/source.txt",
  overwrite: true
});

if (copyResult.status === "success") {
  console.log(`File copied successfully`);
  console.log(`Files processed: ${copyResult.results?.files_processed}`);
  console.log(`Operation time: ${copyResult.results?.operation_time}ms`);
}
```

### Directory Creation and File Writing
```typescript
const createResult = await file_ops({
  action: "create_dir",
  source: "./new_project",
  recursive: true
});

if (createResult.status === "success") {
  const fileResult = await file_ops({
    action: "create_file",
    source: "./new_project/README.md",
    content: "# New Project\n\nThis is a new project created with MCP God Mode."
  });
  
  if (fileResult.status === "success") {
    console.log("Project directory and README created successfully");
  }
}
```

### Recursive Directory Operations
```typescript
const recursiveResult = await file_ops({
  action: "list_recursive",
  source: "./documents",
  pattern: "*.md"
});

if (recursiveResult.status === "success" && recursiveResult.results?.directory_listing) {
  console.log("Markdown files found:");
  recursiveResult.results.directory_listing.forEach(item => {
    if (item.type === "file") {
      console.log(`- ${item.name} (${item.size} bytes)`);
    }
  });
}
```

### File Compression
```typescript
const compressResult = await file_ops({
  action: "compress",
  source: "./large_folder",
  destination: "./archive.zip",
  compression_type: "zip",
  recursive: true
});

if (compressResult.status === "success") {
  const compression = compressResult.results?.compression;
  if (compression) {
    const ratio = ((compression.original_size - compression.compressed_size) / compression.original_size * 100).toFixed(2);
    console.log(`Compression completed: ${ratio}% size reduction`);
    console.log(`Original: ${compression.original_size} bytes`);
    console.log(`Compressed: ${compression.compressed_size} bytes`);
  }
}
```

### File Search by Content
```typescript
const searchResult = await file_ops({
  action: "find_by_content",
  source: "./code",
  search_text: "TODO",
  pattern: "*.js",
  recursive: true
});

if (searchResult.status === "success" && searchResult.results?.search_results) {
  console.log("TODO items found:");
  searchResult.results.search_results.forEach(result => {
    console.log(`${result.file_path}:${result.line_number} - ${result.context.trim()}`);
  });
}
```

## Integration Points

### Server Integration
- **Full Server**: ✅ Included
- **Modular Server**: ❌ Not included
- **Minimal Server**: ✅ Included
- **Ultra-Minimal Server**: ✅ Included

### Dependencies
- Native file system libraries
- Compression and decompression libraries
- Permission management libraries
- File watching and monitoring tools

## Platform-Specific Features

### Windows
- **NTFS Support**: NTFS file system optimization
- **Windows Security**: Windows security framework integration
- **File Permissions**: Windows file permission management
- **Volume Management**: Windows volume management

### Linux
- **Unix File System**: Native Unix file system support
- **Permission System**: Unix permission system integration
- **Symbolic Links**: Unix symbolic link support
- **File Watching**: inotify and fanotify support

### macOS
- **APFS Support**: APFS file system optimization
- **macOS Security**: macOS security framework integration
- **File Permissions**: macOS file permission management
- **Keychain Integration**: macOS keychain integration

### Mobile Platforms
- **Mobile Storage**: Mobile storage optimization
- **Permission Management**: Mobile permission handling
- **File Access**: Mobile file access APIs
- **Security Context**: Mobile security context

## File Operation Features

### Basic Operations
- **File Copy**: File copying with overwrite options
- **File Move**: File moving and renaming
- **File Delete**: File deletion with safety checks
- **Directory Creation**: Directory creation and management

### Advanced Operations
- **Recursive Operations**: Recursive file and directory operations
- **Pattern Matching**: File pattern matching and filtering
- **Content Search**: Text content search within files
- **File Comparison**: File content comparison and analysis

### Compression Support
- **ZIP Compression**: ZIP archive creation and extraction
- **TAR Archives**: TAR archive support
- **Gzip Compression**: Gzip compression and decompression
- **Bzip2 Compression**: Bzip2 compression and decompression

## Security Features

### File Security
- **Permission Management**: File and directory permission control
- **Ownership Control**: File ownership management
- **Access Control**: File access control and validation
- **Security Validation**: File security validation

### Operation Security
- **Overwrite Protection**: File overwrite protection
- **Recursive Safety**: Safe recursive operation handling
- **Path Validation**: File path validation and security
- **Audit Logging**: File operation audit logging

## Error Handling

### Common Issues
- **Permission Denied**: Insufficient file permissions
- **File Not Found**: Source file or directory not found
- **Disk Space**: Insufficient disk space
- **File Locking**: File locking and access issues

### Recovery Actions
- Automatic retry mechanisms
- Alternative operation methods
- Fallback file operations
- Comprehensive error reporting

## Performance Characteristics

### Operation Speed
- **Small Files (< 1MB)**: < 100ms
- **Medium Files (1-100MB)**: 100ms - 10 seconds
- **Large Files (100MB-1GB)**: 10 seconds - 5 minutes
- **Very Large Files (> 1GB)**: 5+ minutes

### Resource Usage
- **CPU**: Low to moderate (5-40% during operations)
- **Memory**: Variable (10-500MB based on file size)
- **Network**: Variable (for network file operations)
- **Disk**: High during file operations

## Monitoring and Logging

### Operation Monitoring
- **Progress Tracking**: File operation progress tracking
- **Performance Metrics**: Operation performance tracking
- **Error Analysis**: Operation error analysis
- **Success Tracking**: Successful operation tracking

### File System Monitoring
- **File Changes**: File change monitoring
- **Directory Changes**: Directory change monitoring
- **Permission Changes**: Permission change monitoring
- **Security Events**: File security event monitoring

## Troubleshooting

### Operation Issues
1. Verify file permissions
2. Check available disk space
3. Review file paths
4. Confirm operation parameters

### Performance Issues
1. Monitor system resources
2. Optimize operation parameters
3. Use appropriate compression
4. Monitor file system performance

## Best Practices

### Implementation
- Use appropriate permission levels
- Implement proper error handling
- Validate file paths
- Monitor operation performance

### Security
- Minimize elevated privilege usage
- Validate file sources
- Implement access controls
- Monitor for suspicious activity

## Related Tools
- **File Operations**: File management and operations
- **System Info**: System information and monitoring
- **Process Management**: Process and service management
- **Network Tools**: Network connectivity and management

## Version History
- **v1.0**: Initial implementation
- **v1.1**: Enhanced file operations
- **v1.2**: Advanced security features
- **v1.3**: Cross-platform improvements
- **v1.4a**: Professional file management features

---

**⚠️ IMPORTANT: File operations can affect system stability and data integrity. Always verify operations and use appropriate permission levels.**

*This document is part of MCP God Mode v1.4a - Advanced AI Agent Toolkit*
