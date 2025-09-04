# File System Read Text Tool

## Overview
The `fs_read_text` tool allows you to read the contents of UTF-8 text files within the sandboxed environment. It's designed to be cross-platform and includes safety features to prevent excessive memory usage.

## Tool Name
`fs_read_text`

## Description
Read a UTF-8 text file within the sandbox

## Input Schema
- `path` (string, required): The file path to read from. Can be relative or absolute path. Examples: './config.txt', '/home/user/documents/readme.md', 'C:\\Users\\User\\Desktop\\notes.txt'.

## Output Schema
- `path` (string): The full path of the file that was read
- `content` (string): The file contents (may be truncated if file is very large)
- `truncated` (boolean): Whether the content was truncated due to size limits

## Natural Language Access
Users can ask for this tool using natural language such as:
- "Read the contents of config.txt"
- "Show me what's in the README file"
- "Read the log file"
- "What does the configuration file contain?"
- "Display the contents of the text file"

## Examples

### Basic Usage
```typescript
// Read a specific file
const result = await server.callTool("fs_read_text", { 
  path: "./config.json" 
});

// Read with absolute path
const result = await server.callTool("fs_read_text", { 
  path: "/home/user/documents/notes.txt" 
});
```

### Example Output
```json
{
  "path": "/home/user/documents/notes.txt",
  "content": "This is the content of the file...",
  "truncated": false
}
```

## Platform Support
- ✅ Windows
- ✅ Linux
- ✅ macOS
- ✅ Android
- ✅ iOS

## Security Features
- Path validation to ensure operations stay within allowed roots
- Sandboxed file system access
- Content size limits to prevent memory issues
- UTF-8 encoding validation

## File Size Limits
- Files are automatically truncated if they exceed the maximum allowed size
- The `truncated` flag indicates if content was cut off
- Designed to handle both small and large text files safely

## Error Handling
- Returns error if file doesn't exist
- Handles permission errors gracefully
- Validates file encoding
- Provides clear error messages for common issues

## Supported File Types
- Plain text files (.txt, .md, .log, etc.)
- Configuration files (.json, .yaml, .ini, etc.)
- Source code files (.js, .ts, .py, .java, etc.)
- Documentation files (.md, .rst, .txt, etc.)

## Related Tools
- `fs_write_text` - Write to text files
- `fs_list` - List files in directories
- `fs_search` - Search for files by pattern
- `file_ops` - Advanced file operations

## Use Cases
- Reading configuration files
- Viewing log files
- Reading documentation
- Inspecting source code
- Reading data files
- Viewing text-based reports
