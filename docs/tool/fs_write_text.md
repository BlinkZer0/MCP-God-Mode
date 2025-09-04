# File System Write Text Tool

## Overview
The `fs_write_text` tool allows you to write text content to files within the sandboxed environment. It's designed to be cross-platform and includes safety features to ensure secure file operations.

## Tool Name
`fs_write_text`

## Description
Write a UTF-8 text file within the sandbox

## Input Schema
- `path` (string, required): The file path to write to. Can be relative or absolute path. Examples: './output.txt', '/home/user/documents/log.txt', 'C:\\Users\\User\\Desktop\\data.txt'.
- `content` (string, required): The text content to write to the file. Can be plain text, JSON, XML, or any text-based format. Examples: 'Hello World', '{"key": "value"}', '<xml>data</xml>'.

## Output Schema
- `path` (string): The full path of the file that was written
- `success` (boolean): Whether the write operation was successful

## Natural Language Access
Users can ask for this tool using natural language such as:
- "Write 'Hello World' to output.txt"
- "Create a log file with this content"
- "Save this data to a text file"
- "Write the configuration to config.json"
- "Create a new file with this text"

## Examples

### Basic Usage
```typescript
// Write simple text
const result = await server.callTool("fs_write_text", { 
  path: "./hello.txt", 
  content: "Hello, World!" 
});

// Write JSON content
const result = await server.callTool("fs_write_text", { 
  path: "./config.json", 
  content: '{"name": "test", "enabled": true}' 
});

// Write with absolute path
const result = await server.callTool("fs_write_text", { 
  path: "/home/user/documents/notes.txt", 
  content: "Important notes here..." 
});
```

### Example Output
```json
{
  "path": "/home/user/documents/notes.txt",
  "success": true
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
- Automatic directory creation if needed
- UTF-8 encoding enforcement

## File Operations
- Creates new files if they don't exist
- Overwrites existing files completely
- Automatically creates parent directories if needed
- Ensures proper file permissions

## Error Handling
- Returns error if path is invalid
- Handles permission errors gracefully
- Validates content encoding
- Provides clear error messages for common issues

## Supported Content Types
- Plain text
- JSON data
- XML markup
- Configuration files
- Log entries
- Source code
- Documentation
- Data exports

## Related Tools
- `fs_read_text` - Read file contents
- `fs_list` - List files in directories
- `fs_search` - Search for files by pattern
- `file_ops` - Advanced file operations

## Use Cases
- Creating log files
- Writing configuration files
- Saving data exports
- Creating documentation
- Writing scripts
- Generating reports
- Saving user input
- Creating temporary files

## Best Practices
- Always validate file paths before writing
- Use appropriate file extensions for content type
- Consider file permissions and security
- Handle large content appropriately
- Use relative paths when possible
