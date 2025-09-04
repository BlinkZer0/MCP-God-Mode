# File System List Tool

## Overview
The `fs_list` tool provides a simple way to list files and directories under a specified path. It's designed to be cross-platform and works within the sandboxed environment.

## Tool Name
`fs_list`

## Description
List files/directories under a relative path (non-recursive)

## Input Schema
- `dir` (string, optional): The directory path to list files and folders from. Examples: '.', './documents', '/home/user/pictures', 'C:\\Users\\User\\Desktop'. Use '.' for current directory. Default: "."

## Output Schema
- `entries` (array): Array of file/directory objects containing:
  - `name` (string): Name of the file or directory
  - `isDir` (boolean): Whether the entry is a directory

## Natural Language Access
Users can ask for this tool using natural language such as:
- "List files in the current directory"
- "Show me what's in the documents folder"
- "List contents of the downloads directory"
- "What files are in this folder?"
- "Show directory contents"

## Examples

### Basic Usage
```typescript
// List current directory
const result = await server.callTool("fs_list", { dir: "." });

// List specific directory
const result = await server.callTool("fs_list", { dir: "./src" });
```

### Example Output
```json
{
  "entries": [
    { "name": "file1.txt", "isDir": false },
    { "name": "folder1", "isDir": true },
    { "name": "README.md", "isDir": false }
  ]
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
- No recursive directory traversal (prevents deep scanning)

## Error Handling
- Returns empty array if directory doesn't exist
- Handles permission errors gracefully
- Validates path boundaries

## Related Tools
- `fs_read_text` - Read file contents
- `fs_write_text` - Write to files
- `fs_search` - Search for files by pattern
- `file_ops` - Advanced file operations

## Use Cases
- Directory exploration
- File inventory
- Path validation
- Basic file system navigation
- Project structure inspection
