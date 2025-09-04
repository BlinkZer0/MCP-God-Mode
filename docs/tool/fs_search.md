# File System Search Tool

## Overview
The `fs_search` tool allows you to search for files by name pattern within the sandboxed environment. It supports glob patterns and provides efficient file discovery capabilities across all platforms.

## Tool Name
`fs_search`

## Description
Search for files by name pattern

## Input Schema
- `pattern` (string, required): The file name pattern to search for. Supports glob patterns and partial matches. Examples: '*.txt', 'config*', '*.js', 'README*', '*.{json,yaml}'.
- `dir` (string, optional): The directory to search in. Examples: '.', './src', '/home/user/documents', 'C:\\Users\\User\\Projects'. Use '.' for current directory. Default: "."

## Output Schema
- `matches` (array): Array of file paths that match the search pattern

## Natural Language Access
Users can ask for this tool using natural language such as:
- "Find all text files in the current directory"
- "Search for configuration files"
- "Find JavaScript files in the src folder"
- "Look for files starting with 'config'"
- "Find all image files"
- "Search for documentation files"

## Examples

### Basic Usage
```typescript
// Search for all text files
const result = await server.callTool("fs_search", { 
  pattern: "*.txt" 
});

// Search for configuration files in specific directory
const result = await server.callTool("fs_search", { 
  pattern: "*.{json,yaml,ini}", 
  dir: "./config" 
});

// Search for files starting with specific prefix
const result = await server.callTool("fs_search", { 
  pattern: "config*", 
  dir: "/home/user/project" 
});
```

### Example Output
```json
{
  "matches": [
    "/home/user/project/config.json",
    "/home/user/project/config.yaml",
    "/home/user/project/config.ini"
  ]
}
```

## Platform Support
- ✅ Windows
- ✅ Linux
- ✅ macOS
- ✅ Android
- ✅ iOS

## Search Patterns
- `*` - Matches any sequence of characters
- `?` - Matches any single character
- `[abc]` - Matches any character in the set
- `*.{ext1,ext2}` - Matches multiple extensions
- `file*` - Matches files starting with "file"
- `*config*` - Matches files containing "config"

## Performance Features
- Uses ripgrep when available for fast searching
- Falls back to native file system operations
- Efficient pattern matching algorithms
- Optimized for large directory structures

## Security Features
- Path validation to ensure operations stay within allowed roots
- Sandboxed file system access
- No recursive directory traversal beyond allowed limits
- Pattern validation to prevent malicious searches

## Error Handling
- Returns empty array if no matches found
- Handles permission errors gracefully
- Validates search patterns
- Provides clear error messages for invalid patterns

## Related Tools
- `fs_list` - List files in directories
- `fs_read_text` - Read file contents
- `fs_write_text` - Write to files
- `file_ops` - Advanced file operations

## Use Cases
- Finding configuration files
- Locating source code files
- Discovering documentation
- Finding log files
- Locating data files
- Project file discovery
- Backup file identification
- Temporary file cleanup

## Best Practices
- Use specific patterns for better performance
- Limit search scope to relevant directories
- Use appropriate file extensions
- Consider case sensitivity on different platforms
- Handle large result sets appropriately
