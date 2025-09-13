# Advanced Grep Tool

## Overview
The **Advanced Grep Tool** is an enhanced text search utility with cross-platform support, contextual display, encoding detection, and performance optimizations. It provides comprehensive text search capabilities with advanced filtering and output options.

## Features
- **Cross-Platform Support**: Windows, Linux, macOS, Android, iOS
- **Contextual Display**: Show lines before and after matches
- **Encoding Detection**: Automatic encoding detection and support
- **Performance Optimizations**: Fast search with configurable performance modes
- **Advanced Filtering**: File pattern inclusion and exclusion
- **Multiple Output Formats**: Text, JSON, CSV, XML output formats
- **Colored Output**: Syntax highlighting for better readability
- **Recursive Search**: Search subdirectories with depth control

## Usage

### Basic Search
```bash
# Search for pattern in current directory
{
  "pattern": "function",
  "path": "."
}

# Search with case-insensitive option
{
  "pattern": "ERROR",
  "path": "./logs",
  "caseInsensitive": true
}

# Search with whole word matching
{
  "pattern": "test",
  "path": "./src",
  "wholeWord": true
}
```

### Advanced Search
```bash
# Regex search with context
{
  "pattern": "\\b\\w+Error\\b",
  "path": "./src",
  "regex": true,
  "contextBefore": 2,
  "contextAfter": 2
}

# Search with file pattern filtering
{
  "pattern": "import",
  "path": "./src",
  "includePattern": ["*.js", "*.ts"],
  "excludePattern": ["*.test.js", "node_modules"]
}

# Search with performance optimization
{
  "pattern": "TODO",
  "path": "./",
  "performanceMode": "fast",
  "maxFileSize": 1048576
}
```

### Output Formatting
```bash
# JSON output with line numbers
{
  "pattern": "function",
  "path": "./src",
  "outputFormat": "json",
  "showLineNumbers": true,
  "showFilename": true
}

# CSV output for data analysis
{
  "pattern": "error",
  "path": "./logs",
  "outputFormat": "csv",
  "caseInsensitive": true
}
```

## Parameters

### Search Parameters
- **pattern**: The search pattern (literal text or regex)
- **path**: Directory or file path to search in
- **caseInsensitive**: Case-insensitive search
- **wholeWord**: Match whole words only
- **regex**: Treat pattern as regex

### Context Parameters
- **contextBefore**: Number of lines to show before each match (0-10)
- **contextAfter**: Number of lines to show after each match (0-10)

### Performance Parameters
- **maxFileSize**: Maximum file size to search in bytes
- **performanceMode**: Performance vs accuracy trade-off (fast, balanced, thorough)
- **limitResults**: Maximum number of results to return

### Filtering Parameters
- **includePattern**: File patterns to include
- **excludePattern**: File patterns to exclude
- **maxDepth**: Maximum directory depth (0 = unlimited)
- **recursive**: Search subdirectories recursively
- **followSymlinks**: Follow symbolic links

### Output Parameters
- **outputFormat**: Output format (text, json, csv, xml)
- **colorOutput**: Enable colored output highlighting
- **showLineNumbers**: Show line numbers
- **showFilename**: Show filename for each match

### Encoding Parameters
- **encoding**: File encoding (auto, utf8, utf16le, latin1, cp1252)
- **binaryFiles**: How to handle binary files (skip, include, text)

## Output Format

### Text Output
```
./src/utils.js:15:function validateInput(input) {
./src/utils.js:16:  if (!input) {
./src/utils.js:17:    throw new Error('Invalid input');
```

### JSON Output
```json
{
  "results": [
    {
      "file": "./src/utils.js",
      "line": 15,
      "content": "function validateInput(input) {",
      "match": "function"
    }
  ],
  "totalMatches": 1,
  "searchTime": "0.05s"
}
```

### CSV Output
```csv
file,line,content,match
./src/utils.js,15,"function validateInput(input) {",function
```

## Cross-Platform Support
- **Windows**: Full support with Windows-specific optimizations
- **Linux**: Complete functionality with Unix-style paths
- **macOS**: Full feature support with macOS integration
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Basic Text Search
```bash
# Search for "error" in source files
{
  "pattern": "error",
  "path": "./src",
  "includePattern": ["*.js", "*.ts"],
  "caseInsensitive": true
}

# Result
{
  "results": [
    {
      "file": "./src/utils.js",
      "line": 17,
      "content": "    throw new Error('Invalid input');",
      "match": "Error"
    }
  ],
  "totalMatches": 1
}
```

### Example 2: Regex Search with Context
```bash
# Search for function definitions with context
{
  "pattern": "function\\s+\\w+\\s*\\(",
  "path": "./src",
  "regex": true,
  "contextBefore": 1,
  "contextAfter": 1
}

# Result
{
  "results": [
    {
      "file": "./src/utils.js",
      "line": 15,
      "content": "function validateInput(input) {",
      "context": {
        "before": ["// Validation function"],
        "after": ["  if (!input) {"]
      }
    }
  ]
}
```

## Error Handling
- **Invalid Patterns**: Clear error messages for invalid regex patterns
- **File Access Errors**: Proper handling of permission issues
- **Encoding Errors**: Automatic encoding detection and fallback
- **Performance Issues**: Configurable performance modes for large searches

## Related Tools
- **File Operations**: File system management tools
- **Text Processing**: Text manipulation tools
- **Search Tools**: Other search and discovery tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Advanced Grep Tool, please refer to the main MCP God Mode documentation or contact the development team.
