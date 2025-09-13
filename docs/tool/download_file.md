# Download File Tool

## Overview
The **Download File Tool** is a simple yet powerful file download utility that allows you to download files from URLs with support for custom output paths and comprehensive error handling.

## Features
- **URL Download**: Download files from HTTP/HTTPS URLs
- **Custom Output**: Specify custom output paths and filenames
- **Error Handling**: Comprehensive error handling and validation
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Progress Tracking**: Download progress monitoring
- **Resume Support**: Resume interrupted downloads
- **Security**: URL validation and security checks

## Usage

### Basic Download
```bash
# Download file with default filename
{
  "url": "https://example.com/file.zip"
}

# Download file with custom filename
{
  "url": "https://example.com/file.zip",
  "outputPath": "my_file.zip"
}

# Download file to specific directory
{
  "url": "https://example.com/file.zip",
  "outputPath": "./downloads/my_file.zip"
}
```

### Advanced Download
```bash
# Download with custom path (Windows)
{
  "url": "https://example.com/file.zip",
  "outputPath": "C:\\Users\\User\\Downloads\\my_file.zip"
}

# Download with custom path (Linux/macOS)
{
  "url": "https://example.com/file.zip",
  "outputPath": "/home/user/downloads/my_file.zip"
}

# Download with custom path (relative)
{
  "url": "https://example.com/file.zip",
  "outputPath": "../downloads/my_file.zip"
}
```

## Parameters

### Required Parameters
- **url**: The URL of the file to download (must be a valid HTTP/HTTPS URL)

### Optional Parameters
- **outputPath**: Custom filename or path for the downloaded file

## Output Format
```json
{
  "success": true,
  "url": "https://example.com/file.zip",
  "outputPath": "my_file.zip",
  "fileSize": 1048576,
  "downloadTime": "00:00:05",
  "status": "completed"
}
```

## Error Handling
- **Invalid URLs**: Clear error messages for invalid or malformed URLs
- **Network Errors**: Proper handling of network connection issues
- **File Errors**: Robust error handling for file system operations
- **Security Errors**: URL validation and security checks

## Cross-Platform Support
- **Windows**: Full support with Windows-style paths
- **Linux**: Complete functionality with Unix-style paths
- **macOS**: Full feature support with macOS integration
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Basic Download
```bash
# Download file
{
  "url": "https://example.com/document.pdf"
}

# Result
{
  "success": true,
  "url": "https://example.com/document.pdf",
  "outputPath": "document.pdf",
  "fileSize": 2048576,
  "downloadTime": "00:00:10",
  "status": "completed"
}
```

### Example 2: Custom Output Path
```bash
# Download with custom path
{
  "url": "https://example.com/image.jpg",
  "outputPath": "./images/my_image.jpg"
}

# Result
{
  "success": true,
  "url": "https://example.com/image.jpg",
  "outputPath": "./images/my_image.jpg",
  "fileSize": 1024000,
  "downloadTime": "00:00:05",
  "status": "completed"
}
```

### Example 3: Error Handling
```bash
# Invalid URL
{
  "url": "invalid-url"
}

# Result
{
  "success": false,
  "error": "Invalid URL format",
  "url": "invalid-url"
}
```

## Security Features
- **URL Validation**: Ensures URLs are properly formatted
- **Protocol Validation**: Only allows HTTP/HTTPS protocols
- **Path Validation**: Prevents directory traversal attacks
- **File Size Limits**: Configurable file size limits
- **Content Type Validation**: Validates file content types

## Related Tools
- **File Operations**: File system management tools
- **Network Tools**: Network communication tools
- **Web Scraping**: Web scraping and data collection tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Download File Tool, please refer to the main MCP God Mode documentation or contact the development team.