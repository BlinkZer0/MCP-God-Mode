# Screenshot Tool

## Overview

The **Screenshot Tool** (`screenshot`) is a cross-platform screen capture utility that provides comprehensive capabilities for capturing active windows, full screens, specific regions, and continuous screenshots across Windows, Linux, macOS, Android, and iOS.

## Features

### 📸 **Capture Actions (9+ Operations)**
- **`capture_active_window`**: Capture the currently focused window
- **`capture_full_screen`**: Capture the entire screen
- **`capture_region`**: Capture a specific rectangular area
- **`capture_specific_window`**: Capture a named window by title
- **`capture_multiple_windows`**: Capture several windows simultaneously
- **`capture_with_cursor`**: Include mouse cursor in the screenshot
- **`capture_with_timestamp`**: Add timestamp overlay to screenshots
- **`capture_continuous`**: Take multiple screenshots at intervals
- **`capture_delayed`**: Delay capture for scene preparation

### 🎨 **Output Formats & Quality**
- **Multiple Formats**: PNG, JPG, JPEG, BMP, TIFF, WebP
- **Quality Control**: Configurable quality settings (1-100)
- **Compression Options**: Various compression levels
- **Color Depth Support**: 24-bit and 32-bit color
- **Transparency Support**: PNG and WebP alpha channels

### 🔧 **Advanced Features**
- **Cross-platform Support**: Windows, Linux, macOS, Android, iOS
- **Window Detection**: Automatic window identification and targeting
- **Region Selection**: Precise area capture with coordinates
- **Timestamp Overlays**: Customizable date/time stamps
- **Continuous Capture**: Automated screenshot sequences
- **Cursor Integration**: Mouse cursor capture options
- **Auto-resize**: Image resizing with aspect ratio preservation
- **Metadata Support**: System and window information embedding

## Usage Examples

### Capture Active Window
```typescript
const result = await screenshot({
  action: "capture_active_window",
  format: "png",
  quality: 90,
  include_cursor: true
});
```

### Capture Full Screen
```typescript
const result = await screenshot({
  action: "capture_full_screen",
  output_file: "./fullscreen.png",
  format: "png",
  add_timestamp: true,
  timestamp_position: "bottom-right"
});
```

### Capture Specific Region
```typescript
const result = await screenshot({
  action: "capture_region",
  region: {
    x: 100,
    y: 100,
    width: 800,
    height: 600
  },
  format: "jpg",
  quality: 95
});
```

### Capture Specific Window
```typescript
const result = await screenshot({
  action: "capture_specific_window",
  window_title: "Chrome",
  format: "png",
  include_cursor: false
});
```

### Continuous Screenshots
```typescript
const result = await screenshot({
  action: "capture_continuous",
  continuous_count: 10,
  continuous_interval: 5,
  output_directory: "./screenshots",
  format: "png"
});
```

### Delayed Capture with Timestamp
```typescript
const result = await screenshot({
  action: "capture_delayed",
  delay_seconds: 3,
  add_timestamp: true,
  timestamp_format: "HH:mm:ss",
  timestamp_position: "top-left",
  timestamp_color: "#FF0000",
  timestamp_size: 20
});
```

## Parameters

### Core Parameters
- **`action`** (required): The screenshot action to perform
- **`output_file`**: Path for the output screenshot file
- **`format`**: Output image format (png, jpg, jpeg, bmp, tiff, webp)
- **`quality`**: Image quality for lossy formats (1-100)

### Region Parameters
- **`region`**: Object with x, y, width, height coordinates
- **`window_title`**: Title of specific window to capture

### Capture Options
- **`include_cursor`**: Whether to include mouse cursor
- **`add_timestamp`**: Whether to add timestamp overlay
- **`delay_seconds`**: Delay before capture (0-60 seconds)
- **`continuous_count`**: Number of screenshots for continuous mode
- **`continuous_interval`**: Interval between continuous captures

### Timestamp Customization
- **`timestamp_format`**: Format for timestamp (YYYY-MM-DD HH:mm:ss)
- **`timestamp_position`**: Position of timestamp (top-left, top-right, bottom-left, bottom-right, center)
- **`timestamp_color`**: Color of timestamp text (hex format)
- **`timestamp_size`**: Font size for timestamp (8-72 pixels)

### Output Options
- **`output_directory`**: Directory for saving screenshots
- **`auto_open`**: Whether to open screenshot after capture
- **`compression_level`**: Compression level for output images
- **`clipboard_copy`**: Whether to copy to clipboard
- **`notification`**: Whether to show capture notifications

### Image Processing
- **`resize`**: Object with width, height, maintain_aspect_ratio, quality
- **`metadata`**: Object with include_system_info, include_window_info, custom_tags

## Output Schema

The tool returns comprehensive information about the screenshot operation:

```typescript
{
  success: boolean,
  action_performed: string,
  output_file: string,
  capture_time: string,
  image_info: {
    format: string,
    width: number,
    height: number,
    file_size: string,
    color_depth?: number,
    compression_ratio?: number
  },
  window_info?: {
    title: string,
    process_name: string,
    position?: {
      x: number,
      y: number
    },
    size?: {
      width: number,
      height: number
    }
  },
  system_info?: {
    platform: string,
    screen_resolution: string,
    color_depth: number,
    refresh_rate?: number
  },
  continuous_results?: {
    total_captured: number,
    files_created: string[],
    capture_interval: number
  },
  message: string,
  error?: string,
  platform: string,
  timestamp: string
}
```

## Natural Language Access
Users can request screenshot operations using natural language:
- "Take a screenshot"
- "Capture screen image"
- "Save screen capture"
- "Record screen content"
- "Capture desktop image"

## Supported Formats

### Input Sources
- **Screen Capture**: Full screen, active window, specific window
- **Region Capture**: Custom rectangular areas
- **Window Capture**: Named windows by title
- **Application Capture**: Process-based window identification

### Output Formats
- **PNG**: Lossless, supports transparency
- **JPEG**: Lossy, good compression
- **BMP**: Windows bitmap format
- **TIFF**: High quality, large file size
- **WebP**: Modern web format, good compression

## Platform Support

### Windows
- **Capture Methods**: GDI+, DirectX, Windows Graphics Capture
- **Window Detection**: Win32 API, process enumeration
- **Cursor Support**: Direct cursor capture
- **Formats**: All major image formats

### Linux
- **Capture Methods**: X11, Wayland, framebuffer
- **Window Detection**: X11 window management
- **Cursor Support**: X11 cursor integration
- **Formats**: Open source image formats

### macOS
- **Capture Methods**: Core Graphics, Screen Capture API
- **Window Detection**: AppKit window management
- **Cursor Support**: Core Graphics cursor
- **Formats**: Apple image formats + standards

### Mobile (Android/iOS)
- **Capture Methods**: Platform screenshot APIs
- **Window Detection**: App-based capture
- **Cursor Support**: Touch indicator capture
- **Formats**: Mobile-optimized formats

## Use Cases

### 🖥️ **System Administration**
- **Documentation**: System setup and configuration screenshots
- **Troubleshooting**: Error message and issue capture
- **Training**: Step-by-step procedure documentation
- **Monitoring**: System status and performance capture

### 💻 **Software Development**
- **Bug Reports**: Issue reproduction and documentation
- **UI Testing**: Interface validation and testing
- **Documentation**: User manual and help content
- **Design Review**: Interface design evaluation

### 📚 **Education & Training**
- **Tutorials**: Step-by-step instruction capture
- **Presentations**: Screen content for slides
- **Demonstrations**: Software feature showcases
- **Assessment**: Student work evaluation

### 🔍 **Quality Assurance**
- **Testing**: Automated test result capture
- **Validation**: Expected vs. actual result comparison
- **Documentation**: Test case evidence
- **Reporting**: Quality metrics and issues

### 📱 **Mobile Development**
- **App Testing**: Mobile interface validation
- **Cross-platform**: Consistent capture across devices
- **User Experience**: Interface flow documentation
- **Debugging**: Mobile app issue capture

## Technical Details

### Capture Engine
- **Multi-platform Support**: Native platform APIs
- **Performance Optimization**: Efficient memory usage
- **Quality Preservation**: Minimal quality loss
- **Real-time Processing**: Low-latency capture

### Image Processing
- **Format Conversion**: Seamless format switching
- **Quality Control**: Configurable compression
- **Metadata Handling**: System information embedding
- **Resize Operations**: Aspect ratio preservation

### Performance Features
- **Memory Management**: Efficient buffer handling
- **Multi-threading**: Parallel processing support
- **Progress Tracking**: Real-time operation status
- **Error Recovery**: Graceful failure handling

## Error Handling

The tool provides comprehensive error handling:

- **Permission Errors**: Clear guidance for access issues
- **Device Errors**: Hardware and driver problem identification
- **Format Errors**: Compatibility and conversion issues
- **Resource Errors**: Memory and disk space validation
- **Platform Errors**: OS-specific issue resolution

## Best Practices

### 🎯 **Quality Optimization**
- Choose appropriate formats for your use case
- Use PNG for quality-critical screenshots
- Use JPEG for web and sharing
- Balance quality and file size

### 📁 **File Management**
- Use descriptive filenames with timestamps
- Organize screenshots in logical directories
- Implement consistent naming conventions
- Regular cleanup of old screenshots

### 🔧 **Performance Tips**
- Use appropriate quality settings
- Avoid unnecessary high-resolution captures
- Use continuous mode sparingly
- Monitor disk space usage

## Troubleshooting

### Common Issues
- **Black Screenshots**: Check display driver settings
- **Permission Denied**: Verify application permissions
- **Large File Sizes**: Adjust quality and format settings
- **Capture Failures**: Ensure sufficient system resources

### Performance Issues
- **Slow Capture**: Reduce quality or resolution
- **Memory Errors**: Close unnecessary applications
- **Disk Space**: Ensure adequate storage
- **CPU Usage**: Monitor system resources

## Future Enhancements

### Planned Features
- **AI-powered Content Recognition**: Automatic text and object detection
- **Cloud Integration**: Direct cloud storage upload
- **Real-time Sharing**: Instant screenshot sharing
- **Advanced Editing**: Built-in image editing capabilities
- **OCR Integration**: Text extraction from screenshots

### Integration Opportunities
- **Video Recording**: Screenshot-to-video workflows
- **Documentation Tools**: Automated documentation generation
- **Testing Frameworks**: Automated test result capture
- **Collaboration Platforms**: Team screenshot sharing

---

*The Screenshot Tool provides professional-grade screen capture capabilities with cross-platform support, making it ideal for system administrators, developers, educators, and anyone who needs comprehensive screenshot functionality.*
