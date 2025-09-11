# Image Editor - Comprehensive Cross-Platform Image Processing

## Overview

The Image Editor is a powerful, cross-platform image processing tool that provides professional-grade editing capabilities with a modern web interface and comprehensive API. Built with Sharp for high-performance image processing and React for an intuitive user experience.

## Features

### 🎨 **Advanced Image Processing**
- **Resize & Crop**: Precise resizing with multiple fit modes and intelligent cropping
- **Rotate & Flip**: Full rotation control with custom background colors
- **Filters & Effects**: Professional filters including blur, sharpen, grayscale, sepia, and more
- **Color Adjustments**: Brightness, contrast, saturation, hue, and gamma correction
- **Advanced Effects**: Vignettes, borders, noise reduction, and enhancement tools

### 🖼️ **Format Support**
- **Input Formats**: JPEG, PNG, GIF, WebP, TIFF, BMP, SVG, PDF
- **Output Formats**: JPEG, PNG, GIF, WebP, TIFF, BMP, SVG, PDF
- **Quality Control**: Configurable quality settings for each format
- **Metadata Preservation**: Maintains EXIF data and image metadata

### 🔧 **Professional Tools**
- **Layer-Based Editing**: Non-destructive editing with layer system
- **Batch Processing**: Process multiple images or operations efficiently
- **Collage Creation**: Combine multiple images into custom layouts
- **Session Management**: Track multiple editing sessions simultaneously
- **Watermarking**: Add text or image watermarks to images

### 🌐 **Cross-Platform Support**
- **Web Interface**: Modern PWA with offline capabilities
- **Desktop Apps**: Native wrappers for Windows, macOS, and Linux
- **Mobile Apps**: iOS and Android support via Capacitor
- **API Access**: Full programmatic access via MCP tool API

## Quick Start

### CLI Usage via Tool API

```bash
# Open an image for editing
image_editor.open({
  source: "/path/to/image.jpg",
  sessionName: "My Edit Session"
})

# Resize the image
image_editor.edit({
  sessionId: "session-id",
  op: "resize",
  params: { width: 800, height: 600, fit: "cover" }
})

# Apply a filter
image_editor.edit({
  sessionId: "session-id",
  op: "filter",
  params: { type: "grayscale" }
})

# Export the result
image_editor.export({
  sessionId: "session-id",
  format: "png",
  quality: 90,
  path: "/path/to/output.png"
})
```

### Web Interface

1. **Access the Editor**: Navigate to `/viewer/image` in your browser
2. **Upload Images**: Drag and drop or click to upload images
3. **Edit**: Use the intuitive interface to apply edits
4. **Export**: Save in your preferred format and quality

### Natural Language Commands

```bash
# Resize image to 800x600
"Resize image to 800x600"

# Apply grayscale filter and export as PNG
"Apply grayscale filter and export as PNG"

# Create a collage from multiple images
"Create collage with session1,session2 in 2x2 layout"

# Batch process multiple sizes
"Batch process with operations: [{'name': 'thumb', 'params': {'width': 150}}, {'name': 'medium', 'params': {'width': 800}}]"
```

## API Reference

### Core Functions

#### `status()`
Get current status of all active editing sessions.

**Returns:**
```typescript
{
  sessions: Array<{
    id: string;
    name: string;
    dimensions?: { width: number; height: number };
    format?: string;
  }>
}
```

#### `open(input)`
Open an image for editing.

**Parameters:**
- `source`: Image path or URL
- `sessionName`: Name for the editing session

**Returns:**
```typescript
{
  sessionId: string;
  name: string;
  dimensions?: { width: number; height: number };
  format?: string;
}
```

#### `edit(input)`
Apply an editing operation to an image session.

**Parameters:**
- `sessionId`: ID of the editing session
- `op`: Operation type (resize, crop, rotate, filter, etc.)
- `params`: Operation-specific parameters

**Returns:**
```typescript
{
  ok: boolean;
  operationId: string;
  layers: Array<Operation>;
}
```

#### `export(input)`
Export the edited image to a file.

**Parameters:**
- `sessionId`: ID of the editing session
- `format`: Output format (jpg, png, gif, webp, etc.)
- `quality`: Quality setting (1-100)
- `path`: Output file path

**Returns:**
```typescript
{
  ok: boolean;
  path: string;
  format: string;
}
```

### Advanced Functions

#### `batchProcess(input)`
Process multiple operations on a single image.

**Parameters:**
- `sessionId`: ID of the editing session
- `operations`: Array of operations to apply
- `outputDir`: Directory for output files

#### `createCollage(input)`
Create a collage from multiple image sessions.

**Parameters:**
- `sessionIds`: Array of session IDs to combine
- `layout`: Layout configuration (rows, cols)
- `outputPath`: Output file path
- `spacing`: Spacing between images

## Supported Operations

### Basic Operations
- **resize**: Resize image with various fit modes
- **crop**: Extract a rectangular region
- **rotate**: Rotate image by specified angle
- **flip**: Flip image horizontally or vertically

### Filters
- **blur**: Apply Gaussian blur
- **sharpen**: Enhance image sharpness
- **grayscale**: Convert to grayscale
- **sepia**: Apply sepia tone effect
- **negate**: Invert image colors

### Adjustments
- **enhance**: Adjust brightness, saturation, hue
- **adjust**: Apply gamma correction and contrast
- **vignette**: Add vignette effect
- **border**: Add colored border

### Advanced
- **composite**: Layer multiple images
- **text**: Add text overlays
- **watermark**: Add watermark images
- **mask**: Apply image masks

## Configuration

### Environment Variables

```bash
# Image processing settings
IMAGE_EDITOR_MAX_SIZE=50MB
IMAGE_EDITOR_TEMP_DIR=/tmp/mcp_image
IMAGE_EDITOR_CACHE_SIZE=100MB

# Quality settings
IMAGE_EDITOR_DEFAULT_QUALITY=80
IMAGE_EDITOR_MAX_QUALITY=100

# Performance settings
IMAGE_EDITOR_MAX_SESSIONS=10
IMAGE_EDITOR_BATCH_SIZE=5
```

### Web Interface Configuration

```typescript
// web/config.ts
export const config = {
  maxFileSize: 50 * 1024 * 1024, // 50MB
  supportedFormats: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'tiff', 'bmp'],
  defaultQuality: 80,
  maxSessions: 10,
  autoSave: true,
  enableOffline: true
};
```

## Cross-Platform Notes

### Windows
- Full support for all image formats
- Native file system integration
- High DPI display support
- Windows-specific optimizations

### macOS
- Native macOS integration
- Retina display support
- macOS-specific file handling
- Touch Bar support (if available)

### Linux
- Full compatibility with all distributions
- X11 and Wayland support
- Package manager integration
- System theme integration

### iOS/Android
- PWA with native app capabilities
- Touch-optimized interface
- Camera integration
- Share sheet integration
- Offline functionality

## Performance Tips

### Large Images
- Use streaming processing for very large images
- Consider downsampling for preview operations
- Use appropriate quality settings for final export
- Enable parallel processing for batch operations

### Memory Management
- Close unused sessions to free memory
- Use appropriate image formats for your use case
- Consider image compression for storage
- Monitor memory usage during batch operations

### Network Optimization
- Use WebP format for web delivery
- Implement progressive loading for large images
- Cache processed results when possible
- Use CDN for static assets

## Troubleshooting

### Common Issues

**"Image format not supported"**
- Ensure the image format is in the supported list
- Check if the file is corrupted
- Try converting to a different format first

**"Out of memory"**
- Reduce image size before processing
- Close unused editing sessions
- Increase system memory or use smaller batch sizes

**"Export failed"**
- Check output directory permissions
- Ensure sufficient disk space
- Verify output format is supported

### Debug Mode

Enable debug mode for detailed logging:

```bash
DEBUG=image_editor:* node server.js
```

### Performance Monitoring

Monitor performance with built-in metrics:

```typescript
const metrics = await image_editor.getMetrics();
console.log('Processing time:', metrics.processingTime);
console.log('Memory usage:', metrics.memoryUsage);
console.log('Active sessions:', metrics.activeSessions);
```

## Contributing

### Development Setup

```bash
# Install dependencies
npm install

# Install Sharp (image processing)
npm install sharp

# Start development server
npm run dev

# Run tests
npm test

# Build for production
npm run build
```

### Adding New Operations

1. Add operation to the `EditInput` schema
2. Implement the operation in the `edit` function
3. Add corresponding Sharp pipeline code
4. Update documentation and tests

### Testing

```bash
# Run unit tests
npm run test:unit

# Run integration tests
npm run test:integration

# Run performance tests
npm run test:performance
```

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

- **Documentation**: [Full API Documentation](./docs/)
- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Community**: [Discord Server](https://discord.gg/your-server)
- **Email**: support@your-domain.com

---

**Image Editor** - Professional image processing made simple and accessible across all platforms.
