# Image Editor

🖼️ **Image Editor** - Advanced image editing and manipulation toolkit powered by Sharp library with professional-grade features for image processing, enhancement, and transformation.

## Overview

The Image Editor tool provides advanced image editing and manipulation capabilities powered by the Sharp library. It offers professional-grade features for image processing, enhancement, and transformation with high performance and cross-platform support.

## Features

- **Sharp Library Integration** - Powered by the high-performance Sharp image processing library
- **Multi-Format Support** - Support for JPEG, PNG, WebP, TIFF, and more
- **High Performance** - Optimized for speed and memory efficiency
- **Professional Tools** - Industry-standard editing features
- **Cross-Platform** - Works across Windows, Linux, macOS, Android, and iOS
- **Batch Processing** - Process multiple images simultaneously

## Usage

### Basic Image Operations

```bash
# Open an image for editing
image_editor --action open --input "image.jpg"

# Save edited image
image_editor --action save --output "edited_image.jpg"
```

### Advanced Editing Operations

```bash
# Resize image with Sharp
image_editor --action resize --width 1920 --height 1080 --fit "cover"

# Apply Sharp filters
image_editor --action filter --filter_type "blur" --sigma 2

# Adjust image properties
image_editor --action adjust --brightness 0.1 --contrast 1.2 --saturation 1.5
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action` | string | Yes | Image editing action to perform |
| `input` | string | No | Input image file path |
| `output` | string | No | Output image file path |
| `width` | number | No | Target width for resize operations |
| `height` | number | No | Target height for resize operations |
| `fit` | string | No | Resize fit mode (cover, contain, fill, inside, outside) |
| `filter_type` | string | No | Type of Sharp filter to apply |
| `sigma` | number | No | Filter sigma value for blur operations |
| `brightness` | number | No | Brightness adjustment (0.0 to 2.0) |
| `contrast` | number | No | Contrast adjustment (0.0 to 2.0) |
| `saturation` | number | No | Saturation adjustment (0.0 to 2.0) |

## Actions

### File Operations
- **open** - Open an image file for editing
- **save** - Save the edited image
- **export** - Export image in different formats
- **close** - Close the current image

### Basic Editing
- **resize** - Resize the image with Sharp
- **crop** - Crop the image to specified dimensions
- **rotate** - Rotate the image
- **flip** - Flip the image horizontally or vertically

### Advanced Editing
- **filter** - Apply Sharp filters
- **adjust** - Adjust brightness, contrast, saturation
- **enhance** - Auto-enhance the image
- **sharpen** - Sharpen the image with Sharp

### Sharp-Specific Operations
- **composite** - Composite images together
- **extract** - Extract image regions
- **trim** - Trim image borders
- **normalize** - Normalize image values

## Examples

### Basic Image Operations
```bash
# Open an image
image_editor --action open --input "photo.jpg"

# Resize with Sharp
image_editor --action resize --width 800 --height 600 --fit "cover"

# Save the result
image_editor --action save --output "resized_photo.jpg"
```

### Advanced Sharp Operations
```bash
# Apply Gaussian blur
image_editor --action filter --filter_type "blur" --sigma 3

# Adjust image properties
image_editor --action adjust --brightness 0.1 --contrast 1.2 --saturation 1.5

# Apply sharpening
image_editor --action sharpen --sigma 1.5 --flat 1.0 --jagged 2.0
```

### Professional Editing
```bash
# Composite images
image_editor --action composite --overlay "watermark.png" --gravity "southeast"

# Extract region
image_editor --action extract --left 100 --top 100 --width 200 --height 200

# Trim borders
image_editor --action trim --threshold 10
```

## Sharp Library Features

### Resize Operations
- **Cover** - Resize to cover the entire area
- **Contain** - Resize to fit within the area
- **Fill** - Resize to fill the area
- **Inside** - Resize to fit inside the area
- **Outside** - Resize to fit outside the area

### Filter Operations
- **Blur** - Gaussian blur with configurable sigma
- **Sharpen** - Unsharp mask with configurable parameters
- **Median** - Median filter for noise reduction
- **Convolve** - Custom convolution kernels

### Color Operations
- **Brightness** - Adjust image brightness
- **Contrast** - Adjust image contrast
- **Saturation** - Adjust color saturation
- **Hue** - Adjust color hue
- **Gamma** - Apply gamma correction

## Supported Formats

### Input Formats
- **JPEG** - Joint Photographic Experts Group
- **PNG** - Portable Network Graphics
- **WebP** - Web Picture format
- **TIFF** - Tagged Image File Format
- **AVIF** - AV1 Image File Format
- **HEIF** - High Efficiency Image Format
- **RAW** - Camera raw formats

### Output Formats
- **JPEG** - High-quality compression with configurable quality
- **PNG** - Lossless compression with transparency
- **WebP** - Modern web format with lossy/lossless options
- **TIFF** - Professional format with compression options
- **AVIF** - Next-generation format

## Advanced Features

### Sharp-Specific Capabilities
- **Pipeline Processing** - Chain multiple operations
- **Stream Processing** - Process large images efficiently
- **Metadata Preservation** - Preserve EXIF and other metadata
- **Color Space Support** - Support for various color spaces

### Performance Optimization
- **Memory Efficiency** - Optimized memory usage
- **Streaming** - Process images without loading entirely into memory
- **Caching** - Intelligent caching for repeated operations
- **Parallel Processing** - Multi-threaded processing

## Cross-Platform Support

The Image Editor tool works across all supported platforms:

- **Windows** - Full functionality with Windows-specific optimizations
- **Linux** - Native Linux support with system integration
- **macOS** - macOS compatibility with security features
- **Android** - Mobile image editing capabilities
- **iOS** - iOS-specific image editing features

## Integration

### With Sharp Library
- Direct Sharp library integration
- Access to all Sharp features
- Performance optimizations
- Advanced image processing capabilities

### With Other Tools
- Integration with multimedia editing tools
- Connection to image processing pipelines
- Linkage with batch processing systems
- Integration with content management systems

## Best Practices

### Image Quality
- Use appropriate compression settings
- Maintain aspect ratios when resizing
- Preserve metadata when possible
- Use lossless formats for editing

### Performance
- Use streaming for large images
- Process images in batches when possible
- Use appropriate image sizes for the task
- Optimize memory usage for large images

### Sharp-Specific Tips
- Use pipeline processing for multiple operations
- Leverage Sharp's built-in optimizations
- Use appropriate fit modes for resizing
- Take advantage of Sharp's format support

## Troubleshooting

### Common Issues
- **Sharp Library Errors** - Check Sharp installation and version
- **Memory Errors** - Use streaming for large images
- **Format Not Supported** - Check Sharp's format support
- **Performance Issues** - Use pipeline processing

### Error Handling
- Clear error messages for Sharp operations
- Suggestions for resolving problems
- Fallback options for failed operations
- Detailed logging for debugging

## Related Tools

- [Image Editing](image_editing.md) - General image editing toolkit
- [Enhanced Media Editor](enhanced_media_editor.md) - Unified multimedia editing suite
- [Multimedia Tool](multimedia_tool.md) - Comprehensive media processing
- [Screenshot](screenshot.md) - Advanced screen capture capabilities

## Legal Notice

This tool is designed for legitimate image editing and processing purposes only. Users must ensure they have appropriate rights to edit any images they process. The tool includes built-in safety controls and audit logging to ensure responsible use.
