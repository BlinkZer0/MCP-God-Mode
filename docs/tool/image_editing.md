# Image Editing Tool

## Overview

The **Image Editing Tool** is a comprehensive, cross-platform image manipulation and processing utility that provides professional-grade image editing capabilities. This tool supports a wide range of operations from basic adjustments to advanced effects and analysis, making it suitable for photographers, designers, developers, and content creators.

## 🎯 **Key Features**

- **30+ Image Editing Actions** - Comprehensive set of editing operations
- **Cross-Platform Support** - Windows, Linux, macOS, Android, iOS
- **Multiple Format Support** - JPG, PNG, BMP, TIFF, WebP, GIF, ICO
- **Batch Processing** - Handle multiple images simultaneously
- **Advanced Effects** - Professional-grade filters and adjustments
- **Image Analysis** - Color analysis, face detection, object recognition
- **Quality Control** - Adjustable compression and quality settings

## 🚀 **Available Actions**

### **Basic Operations**
- `resize` - Resize images with various algorithms
- `crop` - Crop images to specific dimensions
- `rotate` - Rotate images by specified angles
- `flip` - Flip images horizontally, vertically, or both

### **Color & Light Adjustments**
- `adjust_brightness` - Modify image brightness (-100 to +100)
- `adjust_contrast` - Adjust image contrast (-100 to +100)
- `adjust_saturation` - Control color saturation (-100 to +100)
- `adjust_hue` - Shift color hue (-180° to +180°)
- `adjust_gamma` - Gamma correction (0.1 to 5.0)
- `color_correction` - Automatic color balance adjustment
- `white_balance` - Correct color temperature
- `histogram_equalization` - Enhance image contrast automatically

### **Effects & Filters**
- `blur` - Apply Gaussian blur (0-50px radius)
- `sharpen` - Enhance image sharpness (0-100%)
- `noise_reduction` - Remove digital noise (0-100%)
- `edge_detection` - Detect and highlight edges
- `emboss` - Create 3D embossed effect (0-100%)
- `sepia` - Apply vintage sepia tone
- `grayscale` - Convert to black and white
- `invert` - Invert image colors
- `posterize` - Reduce color palette (2-256 levels)
- `solarize` - Create solarization effect

### **Advanced Features**
- `add_text` - Overlay text on images
- `add_watermark` - Add watermark images
- `remove_background` - AI-powered background removal
- `convert_format` - Convert between image formats
- `compress` - Reduce file size with quality control
- `batch_process` - Process multiple images
- `create_thumbnail` - Generate thumbnail images
- `analyze_image` - Analyze image content and colors

## 📋 **Input Parameters**

### **Required Parameters**
- `action` - The image editing action to perform
- `input_file` - Path to the input image file

### **Optional Parameters**

#### **Output Settings**
- `output_file` - Custom output file path
- `format` - Output format (jpg, png, webp, etc.)
- `quality` - Image quality (1-100, default: 90)
- `compression_level` - Compression intensity
- `preserve_metadata` - Keep EXIF/GPS data

#### **Resize Parameters**
- `width` - Target width in pixels
- `height` - Target height in pixels
- `maintain_aspect_ratio` - Preserve proportions
- `resize_algorithm` - Resize method (lanczos, bicubic, etc.)

#### **Crop Parameters**
- `crop_x` - Starting X coordinate
- `crop_y` - Starting Y coordinate
- `crop_width` - Crop width in pixels
- `crop_height` - Crop height in pixels

#### **Rotation & Flip**
- `rotation_angle` - Rotation angle in degrees
- `flip_direction` - Flip direction (horizontal/vertical/both)

#### **Color Adjustments**
- `brightness` - Brightness adjustment (-100 to +100)
- `contrast` - Contrast adjustment (-100 to +100)
- `saturation` - Saturation adjustment (-100 to +100)
- `hue` - Hue shift (-180° to +180°)
- `gamma` - Gamma correction (0.1 to 5.0)

#### **Effect Parameters**
- `blur_radius` - Blur radius in pixels (0-50)
- `sharpen_amount` - Sharpening intensity (0-100%)
- `noise_reduction_strength` - Noise reduction (0-100%)
- `edge_detection_threshold` - Edge sensitivity (0-255)
- `emboss_strength` - Emboss effect intensity (0-100%)
- `posterize_levels` - Color reduction levels (2-256)
- `solarize_threshold` - Solarization threshold (0-255)

#### **Text & Watermark**
- `text_content` - Text to overlay
- `text_font` - Font family
- `text_size` - Font size in pixels
- `text_color` - Text color (hex format)
- `text_x` - Text X position
- `text_y` - Text Y position
- `watermark_file` - Watermark image path
- `watermark_opacity` - Watermark transparency (0-100%)
- `watermark_position` - Watermark placement

#### **Batch Processing**
- `batch_directory` - Directory containing multiple images
- `output_directory` - Output directory for processed images

#### **Analysis Options**
- `analyze_colors` - Extract color palette
- `detect_faces` - Count faces in image
- `detect_objects` - Identify objects in image
- `thumbnail_size` - Thumbnail dimensions

## 📊 **Output Schema**

### **Success Response**
```json
{
  "success": true,
  "action": "resize",
  "input_file": "./input.jpg",
  "output_file": "./output.jpg",
  "original_size": {
    "width": 1920,
    "height": 1080,
    "file_size": 1500000
  },
  "processed_size": {
    "width": 800,
    "height": 600,
    "file_size": 450000
  },
  "format": "jpg",
  "quality": 90,
  "processing_time": 2500,
  "effects_applied": ["resize", "brightness: 10"],
  "analysis_results": {
    "dominant_colors": ["#FF6B6B", "#4ECDC4"],
    "color_palette": ["#FF6B6B", "#4ECDC4", "#45B7D1"],
    "brightness_level": "bright",
    "contrast_level": "high",
    "face_count": 2,
    "detected_objects": ["person", "chair"],
    "image_type": "portrait"
  },
  "batch_results": {
    "total_images": 15,
    "successful": 14,
    "failed": 1,
    "failed_files": ["corrupt.jpg"]
  }
}
```

### **Error Response**
```json
{
  "success": false,
  "action": "resize",
  "input_file": "./input.jpg",
  "output_file": "",
  "original_size": { "width": 0, "height": 0, "file_size": 0 },
  "processed_size": { "width": 0, "height": 0, "file_size": 0 },
  "format": "",
  "quality": 0,
  "processing_time": 0,
  "effects_applied": [],
  "error": "File not found: ./input.jpg"
}
```

## 💡 **Usage Examples**

### **Basic Image Resize**
```json
{
  "action": "resize",
  "input_file": "./photo.jpg",
  "width": 800,
  "height": 600,
  "maintain_aspect_ratio": true,
  "format": "webp",
  "quality": 85
}
```

### **Apply Multiple Effects**
```json
{
  "action": "adjust_brightness",
  "input_file": "./dark_image.jpg",
  "brightness": 25,
  "contrast": 15,
  "saturation": 10,
  "output_file": "./enhanced.jpg"
}
```

### **Create Thumbnail with Analysis**
```json
{
  "action": "create_thumbnail",
  "input_file": "./large_image.jpg",
  "thumbnail_size": 150,
  "analyze_colors": true,
  "detect_faces": true,
  "format": "png"
}
```

### **Batch Process Images**
```json
{
  "action": "batch_process",
  "batch_directory": "./photos/",
  "output_directory": "./processed/",
  "format": "webp",
  "quality": 80,
  "resize": true,
  "width": 1200,
  "height": 800
}
```

### **Add Text Watermark**
```json
{
  "action": "add_text",
  "input_file": "./image.jpg",
  "text_content": "© 2024 My Company",
  "text_font": "Arial",
  "text_size": 24,
  "text_color": "#FFFFFF",
  "text_x": 50,
  "text_y": 50,
  "output_file": "./watermarked.jpg"
}
```

## 🔧 **Technical Details**

### **Supported Formats**
- **Input**: JPG, JPEG, PNG, BMP, TIFF, WebP, GIF, ICO
- **Output**: JPG, JPEG, PNG, BMP, TIFF, WebP, GIF, ICO
- **Best Quality**: PNG, TIFF (lossless)
- **Best Compression**: WebP, JPG (lossy)

### **Resize Algorithms**
- **Lanczos** - Highest quality, slower processing
- **Bicubic** - Good quality, balanced performance
- **Bilinear** - Fast processing, moderate quality
- **Nearest** - Fastest, lowest quality

### **Quality Settings**
- **90-100**: Excellent quality, larger files
- **70-89**: Good quality, balanced size
- **50-69**: Acceptable quality, smaller files
- **1-49**: Low quality, smallest files

### **Performance Considerations**
- **Single Image**: 1-3 seconds processing time
- **Batch Processing**: 2-5 seconds per image
- **High Resolution**: May take longer for 4K+ images
- **Complex Effects**: Multiple effects increase processing time

## 🌟 **Advanced Features**

### **Color Analysis**
- Extract dominant colors from images
- Generate color palettes for design work
- Analyze brightness and contrast levels
- Identify color temperature and white balance

### **AI-Powered Features**
- **Face Detection**: Count and locate faces in images
- **Object Recognition**: Identify common objects
- **Background Removal**: AI-powered background removal
- **Smart Cropping**: Intelligent crop suggestions

### **Batch Processing**
- Process entire directories of images
- Apply consistent settings across multiple files
- Generate progress reports and error logs
- Optimize workflow for large image collections

### **Metadata Preservation**
- Maintain EXIF data (camera settings, GPS)
- Preserve color profiles and ICC data
- Keep creation dates and copyright information
- Support for custom metadata fields

## 🚨 **Limitations & Considerations**

### **File Size Limits**
- **Input**: Maximum 100MB per image
- **Output**: Varies by format and quality
- **Batch**: Maximum 1000 images per batch

### **Format Restrictions**
- **GIF**: Limited to 256 colors
- **ICO**: Maximum 256x256 pixels
- **WebP**: May not be supported on older systems

### **Processing Constraints**
- **Memory**: Requires sufficient RAM for large images
- **Storage**: Ensure adequate disk space for output
- **Network**: Large files may take time to transfer

## 🔒 **Security & Privacy**

### **Data Handling**
- Images are processed locally
- No data is transmitted to external services
- Temporary files are automatically cleaned up
- Input files remain unchanged

### **Access Control**
- Respects file system permissions
- Cannot access files outside allowed directories
- Requires appropriate read/write permissions

## 📚 **Related Tools**

- **Video Editing Tool** - For video frame extraction and editing
- **Screenshot Tool** - For screen capture and annotation
- **OCR Tool** - For text extraction from images
- **File Operations** - For file management and organization

## 🆕 **What's New in v1.4a**

- **New Image Editing Tool** - Comprehensive image manipulation capabilities
- **30+ Editing Actions** - Professional-grade editing operations
- **Cross-Platform Support** - Works on all major operating systems
- **Advanced Effects** - Modern image processing algorithms
- **AI Features** - Face detection and object recognition
- **Batch Processing** - Handle multiple images efficiently

---

*This document is part of MCP God Mode v1.4a - Advanced AI Agent Toolkit*

*For technical support or feature requests, please refer to the project documentation.*

## Natural Language Access
Users can request image editing operations using natural language:
- "Edit images"
- "Process image files"
- "Modify image content"
- "Enhance image quality"
- "Convert image formats"
