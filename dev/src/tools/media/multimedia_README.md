# Multimedia Tool - Unified Cross-Platform Media Editing Suite

## Overview

The Multimedia Tool is a comprehensive, unified multimedia editing suite that combines audio, image, and video processing capabilities into a single, powerful tool. Built with Sharp for image processing, FFmpeg for audio/video processing, and React for an intuitive user experience.

## Features

### 🎵 **Audio Processing**
- **Basic Editing**: Trim, normalize, fade in/out, gain adjustment, reverse
- **Advanced Processing**: Time stretch, pitch shift, audio effects
- **Cross-Platform Recording**: Microphone and system audio (stereo mix) recording
- **Device Detection**: Automatic audio device discovery across platforms
- **Format Support**: MP3, WAV, FLAC, AAC, OGG, M4A, WMA
- **Quality Control**: Configurable bitrate, sample rate, and compression

### 🖼️ **Image Processing**
- **Basic Editing**: Resize, crop, rotate, flip, filter application
- **Advanced Effects**: Blur, sharpen, grayscale, sepia, vignette, border
- **Color Adjustments**: Brightness, contrast, saturation, hue, gamma correction
- **AI Image Generation**: Generate images using AI models with graceful SVG fallback
- **SVG Generation**: Create vector graphics with multiple artistic styles
- **Format Support**: JPEG, PNG, GIF, WebP, TIFF, BMP, SVG, PDF

### 🎬 **Video Processing**
- **Basic Editing**: Cut, merge, resize, format conversion
- **Audio Integration**: Add/remove audio tracks, audio synchronization
- **Subtitle Support**: Add/remove subtitles, timing adjustment
- **Format Support**: MP4, AVI, MOV, MKV, WebM, FLV, WMV, M4V

### 🔧 **Universal Features**
- **Session Management**: Track multiple editing sessions simultaneously
- **Project Organization**: Group related media sessions into projects
- **Batch Processing**: Process multiple files or operations efficiently
- **Cross-Platform**: Works on Windows, macOS, Linux, iOS, Android
- **Web Interface**: Modern PWA with offline capabilities
- **Natural Language**: Voice commands for all operations
- **Content Generation**: AI-powered image and SVG generation with intelligent fallback
- **Audio Recording**: Cross-platform system audio and microphone recording

## Quick Start

### CLI Usage via Tool API

```bash
# Open a media file
multimedia_tool.open({
  source: "/path/to/media.jpg",
  sessionName: "My Edit Session",
  type: "image"
})

# Apply an operation
multimedia_tool.edit({
  sessionId: "session-id",
  operation: "resize",
  params: { width: 800, height: 600 }
})

# Export the result
multimedia_tool.export({
  sessionId: "session-id",
  format: "png",
  quality: 90,
  path: "/path/to/output.png"
})
```

### Web Interface

1. **Access the Tool**: Navigate to `/viewer/multimedia` in your browser
2. **Upload Media**: Drag and drop or click to upload media files
3. **Edit**: Use the intuitive interface to apply edits
4. **Export**: Save in your preferred format and quality

### Natural Language Commands

```bash
# Open and edit an image
"Open image /path/to/photo.jpg, resize to 800x600, apply grayscale filter, and export as PNG"

# Process audio
"Load audio /path/to/song.mp3, normalize volume, add 2 second fade in, and export as WAV"

# Record system audio
"Record what's playing for 30 seconds"
"Record system audio for 60 seconds"
"Record stereo mix for 45 seconds"

# Generate content
"Generate an SVG of a mountain landscape with geometric style"
"Create an AI image of a futuristic city with realistic style"
"Generate SVG 800x600 of abstract patterns"

# Batch process multiple files
"Batch process sessions 1,2,3 with operations: resize to 1920x1080, apply sharpen filter"

# Create a project
"Create mixed media project named 'My Video' with sessions 1,2,3"
```

## API Reference

### Core Functions

#### `status()`
Get current status of all active sessions and projects.

**Returns:**
```typescript
{
  sessions: Array<{
    id: string;
    name: string;
    type: "audio" | "image" | "video";
    metadata: any;
    layers: number;
    createdAt: string;
    modifiedAt: string;
  }>;
  projects: Array<{
    name: string;
    type: string;
    sessionCount: number;
  }>;
  totalSessions: number;
  totalProjects: number;
}
```

#### `open(input)`
Open a media file for editing.

**Parameters:**
- `source`: Media path or URL
- `sessionName`: Name for the editing session
- `type`: Media type (audio, image, video) - auto-detected if not specified

**Returns:**
```typescript
{
  sessionId: string;
  name: string;
  type: "audio" | "image" | "video";
  metadata: any;
}
```

#### `edit(input)`
Apply an editing operation to a media session.

**Parameters:**
- `sessionId`: ID of the editing session
- `operation`: Operation type (see supported operations below)
- `params`: Operation-specific parameters

**Returns:**
```typescript
{
  operationId: string;
  layers: Array<Operation>;
}
```

#### `export(input)`
Export the edited media to a file.

**Parameters:**
- `sessionId`: ID of the editing session
- `format`: Output format
- `quality`: Quality setting (1-100)
- `path`: Output file path
- `options`: Additional export options

**Returns:**
```typescript
{
  success: boolean;
  path: string;
  format: string;
}
```

### Advanced Functions

#### `batchProcess(input)`
Process multiple operations on multiple sessions.

**Parameters:**
- `sessionIds`: Array of session IDs to process
- `operations`: Array of operations to apply
- `outputDir`: Directory for output files

#### `createProject(input)`
Create a project to organize related sessions.

**Parameters:**
- `name`: Project name
- `type`: Project type (audio, image, video, mixed)
- `sessions`: Array of session IDs to include

#### `getSession(sessionId)`
Get detailed information about a session.

#### `deleteSession(sessionId)`
Delete a session and clean up associated files.

#### `recordAudio(input)`
Record audio from microphone or system audio (stereo mix).

**Parameters:**
- `deviceType`: 'microphone', 'stereo_mix', or 'auto'
- `duration`: Recording duration in seconds
- `format`: Output format (wav, mp3, flac, aac)
- `quality`: Recording quality (1-100)

**Returns:**
```typescript
{
  sessionId: string;
  path: string;
  duration: number;
}
```

#### `getAudioDevices()`
Get list of available audio input devices.

**Returns:**
```typescript
{
  input: Array<{
    name: string;
    id: string;
    type: 'microphone' | 'stereo_mix';
    platform: string;
  }>;
  output: Array<{
    name: string;
    id: string;
    type: string;
    platform: string;
  }>;
}
```

#### `generateSVG(input)`
Generate SVG vector graphics from text prompts.

**Parameters:**
- `prompt`: Description of the SVG to generate
- `width`: SVG width in pixels
- `height`: SVG height in pixels
- `style`: Generation style (minimal, geometric, organic, technical, artistic, detailed)
- `colors`: Optional color palette (hex codes)
- `elements`: Optional specific elements to include

**Returns:**
```typescript
{
  sessionId: string;
  name: string;
  dimensions: { width: number; height: number };
  format: "svg";
  path: string;
  svgContent: string;
}
```

#### `generateAIImage(input)`
Generate AI images with graceful SVG fallback.

**Parameters:**
- `prompt`: Description of the image to generate
- `width`: Image width in pixels
- `height`: Image height in pixels
- `style`: Generation style (realistic, artistic, cartoon, abstract, photographic, digital_art)
- `model`: AI model to use (auto-detect if not specified)
- `fallbackToSVG`: Enable SVG fallback when model not supported
- `generationQuality`: Quality level (low, medium, high)

**Returns:**
```typescript
{
  sessionId: string;
  name: string;
  dimensions: { width: number; height: number };
  format: "png" | "svg";
  path: string;
  model: string;
}
```

## Supported Operations

### Audio Operations
- **trim**: Trim audio from start to end time
- **normalize**: Normalize audio volume levels
- **fade**: Add fade in/out effects
- **gain**: Adjust audio gain in decibels
- **reverse**: Reverse audio playback
- **time_stretch**: Change playback speed without pitch
- **pitch_shift**: Change pitch without speed

### Image Operations
- **resize**: Resize image with various fit modes
- **crop**: Extract a rectangular region
- **rotate**: Rotate image by specified angle
- **flip**: Flip image horizontally or vertically
- **filter**: Apply filters (blur, sharpen, grayscale, sepia, negate)
- **enhance**: Adjust brightness, saturation, hue
- **adjust**: Apply gamma correction and contrast
- **vignette**: Add vignette effect
- **border**: Add colored border
- **generate_svg**: Generate SVG vector graphics from prompts
- **generate_ai_image**: Generate AI images with SVG fallback

### Video Operations
- **cut**: Cut video from start to end time
- **merge**: Merge multiple video files
- **convert**: Convert between video formats
- **resize_video**: Resize video dimensions
- **add_audio**: Add audio track to video
- **add_subtitles**: Add subtitle track
- **apply_effects**: Apply video effects

### Universal Operations
- **composite**: Layer multiple media elements
- **watermark**: Add text or image watermarks
- **batch_process**: Process multiple operations

### Audio Recording Operations
- **record_audio**: Record from microphone or system audio
- **get_audio_devices**: List available audio input devices
- **start_recording**: Begin audio recording session

### Content Generation Operations
- **generate_svg**: Create SVG vector graphics from text descriptions
- **generate_ai_image**: Generate AI images with intelligent fallback

## Configuration

### Environment Variables

```bash
# Multimedia processing settings
MULTIMEDIA_MAX_FILE_SIZE=100MB
MULTIMEDIA_TEMP_DIR=/tmp/mcp_multimedia
MULTIMEDIA_CACHE_SIZE=200MB

# Quality settings
MULTIMEDIA_DEFAULT_QUALITY=80
MULTIMEDIA_MAX_QUALITY=100

# Performance settings
MULTIMEDIA_MAX_SESSIONS=20
MULTIMEDIA_BATCH_SIZE=10
MULTIMEDIA_PARALLEL_PROCESSING=true

# AI Model Configuration
OPENAI_API_KEY=your_openai_api_key_here
STABILITY_API_KEY=your_stability_api_key_here

# Audio Recording Settings
AUDIO_RECORDING_DEFAULT_DURATION=30
AUDIO_RECORDING_DEFAULT_FORMAT=wav
AUDIO_RECORDING_DEFAULT_QUALITY=80

# Content Generation Settings
SVG_GENERATION_DEFAULT_STYLE=minimal
AI_IMAGE_GENERATION_DEFAULT_STYLE=realistic
AI_IMAGE_GENERATION_FALLBACK_TO_SVG=true
```

### Web Interface Configuration

```typescript
// web/config.ts
export const config = {
  maxFileSize: 100 * 1024 * 1024, // 100MB
  supportedFormats: {
    audio: ['mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a'],
    image: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'tiff', 'bmp', 'svg'],
    video: ['mp4', 'avi', 'mov', 'mkv', 'webm', 'flv', 'wmv', 'm4v']
  },
  defaultQuality: 80,
  maxSessions: 20,
  autoSave: true,
  enableOffline: true
};
```

## New Features

### 🎙️ **Cross-Platform Audio Recording**

The multimedia tool now supports comprehensive audio recording capabilities across all platforms:

#### **System Audio Recording (Stereo Mix)**
- **Windows**: DirectShow integration for stereo mix capture
- **macOS**: AVFoundation support for system audio recording
- **Linux**: PulseAudio/ALSA integration for loopback recording
- **Natural Language**: "Record what's playing", "Record system audio", "Record stereo mix"

#### **Microphone Recording**
- **Cross-Platform**: Automatic device detection and configuration
- **Quality Control**: Configurable bitrate, sample rate, and compression
- **Format Support**: WAV, MP3, FLAC, AAC output formats
- **Real-Time**: Live recording with visual feedback

### 🎨 **AI-Powered Content Generation**

#### **SVG Generation**
- **Multiple Styles**: Minimal, geometric, organic, technical, artistic, detailed
- **Intelligent Parsing**: Extracts elements and colors from natural language prompts
- **Customizable**: Width, height, color palette, and element specification
- **Vector Graphics**: Scalable, lightweight output perfect for web and print

#### **AI Image Generation**
- **Model Support**: OpenAI DALL-E, Stability AI, local models
- **Graceful Fallback**: Automatically falls back to SVG when AI models unavailable
- **Style Options**: Realistic, artistic, cartoon, abstract, photographic, digital art
- **Quality Control**: Low, medium, high quality settings
- **Smart Mapping**: AI styles intelligently mapped to appropriate SVG equivalents

#### **Intelligent Fallback System**
- **Model Detection**: Automatically detects available AI models
- **API Key Validation**: Checks for required API keys before attempting generation
- **Network Resilience**: Handles network failures gracefully
- **Style Translation**: Converts AI image styles to appropriate SVG styles

### 🌐 **Enhanced Natural Language Interface**

#### **Audio Recording Commands**
```bash
"Record what's playing for 30 seconds"
"Record system audio for 60 seconds"
"Record stereo mix for 45 seconds"
"Record microphone for 2 minutes"
"Start recording system audio"
```

#### **Content Generation Commands**
```bash
"Generate an SVG of a mountain landscape with geometric style"
"Create an AI image of a futuristic city with realistic style"
"Generate SVG 800x600 of abstract patterns"
"Make an artistic SVG with blue and green colors"
"Generate AI image with DALL-E model"
```

### 🎛️ **Enhanced Web Interface**

#### **Audio Recording Panel**
- **Device Selection**: Visual list of available audio devices
- **Recording Controls**: One-click recording for system audio and microphone
- **Real-Time Status**: Visual feedback during recording
- **Format Options**: Quality and format selection

#### **Content Generation Panel**
- **Prompt Input**: Multi-line textarea for detailed descriptions
- **Style Selection**: Dropdown with all available generation styles
- **Dimension Control**: Width and height input fields
- **Model Selection**: AI model picker with auto-detection
- **Quick Generation**: One-click buttons for rapid content creation

## Cross-Platform Notes

### Windows
- Full support for all media formats
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

### Large Media Files
- Use streaming processing for very large files
- Consider downsampling for preview operations
- Use appropriate quality settings for final export
- Enable parallel processing for batch operations

### Memory Management
- Close unused sessions to free memory
- Use appropriate media formats for your use case
- Consider media compression for storage
- Monitor memory usage during batch operations

### Network Optimization
- Use WebP format for web delivery
- Implement progressive loading for large media
- Cache processed results when possible
- Use CDN for static assets

## Troubleshooting

### Common Issues

**"Media format not supported"**
- Ensure the media format is in the supported list
- Check if the file is corrupted
- Try converting to a different format first

**"Out of memory"**
- Reduce media file size before processing
- Close unused editing sessions
- Increase system memory or use smaller batch sizes

**"Export failed"**
- Check output directory permissions
- Ensure sufficient disk space
- Verify output format is supported

**"Audio recording failed"**
- Check audio device permissions
- Ensure audio device is not in use by another application
- Verify system audio (stereo mix) is enabled on Windows
- Check PulseAudio/ALSA configuration on Linux

**"AI image generation failed"**
- Verify API keys are set correctly (OPENAI_API_KEY, STABILITY_API_KEY)
- Check network connectivity
- Ensure fallbackToSVG is enabled for graceful degradation
- Verify model availability and permissions

**"SVG generation failed"**
- Check prompt length and content
- Verify dimension parameters are valid
- Ensure sufficient memory for complex SVG generation

### Debug Mode

Enable debug mode for detailed logging:

```bash
DEBUG=multimedia_tool:* node server.js
```

### Performance Monitoring

Monitor performance with built-in metrics:

```typescript
const metrics = await multimedia_tool.getMetrics();
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

# Install FFmpeg (audio/video processing)
npm install fluent-ffmpeg ffmpeg-static

# Install additional dependencies for new features
npm install @modelcontextprotocol/sdk  # MCP SDK

# Start development server
npm run dev

# Run tests
npm test

# Build for production
npm run build
```

### Adding New Operations

1. Add operation to the `EditInput` schema
2. Implement the operation in the appropriate export function
3. Add corresponding processing code
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

**Multimedia Tool** - Professional multimedia processing made simple and accessible across all platforms.
