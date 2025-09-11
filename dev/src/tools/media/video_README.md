# Video Editor Tool

## Overview
The Video Editor tool provides comprehensive cross-platform video editing capabilities with recording functionality. It offers unrestricted access to all video processing features across Windows, macOS, Linux, iOS, and Android platforms.

## Features

### Core Capabilities
- **Video Import/Export**: Support for MP4, AVI, MOV, MKV, WebM, FLV, WMV, 3GP, M4V
- **Recording**: High-quality video recording with device selection
- **Editing**: Non-destructive video editing with real-time preview
- **Effects**: Professional video effects and processing
- **Batch Processing**: Process multiple video files simultaneously
- **Natural Language Interface**: Intuitive voice commands for all operations

### Recording Features
- **Unlimited Duration**: Record video for any length of time
- **Device Selection**: Choose from all available video input devices
- **Quality Control**: Full control over resolution, frame rate, and bitrate
- **Real-Time Preview**: Live video preview during recording
- **Audio Sync**: Synchronized audio recording with video
- **Format Selection**: Record directly to any supported format

### Editing Operations
- **Trim/Cut**: Precise video trimming and cutting
- **Crop**: Customizable video cropping
- **Resize**: Resolution changes with aspect ratio control
- **Rotate/Flip**: Video orientation changes
- **Speed Control**: Variable speed playback (0.1x to 10x)
- **Fade Effects**: Customizable fade in/out effects
- **Color Correction**: Brightness, contrast, saturation, hue adjustment
- **Filters**: Advanced video filters and effects
- **Transitions**: Smooth transitions between clips
- **Text Overlay**: Add text and graphics to video
- **Audio Mixing**: Audio track management and mixing

### Cross-Platform Support
- **Windows**: DirectShow and Media Foundation integration
- **macOS**: AVFoundation and Core Media support
- **Linux**: V4L2 and GStreamer support
- **Mobile**: PWA support for iOS and Android
- **Web**: Full browser-based video processing

## Installation

### Dependencies
```bash
npm install ffmpeg-static fluent-ffmpeg multer
npm install @ffmpeg/ffmpeg @ffmpeg/util
npm install video.js
```

### Server Setup
The video editor is automatically registered with the MCP server. No additional configuration is required.

## Usage

### Command Line Interface

#### Basic Operations
```bash
# Get status
video_editor.status()

# Open video file
video_editor.open({
  source: "/path/to/video.mp4",
  sessionName: "My Video"
})

# Record video
video_editor.record({
  duration: 30,
  device: "default",
  format: "mp4",
  resolution: "1920x1080",
  frameRate: 30
})

# Edit video
video_editor.edit({
  sessionId: "session-id",
  op: "trim",
  params: { start: 10, end: 20 }
})

# Export video
video_editor.export({
  sessionId: "session-id",
  format: "mp4",
  resolution: "1280x720",
  quality: "high"
})
```

#### Advanced Operations
```bash
# Batch processing
video_editor.batch_process({
  inputFiles: ["file1.mp4", "file2.avi"],
  operation: "resize",
  operationParams: { width: 1920, height: 1080 },
  format: "mp4"
})

# Video analysis
video_editor.analyze({
  sessionId: "session-id"
})

# Open viewer
video_editor.open_viewer({
  sessionId: "session-id"
})
```

### Natural Language Interface

#### Basic Commands
- "Open video file video.mp4"
- "Record 30 seconds of video"
- "Trim from 10 to 20 seconds"
- "Crop to 1920x1080"
- "Export as MP4"

#### Advanced Workflows
- "Open video.mp4, trim from 5 to 15 seconds, resize to 1280x720, and export as MP4"
- "Load video.mp4, crop to 1920x1080, adjust brightness by 0.2, and save as AVI"
- "Record 60 seconds, trim from 5 to 55 seconds, and export as WebM"

#### Recording Commands
- "Record 30 seconds using webcam"
- "Record 120 seconds at 4K, 60fps"
- "Start recording for 60 seconds with audio"

### Web Interface

#### Access
Navigate to `http://localhost:3000/viewer/video` to access the web-based video editor.

#### Features
- **Timeline Display**: High-resolution timeline visualization
- **Preview Controls**: Play, pause, stop, and seek controls
- **Edit Tools**: Visual editing tools for precise video manipulation
- **Multi-Track Support**: Multiple video and audio track editing
- **Export Options**: Direct export to various formats

## API Reference

### Tool Commands

#### `video_editor.status()`
Get the current status of the video editor.

**Returns:**
```json
{
  "enabled": true,
  "unrestricted": true,
  "active_sessions": 2,
  "total_sessions": 5,
  "storage_directory": "./.video_sessions",
  "supported_formats": ["mp4", "avi", "mov", "mkv", "webm", "flv", "wmv"],
  "default_frame_rate": 30,
  "default_resolution": "1920x1080",
  "default_bitrate": 5000
}
```

#### `video_editor.open(params)`
Open a video file for editing.

**Parameters:**
- `source` (string): Path to video file or URL
- `sessionName` (string): Name for the session
- `format` (string, optional): Override format detection

**Returns:**
```json
{
  "sessionId": "uuid",
  "name": "session-name",
  "durationSec": 120.5,
  "resolution": "1920x1080",
  "frameRate": 30,
  "format": "mp4",
  "hasAudio": true,
  "metadata": { ... }
}
```

#### `video_editor.record(params)`
Record video from an input device.

**Parameters:**
- `duration` (number): Recording duration in seconds
- `device` (string, optional): Video input device name
- `format` (string, optional): Output format (default: "mp4")
- `resolution` (string, optional): Video resolution (default: "1920x1080")
- `frameRate` (number, optional): Frame rate (default: 30)
- `bitrate` (number, optional): Bitrate in kbps (default: 5000)
- `quality` (string, optional): Quality setting (default: "high")
- `enableAudio` (boolean, optional): Enable audio recording
- `enablePreview` (boolean, optional): Enable preview during recording
- `sessionName` (string, optional): Session name (default: "recording")

**Returns:**
```json
{
  "sessionId": "uuid",
  "name": "recording",
  "durationSec": 30.0,
  "resolution": "1920x1080",
  "frameRate": 30,
  "format": "mp4",
  "device": "default",
  "recording_quality": "high",
  "audio_enabled": true,
  "preview_enabled": true
}
```

#### `video_editor.edit(params)`
Apply editing operations to a video session.

**Parameters:**
- `sessionId` (string): Session ID
- `op` (string): Operation type
- `params` (object): Operation parameters

**Operations:**
- `trim`: `{ start: number, end: number }`
- `crop`: `{ x: number, y: number, width: number, height: number }`
- `resize`: `{ width: number, height: number }`
- `rotate`: `{ angle: number }`
- `flip`: `{ direction: "horizontal" | "vertical" }`
- `speed`: `{ rate: number }`
- `fade`: `{ fadeIn: number, fadeOut: number }`
- `brightness`: `{ value: number }`
- `contrast`: `{ value: number }`
- `saturation`: `{ value: number }`

**Returns:**
```json
{
  "editId": "uuid",
  "operation": "trim",
  "parameters": { "start": 10, "end": 20 },
  "sessionId": "uuid",
  "totalEdits": 3
}
```

#### `video_editor.export(params)`
Export a video session to a file.

**Parameters:**
- `sessionId` (string): Session ID
- `format` (string, optional): Output format
- `resolution` (string, optional): Output resolution
- `frameRate` (number, optional): Output frame rate
- `bitrate` (number, optional): Bitrate for compressed formats
- `quality` (string, optional): Quality setting
- `codec` (string, optional): Video codec
- `audioCodec` (string, optional): Audio codec
- `outputPath` (string, optional): Output file path

**Returns:**
```json
{
  "exported": true,
  "sessionId": "uuid",
  "outputPath": "/path/to/output.mp4",
  "format": "mp4",
  "resolution": "1920x1080",
  "frameRate": 30,
  "bitrate": 5000,
  "quality": "high",
  "editsApplied": 3
}
```

#### `video_editor.batch_process(params)`
Process multiple video files simultaneously.

**Parameters:**
- `inputFiles` (array): Array of input file paths
- `operation` (string, optional): Operation to apply
- `operationParams` (object, optional): Operation parameters
- `format` (string, optional): Output format
- `resolution` (string, optional): Output resolution
- `frameRate` (number, optional): Output frame rate
- `bitrate` (number, optional): Bitrate
- `quality` (string, optional): Quality setting
- `codec` (string, optional): Video codec
- `audioCodec` (string, optional): Audio codec
- `outputDir` (string, optional): Output directory

**Returns:**
```json
{
  "batchProcessed": true,
  "totalFiles": 3,
  "successfulFiles": 3,
  "failedFiles": 0,
  "results": [
    {
      "inputFile": "file1.mp4",
      "success": true,
      "sessionId": "uuid",
      "outputPath": "/path/to/output1.mp4"
    }
  ]
}
```

### Server Routes

#### `GET /viewer/video`
Serve the web-based video editor interface.

#### `POST /api/video/import`
Import a video file for editing.

**Body:**
- `file`: Video file (multipart/form-data)
- `sessionName`: Session name (optional)

#### `POST /api/video/export`
Export a video session.

**Body:**
```json
{
  "sessionId": "uuid",
  "format": "mp4",
  "resolution": "1920x1080",
  "quality": "high"
}
```

#### `GET /api/video/session/:id`
Get session information.

#### `POST /api/video/transform`
Apply video transformations.

**Body:**
```json
{
  "sessionId": "uuid",
  "operation": "resize",
  "parameters": { "width": 1920, "height": 1080 }
}
```

## Configuration

### Environment Variables
```bash
# Video Editor Configuration
VIDEO_EDITOR_STORAGE_DIR=./.video_sessions
VIDEO_EDITOR_MAX_DURATION=86400
VIDEO_EDITOR_DEFAULT_FRAME_RATE=30
VIDEO_EDITOR_DEFAULT_RESOLUTION=1920x1080
VIDEO_EDITOR_DEFAULT_BITRATE=5000
VIDEO_EDITOR_SUPPORTED_FORMATS=mp4,avi,mov,mkv,webm,flv,wmv
VIDEO_EDITOR_WEB_PORT=3000
```

### Storage
Video sessions are stored in the configured storage directory with the following structure:
```
.video_sessions/
├── session-id-1/
│   ├── source (original video file)
│   ├── edits.json (edit operations)
│   └── metadata.json (session metadata)
└── session-id-2/
    └── ...
```

## Troubleshooting

### Common Issues

#### Video Device Not Found
- Check available video devices: `video_editor.status()`
- Use "default" device if specific device is not available
- Ensure video drivers are properly installed

#### Format Not Supported
- Check supported formats: `video_editor.status()`
- Convert unsupported formats using external tools
- Use FFmpeg for format conversion

#### Recording Issues
- Check camera permissions
- Verify video input device is working
- Test with system video recording tools

#### Export Failures
- Check file permissions
- Ensure sufficient disk space
- Verify output directory exists

### Performance Optimization

#### Large Files
- Use appropriate resolutions for your use case
- Consider format compression for storage
- Process files in chunks for very large files

#### Batch Processing
- Process files sequentially to avoid resource conflicts
- Use appropriate quality settings for batch operations
- Monitor system resources during batch processing

## Examples

### Basic Video Editing Workflow
```javascript
// Open video file
const session = await video_editor.open({
  source: "/path/to/video.mp4",
  sessionName: "My Video"
});

// Apply edits
await video_editor.edit({
  sessionId: session.sessionId,
  op: "trim",
  params: { start: 10, end: 30 }
});

await video_editor.edit({
  sessionId: session.sessionId,
  op: "resize",
  params: { width: 1280, height: 720 }
});

// Export
await video_editor.export({
  sessionId: session.sessionId,
  format: "mp4",
  resolution: "1280x720",
  quality: "high"
});
```

### Recording Workflow
```javascript
// Record video
const recording = await video_editor.record({
  duration: 60,
  device: "webcam",
  format: "mp4",
  resolution: "1920x1080",
  frameRate: 30
});

// Process recording
await video_editor.edit({
  sessionId: recording.sessionId,
  op: "crop",
  params: { x: 0, y: 0, width: 1920, height: 1080 }
});

// Export
await video_editor.export({
  sessionId: recording.sessionId,
  format: "mp4",
  quality: "high"
});
```

### Batch Processing
```javascript
// Batch process multiple files
const result = await video_editor.batch_process({
  inputFiles: [
    "/path/to/file1.mp4",
    "/path/to/file2.avi",
    "/path/to/file3.mov"
  ],
  operation: "resize",
  operationParams: { width: 1920, height: 1080 },
  format: "mp4",
  quality: "high",
  outputDir: "/path/to/output"
});
```

## License
This tool operates without restrictions and provides full access to all video processing capabilities.

## Support
For support and feature requests, please refer to the MCP God Mode documentation and community resources.
