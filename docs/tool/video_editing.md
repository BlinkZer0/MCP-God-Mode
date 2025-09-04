# Video Editing Tool

## Overview
Advanced video editing and manipulation tool with cross-platform support. Perform video processing, editing, format conversion, effects application, video analysis, and recording across Windows, Linux, macOS, Android, and iOS.

## Description
Advanced video editing and manipulation tool with cross-platform support. Perform video processing, editing, format conversion, effects application, video analysis, and recording across Windows, Linux, macOS, Android, and iOS. Includes comprehensive screen recording, webcam capture, and window recording capabilities.

## Input Schema
- **action** (required): Video editing action to perform. 'convert' for format conversion, 'trim' for cutting video segments, 'merge' for combining videos, 'split' for dividing videos, 'resize' for changing dimensions, 'apply_effects' for visual effects, 'extract_audio' for audio extraction, 'add_subtitles' for subtitle overlay, 'stabilize' for video stabilization, 'analyze' for video analysis, 'compress' for size reduction, 'enhance' for quality improvement, 'record' for general video recording, 'record_screen' for screen recording, 'record_webcam' for webcam recording, 'record_window' for specific window recording, 'record_region' for region recording.
- **input_file** (required): Path to the input video file. Examples: './video.mp4', '/home/user/videos/input.avi', 'C:\\Users\\User\\Videos\\input.mov'. Required for all actions except recording actions.
- **output_file** (optional): Path for the output video file. Examples: './output.mp4', '/home/user/videos/output.avi'. If not specified, auto-generates based on input file.
- **format** (optional): Output video format. Examples: 'mp4', 'avi', 'mov', 'mkv', 'webm'. Defaults to input format if not specified.
- **start_time** (optional): Start time for trim/split operations. Format: 'HH:MM:SS' or 'HH:MM:SS.mmm'. Examples: '00:00:10', '01:30:45.500'.
- **end_time** (optional): End time for trim/split operations. Format: 'HH:MM:SS' or 'HH:MM:SS.mmm'. Examples: '00:02:30', '03:15:20.750'.
- **resolution** (optional): Target resolution for resize operations. Examples: '1920x1080', '1280x720', '4K', '720p'.
- **quality** (optional): Video quality setting. 'low' for fast processing, 'high' for best quality, 'ultra' for maximum quality.
- **effects** (optional): Visual effects to apply. Examples: ['brightness:1.2', 'contrast:1.1', 'saturation:0.8', 'blur:5', 'sharpen:2'].
- **subtitle_file** (optional): Path to subtitle file for overlay. Examples: './subtitles.srt', '/home/user/subtitles.vtt'.
- **compression_level** (optional): Compression level for output video. Higher compression reduces file size but may affect quality.
- **audio_codec** (optional): Audio codec for output. Examples: 'aac', 'mp3', 'opus', 'flac'.
- **video_codec** (optional): Video codec for output. Examples: 'h264', 'h265', 'vp9', 'av1'.
- **duration** (optional): Duration for recording operations in seconds. Examples: 30 for 30 seconds, 300 for 5 minutes.
- **frame_rate** (optional): Frame rate for recording or processing in fps. Examples: 24 for film, 30 for standard, 60 for smooth motion.
- **audio_source** (optional): Audio source for recording. Examples: 'default', 'microphone', 'system_audio', 'none'.
- **video_source** (optional): Video source for recording. Examples: 'screen', 'webcam', 'window', 'region'.
- **include_cursor** (optional): Whether to include mouse cursor in screen recordings. Set to true to capture cursor movements.
- **include_audio** (optional): Whether to include audio in recordings. Set to false for silent recordings.
- **recording_area** (optional): Specific area to record when using 'record_region' action.
- **window_title** (optional): Title of the specific window to record when using 'record_window' action.
- **webcam_device** (optional): Webcam device name for webcam recording. Examples: 'default', 'HD WebCam', 'USB Camera'.
- **delay_seconds** (optional): Delay before starting recording in seconds. Useful for preparing the scene.
- **auto_stop** (optional): Whether to automatically stop recording after the specified duration. Set to false for manual stop.
- **show_recording_indicator** (optional): Whether to show a recording indicator during capture. Set to false for stealth recording.

## Output Schema
- **success**: Whether the video editing operation was successful.
- **action_performed**: The video editing action that was executed.
- **input_file**: Path to the input video file.
- **output_file**: Path to the output video file.
- **processing_time**: Time taken to process the video in seconds.
- **file_size_reduction**: Percentage reduction in file size (for compression operations).
- **quality_metrics**: Quality metrics of the processed video including resolution, bitrate, frame rate, and duration.
- **message**: Summary message of the video editing operation.
- **error**: Error message if the operation failed.
- **platform**: Platform where the video editing tool was executed.
- **timestamp**: Timestamp when the operation was performed.

## Natural Language Access
Users can request video editing operations using natural language:
- "Convert my video to MP4 format"
- "Trim the video from 1 minute to 3 minutes"
- "Resize my video to 1080p resolution"
- "Add brightness and contrast effects to my video"
- "Extract audio from my video file"
- "Compress my video to reduce file size"
- "Merge two video files together"
- "Add subtitles to my video"
- "Stabilize shaky video footage"
- "Enhance video quality"
- "Record my screen for 5 minutes"
- "Record from my webcam for 2 minutes"
- "Record the Chrome window for 10 minutes"
- "Record this specific area of my screen"

## Usage Examples

### Convert Video Format
```javascript
// Convert AVI to MP4
const result = await video_editing({
  action: "convert",
  input_file: "./input.avi",
  output_file: "./output.mp4",
  format: "mp4",
  quality: "high"
});
```

### Trim Video
```javascript
// Trim video from 30 seconds to 2 minutes
const result = await video_editing({
  action: "trim",
  input_file: "./long_video.mp4",
  start_time: "00:00:30",
  end_time: "00:02:00",
  output_file: "./trimmed_video.mp4"
});
```

### Apply Visual Effects
```javascript
// Apply brightness and contrast effects
const result = await video_editing({
  action: "apply_effects",
  input_file: "./dark_video.mp4",
  effects: ["brightness:1.3", "contrast:1.2", "saturation:1.1"],
  quality: "ultra"
});
```

### Compress Video
```javascript
// Compress video to reduce file size
const result = await video_editing({
  action: "compress",
  input_file: "./large_video.mp4",
  compression_level: "high",
  quality: "medium"
});
```

### Resize Video
```javascript
// Resize video to 720p
const result = await video_editing({
  action: "resize",
  input_file: "./hd_video.mp4",
  resolution: "1280x720",
  output_file: "./720p_video.mp4"
});
```

### Screen Recording
```javascript
// Record screen for 60 seconds
const result = await video_editing({
  action: "record_screen",
  duration: 60,
  frame_rate: 30,
  include_cursor: true,
  include_audio: true,
  format: "mp4"
});
```

### Webcam Recording
```javascript
// Record from webcam for 30 seconds
const result = await video_editing({
  action: "record_webcam",
  duration: 30,
  frame_rate: 24,
  audio_source: "microphone",
  webcam_device: "HD WebCam",
  format: "mp4"
});
```

### Window Recording
```javascript
// Record specific application window
const result = await video_editing({
  action: "record_window",
  window_title: "Chrome",
  duration: 120,
  include_cursor: true,
  include_audio: false,
  format: "mp4"
});
```

### Region Recording
```javascript
// Record specific screen region
const result = await video_editing({
  action: "record_region",
  recording_area: {
    x: 100,
    y: 100,
    width: 800,
    height: 600
  },
  duration: 45,
  frame_rate: 30,
  include_cursor: true,
  format: "mp4"
});
```

## Platform Support
- **Windows**: Full support with FFmpeg and native video tools
- **Linux**: Full support with FFmpeg, OpenCV, and GStreamer
- **macOS**: Full support with FFmpeg and Core Video frameworks
- **Android**: Limited support through Termux and system APIs
- **iOS**: Limited support through system frameworks and jailbreak tools

## Video Processing Capabilities

### Format Conversion
- Support for all major video formats (MP4, AVI, MOV, MKV, WebM)
- Batch conversion capabilities
- Quality-preserving conversions
- Custom codec selection

### Video Editing
- Precise trimming and splitting
- Multiple video merging
- Frame-accurate editing
- Non-destructive editing workflow

### Effects and Enhancement
- Brightness, contrast, and saturation adjustment
- Blur, sharpen, and noise reduction
- Color correction and grading
- Video stabilization and enhancement

### Audio Processing
- Audio extraction from video
- Audio format conversion
- Volume normalization
- Audio quality enhancement

### Quality Control
- Multiple quality presets
- Custom quality settings
- Compression optimization
- Quality metrics analysis

## Performance Features
- Hardware acceleration support
- Multi-threaded processing
- Progress monitoring
- Batch processing capabilities
- Memory optimization

## Security Features
- File validation and sanitization
- Safe file path handling
- Input file verification
- Output file security checks

## Error Handling
- File format validation
- Codec compatibility checks
- Memory and storage validation
- Processing error recovery
- Detailed error messages

## Related Tools
- `file_ops` - File system operations
- `fs_read_text` - Read text files
- `fs_write_text` - Write text files
- `download_file` - Download video files
- `mobile_hardware` - Mobile camera access

## Use Cases
- **Content Creation**: Edit and enhance video content for social media
- **Professional Video**: Process videos for professional presentations
- **Educational Content**: Create and edit educational videos
- **Personal Projects**: Edit home videos and personal content
- **Content Optimization**: Compress and optimize videos for web
- **Format Conversion**: Convert videos for different devices and platforms
- **Video Analysis**: Analyze video quality and characteristics
- **Batch Processing**: Process multiple videos simultaneously
- **Screen Recording**: Capture screen content for tutorials and demos
- **Webcam Recording**: Record video content from camera devices
- **Window Recording**: Capture specific application windows
- **Region Recording**: Record custom screen areas
- **Tutorial Creation**: Create step-by-step video guides
- **Bug Reporting**: Record software issues for developers
- **Live Streaming**: Prepare content for streaming platforms
