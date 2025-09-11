# Audio Editor Tool

## Overview
The Audio Editor tool provides comprehensive cross-platform audio editing capabilities with recording functionality. It offers unrestricted access to all audio processing features across Windows, macOS, Linux, iOS, and Android platforms.

## Features

### Core Capabilities
- **Audio Import/Export**: Support for WAV, MP3, FLAC, OGG, M4A, AAC, AIFF, WMA
- **Recording**: High-quality audio recording with device selection
- **Editing**: Non-destructive audio editing with real-time preview
- **Effects**: Professional audio effects and processing
- **Batch Processing**: Process multiple audio files simultaneously
- **Natural Language Interface**: Intuitive voice commands for all operations

### Recording Features
- **Unlimited Duration**: Record audio for any length of time
- **Device Selection**: Choose from all available audio input devices
- **Quality Control**: Full control over sample rate, bit depth, and channels
- **Real-Time Monitoring**: Live audio monitoring during recording
- **Format Selection**: Record directly to any supported format

### Editing Operations
- **Trim/Cut**: Precise audio trimming and cutting
- **Volume/Gain**: Unlimited gain adjustment
- **Fade Effects**: Customizable fade in/out effects
- **Normalization**: Loudness normalization to industry standards
- **Time Stretching**: Tempo changes without pitch alteration
- **Pitch Shifting**: Pitch changes without tempo alteration
- **Reverse**: Audio reversal
- **Advanced Effects**: Professional audio effects and processing

### Cross-Platform Support
- **Windows**: DirectShow and WASAPI integration
- **macOS**: Core Audio and AVFoundation support
- **Linux**: ALSA and PulseAudio support
- **Mobile**: PWA support for iOS and Android
- **Web**: Full browser-based audio processing

## Installation

### Dependencies
```bash
npm install ffmpeg-static fluent-ffmpeg multer
npm install @ffmpeg/ffmpeg @ffmpeg/util
npm install wavesurfer.js
```

### Server Setup
The audio editor is automatically registered with the MCP server. No additional configuration is required.

## Usage

### Command Line Interface

#### Basic Operations
```bash
# Get status
audio_editor.status()

# Open audio file
audio_editor.open({
  source: "/path/to/audio.mp3",
  sessionName: "My Audio"
})

# Record audio
audio_editor.record({
  duration: 30,
  device: "default",
  format: "wav",
  sampleRate: 44100,
  channels: 2
})

# Edit audio
audio_editor.edit({
  sessionId: "session-id",
  op: "trim",
  params: { start: 10, end: 20 }
})

# Export audio
audio_editor.export({
  sessionId: "session-id",
  format: "mp3",
  bitRateKbps: 192
})
```

#### Advanced Operations
```bash
# Batch processing
audio_editor.batch_process({
  inputFiles: ["file1.mp3", "file2.wav"],
  operation: "normalize",
  format: "flac"
})

# Audio analysis
audio_editor.analyze({
  sessionId: "session-id"
})

# Open viewer
audio_editor.open_viewer({
  sessionId: "session-id"
})
```

### Natural Language Interface

#### Basic Commands
- "Open audio file audio.mp3"
- "Record 30 seconds of audio"
- "Trim from 10 to 20 seconds"
- "Normalize the audio"
- "Export as MP3"

#### Advanced Workflows
- "Open audio.mp3, trim from 5 to 15 seconds, normalize, and export as WAV"
- "Record 60 seconds, adjust volume by 3 dB, and save as FLAC"
- "Batch process file1.mp3 and file2.wav with normalize"

#### Recording Commands
- "Record 30 seconds using microphone"
- "Record 120 seconds at 48kHz, 24-bit"
- "Start recording for 60 seconds with monitoring"

### Web Interface

#### Access
Navigate to `http://localhost:3000/viewer/audio` to access the web-based audio editor.

#### Features
- **Waveform Display**: High-resolution waveform visualization
- **Spectrogram**: Real-time spectrogram analysis
- **Transport Controls**: Play, pause, stop, and seek controls
- **Edit Tools**: Visual editing tools for precise audio manipulation
- **Export Options**: Direct export to various formats

## API Reference

### Tool Commands

#### `audio_editor.status()`
Get the current status of the audio editor.

**Returns:**
```json
{
  "enabled": true,
  "unrestricted": true,
  "active_sessions": 2,
  "total_sessions": 5,
  "storage_directory": "./.audio_sessions",
  "supported_formats": ["wav", "mp3", "flac", "ogg", "m4a", "aac"],
  "default_sample_rate": 44100,
  "default_channels": 2,
  "default_bit_depth": 16
}
```

#### `audio_editor.open(params)`
Open an audio file for editing.

**Parameters:**
- `source` (string): Path to audio file or URL
- `sessionName` (string): Name for the session
- `format` (string, optional): Override format detection

**Returns:**
```json
{
  "sessionId": "uuid",
  "name": "session-name",
  "durationSec": 120.5,
  "sampleRate": 44100,
  "channels": 2,
  "format": "mp3",
  "metadata": { ... }
}
```

#### `audio_editor.record(params)`
Record audio from an input device.

**Parameters:**
- `duration` (number): Recording duration in seconds
- `device` (string, optional): Audio input device name
- `format` (string, optional): Output format (default: "wav")
- `sampleRate` (number, optional): Sample rate (default: 44100)
- `channels` (number, optional): Number of channels (default: 2)
- `bitDepth` (number, optional): Bit depth (default: 16)
- `quality` (string, optional): Quality setting (default: "high")
- `enableMonitoring` (boolean, optional): Enable real-time monitoring
- `sessionName` (string, optional): Session name (default: "recording")

**Returns:**
```json
{
  "sessionId": "uuid",
  "name": "recording",
  "durationSec": 30.0,
  "sampleRate": 44100,
  "channels": 2,
  "format": "wav",
  "device": "default",
  "recording_quality": "high",
  "monitoring_enabled": true
}
```

#### `audio_editor.edit(params)`
Apply editing operations to an audio session.

**Parameters:**
- `sessionId` (string): Session ID
- `op` (string): Operation type
- `params` (object): Operation parameters

**Operations:**
- `trim`: `{ start: number, end: number }`
- `gain`: `{ gainDb: number }`
- `fade`: `{ fadeInMs: number, fadeOutMs: number }`
- `normalize`: `{}`
- `reverse`: `{}`
- `time_stretch`: `{ rate: number }`
- `pitch_shift`: `{ semitones: number }`

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

#### `audio_editor.export(params)`
Export an audio session to a file.

**Parameters:**
- `sessionId` (string): Session ID
- `format` (string, optional): Output format
- `sampleRate` (number, optional): Output sample rate
- `bitRateKbps` (number, optional): Bit rate for compressed formats
- `outputPath` (string, optional): Output file path
- `quality` (string, optional): Quality setting

**Returns:**
```json
{
  "exported": true,
  "sessionId": "uuid",
  "outputPath": "/path/to/output.mp3",
  "format": "mp3",
  "sampleRate": 44100,
  "bitRate": 192,
  "quality": "high",
  "editsApplied": 3
}
```

#### `audio_editor.batch_process(params)`
Process multiple audio files simultaneously.

**Parameters:**
- `inputFiles` (array): Array of input file paths
- `operation` (string, optional): Operation to apply
- `operationParams` (object, optional): Operation parameters
- `format` (string, optional): Output format
- `sampleRate` (number, optional): Output sample rate
- `bitRateKbps` (number, optional): Bit rate
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
      "inputFile": "file1.mp3",
      "success": true,
      "sessionId": "uuid",
      "outputPath": "/path/to/output1.mp3"
    }
  ]
}
```

### Server Routes

#### `GET /viewer/audio`
Serve the web-based audio editor interface.

#### `POST /api/audio/import`
Import an audio file for editing.

**Body:**
- `file`: Audio file (multipart/form-data)
- `sessionName`: Session name (optional)

#### `POST /api/audio/export`
Export an audio session.

**Body:**
```json
{
  "sessionId": "uuid",
  "format": "mp3",
  "bitRateKbps": 192
}
```

#### `GET /api/audio/session/:id`
Get session information.

#### `POST /api/audio/transform`
Apply audio transformations.

**Body:**
```json
{
  "sessionId": "uuid",
  "operation": "normalize",
  "parameters": {}
}
```

## Configuration

### Environment Variables
```bash
# Audio Editor Configuration
AUDIO_EDITOR_STORAGE_DIR=./.audio_sessions
AUDIO_EDITOR_MAX_DURATION=86400
AUDIO_EDITOR_DEFAULT_SAMPLE_RATE=44100
AUDIO_EDITOR_DEFAULT_CHANNELS=2
AUDIO_EDITOR_DEFAULT_BIT_DEPTH=16
AUDIO_EDITOR_SUPPORTED_FORMATS=wav,mp3,flac,ogg,m4a,aac
AUDIO_EDITOR_WEB_PORT=3000
```

### Storage
Audio sessions are stored in the configured storage directory with the following structure:
```
.audio_sessions/
├── session-id-1/
│   ├── source (original audio file)
│   ├── edits.json (edit operations)
│   └── metadata.json (session metadata)
└── session-id-2/
    └── ...
```

## Troubleshooting

### Common Issues

#### Audio Device Not Found
- Check available audio devices: `audio_editor.status()`
- Use "default" device if specific device is not available
- Ensure audio drivers are properly installed

#### Format Not Supported
- Check supported formats: `audio_editor.status()`
- Convert unsupported formats using external tools
- Use FFmpeg for format conversion

#### Recording Issues
- Check microphone permissions
- Verify audio input device is working
- Test with system audio recording tools

#### Export Failures
- Check file permissions
- Ensure sufficient disk space
- Verify output directory exists

### Performance Optimization

#### Large Files
- Use appropriate sample rates for your use case
- Consider format compression for storage
- Process files in chunks for very large files

#### Batch Processing
- Process files sequentially to avoid resource conflicts
- Use appropriate quality settings for batch operations
- Monitor system resources during batch processing

## Examples

### Basic Audio Editing Workflow
```javascript
// Open audio file
const session = await audio_editor.open({
  source: "/path/to/audio.mp3",
  sessionName: "My Track"
});

// Apply edits
await audio_editor.edit({
  sessionId: session.sessionId,
  op: "trim",
  params: { start: 10, end: 30 }
});

await audio_editor.edit({
  sessionId: session.sessionId,
  op: "normalize",
  params: {}
});

// Export
await audio_editor.export({
  sessionId: session.sessionId,
  format: "wav",
  outputPath: "/path/to/output.wav"
});
```

### Recording Workflow
```javascript
// Record audio
const recording = await audio_editor.record({
  duration: 60,
  device: "microphone",
  format: "wav",
  sampleRate: 48000,
  channels: 2
});

// Process recording
await audio_editor.edit({
  sessionId: recording.sessionId,
  op: "normalize",
  params: {}
});

// Export
await audio_editor.export({
  sessionId: recording.sessionId,
  format: "mp3",
  bitRateKbps: 256
});
```

### Batch Processing
```javascript
// Batch process multiple files
const result = await audio_editor.batch_process({
  inputFiles: [
    "/path/to/file1.mp3",
    "/path/to/file2.wav",
    "/path/to/file3.flac"
  ],
  operation: "normalize",
  format: "mp3",
  bitRateKbps: 192,
  outputDir: "/path/to/output"
});
```

## License
This tool operates without restrictions and provides full access to all audio processing capabilities.

## Support
For support and feature requests, please refer to the MCP God Mode documentation and community resources.
