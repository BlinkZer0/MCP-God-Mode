# Enhanced Media Editor Tool

## Overview
The **Enhanced Media Editor Tool** is a comprehensive cross-platform unified media editing suite that provides advanced audio, video, and image editing capabilities. It combines Kdenlive 25.09.0, Audacity 3.7.6, GIMP 3.0, and AI generation features with intelligent fallback options.

## Features
- **Unified Media Editing**: Advanced audio, video, and image editing in one tool
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **AI Generation**: Intelligent AI generation with SVG, animated SVG, and MIDI fallbacks
- **Professional Tools**: Integration with Kdenlive, Audacity, and GIMP
- **Natural Language Interface**: Intuitive natural language command processing
- **Advanced Features**: Timeline-based editing, multi-track audio, layer-based image editing

## Usage

### Media Processing
```bash
# Process audio
{
  "action": "process_audio",
  "audioOperation": "normalize",
  "source": "./audio_file.wav"
}

# Process image
{
  "action": "process_image",
  "imageOperation": "resize",
  "source": "./image.jpg",
  "imageParams": {
    "width": 1920,
    "height": 1080
  }
}

# Process video
{
  "action": "process_video",
  "videoOperation": "add_clip",
  "source": "./video.mp4"
}
```

### AI Generation
```bash
# Generate AI image
{
  "action": "generate_ai_image",
  "prompt": "A beautiful sunset over mountains",
  "width": 1024,
  "height": 1024
}

# Generate AI video
{
  "action": "generate_ai_video",
  "prompt": "A cat playing with a ball",
  "width": 1920,
  "height": 1080
}

# Generate AI audio
{
  "action": "generate_ai_audio",
  "prompt": "Peaceful nature sounds"
}
```

### Session Management
```bash
# Create session
{
  "action": "create_session",
  "sessionName": "My Project",
  "type": "mixed"
}

# Get session
{
  "action": "get_session",
  "sessionId": "session_001"
}

# Delete session
{
  "action": "delete_session",
  "sessionId": "session_001"
}
```

## Parameters

### Media Parameters
- **action**: Media editor action to perform
- **source**: Media source path or URL
- **type**: Media type (audio, image, video, mixed)
- **sessionId**: Session identifier for operations

### Audio Parameters
- **audioOperation**: Audio operation to apply
- **audioParams**: Audio operation parameters
- **trackId**: Audio track identifier

### Image Parameters
- **imageOperation**: Image operation to apply
- **imageParams**: Image operation parameters
- **layerId**: Image layer identifier

### Video Parameters
- **videoOperation**: Video operation to apply
- **videoParams**: Video operation parameters
- **clipId**: Video clip identifier

## Output Format
```json
{
  "success": true,
  "action": "process_audio",
  "result": {
    "sessionId": "session_001",
    "audioOperation": "normalize",
    "status": "completed",
    "outputPath": "./processed_audio.wav"
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows media editing
- **Linux**: Complete functionality with Linux media editing
- **macOS**: Full feature support with macOS media editing
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Audio Processing
```bash
# Process audio
{
  "action": "process_audio",
  "audioOperation": "normalize",
  "source": "./audio_file.wav"
}

# Result
{
  "success": true,
  "result": {
    "sessionId": "session_001",
    "audioOperation": "normalize",
    "status": "completed",
    "outputPath": "./processed_audio.wav"
  }
}
```

### Example 2: Image Processing
```bash
# Process image
{
  "action": "process_image",
  "imageOperation": "resize",
  "source": "./image.jpg",
  "imageParams": {
    "width": 1920,
    "height": 1080
  }
}

# Result
{
  "success": true,
  "result": {
    "sessionId": "session_001",
    "imageOperation": "resize",
    "status": "completed",
    "outputPath": "./resized_image.jpg"
  }
}
```

### Example 3: AI Generation
```bash
# Generate AI image
{
  "action": "generate_ai_image",
  "prompt": "A beautiful sunset over mountains",
  "width": 1024,
  "height": 1024
}

# Result
{
  "success": true,
  "result": {
    "generated_content": "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAyNCIgaGVpZ2h0PSIxMDI0Ii4uLg==",
    "content_type": "svg",
    "fallback_used": true,
    "prompt": "A beautiful sunset over mountains"
  }
}
```

## Error Handling
- **Media Errors**: Proper handling of media file access and processing issues
- **AI Errors**: Secure handling of AI generation failures with intelligent fallbacks
- **Session Errors**: Robust error handling for session management failures
- **Format Errors**: Safe handling of unsupported media formats

## Related Tools
- **Media Processing**: Media processing and editing tools
- **AI Generation**: AI content generation tools
- **File Management**: File management and operations tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Enhanced Media Editor Tool, please refer to the main MCP God Mode documentation or contact the development team.
