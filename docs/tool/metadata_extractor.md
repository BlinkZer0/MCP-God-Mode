# Metadata Extractor Tool

## Overview
The **Metadata Extractor Tool** provides comprehensive metadata extraction and geolocation capabilities for media files, URLs, and social media posts. This tool combines advanced metadata analysis with platform-aware stripping detection, visual analysis, and geotagging assistance for forensic and OSINT operations.

## Features
- **Multi-Source Input**: URL, file, Reddit links, and social media posts
- **Platform-Aware Analysis**: Knows which platforms strip metadata
- **Comprehensive Metadata Extraction**: EXIF, video, audio, and file metadata
- **Visual Analysis**: OCR, object detection, license plate recognition
- **Geolocation Services**: GPS extraction, map integration, weather lookup
- **Cross-Platform Search**: Find cross-posts on other platforms
- **Security Assessment**: Privacy risk analysis and recommendations
- **Cross-Platform**: Works on Windows, Linux, macOS, Android, and iOS

## Core Functions

### URL/File Intake
- **Reddit Links**: Direct Reddit post URL processing
- **Social Media URLs**: Instagram, Twitter, Facebook, TikTok, YouTube
- **Direct URLs**: Any media file URL
- **File Upload**: Local file processing
- **Batch Processing**: Multiple files or URLs

### Metadata Extraction
- **EXIF Data**: Camera settings, GPS coordinates, timestamps
- **Video Metadata**: Codec, resolution, frame rate, duration
- **Audio Metadata**: Bitrate, sample rate, artist, album information
- **File Information**: Size, type, creation/modification dates
- **Software Tags**: Editing software, camera firmware, processing tools

### Platform-Aware Stripping Detection
- **Reddit**: Metadata stripped - no EXIF data expected
- **Imgur**: Metadata stripped - no EXIF data expected
- **TikTok**: Metadata stripped - no EXIF data expected
- **YouTube**: Metadata stripped - no EXIF data expected
- **Instagram**: Low metadata survival chance
- **Twitter**: Low metadata survival chance
- **Facebook**: Low metadata survival chance
- **Unknown Platforms**: Medium to high metadata survival chance

### Visual Analysis
- **OCR Text Detection**: Signs, license plates, text in images
- **Object Detection**: Cars, buildings, people, landmarks
- **Face Detection**: Number of faces and approximate locations
- **Landmark Recognition**: Famous landmarks and locations
- **Text Region Analysis**: Bounding boxes and confidence scores

### Geolocation Services
- **GPS Coordinate Extraction**: Latitude, longitude, altitude
- **Address Resolution**: Street address, city, country
- **Map Integration**: Google Maps links and Street View
- **Weather Lookup**: Historical weather data based on timestamp
- **Sun Position Analysis**: Shadow direction and time of day

### Cross-Post Tracking
- **Reverse Image Search**: Google Lens, Yandex, Perplexity integration
- **Platform Detection**: Find same content on other platforms
- **Metadata Comparison**: Compare metadata across platforms
- **Upload Date Analysis**: Timeline of content sharing

## Parameters

### Required Parameters
- `input_type` (enum): Type of input to process
  - Options: "url", "file", "reddit_link", "social_media"
- `input_source` (string): URL, file path, or social media link to analyze
- `extraction_type` (enum): Type of extraction to perform
  - Options: "metadata_only", "geolocation", "visual_analysis", "comprehensive"

### Optional Parameters
- `include_exif` (boolean): Extract EXIF metadata from images
- `include_video_metadata` (boolean): Extract metadata from video files
- `include_audio_metadata` (boolean): Extract metadata from audio files
- `platform_stripping_check` (boolean): Check if platform strips metadata
- `visual_analysis` (boolean): Perform visual analysis (OCR, object detection)
- `cross_post_search` (boolean): Search for cross-posts on other platforms
- `geotagging_assist` (boolean): Provide geotagging assistance with maps
- `weather_lookup` (boolean): Look up weather data based on timestamp
- `sun_position_analysis` (boolean): Analyze sun position based on shadows
- `output_format` (enum): Output format for results
  - Options: "json", "csv", "html", "pdf"
- `include_original_file` (boolean): Include original file in output

## Output Schema

```json
{
  "success": boolean,
  "message": string,
  "extraction_results": {
    "input_source": string,
    "input_type": string,
    "platform_info": {
      "platform": string,
      "strips_metadata": boolean,
      "metadata_survival_chance": string,
      "warning_message": string
    },
    "file_info": {
      "filename": string,
      "file_size": number,
      "file_type": string,
      "mime_type": string,
      "creation_date": string,
      "modification_date": string
    },
    "exif_metadata": {
      "camera_make": string,
      "camera_model": string,
      "lens_model": string,
      "focal_length": string,
      "aperture": string,
      "shutter_speed": string,
      "iso": string,
      "flash": string,
      "white_balance": string,
      "gps_latitude": number,
      "gps_longitude": number,
      "gps_altitude": number,
      "gps_timestamp": string,
      "gps_direction": number,
      "software_used": string,
      "editing_software": string,
      "copyright": string,
      "artist": string
    },
    "video_metadata": {
      "duration": string,
      "resolution": string,
      "frame_rate": string,
      "codec": string,
      "bitrate": string,
      "audio_codec": string,
      "audio_bitrate": string,
      "creation_date": string,
      "software_used": string
    },
    "audio_metadata": {
      "duration": string,
      "bitrate": string,
      "sample_rate": string,
      "channels": string,
      "codec": string,
      "artist": string,
      "album": string,
      "title": string,
      "genre": string,
      "year": string
    },
    "geolocation_data": {
      "coordinates": {
        "latitude": number,
        "longitude": number,
        "altitude": number,
        "accuracy": number
      },
      "address": string,
      "city": string,
      "country": string,
      "timezone": string,
      "map_url": string,
      "street_view_url": string
    },
    "visual_analysis": {
      "ocr_text": string[],
      "detected_objects": string[],
      "license_plates": string[],
      "faces_detected": number,
      "landmarks": string[],
      "text_regions": [
        {
          "text": string,
          "confidence": number,
          "bounding_box": {
            "x": number,
            "y": number,
            "width": number,
            "height": number
          }
        }
      ]
    },
    "weather_data": {
      "date": string,
      "temperature": string,
      "conditions": string,
      "humidity": string,
      "wind_speed": string,
      "sunrise": string,
      "sunset": string
    },
    "sun_position": {
      "azimuth": number,
      "elevation": number,
      "shadow_direction": string,
      "time_of_day": string
    },
    "cross_posts": [
      {
        "platform": string,
        "url": string,
        "title": string,
        "upload_date": string,
        "metadata_available": boolean
      }
    ],
    "security_indicators": {
      "metadata_stripped": boolean,
      "privacy_risks": string[],
      "data_exposure_level": string,
      "recommendations": string[]
    },
    "extraction_timestamp": string,
    "processing_time": number
  }
}
```

## Natural Language Access
Users can request metadata extractor operations using natural language:
- "Extract file metadata"
- "Read file information"
- "Analyze file properties"
- "Extract file details"
- "Process file metadata"

## Usage Examples

### Basic Metadata Extraction
```json
{
  "input_type": "url",
  "input_source": "https://example.com/photo.jpg",
  "extraction_type": "metadata_only",
  "include_exif": true
}
```

### Reddit Post Analysis
```json
{
  "input_type": "reddit_link",
  "input_source": "https://reddit.com/r/pics/comments/example",
  "extraction_type": "comprehensive",
  "platform_stripping_check": true,
  "visual_analysis": true,
  "cross_post_search": true
}
```

### Social Media Investigation
```json
{
  "input_type": "social_media",
  "input_source": "https://instagram.com/p/example",
  "extraction_type": "comprehensive",
  "include_exif": true,
  "visual_analysis": true,
  "geotagging_assist": true,
  "weather_lookup": true,
  "sun_position_analysis": true
}
```

### Forensic Analysis
```json
{
  "input_type": "file",
  "input_source": "/path/to/suspicious_image.jpg",
  "extraction_type": "comprehensive",
  "include_exif": true,
  "visual_analysis": true,
  "cross_post_search": true,
  "output_format": "pdf"
}
```

## Platform Metadata Stripping

### High Stripping (No Metadata Expected)
- **Reddit**: All metadata stripped
- **Imgur**: All metadata stripped
- **TikTok**: All metadata stripped
- **YouTube**: All metadata stripped

### Medium Stripping (Low Metadata Survival)
- **Instagram**: Some metadata may survive
- **Twitter**: Some metadata may survive
- **Facebook**: Some metadata may survive

### Low Stripping (Metadata Likely Survives)
- **Direct URLs**: Metadata usually preserved
- **File Uploads**: Metadata usually preserved
- **Unknown Platforms**: Metadata may survive

## Visual Analysis Capabilities

### OCR Text Detection
- **Street Signs**: Traffic signs, street names
- **License Plates**: Vehicle identification
- **Building Signs**: Business names, addresses
- **Text in Images**: Any readable text content

### Object Detection
- **Vehicles**: Cars, trucks, motorcycles
- **Buildings**: Houses, commercial buildings
- **People**: Face detection and counting
- **Landmarks**: Famous locations and monuments

### Advanced Analysis
- **Face Recognition**: Number of faces detected
- **Landmark Identification**: Famous landmarks
- **Text Region Mapping**: Bounding boxes for text
- **Confidence Scoring**: Accuracy of detections

## Geolocation Services

### GPS Data Extraction
- **Coordinates**: Latitude, longitude, altitude
- **Accuracy**: GPS accuracy radius
- **Direction**: Camera direction and orientation
- **Timestamp**: When photo was taken

### Map Integration
- **Google Maps**: Direct map links
- **Street View**: Street-level imagery
- **Address Resolution**: Human-readable addresses
- **Timezone Information**: Local timezone data

### Weather and Sun Analysis
- **Historical Weather**: Weather conditions at time of photo
- **Sun Position**: Azimuth and elevation
- **Shadow Analysis**: Shadow direction and length
- **Time of Day**: Morning, afternoon, evening

## Cross-Post Detection

### Search Methods
- **Reverse Image Search**: Google Lens, Yandex
- **Perplexity AI**: AI-powered image search
- **Platform APIs**: Direct platform searches
- **Hash Comparison**: Image hash matching

### Analysis Features
- **Platform Detection**: Where content appears
- **Upload Timeline**: When content was shared
- **Metadata Comparison**: Compare across platforms
- **Original Source**: Find original upload

## Security and Privacy

### Privacy Risk Assessment
- **GPS Exposure**: Location data risks
- **Personal Information**: EXIF data exposure
- **Camera Identification**: Device fingerprinting
- **Timing Analysis**: Activity pattern analysis

### Recommendations
- **Metadata Stripping**: Remove sensitive data
- **GPS Removal**: Strip location information
- **Privacy Tools**: Use privacy-preserving software
- **Sharing Guidelines**: Best practices for sharing

## Performance Considerations

### Processing Times
- **Basic Metadata**: 1-5 seconds
- **Visual Analysis**: 10-30 seconds
- **Cross-Post Search**: 30-60 seconds
- **Comprehensive Analysis**: 1-3 minutes

### Optimization Factors
- **File Size**: Larger files take longer
- **Analysis Depth**: More analysis = longer time
- **Network Speed**: URL downloads depend on speed
- **Platform APIs**: API rate limits affect speed

## Integration Examples

### OSINT Investigation
```json
{
  "investigation": {
    "target": "suspicious_social_media_post",
    "analysis": {
      "tool": "metadata_extractor",
      "type": "comprehensive",
      "platform_stripping_check": true,
      "visual_analysis": true,
      "cross_post_search": true
    },
    "purpose": "Digital forensics and intelligence gathering"
  }
}
```

### Privacy Assessment
```json
{
  "privacy_assessment": {
    "content": "user_uploaded_photo",
    "analysis": {
      "tool": "metadata_extractor",
      "type": "comprehensive",
      "include_exif": true,
      "visual_analysis": true
    },
    "purpose": "Privacy risk assessment and recommendations"
  }
}
```

## Best Practices

### Investigation Workflow
1. **Platform Check**: Determine metadata survival chances
2. **Basic Extraction**: Extract available metadata
3. **Visual Analysis**: Perform OCR and object detection
4. **Cross-Post Search**: Find content on other platforms
5. **Geolocation**: Analyze location data if available
6. **Security Assessment**: Evaluate privacy risks

### Data Handling
- **Secure Storage**: Protect extracted data
- **Access Control**: Limit who can access results
- **Data Retention**: Implement retention policies
- **Legal Compliance**: Follow applicable laws

### Analysis Techniques
- **Correlation**: Cross-reference multiple sources
- **Timeline Analysis**: Analyze upload and creation dates
- **Location Verification**: Verify GPS data accuracy
- **Metadata Validation**: Check for tampering

## Troubleshooting

### Common Issues
1. **No Metadata Found**: Platform may strip metadata
2. **Slow Processing**: Large files or complex analysis
3. **API Limits**: Rate limiting on external services
4. **File Access**: Permission issues with local files

### Debug Information
- Enable verbose logging for detailed analysis
- Check platform connectivity and API status
- Validate input URLs and file paths
- Monitor processing time and resource usage

## Related Tools
- `social_network_ripper`: Social media account analysis
- `osint_reconnaissance`: Open source intelligence gathering
- `ip_geolocation`: IP-based geolocation services
- `network_triangulation`: Device location triangulation
- `traffic_analysis`: Network traffic analysis
- `vulnerability_assessment`: Security vulnerability analysis
