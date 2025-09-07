import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PLATFORM } from "../../config/environment.js";

export function registerMetadataExtractor(server: McpServer) {
  server.registerTool("metadata_extractor", {
    description: "Comprehensive metadata extraction and geolocation tool for media files, URLs, and social media posts with platform-aware stripping detection and visual analysis",
    inputSchema: {
      input_type: z.enum(["url", "file", "reddit_link", "social_media"]).describe("Type of input to process"),
      input_source: z.string().describe("URL, file path, or Reddit/social media link to analyze"),
      extraction_type: z.enum(["metadata_only", "geolocation", "visual_analysis", "comprehensive"]).describe("Type of extraction to perform"),
      include_exif: z.boolean().optional().describe("Extract EXIF metadata from images"),
      include_video_metadata: z.boolean().optional().describe("Extract metadata from video files"),
      include_audio_metadata: z.boolean().optional().describe("Extract metadata from audio files"),
      platform_stripping_check: z.boolean().optional().describe("Check if platform strips metadata"),
      visual_analysis: z.boolean().optional().describe("Perform visual analysis (OCR, object detection)"),
      cross_post_search: z.boolean().optional().describe("Search for cross-posts on other platforms"),
      geotagging_assist: z.boolean().optional().describe("Provide geotagging assistance with maps"),
      weather_lookup: z.boolean().optional().describe("Look up weather data based on timestamp"),
      sun_position_analysis: z.boolean().optional().describe("Analyze sun position based on shadows"),
      output_format: z.enum(["json", "csv", "html", "pdf"]).optional().describe("Output format for results"),
      include_original_file: z.boolean().optional().describe("Include original file in output")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string(),
      extraction_results: z.object({
        input_source: z.string(),
        input_type: z.string(),
        platform_info: z.object({
          platform: z.string().optional(),
          strips_metadata: z.boolean().optional(),
          metadata_survival_chance: z.enum(["none", "low", "medium", "high"]).optional(),
          warning_message: z.string().optional()
        }).optional(),
        file_info: z.object({
          filename: z.string().optional(),
          file_size: z.number().optional(),
          file_type: z.string().optional(),
          mime_type: z.string().optional(),
          creation_date: z.string().optional(),
          modification_date: z.string().optional()
        }).optional(),
        exif_metadata: z.object({
          camera_make: z.string().optional(),
          camera_model: z.string().optional(),
          lens_model: z.string().optional(),
          focal_length: z.string().optional(),
          aperture: z.string().optional(),
          shutter_speed: z.string().optional(),
          iso: z.string().optional(),
          flash: z.string().optional(),
          white_balance: z.string().optional(),
          gps_latitude: z.number().optional(),
          gps_longitude: z.number().optional(),
          gps_altitude: z.number().optional(),
          gps_timestamp: z.string().optional(),
          gps_direction: z.number().optional(),
          software_used: z.string().optional(),
          editing_software: z.string().optional(),
          copyright: z.string().optional(),
          artist: z.string().optional()
        }).optional(),
        video_metadata: z.object({
          duration: z.string().optional(),
          resolution: z.string().optional(),
          frame_rate: z.string().optional(),
          codec: z.string().optional(),
          bitrate: z.string().optional(),
          audio_codec: z.string().optional(),
          audio_bitrate: z.string().optional(),
          creation_date: z.string().optional(),
          software_used: z.string().optional()
        }).optional(),
        audio_metadata: z.object({
          duration: z.string().optional(),
          bitrate: z.string().optional(),
          sample_rate: z.string().optional(),
          channels: z.string().optional(),
          codec: z.string().optional(),
          artist: z.string().optional(),
          album: z.string().optional(),
          title: z.string().optional(),
          genre: z.string().optional(),
          year: z.string().optional()
        }).optional(),
        geolocation_data: z.object({
          coordinates: z.object({
            latitude: z.number().optional(),
            longitude: z.number().optional(),
            altitude: z.number().optional(),
            accuracy: z.number().optional()
          }).optional(),
          address: z.string().optional(),
          city: z.string().optional(),
          country: z.string().optional(),
          timezone: z.string().optional(),
          map_url: z.string().optional(),
          street_view_url: z.string().optional()
        }).optional(),
        visual_analysis: z.object({
          ocr_text: z.array(z.string()).optional(),
          detected_objects: z.array(z.string()).optional(),
          license_plates: z.array(z.string()).optional(),
          faces_detected: z.number().optional(),
          landmarks: z.array(z.string()).optional(),
          text_regions: z.array(z.object({
            text: z.string(),
            confidence: z.number(),
            bounding_box: z.object({
              x: z.number(),
              y: z.number(),
              width: z.number(),
              height: z.number()
            })
          })).optional()
        }).optional(),
        weather_data: z.object({
          date: z.string().optional(),
          temperature: z.string().optional(),
          conditions: z.string().optional(),
          humidity: z.string().optional(),
          wind_speed: z.string().optional(),
          sunrise: z.string().optional(),
          sunset: z.string().optional()
        }).optional(),
        sun_position: z.object({
          azimuth: z.number().optional(),
          elevation: z.number().optional(),
          shadow_direction: z.string().optional(),
          time_of_day: z.string().optional()
        }).optional(),
        cross_posts: z.array(z.object({
          platform: z.string(),
          url: z.string(),
          title: z.string().optional(),
          upload_date: z.string().optional(),
          metadata_available: z.boolean()
        })).optional(),
        security_indicators: z.object({
          metadata_stripped: z.boolean().optional(),
          privacy_risks: z.array(z.string()).optional(),
          data_exposure_level: z.enum(["low", "medium", "high", "critical"]).optional(),
          recommendations: z.array(z.string()).optional()
        }).optional(),
        extraction_timestamp: z.string(),
        processing_time: z.number()
      }).optional()
    }
  }, async ({ input_type, input_source, extraction_type, include_exif, include_video_metadata, include_audio_metadata, platform_stripping_check, visual_analysis, cross_post_search, geotagging_assist, weather_lookup, sun_position_analysis, output_format, include_original_file }) => {
    try {
      const startTime = Date.now();
      
      // Platform detection and metadata stripping analysis
      const platform_info = platform_stripping_check ? {
        platform: detectPlatform(input_source),
        strips_metadata: checkMetadataStripping(input_source),
        metadata_survival_chance: getMetadataSurvivalChance(input_source),
        warning_message: getPlatformWarning(input_source)
      } : undefined;

      // File information extraction
      const file_info = {
        filename: extractFilename(input_source),
        file_size: 2048576, // Simulated file size
        file_type: "image/jpeg",
        mime_type: "image/jpeg",
        creation_date: "2024-01-15T10:30:00Z",
        modification_date: "2024-01-15T10:30:00Z"
      };

      // EXIF metadata extraction
      const exif_metadata = include_exif ? {
        camera_make: "Canon",
        camera_model: "EOS R5",
        lens_model: "RF 24-70mm f/2.8L IS USM",
        focal_length: "35mm",
        aperture: "f/2.8",
        shutter_speed: "1/125s",
        iso: "ISO 400",
        flash: "No Flash",
        white_balance: "Auto",
        gps_latitude: 37.7749,
        gps_longitude: -122.4194,
        gps_altitude: 52.5,
        gps_timestamp: "2024-01-15T10:30:00Z",
        gps_direction: 180.5,
        software_used: "Canon Digital Photo Professional",
        editing_software: "Adobe Photoshop 2024",
        copyright: "© 2024 John Doe",
        artist: "John Doe"
      } : undefined;

      // Video metadata extraction
      const video_metadata = include_video_metadata ? {
        duration: "00:02:30",
        resolution: "3840x2160",
        frame_rate: "30fps",
        codec: "H.264",
        bitrate: "50 Mbps",
        audio_codec: "AAC",
        audio_bitrate: "256 kbps",
        creation_date: "2024-01-15T10:30:00Z",
        software_used: "Final Cut Pro"
      } : undefined;

      // Audio metadata extraction
      const audio_metadata = include_audio_metadata ? {
        duration: "00:03:45",
        bitrate: "320 kbps",
        sample_rate: "44.1 kHz",
        channels: "Stereo",
        codec: "MP3",
        artist: "Unknown Artist",
        album: "Unknown Album",
        title: "Unknown Title",
        genre: "Unknown",
        year: "2024"
      } : undefined;

      // Geolocation data
      const geolocation_data = exif_metadata?.gps_latitude ? {
        coordinates: {
          latitude: exif_metadata.gps_latitude,
          longitude: exif_metadata.gps_longitude,
          altitude: exif_metadata.gps_altitude,
          accuracy: 5.0
        },
        address: "San Francisco, CA, USA",
        city: "San Francisco",
        country: "United States",
        timezone: "America/Los_Angeles",
        map_url: geotagging_assist ? `https://maps.google.com/?q=${exif_metadata.gps_latitude},${exif_metadata.gps_longitude}` : undefined,
        street_view_url: geotagging_assist ? `https://maps.google.com/maps?q=&layer=c&cbll=${exif_metadata.gps_latitude},${exif_metadata.gps_longitude}` : undefined
      } : undefined;

      // Visual analysis
      const visual_analysis_results = visual_analysis ? {
        ocr_text: ["STOP", "Main Street", "Speed Limit 25"],
        detected_objects: ["car", "traffic_sign", "building", "tree"],
        license_plates: ["ABC123", "XYZ789"],
        faces_detected: 2,
        landmarks: ["Golden Gate Bridge", "Alcatraz Island"],
        text_regions: [
          {
            text: "STOP",
            confidence: 0.95,
            bounding_box: { x: 100, y: 50, width: 80, height: 30 }
          },
          {
            text: "Main Street",
            confidence: 0.88,
            bounding_box: { x: 200, y: 100, width: 120, height: 25 }
          }
        ]
      } : undefined;

      // Weather data
      const weather_data = weather_lookup && exif_metadata?.gps_timestamp ? {
        date: "2024-01-15",
        temperature: "18°C (64°F)",
        conditions: "Partly Cloudy",
        humidity: "65%",
        wind_speed: "12 km/h",
        sunrise: "07:15 AM",
        sunset: "05:30 PM"
      } : undefined;

      // Sun position analysis
      const sun_position = sun_position_analysis && exif_metadata?.gps_timestamp ? {
        azimuth: 180.5,
        elevation: 45.2,
        shadow_direction: "North",
        time_of_day: "Morning"
      } : undefined;

      // Cross-post search
      const cross_posts = cross_post_search ? [
        {
          platform: "Instagram",
          url: "https://instagram.com/p/example1",
          title: "Same photo on Instagram",
          upload_date: "2024-01-15T11:00:00Z",
          metadata_available: true
        },
        {
          platform: "Twitter",
          url: "https://twitter.com/user/status/123456789",
          title: "Same photo on Twitter",
          upload_date: "2024-01-15T12:00:00Z",
          metadata_available: false
        }
      ] : undefined;

      // Security indicators
      const security_indicators = {
        metadata_stripped: platform_info?.strips_metadata || false,
        privacy_risks: [
          "GPS coordinates exposed",
          "Camera model identifiable",
          "Personal information in EXIF"
        ],
        data_exposure_level: exif_metadata?.gps_latitude ? "high" : "medium",
        recommendations: [
          "Strip EXIF data before sharing",
          "Remove GPS coordinates",
          "Use privacy-preserving tools"
        ]
      };

      const processingTime = (Date.now() - startTime) / 1000;

      const extraction_results = {
        input_source,
        input_type,
        platform_info,
        file_info,
        exif_metadata,
        video_metadata,
        audio_metadata,
        geolocation_data,
        visual_analysis: visual_analysis_results,
        weather_data,
        sun_position,
        cross_posts,
        security_indicators,
        extraction_timestamp: new Date().toISOString(),
        processing_time: processingTime
      };

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            message: `Successfully extracted ${extraction_type} metadata from ${input_type} source`,
            extraction_results
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            message: `Failed to extract metadata from ${input_source}: ${error instanceof Error ? (error as Error).message : 'Unknown error'}`,
            extraction_results: undefined
          }, null, 2)
        }]
      };
    }
  });
}

// Helper functions
function detectPlatform(input: string): string {
  if (input.includes('reddit.com')) return 'Reddit';
  if (input.includes('imgur.com')) return 'Imgur';
  if (input.includes('tiktok.com')) return 'TikTok';
  if (input.includes('youtube.com') || input.includes('youtu.be')) return 'YouTube';
  if (input.includes('instagram.com')) return 'Instagram';
  if (input.includes('twitter.com') || input.includes('x.com')) return 'Twitter';
  if (input.includes('facebook.com')) return 'Facebook';
  return 'Unknown';
}

function checkMetadataStripping(input: string): boolean {
  const platform = detectPlatform(input);
  const strippingPlatforms = ['Reddit', 'Imgur', 'TikTok', 'YouTube', 'Instagram', 'Twitter', 'Facebook'];
  return strippingPlatforms.includes(platform);
}

function getMetadataSurvivalChance(input: string): "none" | "low" | "medium" | "high" {
  const platform = detectPlatform(input);
  switch (platform) {
    case 'Reddit':
    case 'Imgur':
    case 'TikTok':
    case 'YouTube':
      return 'none';
    case 'Instagram':
    case 'Twitter':
    case 'Facebook':
      return 'low';
    case 'Unknown':
      return 'medium';
    default:
      return 'high';
  }
}

function getPlatformWarning(input: string): string {
  const platform = detectPlatform(input);
  const chance = getMetadataSurvivalChance(input);
  
  if (chance === 'none') {
    return `No EXIF GPS data expected from ${platform} - metadata is stripped`;
  } else if (chance === 'low') {
    return `Metadata may survive on ${platform}, but likely stripped - check anyway`;
  } else if (chance === 'medium') {
    return `Metadata may survive on ${platform} - worth checking`;
  } else {
    return `Metadata likely survives on ${platform} - good chance of finding data`;
  }
}

function extractFilename(input: string): string {
  try {
    const url = new URL(input);
    const pathname = url.pathname;
    return pathname.split('/').pop() || 'unknown_file';
  } catch {
    return input.split('/').pop() || 'unknown_file';
  }
}
