# Mobile Hardware Access Tool

## Overview
The `mobile_hardware` tool provides comprehensive access to mobile device hardware features including camera, GPS, biometrics, Bluetooth, NFC, sensors, and more. This tool is designed for cross-platform mobile development and testing.

## Tool Name
`mobile_hardware`

## Description
Advanced mobile hardware access and sensor data collection for Android and iOS devices

## Input Schema
- `feature` (string, required): The hardware feature to access. Options include:
  - `camera` - Access camera for photo/video capture
  - `location` - Access GPS and positioning services
  - `biometrics` - Access fingerprint/face recognition
  - `bluetooth` - Access Bluetooth connectivity
  - `nfc` - Access Near Field Communication
  - `sensors` - Access accelerometer, gyroscope, compass
  - `notifications` - Access system notifications
  - `audio` - Access microphone and speakers
  - `vibration` - Access haptic feedback

- `action` (string, required): The action to perform on the hardware feature:
  - `check_availability` - Verify if feature exists and is accessible
  - `get_status` - Show current state of the feature
  - `request_permission` - Ask for user authorization
  - `get_data` - Retrieve sensor information or data
  - `control` - Activate/deactivate features

- `parameters` (object, optional): Additional parameters for the hardware operation. Format varies by feature:
  - Camera: `{duration: 5000, quality: 'high'}`
  - Location: `{accuracy: 'fine'}`
  - Vibration: `{pattern: [100, 200, 100]}`

## Natural Language Access
Users can ask for this tool using natural language such as:
- "Check if the camera is available on this device"
- "Get the current GPS location"
- "Test the fingerprint sensor"
- "Check Bluetooth connectivity status"
- "Access the device accelerometer"
- "Test haptic feedback"
- "Check microphone permissions"
- "Get sensor data from the device"

## Examples

### Camera Access
```typescript
// Check camera availability
const result = await server.callTool("mobile_hardware", { 
  feature: "camera",
  action: "check_availability"
});

// Request camera permission
const result = await server.callTool("mobile_hardware", { 
  feature: "camera",
  action: "request_permission",
  parameters: { quality: "high" }
});
```

### Location Services
```typescript
// Get current location
const result = await server.callTool("mobile_hardware", { 
  feature: "location",
  action: "get_data",
  parameters: { accuracy: "fine" }
});

// Check location permission
const result = await server.callTool("mobile_hardware", { 
  feature: "location",
  action: "get_status"
});
```

### Sensor Access
```typescript
// Get accelerometer data
const result = await server.callTool("mobile_hardware", { 
  feature: "sensors",
  action: "get_data"
});

// Check sensor availability
const result = await server.callTool("mobile_hardware", { 
  feature: "sensors",
  action: "check_availability"
});
```

## Platform Support
- ✅ Android (with appropriate permissions)
- ✅ iOS (with appropriate permissions)
- ❌ Windows (not applicable)
- ❌ Linux (not applicable)
- ❌ macOS (not applicable)

## Hardware Features

### Camera
- Photo capture
- Video recording
- Quality settings
- Flash control
- Focus control
- Zoom capabilities

### Location Services
- GPS coordinates
- Accuracy levels
- Location history
- Geofencing
- Route tracking
- Speed monitoring

### Biometrics
- Fingerprint recognition
- Face recognition
- Iris scanning
- Biometric security
- Authentication status

### Bluetooth
- Device discovery
- Pairing management
- Connection status
- Signal strength
- Device information

### NFC
- Tag reading
- Data writing
- Payment processing
- Access control
- Information exchange

### Sensors
- Accelerometer
- Gyroscope
- Magnetometer (compass)
- Barometer
- Light sensor
- Proximity sensor

### Audio
- Microphone access
- Speaker control
- Audio recording
- Volume control
- Audio routing

### Vibration
- Haptic feedback
- Custom patterns
- Intensity control
- Duration settings

## Permission Management
- Automatic permission detection
- User-friendly permission requests
- Permission status checking
- Graceful fallbacks for denied permissions

## Security Features
- Permission-based access control
- Secure data handling
- Privacy protection
- User consent requirements
- Data encryption where applicable

## Error Handling
- Graceful degradation for unavailable features
- Clear error messages
- Fallback options
- Permission denial handling
- Hardware failure recovery

## Related Tools
- `mobile_device_info` - Device information
- `mobile_file_ops` - File operations
- `mobile_system_tools` - System management
- `system_restore` - System backup and restore

## Use Cases
- Mobile app development
- Hardware testing
- Sensor data collection
- Location-based services
- Biometric authentication
- IoT device integration
- Accessibility features
- Security testing

## Best Practices
- Always check feature availability first
- Request permissions before use
- Handle permission denials gracefully
- Respect user privacy settings
- Use appropriate accuracy levels
- Implement proper error handling
- Follow platform guidelines
- Test on multiple devices

## Privacy Considerations
- Only request necessary permissions
- Explain why permissions are needed
- Handle sensitive data securely
- Respect user privacy preferences
- Comply with data protection regulations
- Implement proper data retention policies
