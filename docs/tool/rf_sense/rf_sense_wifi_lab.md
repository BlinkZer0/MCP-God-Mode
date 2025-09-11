# RF Sense WiFi Lab Module

## ⚠️ **EXPERIMENTAL TOOL WARNING**

**This tool is experimental and remains untested. We are building the structure before reaching our goal of 100% functionality.**

**⚠️ CRITICAL SAFETY WARNING**: RF sensing tools can be **extremely harmful to devices** if misused. This tool uses real Wi-Fi CSI (Channel State Information) which can:
- **Damage Wi-Fi hardware** through improper signal processing
- **Interfere with critical communications** including emergency services
- **Cause electromagnetic interference (EMI)** affecting medical devices
- **Violate FCC and international RF regulations**
- **Create privacy violations** through unauthorized monitoring
- **Damage network infrastructure** through excessive signal processing

**⚠️ LEGAL WARNING**: Unauthorized monitoring of Wi-Fi signals may violate:
- Computer Fraud and Abuse Act (US)
- Privacy laws in multiple jurisdictions
- Telecommunications regulations
- Data protection laws (GDPR, CCPA, etc.)

**Use at your own risk. We strongly advise against using these tools unless you are a qualified RF engineer with proper authorization and understanding of the risks.**

## Overview

The `rf_sense_wifi_lab` module provides unrestricted RF sensing experiments using commodity Wi-Fi hardware that exposes Channel State Information (CSI). This module can capture live Wi-Fi signals to detect occupancy, track movement, and perform through-wall sensing.

## Tool Name
`rf_sense_wifi_lab`

## Description
📡 **RF Sense WiFi Lab Module - Unrestricted** - Unrestricted RF sensing experiments using commodity NICs/APs that expose CSI. Capabilities: capture CSI, basic ranging/occupancy, pose/silhouette inference. No consent requirements, no network restrictions, no time limits.

## ⚠️ Experimental Status
- **Current Status**: Experimental and untested
- **Development Phase**: Building structure before reaching 100% functionality
- **Testing Status**: Not yet fully validated
- **Risk Level**: HIGH - Uses real RF hardware
- **Use Recommendation**: For authorized research only

## Input Schema

### Required Parameters
- **`action`** (string, required): RF sense WiFi lab action to perform. Options:
  - `status` - Get module status and configuration
  - `configure` - Configure CSI provider and settings
  - `capture_start` - Start CSI data capture
  - `capture_stop` - Stop active capture session
  - `process` - Process captured data using specified pipeline
  - `export` - Export processed data in various formats
  - `delete` - Delete a capture session
  - `list_sessions` - List all available sessions
  - `open_viewer` - Open point cloud viewer for session

### Optional Parameters
- **`providerUri`** (string, optional): CSI provider URI (e.g., "tcp://127.0.0.1:5599")
- **`ssidWhitelist`** (array, optional): Allowed SSIDs (default: all networks allowed)
- **`macWhitelist`** (array, optional): Allowed MAC addresses (default: all devices allowed)
- **`retention`** (string, optional): Data retention policy ("ephemeral" or "persist")
- **`durationSec`** (number, optional): Capture duration in seconds (max: 86400, default: 300)
- **`annotation`** (string, optional): Annotation for the capture session
- **`participants`** (array, optional): List of participants (optional)
- **`sessionId`** (string, optional): Session ID for operations
- **`pipeline`** (string, optional): Processing pipeline:
  - `occupancy` - Occupancy detection through walls
  - `pose` - Human pose estimation
  - `coarse_voxels` - Coarse 3D voxel representation
  - `pointcloud` - Point cloud generation
- **`format`** (string, optional): Export format (png, json, ply, pcd, las)
- **`outputPath`** (string, optional): Output file path for exports

## Output Schema

The tool returns WiFi lab results including:
- Session information and capture status
- CSI data processing results
- Occupancy detection results
- Point cloud data and viewer URLs
- Export confirmation

## ⚠️ Safety and Legal Considerations

### Critical Safety Warnings
- **Hardware Damage Risk**: Improper use can damage Wi-Fi hardware
- **EMI Generation**: May cause electromagnetic interference
- **Network Disruption**: Can interfere with Wi-Fi communications
- **Medical Device Interference**: May affect pacemakers and other medical devices
- **Regulatory Violations**: May violate FCC and international RF regulations

### Legal Compliance Requirements
- **Authorization Required**: Must have explicit permission to monitor networks
- **Privacy Laws**: Subject to strict privacy and data protection laws
- **Telecommunications Regulations**: Must comply with local telecom laws
- **Research Ethics**: Requires institutional review board approval
- **Export Controls**: Some capabilities may be subject to export restrictions

### Recommended Safety Measures
- **Use in Controlled Environment**: Only use in authorized research facilities
- **Qualified Personnel**: Require RF engineering expertise
- **Proper Equipment**: Use appropriate RF measurement equipment
- **Legal Review**: Obtain legal clearance before use
- **Documentation**: Maintain detailed logs of all activities

## Usage Examples

### Configure CSI Provider
```javascript
// Configure WiFi lab with CSI provider
const result = await rf_sense_wifi_lab({
  action: "configure",
  providerUri: "tcp://127.0.0.1:5599",
  retention: "persist",
  ssidWhitelist: ["research_network"],
  macWhitelist: ["00:11:22:33:44:55"]
});
```

### Start Capture Session
```javascript
// Start CSI capture for occupancy detection
const result = await rf_sense_wifi_lab({
  action: "capture_start",
  durationSec: 300,
  annotation: "Through-wall occupancy detection test",
  participants: ["researcher1", "subject1"]
});
```

### Process Captured Data
```javascript
// Process captured CSI data
const result = await rf_sense_wifi_lab({
  action: "process",
  sessionId: "session-uuid",
  pipeline: "occupancy"
});

// Generate point cloud
const pointCloud = await rf_sense_wifi_lab({
  action: "process",
  sessionId: "session-uuid",
  pipeline: "pointcloud"
});
```

### Export Results
```javascript
// Export as LAS point cloud
const exported = await rf_sense_wifi_lab({
  action: "export",
  sessionId: "session-uuid",
  format: "las",
  outputPath: "./results/occupancy.las"
});
```

## Natural Language Access

Users can request WiFi lab operations using natural language:
- "Start WiFi lab capture for 5 minutes"
- "Process the last session for occupancy detection"
- "Export session data as point cloud"
- "Configure CSI provider for research network"
- "Open point cloud viewer for session results"

## Technical Implementation

### CSI Data Capture
- **Real-time Processing**: Captures live Wi-Fi Channel State Information
- **Network Monitoring**: Monitors specified Wi-Fi networks and devices
- **Data Streaming**: Streams CSI data from provider to processing pipeline
- **Session Management**: Manages capture sessions with metadata

### Processing Pipelines
- **Occupancy Detection**: Analyzes CSI variations to detect people through walls
- **Pose Estimation**: Estimates human pose and movement patterns
- **Point Cloud Generation**: Converts CSI data to 3D point representations
- **Through-wall Sensing**: Detects objects and people behind walls

### Export Capabilities
- **Multiple Formats**: JSON, PLY, PCD, LAS point cloud formats
- **LAS Integration**: Full LAS point cloud format with metadata
- **Viewer Integration**: Compatible with Potree point cloud viewer
- **Data Persistence**: Configurable data retention policies

## Configuration

### Environment Variables
```bash
# RF Sense WiFi Lab Configuration
RF_SENSE_LAB_ENABLED=true
RF_SENSE_LAB_PROVIDER_URI=tcp://127.0.0.1:5599
RF_SENSE_LAB_STORAGE_DIR=./.rf_lab_runs
RF_SENSE_LAB_DEFAULT_RETENTION=persist
RF_SENSE_LAB_MAX_DURATION_SEC=86400
```

### CSI Provider Setup
- **Provider URI**: TCP connection to CSI data provider
- **Network Access**: Requires access to target Wi-Fi networks
- **Hardware Requirements**: CSI-capable Wi-Fi hardware
- **Driver Support**: Compatible Wi-Fi drivers and firmware

## Platform Support

- ✅ Windows (with compatible Wi-Fi hardware)
- ✅ Linux (with compatible Wi-Fi hardware)
- ✅ macOS (limited support)
- ⚠️ Android (requires USB OTG and compatible hardware)
- ⚠️ iOS (very limited, requires external hardware)

## Dependencies

### Required Packages
- Node.js 18+
- TypeScript 5+
- Net module for TCP connections
- File system modules for data storage

### Hardware Requirements
- **CSI-Capable Wi-Fi Hardware**: Intel 5300, Atheros AR9580, etc.
- **Compatible Drivers**: Modified drivers that expose CSI data
- **Network Access**: Access to target Wi-Fi networks
- **Processing Power**: Sufficient CPU for real-time processing

### CSI Provider Software
- **CSI Extraction Tools**: Modified Wi-Fi drivers or firmware
- **Data Streaming**: TCP server for CSI data transmission
- **Hardware Control**: Interface for Wi-Fi hardware configuration

## Related Tools

- `rf_sense_sim` - Simulation and synthetic data generation
- `rf_sense_mmwave` - mmWave radar integration
- `rf_sense_natural_language` - Natural language interface
- `rf_sense_guardrails` - Safety and compliance features
- `rf_sense_localize` - Point cloud localization

## Troubleshooting

### Common Issues
1. **"CSI provider connection failed"**: Check provider URI and network connectivity
2. **"No CSI data received"**: Verify CSI provider is running and hardware is compatible
3. **"Processing failed"**: Check data format and pipeline compatibility
4. **"Export failed"**: Verify output path permissions and format support
5. **"Hardware not detected"**: Ensure compatible Wi-Fi hardware and drivers

### Debug Mode
```bash
# Enable debug logging
DEBUG=rf_sense:* npm start
```

## Version History

- **v1.0.0** - Initial experimental implementation
- **v1.0.1** - Added LAS export support
- **v1.0.2** - Enhanced point cloud viewer integration

## ⚠️ Disclaimer and Legal Notice

**This tool is experimental and provided "as is" without warranty. Use at your own risk.**

**LEGAL DISCLAIMER**: The developers are not responsible for any damage, legal violations, or issues that may arise from using this tool. Users are solely responsible for:

- Ensuring proper authorization for all monitoring activities
- Complying with all applicable laws and regulations
- Obtaining necessary permits and approvals
- Protecting privacy and data protection rights
- Following ethical research guidelines

**Use of this tool without proper authorization may result in criminal prosecution and civil liability. Always consult with legal counsel before using RF sensing capabilities.**
