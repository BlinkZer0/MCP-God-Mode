# RF Sense Simulation Module

## ⚠️ **EXPERIMENTAL TOOL WARNING**

**This tool is experimental and remains untested. We are building the structure before reaching our goal of 100% functionality.**

**⚠️ IMPORTANT SAFETY NOTICE**: RF sensing tools can be **harmful to devices** if misused. These tools should only be used by individuals who understand RF technology and potential risks. Improper use may:
- Damage RF hardware and antennas
- Interfere with critical communications systems
- Cause electromagnetic interference (EMI)
- Violate local RF regulations
- Create safety hazards

**Use at your own risk. We strongly advise against using these tools unless you know what you're doing.**

## Overview

The `rf_sense_sim` module provides rapid prototyping and testing capabilities with synthetic datasets. This simulation module allows you to test RF sensing algorithms and workflows without requiring actual RF hardware, making it ideal for development, testing, and educational purposes.

## Tool Name
`rf_sense_sim`

## Description
📡 **RF Sense Simulation Module** - Rapid prototyping with synthetic or public, consented datasets; no live RF. Capabilities: load example CSI/motion datasets; run toy reconstructions; export heatmaps/coarse point voxels. Good for: UI/UX, pipelines, NLU prompts, eval metrics—zero legal risk.

## ⚠️ Experimental Status
- **Current Status**: Experimental and untested
- **Development Phase**: Building structure before reaching 100% functionality
- **Testing Status**: Not yet fully validated
- **Use Recommendation**: For development and testing only

## Input Schema

### Required Parameters
- **`action`** (string, required): RF sense simulation action to perform. Options:
  - `status` - Get module status and configuration
  - `simulate` - Start a simulation session
  - `process` - Process captured data using specified pipeline
  - `export` - Export processed data in various formats
  - `visualize` - Generate visualization descriptions
  - `delete` - Delete a simulation session
  - `list_sessions` - List all available sessions

### Optional Parameters
- **`durationSec`** (number, optional): Duration in seconds for simulation (default: 30, max: 300)
- **`scenario`** (string, optional): Simulation scenario type:
  - `empty_room` - Empty room baseline
  - `single_person` - Single person moving
  - `multiple_people` - Multiple people scenario
  - `gesture_demo` - Gesture demonstration
  - `motion_pattern` - Complex motion patterns
- **`annotation`** (string, optional): Annotation for the simulation session
- **`outputFormat`** (string, optional): Output format for simulation:
  - `heatmap` - Occupancy heatmap
  - `voxels` - 3D voxel representation
  - `pointcloud` - Point cloud data
  - `skeleton` - Skeleton/pose data
- **`resolution`** (string, optional): Simulation resolution:
  - `low` - Low resolution (16x16)
  - `medium` - Medium resolution (32x32)
  - `high` - High resolution (64x64)
- **`sessionId`** (string, optional): Session ID for operations
- **`pipeline`** (string, optional): Processing pipeline:
  - `occupancy` - Occupancy detection
  - `pose` - Pose estimation
  - `coarse_voxels` - Coarse voxel processing
  - `pointcloud` - Point cloud generation
  - `gesture_detection` - Gesture recognition
- **`format`** (string, optional): Export format:
  - `png` - PNG image
  - `json` - JSON data
  - `ply` - PLY point cloud
  - `pcd` - PCD point cloud
  - `csv` - CSV data
  - `las` - LAS point cloud
- **`outputPath`** (string, optional): Output file path for exports
- **`visualizeType`** (string, optional): Visualization type
- **`style`** (string, optional): Visualization style (default, thermal, wireframe, solid)

## Output Schema

The tool returns simulation results including:
- Session information and metadata
- Generated synthetic data
- Processing results
- Export confirmation
- Visualization descriptions

## ⚠️ Safety and Legal Considerations

### Experimental Tool Warning
- **Not Production Ready**: This tool is experimental and may not work as expected
- **Limited Testing**: Has not been fully tested in all scenarios
- **Development Phase**: Currently building structure before full implementation
- **Use with Caution**: Only use if you understand the limitations

### RF Safety Considerations
- **No Live RF**: This simulation module does not use actual RF hardware
- **Synthetic Data Only**: All data is computer-generated
- **Zero Legal Risk**: No actual RF transmission or reception
- **Safe for Development**: Ideal for algorithm testing and UI development

## Usage Examples

### Basic Simulation
```javascript
// Start a simple simulation
const result = await rf_sense_sim({
  action: "simulate",
  durationSec: 30,
  scenario: "single_person",
  outputFormat: "heatmap",
  resolution: "medium"
});
```

### High-Resolution Simulation
```javascript
// Run high-resolution simulation
const result = await rf_sense_sim({
  action: "simulate",
  durationSec: 60,
  scenario: "multiple_people",
  outputFormat: "pointcloud",
  resolution: "high",
  annotation: "Multi-person occupancy test"
});
```

### Process and Export
```javascript
// Process simulation data
const processed = await rf_sense_sim({
  action: "process",
  sessionId: "session-uuid",
  pipeline: "occupancy"
});

// Export results
const exported = await rf_sense_sim({
  action: "export",
  sessionId: "session-uuid",
  format: "las",
  outputPath: "./results/simulation.las"
});
```

## Natural Language Access

Users can request RF sense simulation operations using natural language:
- "Start a simulated RF session for 30 seconds"
- "Run a single person occupancy simulation"
- "Generate high-resolution point cloud data"
- "Export simulation results as LAS format"
- "Process the last session with occupancy detection"

## Technical Implementation

### Synthetic Data Generation
- **Frame Generation**: Creates realistic RF sensing frames
- **Motion Simulation**: Simulates human movement patterns
- **Noise Modeling**: Adds realistic environmental noise
- **Temporal Consistency**: Maintains coherent motion over time

### Processing Pipelines
- **Occupancy Detection**: Aggregates frames to create heatmaps
- **Pose Estimation**: Detects body parts and skeletal structures
- **Point Cloud Generation**: Converts 2D data to 3D points
- **Gesture Recognition**: Identifies specific movement patterns

### Export Capabilities
- **Multiple Formats**: Supports JSON, PLY, PCD, CSV, LAS
- **LAS Integration**: Full LAS point cloud format support
- **Viewer Integration**: Compatible with Potree point cloud viewer
- **Metadata Preservation**: Maintains simulation parameters

## Configuration

### Environment Variables
```bash
# RF Sense Simulation Configuration
RF_SENSE_SIM_ENABLED=true
RF_SENSE_SIM_STORAGE_DIR=./.rf_sim_runs
RF_SENSE_SIM_MAX_DURATION_SEC=300
RF_SENSE_SIM_DEFAULT_RETENTION=ephemeral
```

### Storage Directory
- **Default Location**: `./.rf_sim_runs/`
- **Session Structure**: Each session gets a unique UUID directory
- **Data Files**: Raw simulation data, processed results, audit logs
- **Cleanup**: Ephemeral sessions are automatically cleaned up

## Platform Support

- ✅ Windows
- ✅ Linux  
- ✅ macOS
- ✅ Android (limited)
- ✅ iOS (limited)

## Dependencies

### Required Packages
- Node.js 18+
- TypeScript 5+
- Standard Node.js modules (fs, path, crypto)

### Optional Dependencies
- LAS point cloud utilities
- Potree viewer integration
- Point cloud processing libraries

## Related Tools

- `rf_sense_wifi_lab` - Real Wi-Fi CSI experiments
- `rf_sense_mmwave` - mmWave radar integration
- `rf_sense_natural_language` - Natural language interface
- `rf_sense_guardrails` - Safety and compliance features
- `rf_sense_localize` - Point cloud localization

## Troubleshooting

### Common Issues
1. **"Module disabled"**: Check RF_SENSE_SIM_ENABLED environment variable
2. **"Storage directory error"**: Ensure write permissions for storage directory
3. **"Invalid scenario"**: Use supported scenario types only
4. **"Export failed"**: Check output path permissions and format support

### Debug Mode
```bash
# Enable debug logging
DEBUG=rf_sense:* npm start
```

## Version History

- **v1.0.0** - Initial experimental implementation
- **v1.0.1** - Added LAS export support
- **v1.0.2** - Enhanced point cloud viewer integration

## ⚠️ Disclaimer

This tool is experimental and provided "as is" without warranty. Use at your own risk. The developers are not responsible for any damage or issues that may arise from using this tool. Always ensure you understand RF technology and safety considerations before using any RF-related tools.
