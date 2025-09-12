# Unified RF Sense Tool

## ⚠️ **EXPERIMENTAL TOOL WARNING**

**This tool is experimental and remains untested. We are building the structure before reaching our goal of 100% functionality.**

**⚠️ CRITICAL SAFETY WARNING**: RF sensing tools can be **extremely harmful to devices** if misused. This unified tool consolidates all RF sensing capabilities which can:
- **Damage RF hardware** through improper signal processing
- **Interfere with critical communications** including emergency services
- **Cause electromagnetic interference (EMI)** affecting medical devices
- **Violate FCC and international RF regulations**
- **Create privacy violations** through unauthorized monitoring
- **Cause severe RF burns** from high-power millimeter wave radiation
- **Generate harmful interference** affecting pacemakers and medical devices

**⚠️ LEGAL WARNING**: Unauthorized use of RF sensing may violate:
- Computer Fraud and Abuse Act (US)
- Privacy laws in multiple jurisdictions
- Telecommunications regulations
- Data protection laws (GDPR, CCPA, etc.)
- FCC regulations with fines up to $1.5 million

**Use at your own risk. We strongly advise against using these tools unless you are a qualified RF engineer with proper authorization and understanding of the extreme risks involved.**

## Overview

The `rf_sense` tool provides a unified interface to all RF sensing capabilities, consolidating six specialized modules into a single, comprehensive tool. This unified approach simplifies access to RF sensing operations while maintaining all the safety warnings and experimental status of the individual modules.

## Tool Name
`rf_sense`

## Description
📡 **Unified RF Sense Tool** - Consolidated RF sensing capabilities with comprehensive through-wall detection, occupancy sensing, and object tracking. Provides access to simulation, Wi-Fi CSI experiments, mmWave radar, natural language interface, safety guardrails, and point cloud localization through a single unified interface.

## ⚠️ Experimental Status
- **Current Status**: Experimental and untested
- **Development Phase**: Building structure before reaching 100% functionality
- **Testing Status**: Not yet fully validated
- **Risk Level**: EXTREME - Consolidates all RF sensing capabilities
- **Use Recommendation**: For authorized research facilities only

## Available Modules

### 1. **sim** - Simulation Module
- **Purpose**: Synthetic data generation and testing (zero legal risk)
- **Capabilities**: Load example CSI/motion datasets, run toy reconstructions, export heatmaps/coarse point voxels
- **Good for**: UI/UX, pipelines, NLU prompts, eval metrics
- **Risk Level**: LOW (no live RF)

### 2. **wifi_lab** - WiFi Lab Module  
- **Purpose**: Real Wi-Fi CSI experiments with through-wall sensing
- **Capabilities**: Capture CSI, basic ranging/occupancy, pose/silhouette inference
- **Features**: No consent requirements, no network restrictions, no time limits
- **Risk Level**: HIGH (uses real RF hardware)

### 3. **mmwave** - mmWave Module
- **Purpose**: FMCW mmWave radar with through-wall object detection
- **Capabilities**: Point clusters, object tracks, gesture events, export to PCD/PLY/JSON
- **Features**: No consent requirements, no power limits, no time restrictions
- **Risk Level**: EXTREME (high-power mmWave radar)

### 4. **natural_language** - Natural Language Interface
- **Purpose**: Intuitive interface for RF sensing operations
- **Capabilities**: Parse natural language commands, route to appropriate modules
- **Features**: Cross-platform support, intelligent parsing
- **Risk Level**: MEDIUM (interface only, no direct RF)

### 5. **guardrails** - Safety and Compliance
- **Purpose**: Safety guardrails and compliance features
- **Capabilities**: Operation validation, consent management, audit logging
- **Features**: Evidence preservation, legal hold capabilities
- **Risk Level**: LOW (safety features only)

### 6. **localize** - Point Cloud Localization
- **Purpose**: Point cloud localization and mapping
- **Capabilities**: 6-DoF pose estimation, NDT/ICP registration, LAS export
- **Features**: Point cloud alignment, map-based localization
- **Risk Level**: MEDIUM (processes RF-derived data)

## Input Schema

### Required Parameters
- **`module`** (string, required): RF Sense module to use. Options:
  - `sim` - Simulation module
  - `wifi_lab` - WiFi Lab module
  - `mmwave` - mmWave module
  - `natural_language` - Natural Language interface
  - `guardrails` - Safety and compliance
  - `localize` - Point cloud localization
- **`action`** (string, required): Action to perform (specific to each module)

### Common Optional Parameters
- **`sessionId`** (string, optional): Session ID for operations
- **`annotation`** (string, optional): Annotation for the session
- **`outputPath`** (string, optional): Output file path
- **`format`** (string, optional): Output format

### Module-Specific Parameters

#### Simulation Module (sim)
- **`durationSec`** (number, optional): Duration in seconds for simulation (max 300)
- **`scenario`** (string, optional): Simulation scenario type
- **`outputFormat`** (string, optional): Output format for simulation
- **`resolution`** (string, optional): Simulation resolution
- **`pipeline`** (string, optional): Processing pipeline
- **`visualizeType`** (string, optional): Visualization type
- **`style`** (string, optional): Visualization style

#### WiFi Lab Module (wifi_lab)
- **`providerUri`** (string, optional): CSI provider URI (tcp://host:port)
- **`ssidWhitelist`** (array, optional): Allowed SSIDs
- **`macWhitelist`** (array, optional): Allowed MAC addresses
- **`retention`** (string, optional): Data retention policy
- **`participants`** (array, optional): List of participants
- **`durationSec`** (number, optional): Capture duration in seconds (max 86400)

#### mmWave Module (mmwave)
- **`sdkPath`** (string, optional): Path to vendor SDK
- **`deviceConfig`** (object, optional): Device configuration
- **`captureMode`** (string, optional): Capture mode
- **`durationSec`** (number, optional): Capture duration in seconds (max 86400)

#### Natural Language Module (natural_language)
- **`command`** (string, optional): Natural language command
- **`context`** (string, optional): Additional context
- **`userIntent`** (string, optional): User's intended goal
- **`platform`** (string, optional): Target platform preference

#### Guardrails Module (guardrails)
- **`operation`** (string, optional): Operation to validate
- **`parameters`** (object, optional): Operation parameters
- **`consent`** (object, optional): Consent information
- **`module_name`** (string, optional): RF sensing module
- **`target_platform`** (string, optional): Target platform
- **`config`** (object, optional): Configuration updates
- **`user`** (string, optional): User identifier

#### Localize Module (localize)
- **`map_path`** (string, optional): Path to reference map file
- **`scan_path`** (string, optional): Path to scan file
- **`scan_points`** (array, optional): Raw point cloud data as [x,y,z] coordinates
- **`intensity`** (array, optional): Intensity values for each point
- **`times`** (array, optional): Timestamp values for each point
- **`voxel`** (number, optional): Voxel size for downsampling in meters
- **`max_iter`** (number, optional): Maximum iterations for ICP refinement
- **`emit_las`** (boolean, optional): Whether to emit transformed LAS file
- **`out_path`** (string, optional): Output path for transformed LAS file
- **`safety_mode`** (string, optional): Safety mode ("on" or "off")

### Additional Parameters
- **`additional_params`** (object, optional): Additional module-specific parameters

## Output Schema

The tool returns a JSON object containing:
- **`success`** (boolean): Whether the operation was successful
- **`module`** (string): The module that was used
- **`action`** (string): The action that was performed
- **`result`** (any): The result from the target module
- **`error`** (string, optional): Error message if operation failed
- **`timestamp`** (string): ISO timestamp of the operation
- **`warning`** (string): Safety warning about experimental nature

## Usage Examples

### Simulation Module
```javascript
// Start a simulation session
const result = await rf_sense({
  module: "sim",
  action: "simulate",
  durationSec: 30,
  scenario: "single_person",
  outputFormat: "heatmap",
  resolution: "high"
});

// Process simulation data
const processed = await rf_sense({
  module: "sim",
  action: "process",
  sessionId: "session-uuid",
  pipeline: "occupancy"
});
```

### WiFi Lab Module
```javascript
// Configure WiFi Lab
const config = await rf_sense({
  module: "wifi_lab",
  action: "configure",
  providerUri: "tcp://127.0.0.1:5599",
  retention: "persist"
});

// Start WiFi capture
const capture = await rf_sense({
  module: "wifi_lab",
  action: "capture_start",
  durationSec: 300,
  annotation: "Through-wall occupancy detection test"
});
```

### mmWave Module
```javascript
// Configure mmWave radar
const config = await rf_sense({
  module: "mmwave",
  action: "configure",
  sdkPath: "/path/to/vendor/sdk",
  deviceConfig: {
    frequency: 60,
    bandwidth: 4,
    txPower: 10
  }
});

// Start mmWave capture
const capture = await rf_sense({
  module: "mmwave",
  action: "capture_start",
  captureMode: "point_cloud",
  durationSec: 60
});
```

### Natural Language Interface
```javascript
// Use natural language command
const result = await rf_sense({
  module: "natural_language",
  command: "Start a simulated RF session for 30 seconds and render occupancy heatmap",
  context: "Testing through-wall detection",
  platform: "linux"
});
```

### Guardrails Module
```javascript
// Validate operation
const validation = await rf_sense({
  module: "guardrails",
  action: "validate_operation",
  operation: "mmWave_capture",
  parameters: {
    duration: 60,
    power: 10
  }
});
```

### Localize Module
```javascript
// Localize point cloud
const localization = await rf_sense({
  module: "localize",
  map_path: "./reference_map.las",
  scan_path: "./new_scan.las",
  voxel: 0.05,
  max_iter: 60,
  emit_las: true,
  out_path: "./localized_scan.las",
  safety_mode: "on"
});
```

## Natural Language Access

Users can request RF sensing operations using natural language through the natural language module:

### Common Commands
- "Start a simulated RF session for 30 seconds"
- "Run WiFi lab capture in Room A for 15 seconds"
- "Configure mmWave radar for point cloud generation"
- "Process the last session with occupancy detection"
- "Export simulation results as LAS format"
- "Validate mmWave operation parameters"

### Module-Specific Commands
- **Simulation**: "Run single person occupancy simulation"
- **WiFi Lab**: "Capture Wi-Fi CSI data for through-wall sensing"
- **mmWave**: "Start mmWave radar with gesture detection"
- **Localize**: "Localize point cloud against reference map"

## Technical Implementation

### Unified Architecture
- **Single Tool Interface**: All RF Sense capabilities accessible through one tool
- **Module Routing**: Intelligent routing to appropriate specialized modules
- **Parameter Mapping**: Automatic parameter mapping between unified and module-specific schemas
- **Backward Compatibility**: Individual modules remain available for existing integrations

### Safety Integration
- **Comprehensive Warnings**: All safety warnings from individual modules preserved
- **Risk Assessment**: Module-specific risk levels clearly indicated
- **Guardrail Integration**: Safety and compliance features accessible through unified interface
- **Audit Logging**: All operations logged for security and compliance

### Cross-Platform Support
- **Universal Compatibility**: Works across Windows, Linux, macOS, Android, iOS
- **Platform Detection**: Automatic platform detection and optimization
- **Hardware Abstraction**: Abstracts platform-specific RF hardware differences
- **Driver Integration**: Supports various RF hardware drivers and SDKs

## Configuration

### Environment Variables
```bash
# RF Sense Unified Configuration
RF_SENSE_ENABLED=true
RF_SENSE_DEFAULT_MODULE=sim
RF_SENSE_SAFETY_MODE=on
RF_SENSE_AUDIT_LOGGING=true
RF_SENSE_MAX_DURATION_SEC=300
RF_SENSE_STORAGE_DIR=./.rf_sense_runs
```

### Module-Specific Configuration
Each module maintains its own configuration while being accessible through the unified interface:
- **Simulation**: `RF_SENSE_SIM_*` variables
- **WiFi Lab**: `RF_SENSE_WIFI_LAB_*` variables  
- **mmWave**: `RF_SENSE_MMWAVE_*` variables
- **Natural Language**: `RF_SENSE_NL_*` variables
- **Guardrails**: `RF_SENSE_GUARDRAILS_*` variables
- **Localize**: `RF_SENSE_LOCALIZE_*` variables

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

### Module-Specific Dependencies
- **Simulation**: LAS point cloud utilities, Potree viewer integration
- **WiFi Lab**: Wi-Fi CSI capture libraries, network interface access
- **mmWave**: Vendor SDKs, mmWave radar drivers
- **Natural Language**: NLP processing libraries
- **Guardrails**: Audit logging, compliance frameworks
- **Localize**: Point cloud processing, NDT/ICP algorithms

## Related Tools

### Individual Module Tools (Backward Compatibility)
- `rf_sense_sim` - Simulation module (individual)
- `rf_sense_wifi_lab` - WiFi Lab module (individual)
- `rf_sense_mmwave` - mmWave module (individual)
- `rf_sense_natural_language` - Natural Language interface (individual)
- `rf_sense_guardrails` - Safety and compliance (individual)
- `rf_sense_localize` - Point cloud localization (individual)

### Supporting Tools
- RF Sense viewer API for point cloud visualization
- LAS/PLY point cloud utilities
- Security guard and audit logging
- Cross-platform hardware abstraction

## Troubleshooting

### Common Issues
1. **"Unknown RF Sense module"**: Check module parameter spelling and supported values
2. **"Module disabled"**: Check module-specific environment variables
3. **"Invalid action"**: Verify action parameter for the specified module
4. **"Parameter mapping error"**: Check parameter names and types for the target module
5. **"Safety mode violation"**: Ensure proper authorization and safety mode configuration

### Debug Mode
```bash
# Enable debug logging for unified tool
DEBUG=rf_sense:unified npm start

# Enable debug logging for specific module
DEBUG=rf_sense:sim npm start
```

### Module-Specific Debugging
Each module maintains its own debug configuration:
```bash
# Debug specific modules
DEBUG=rf_sense:sim,rf_sense:wifi_lab npm start
```

## Version History

- **v1.0.0** - Initial unified implementation
- **v1.0.1** - Added comprehensive parameter mapping
- **v1.0.2** - Enhanced safety integration and warnings
- **v1.0.3** - Improved cross-platform compatibility

## ⚠️ Disclaimer

This unified tool is experimental and provided "as is" without warranty. Use at your own risk. The developers are not responsible for any damage or issues that may arise from using this tool. Always ensure you understand RF technology and safety considerations before using any RF-related tools. The unified interface does not reduce the risks associated with individual RF Sense modules - all safety warnings and experimental status apply to the entire unified tool.

**CRITICAL**: This tool consolidates all RF sensing capabilities into a single interface. The experimental and potentially harmful nature of all individual modules applies to the unified tool. Use only with proper authorization, RF engineering knowledge, and understanding of the extreme risks involved.
