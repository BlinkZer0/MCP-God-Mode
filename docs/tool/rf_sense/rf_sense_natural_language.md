# RF Sense Natural Language Interface

## ⚠️ **EXPERIMENTAL TOOL WARNING**

**This tool is experimental and remains untested. We are building the structure before reaching our goal of 100% functionality.**

**⚠️ IMPORTANT SAFETY NOTICE**: This interface controls RF sensing tools that can be **harmful to devices** if misused. The natural language interface does not provide safety protections - users are still responsible for understanding the risks of RF operations.

**Use at your own risk. We strongly advise against using these tools unless you know what you're doing.**

## Overview

The `rf_sense_natural_language` module provides an intuitive natural language interface for all RF sensing operations. It parses natural language commands and routes them to the appropriate RF sensing modules (simulation, WiFi lab, or mmWave).

## Tool Name
`rf_sense_natural_language`

## Description
🧠 **RF Sense Natural Language Interface** - Process natural language commands for RF sensing operations with intelligent parsing and routing to appropriate modules (simulation, WiFi lab, mmWave). Supports commands like 'Start a simulated RF session for 30s and render occupancy heatmap', 'Run wifi lab capture in Room A for 15s', 'With mmwave, capture 5s and export point cloud'.

## ⚠️ Experimental Status
- **Current Status**: Experimental and untested
- **Development Phase**: Building structure before reaching 100% functionality
- **Testing Status**: Not yet fully validated
- **Use Recommendation**: For development and testing only

## Input Schema

### Required Parameters
- **`command`** (string, required): Natural language command for RF sensing operations

### Optional Parameters
- **`context`** (string, optional): Additional context about the operation
- **`userIntent`** (string, optional): User's intended goal or objective
- **`platform`** (string, optional): Target platform preference (auto-detect if not specified)

## Output Schema

The tool returns parsed command results including:
- Parsed command parameters
- Target module identification
- Operation confirmation
- Routing information
- Status updates

## ⚠️ Safety and Legal Considerations

### Interface Safety Notes
- **No Safety Override**: This interface does not bypass safety warnings
- **User Responsibility**: Users remain responsible for understanding RF risks
- **Command Validation**: Commands are parsed but not safety-validated
- **Expertise Required**: Still requires RF engineering knowledge

### Supported Command Types
- **Simulation Commands**: Safe synthetic data generation
- **WiFi Lab Commands**: Real Wi-Fi CSI experiments (HIGH RISK)
- **mmWave Commands**: Real mmWave radar operations (EXTREME RISK)

## Usage Examples

### Simulation Commands (Safe)
```javascript
// Safe simulation commands
const result = await rf_sense_natural_language({
  command: "Start a simulated RF session for 30 seconds and render occupancy heatmap"
});

const result2 = await rf_sense_natural_language({
  command: "Run a single person simulation with high resolution point cloud output"
});
```

### WiFi Lab Commands (High Risk)
```javascript
// High-risk WiFi lab commands
const result = await rf_sense_natural_language({
  command: "Run wifi lab capture in Room A for 15 seconds with occupancy detection",
  context: "Authorized research facility",
  userIntent: "Occupancy monitoring research"
});
```

### mmWave Commands (Extreme Risk)
```javascript
// Extreme-risk mmWave commands
const result = await rf_sense_natural_language({
  command: "With mmwave, capture 5 seconds and export point cloud",
  context: "Authorized RF research lab",
  userIntent: "High-resolution radar sensing",
  platform: "linux"
});
```

### Complex Commands
```javascript
// Multi-step commands
const result = await rf_sense_natural_language({
  command: "Start mmWave capture for 60 seconds, process with object tracking, and export as LAS format"
});
```

## Natural Language Command Examples

### Simulation Commands
- "Start a simulated RF session for 30 seconds and render occupancy heatmap"
- "Run a single person simulation with high resolution point cloud output"
- "Generate synthetic gesture data for 10 seconds and export as PLY"
- "Create a multiple people simulation scenario with medium resolution"
- "Process the last simulation session with pose estimation pipeline"

### WiFi Lab Commands
- "Run wifi lab capture in Room A for 15 seconds"
- "Start WiFi CSI capture for occupancy detection through walls"
- "Process the last WiFi session with pose estimation"
- "Export WiFi lab results as point cloud format"
- "Configure WiFi lab for research network monitoring"

### mmWave Commands
- "With mmwave, capture 5 seconds and export point cloud"
- "Start mmWave radar scan for object tracking"
- "Configure 77 GHz mmWave radar with safety limits"
- "Process mmWave data for gesture detection"
- "Export mmWave results as LAS point cloud"

### Multi-Module Commands
- "Compare simulation vs WiFi lab occupancy detection"
- "Run both simulation and mmWave capture for comparison"
- "Process all available sessions with point cloud pipeline"

## Command Parsing Features

### Intelligent Routing
- **Module Detection**: Automatically identifies target RF sensing module
- **Parameter Extraction**: Extracts duration, resolution, format, and other parameters
- **Context Awareness**: Considers user intent and context
- **Platform Optimization**: Routes to platform-appropriate implementations

### Parameter Recognition
- **Time Expressions**: "30 seconds", "5 minutes", "1 hour"
- **Resolution Settings**: "high resolution", "medium quality", "low res"
- **Output Formats**: "point cloud", "heatmap", "LAS format", "PLY export"
- **Scenarios**: "single person", "multiple people", "empty room"
- **Pipelines**: "occupancy detection", "pose estimation", "object tracking"

### Error Handling
- **Command Validation**: Validates command syntax and parameters
- **Module Availability**: Checks if target modules are available
- **Parameter Validation**: Ensures parameters are within safe limits
- **Fallback Suggestions**: Provides alternative command suggestions

## Technical Implementation

### Command Processing Pipeline
1. **Natural Language Parsing**: Analyzes command structure and intent
2. **Parameter Extraction**: Identifies and extracts command parameters
3. **Module Routing**: Determines appropriate RF sensing module
4. **Command Translation**: Converts to module-specific API calls
5. **Execution**: Routes command to target module
6. **Response Processing**: Formats and returns results

### Supported Command Patterns
- **Action + Duration**: "Start capture for X seconds"
- **Action + Target**: "Process session with pipeline"
- **Action + Format**: "Export results as format"
- **Action + Parameters**: "Configure with settings"
- **Multi-step**: "Start, process, and export"

### Module Integration
- **rf_sense_sim**: Simulation and synthetic data generation
- **rf_sense_wifi_lab**: Real Wi-Fi CSI experiments
- **rf_sense_mmwave**: Real mmWave radar operations
- **rf_sense_localize**: Point cloud localization
- **rf_sense_guardrails**: Safety and compliance features

## Configuration

### Environment Variables
```bash
# RF Sense Natural Language Configuration
RF_SENSE_NL_ENABLED=true
RF_SENSE_NL_PLATFORM=auto
RF_SENSE_NL_SAFETY_MODE=true
RF_SENSE_NL_COMMAND_TIMEOUT=30000
```

### Command Processing Settings
- **Timeout**: Maximum time for command processing
- **Safety Mode**: Enable additional safety checks
- **Platform Detection**: Automatic or manual platform selection
- **Module Availability**: Check module availability before routing

## Platform Support

- ✅ Windows
- ✅ Linux
- ✅ macOS
- ✅ Android
- ✅ iOS

## Dependencies

### Required Packages
- Node.js 18+
- TypeScript 5+
- Natural language processing utilities
- RF sensing module integrations

### Optional Dependencies
- Advanced NLP libraries for complex command parsing
- Machine learning models for intent recognition
- Speech recognition for voice commands

## Related Tools

- `rf_sense_sim` - Simulation and synthetic data generation
- `rf_sense_wifi_lab` - Wi-Fi CSI-based sensing
- `rf_sense_mmwave` - mmWave radar integration
- `rf_sense_guardrails` - Safety and compliance features
- `rf_sense_localize` - Point cloud localization

## Troubleshooting

### Common Issues
1. **"Command not recognized"**: Check command syntax and supported patterns
2. **"Module not available"**: Verify target module is enabled and configured
3. **"Parameter parsing failed"**: Ensure parameters are in supported format
4. **"Routing error"**: Check module availability and configuration
5. **"Timeout error"**: Increase timeout or simplify command

### Command Debugging
```bash
# Enable debug logging for command processing
DEBUG=rf_sense:nl:* npm start
```

### Supported Command Formats
- Use clear, simple language
- Specify durations in seconds, minutes, or hours
- Include module names when ambiguous
- Provide context for complex operations
- Use supported parameter values

## Version History

- **v1.0.0** - Initial experimental implementation
- **v1.0.1** - Added multi-module command support
- **v1.0.2** - Enhanced parameter extraction
- **v1.0.3** - Improved error handling and validation

## ⚠️ Disclaimer

This tool is experimental and provided "as is" without warranty. Use at your own risk. The natural language interface does not provide safety protections for the underlying RF sensing operations. Users are still responsible for understanding the risks and ensuring proper authorization for all RF operations.

**The developers are not responsible for any damage, legal violations, or issues that may arise from using this tool. Always consult with legal counsel and RF safety experts before using any RF sensing capabilities.**
