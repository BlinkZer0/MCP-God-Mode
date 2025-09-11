# RF Sense Tools - Real Implementation

## Overview

The RF Sense Tools provide comprehensive radio frequency sensing capabilities with real hardware integration. This toolkit includes four main modules with full functionality:

1. **rf_sense.sim** - Simulation and synthetic data generation for testing
2. **rf_sense.wifi_lab** - Real Wi-Fi CSI experiments with commodity hardware
3. **rf_sense.mmwave** - Real FMCW mmWave radar integration with vendor SDKs
4. **rf_sense.natural_language** - Natural language interface for all RF operations

## Features

### Core Capabilities
- **CSI Data Processing**: Channel State Information analysis and processing
- **Motion Detection**: Occupancy detection and motion pattern analysis
- **Pose Estimation**: Human pose and gesture recognition
- **Point Cloud Generation**: 3D point cloud creation and visualization
- **Through-Wall Sensing**: Detect and track objects and people through walls and obstacles
- **Cross-Platform Support**: Windows, Linux, macOS, Android, iOS
- **Natural Language Interface**: Intuitive command processing
- **Surveillance**: Real-time monitoring and surveillance capabilities
- **Tracking**: Person and object tracking across multiple rooms
- **Intrusion Detection**: Security monitoring and perimeter protection

### Unrestricted Operations
- **No Consent Management**: No consent requirements
- **No Audit Logging**: No operation logging
- **No Data Protection**: No encryption or security requirements
- **No Legal Compliance**: No compliance requirements
- **No Geofencing**: No geographic restrictions
- **No Rate Limiting**: No operation frequency limits
- **No Time Limits**: Unlimited operation duration
- **No Power Limits**: Unlimited transmit power
- **No Network Restrictions**: All networks allowed

## Modules

### 1. RF Sense Simulation (rf_sense.sim)

**Purpose**: Rapid prototyping and testing with synthetic datasets
**Capabilities**:
- Generate synthetic CSI data
- Simulate motion patterns
- Create occupancy heatmaps
- Export visualization data
- Test algorithms without hardware

**Use Cases**:
- UI/UX development
- Algorithm testing
- Educational demonstrations
- Performance evaluation
- Development and debugging
- Through-wall sensing research
- Privacy-preserving occupancy detection

### 2. RF Sense WiFi Lab (rf_sense.wifi_lab)

**Purpose**: Real Wi-Fi CSI experiments with commodity hardware
**Capabilities**:
- Capture live CSI data from Wi-Fi networks
- Process occupancy detection through walls
- Generate pose estimates and human silhouettes
- Export point clouds and heatmaps
- Real-time data processing
- Network protocol integration
- Through-wall object and person detection
- Multi-room occupancy monitoring

**Requirements**:
- Wi-Fi CSI capable hardware
- Network access to target networks
- Appropriate permissions for RF operations

### 3. RF Sense mmWave (rf_sense.mmwave)

**Purpose**: High-resolution radar sensing with FMCW mmWave systems
**Capabilities**:
- FMCW radar integration with vendor SDKs
- Object tracking and detection through walls
- Gesture recognition and pose estimation
- High-resolution point clouds
- Real-time radar data processing
- Multi-target tracking across rooms
- Through-wall human detection
- Penetration through common building materials

**Requirements**:
- mmWave radar development kit
- Vendor SDK installation
- Appropriate hardware drivers
- RF regulatory compliance

### 4. RF Sense Natural Language Interface (rf_sense.natural_language)

**Purpose**: Intuitive natural language interface for all RF sensing operations
**Capabilities**:
- Parse natural language commands
- Route commands to appropriate modules
- Intelligent command interpretation
- Cross-module operation coordination
- User-friendly command processing

**Supported Commands**:
- "Start a simulated RF session for 30 seconds and render occupancy"
- "Run WiFi lab capture for 20 seconds in Room A"
- "Begin mmWave radar scan for point cloud generation"
- "Process last session into occupancy heatmap"
- "Export session as PLY format"
- "Detect people through walls in adjacent rooms"
- "Monitor occupancy across multiple rooms"
- "Track movement through building materials"

## Installation

### Prerequisites
- Node.js 18+
- TypeScript 5+
- Platform-specific dependencies

### Setup
```bash
# Install dependencies
npm install

# Configure environment (optional - all defaults are unrestricted)
cp .env.example .env

# Start the server
npm start
```

## Configuration

### Environment Variables
```bash
# RF Sense Lab Configuration
RF_SENSE_LAB_ENABLED=true
RF_SENSE_LAB_PROVIDER_URI="tcp://127.0.0.1:5599"
RF_SENSE_LAB_STORAGE_DIR="./.rf_lab_runs"
RF_SENSE_LAB_DEFAULT_RETENTION="persist"
RF_SENSE_LAB_MAX_DURATION_SEC=3600

# RF Sense mmWave Configuration
RF_SENSE_MMWAVE_ENABLED=true
RF_SENSE_MMWAVE_STORAGE_DIR="./.rf_mmwave_runs"
RF_SENSE_MMWAVE_DEFAULT_RETENTION="persist"
RF_SENSE_MMWAVE_MAX_DURATION_SEC=3600

# RF Sense Natural Language Configuration
RF_SENSE_NL_ENABLED=true

# RF Sense Simulation Configuration
RF_SENSE_SIM_ENABLED=true
RF_SENSE_SIM_STORAGE_DIR="./.rf_sim_runs"
RF_SENSE_SIM_MAX_DURATION_SEC=300
```

## Usage

### Natural Language Commands
```bash
# Start simulation for testing
"Start a simulated RF session for 30 seconds and render occupancy heatmap"

# Run real WiFi lab experiment
"Run WiFi lab capture for 20 seconds in Room A"

# Real mmWave operation
"Start mmWave capture for 15 seconds and generate point cloud"

# Process and export data
"Process last session into occupancy heatmap and export as PLY"

# Through-wall sensing commands
"Detect people through walls in adjacent rooms"
"Monitor occupancy across multiple rooms using WiFi CSI"
"Track movement through building materials with mmWave radar"
"Generate through-wall occupancy map for entire building"
```

### API Usage
```typescript
// Configure WiFi lab
await rfSenseWifiLab.configure({
  providerUri: "tcp://127.0.0.1:5599",
  retention: "persist"
});

// Start real WiFi capture for through-wall sensing
const session = await rfSenseWifiLab.captureStart({
  durationSec: 300, // 5 minutes
  annotation: "Through-wall occupancy detection across multiple rooms",
  participants: ["user1", "user2"]
});

// Process captured data for through-wall detection
const result = await rfSenseWifiLab.process({
  sessionId: session.sessionId,
  pipeline: "occupancy" // Detects people through walls
});

// Export results
await rfSenseWifiLab.export({
  sessionId: session.sessionId,
  format: "json",
  path: "./occupancy_data.json"
});

// Configure mmWave radar
await rfSenseMmWave.configure({
  sdkPath: "/opt/mmwave_sdk",
  deviceConfig: {
    frequency: 77,
    bandwidth: 2,
    txPower: 20,
    frameRate: 100
  }
});

// Start mmWave capture for through-wall object detection
const mmWaveSession = await rfSenseMmWave.captureStart({
  durationSec: 60,
  captureMode: "point_cloud",
  annotation: "Through-wall object and person detection test"
});

// Process mmWave data for through-wall tracking
const mmWaveResult = await rfSenseMmWave.process({
  sessionId: mmWaveSession.sessionId,
  pipeline: "object_tracking" // Tracks objects through walls
});
```

## Through-Wall Sensing Capabilities

### Overview
RF sensing technology enables detection and tracking of objects and people through walls and other obstacles using radio frequency signals. This capability is particularly powerful for:

- **Privacy-Preserving Monitoring**: Detect occupancy without cameras
- **Security Applications**: Perimeter protection and intrusion detection
- **Smart Building Systems**: Energy-efficient occupancy-based automation
- **Search and Rescue**: Locate people in collapsed buildings or disaster areas
- **Healthcare Monitoring**: Non-invasive patient monitoring

### Technical Principles

#### WiFi CSI Through-Wall Sensing
- **Channel State Information (CSI)**: Analyzes how Wi-Fi signals are affected by human movement
- **Signal Penetration**: Wi-Fi signals can penetrate common building materials (drywall, wood, glass)
- **Multi-Path Analysis**: Detects signal reflections and distortions caused by moving objects
- **Machine Learning**: Uses AI to distinguish human movement from other environmental changes

#### mmWave Radar Through-Wall Sensing
- **High-Frequency Radar**: Uses millimeter-wave frequencies (24-77 GHz) for high-resolution detection
- **Material Penetration**: Can penetrate through drywall, wood, and other common building materials
- **Point Cloud Generation**: Creates 3D representations of objects and people behind walls
- **Real-Time Processing**: Provides immediate feedback on detected movements and positions

### Supported Materials
- **Drywall**: Excellent penetration for both WiFi CSI and mmWave
- **Wood**: Good penetration, especially for lower frequencies
- **Glass**: Moderate penetration, may require higher power
- **Concrete**: Limited penetration, may require specialized equipment
- **Metal**: Very limited penetration, may block signals entirely

### Use Cases and Applications

#### Residential Applications
- **Smart Home Automation**: Occupancy-based lighting and HVAC control
- **Elderly Care**: Fall detection and activity monitoring
- **Security**: Intrusion detection without visible cameras
- **Energy Efficiency**: Room-by-room occupancy optimization

#### Commercial Applications
- **Office Buildings**: Space utilization and occupancy analytics
- **Retail**: Customer flow analysis and security monitoring
- **Healthcare**: Patient monitoring and staff efficiency
- **Education**: Classroom occupancy and safety monitoring

#### Emergency and Rescue
- **Disaster Response**: Locate survivors in collapsed buildings
- **Firefighting**: Find people in smoke-filled rooms
- **Law Enforcement**: Tactical surveillance and hostage situations
- **Search and Rescue**: Mountain and wilderness rescue operations

## Point Cloud Viewer

The RF Sense tools include a web-based point cloud viewer for visualizing 3D data:

### Features
- **3D Visualization**: Three.js-based point cloud rendering
- **Interactive Controls**: Pan, zoom, rotate
- **Live Data**: Real-time point cloud updates
- **Export Support**: PLY, PCD, JSON formats
- **PWA Support**: Progressive Web App capabilities
- **Unrestricted Access**: No access controls

### Access
- **URL**: `http://localhost:3000/viewer/pointcloud`
- **API**: `http://localhost:3000/api/rf_sense/points`

## Legal and Ethical Considerations

### Consent and Privacy
- **Consent Required**: Obtain appropriate consent for RF sensing operations
- **Participant Rights**: Respect participant privacy and data rights
- **Data Minimization**: Collect only necessary data for the intended purpose
- **Purpose Limitation**: Use data only for stated purposes

### Data Protection
- **Security**: Implement appropriate data security measures
- **Retention**: Follow data retention policies and legal requirements
- **Access Control**: Implement proper access controls for sensitive data
- **Encryption**: Use encryption for data in transit and at rest

### Compliance
- **RF Regulations**: Comply with local RF transmission regulations
- **Privacy Laws**: Follow applicable privacy laws (GDPR, CCPA, etc.)
- **Research Ethics**: Follow institutional research ethics guidelines
- **Data Protection**: Implement appropriate data protection measures

## Troubleshooting

### Common Issues
1. **Hardware Not Found**: Ensure RF hardware is properly connected and drivers are installed
2. **Network Access**: Verify network permissions and CSI provider connectivity
3. **SDK Issues**: Check vendor SDK installation and configuration
4. **Storage Permissions**: Ensure write permissions for data storage directories
5. **RF Regulations**: Verify compliance with local RF transmission regulations

### Debug Mode
```bash
# Enable debug logging
DEBUG=rf_sense:* npm start

# Verbose output
npm start -- --verbose
```

## Contributing

### Development Setup
```bash
# Clone repository
git clone <repository-url>

# Install dependencies
npm install

# Run tests
npm test

# Build project
npm run build
```

### Code Style
- TypeScript strict mode
- ESLint configuration
- Prettier formatting
- Comprehensive testing

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

### Documentation
- [API Reference](docs/api.md)
- [User Guide](docs/user-guide.md)
- [Developer Guide](docs/developer-guide.md)

### Community
- [GitHub Issues](https://github.com/your-repo/issues)
- [Discussions](https://github.com/your-repo/discussions)
- [Discord](https://discord.gg/your-server)

### Professional Support
- Email: support@your-domain.com
- Phone: +1-555-0123
- Enterprise: enterprise@your-domain.com