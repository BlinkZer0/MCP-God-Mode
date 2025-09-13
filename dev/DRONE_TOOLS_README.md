# 🛸 Unified Drone Management Tool - MCP God Mode v1.9

**NEW in v1.9**: All drone functionality has been consolidated into a single unified tool that combines defense, offense, mobile optimization, and natural language processing capabilities with intelligent operation routing.

## 🚀 Overview

The Unified Drone Management Tool provides comprehensive automated threat response capabilities through a single interface that intelligently routes operations based on platform, context, and user intent. This tool combines all previously separate drone functionalities into one powerful, cohesive system.

### Key Features

- **Unified Interface**: Single tool for all drone operations (defense, offense, mobile, natural language)
- **Intelligent Routing**: Automatically detects platform and optimizes operations accordingly
- **Defensive Operations**: Scan surroundings, deploy shields, evade threats
- **Offensive Operations**: Jam signals, deploy decoys, execute counter-strikes
- **Mobile Optimization**: Battery-efficient, network-aware operations for mobile platforms
- **Natural Language Processing**: Understand commands like "scan for threats" or "jam the signals"
- **Safety Controls**: Risk acknowledgment, double confirmation, compliance modes
- **Audit Logging**: Comprehensive operation logging for compliance
- **Cross-Platform**: Works on Windows, Linux, macOS, Android, iOS with platform-specific optimizations
- **Flipper Zero Integration**: Real hardware control when enabled

## 🛠️ Installation & Setup

### Prerequisites

- Node.js 18+ (for refactored build)
- MCP God Mode platform installed

### Environment Configuration

1. Copy the environment template:
   ```bash
   cp drone.env.example .env
   ```

2. Configure your settings in `.env`:
   ```bash
   # Enable drone management
   MCPGM_DRONE_ENABLED=true
   
   # Require confirmation for operations
   MCPGM_REQUIRE_CONFIRMATION=true
   
   # Enable audit logging
   MCPGM_AUDIT_ENABLED=true
   
   # Compliance modes (disable offensive operations)
   MCPGM_MODE_HIPAA=false
   MCPGM_MODE_GDPR=false
   
   # Flipper Zero integration (optional)
   MCPGM_FLIPPER_ENABLED=false
   ```

### Build Setup

1. Build the TypeScript:
   ```bash
   npm run build
   ```

2. Test the unified tool:
   ```bash
   node dist/server-refactored.js
   ```

## 🛸 Unified Drone Tool

### Tool Registration

The unified drone tool is registered as `drone_unified` and provides all drone functionality through a single interface.

### Operation Modes

The tool supports four operation modes that are automatically selected based on context:

1. **Defense Mode** (`defense`): Defensive operations for threat protection
2. **Offense Mode** (`offense`): Offensive operations for counter-strikes
3. **Mobile Mode** (`mobile`): Mobile-optimized operations for Android/iOS
4. **Natural Language Mode** (`natural_language`): Intelligent command processing

### Available Actions

#### Defense Actions
- `scan_surroundings`: Network scanning and threat detection
- `deploy_shield`: Firewall hardening and protection deployment
- `evade_threat`: Traffic rerouting and threat avoidance

#### Offense Actions
- `jam_signals`: Signal jamming and disruption
- `deploy_decoy`: Honeypot and decoy deployment
- `counter_strike`: Reconnaissance and counter-attack operations

### Parameters

- `mode`: Operation mode (auto-detected from context)
- `action`: Specific drone action to perform
- `target`: Target network, system, or IP address
- `parameters`: Operation-specific parameters including:
  - `threatType`: Type of threat (ddos, intrusion, probe, etc.)
  - `intensity`: Operation intensity (low, medium, high)
  - `enableBatteryOptimization`: Enable battery optimization (mobile)
  - `enableNetworkOptimization`: Enable network optimization (mobile)
  - `enableBackgroundMode`: Enable background mode (mobile)
- `riskAcknowledged`: Required for offensive operations
- `threatLevel`: Threat level (1-10, affects confirmation requirements)
- `autoConfirm`: Skip confirmation prompts
- `naturalLanguageCommand`: Natural language command processing

## 🧠 Natural Language Processing

The unified tool includes advanced natural language processing capabilities:

### Example Commands

- "Scan for threats on the network"
- "Deploy protection against DDoS attacks"
- "Jam the signals from the attacker"
- "Evade the threat by rerouting traffic"
- "Deploy a decoy to mislead the attacker"
- "Counter-strike against the source IP"

### Supported Patterns

The tool recognizes various command patterns:
- **Scan actions**: scan, search, detect, find, discover, investigate
- **Shield actions**: shield, protect, defend, block, secure, guard
- **Evade actions**: evade, avoid, escape, retreat, hide, dodge
- **Jam actions**: jam, disrupt, block, interfere, scramble
- **Decoy actions**: decoy, fake, bait, trap, lure, distract
- **Strike actions**: strike, attack, retaliate, counter, hit, engage

## 📱 Mobile Optimization

When running on mobile platforms (Android/iOS), the tool automatically:

- Optimizes battery usage
- Reduces network data consumption
- Uses touch-friendly interfaces
- Implements background mode support
- Provides platform-specific optimizations

### Mobile Performance Metrics

The tool tracks and reports:
- Battery usage per operation
- Data consumption
- Operation duration
- Platform limitations

## ⚠️ Safety & Legal Compliance

### Safety Controls

- **Risk Acknowledgment**: Required for all offensive operations
- **Double Confirmation**: Required for high-threat operations (threat level > 7)
- **Compliance Modes**: HIPAA/GDPR modes disable offensive operations
- **Audit Logging**: All operations are logged for compliance

### Legal Warnings

All offensive operations include legal warnings:
- Signal jamming may violate telecommunications regulations
- Counter-strikes may violate computer crime laws
- Decoy deployment may be considered deceptive practices

## 🔧 Usage Examples

### Basic Defense Operation

```javascript
// Scan for threats
{
  "mode": "defense",
  "action": "scan_surroundings",
  "target": "192.168.1.0/24",
  "parameters": {
    "threatType": "general",
    "intensity": "low"
  }
}
```

### Offensive Operation with Risk Acknowledgment

```javascript
// Jam signals with risk acknowledgment
{
  "mode": "offense",
  "action": "jam_signals",
  "target": "192.168.1.100",
  "parameters": {
    "intensity": "medium"
  },
  "riskAcknowledged": true,
  "threatLevel": 6
}
```

### Natural Language Command

```javascript
// Natural language processing
{
  "mode": "natural_language",
  "naturalLanguageCommand": "Deploy protection against DDoS attacks on 192.168.1.0/24",
  "target": "192.168.1.0/24"
}
```

### Mobile-Optimized Operation

```javascript
// Mobile-optimized operation (automatically detected on mobile platforms)
{
  "mode": "mobile",
  "action": "scan_surroundings",
  "target": "192.168.1.0/24",
  "parameters": {
    "enableBatteryOptimization": true,
    "enableNetworkOptimization": true,
    "enableBackgroundMode": false
  }
}
```

## 🔍 Platform Detection

The tool automatically detects the platform and adjusts operations accordingly:

- **Windows**: Full desktop capabilities with Windows-specific commands
- **Linux**: Full desktop capabilities with Linux-specific commands
- **macOS**: Full desktop capabilities with macOS-specific commands
- **Android**: Mobile-optimized operations with Android-specific features
- **iOS**: Mobile-optimized operations with iOS-specific features

## 📊 Reporting

The unified tool provides comprehensive reporting including:

- Operation success/failure status
- Platform-specific optimizations applied
- Performance metrics (mobile platforms)
- Audit logs for compliance
- Natural language response summaries
- Legal warnings and disclaimers

## 🚀 Migration from Previous Versions

If you were using the separate drone tools (defense, offense, natural language, mobile), the unified tool provides backward compatibility through natural language processing. Simply use natural language commands and the tool will automatically route to the appropriate operation mode.

### Legacy Tool Mapping

- `drone_defense_enhanced` → `drone_unified` (defense mode)
- `drone_offense_enhanced` → `drone_unified` (offense mode)
- `drone_natural_language` → `drone_unified` (natural_language mode)
- `drone_mobile_optimized` → `drone_unified` (mobile mode)

## 🔧 Troubleshooting

### Common Issues

1. **Tool not registered**: Ensure the build completed successfully
2. **Permission errors**: Check environment configuration
3. **Mobile features not working**: Verify mobile platform detection
4. **Offensive operations blocked**: Check compliance mode settings

### Debug Information

Enable debug logging by setting:
```bash
MCPGM_DEBUG=true
```

## 📝 Changelog

### v1.9 - Unified Drone Tool
- **NEW**: Consolidated all drone functionality into single unified tool
- **NEW**: Intelligent operation routing based on platform and context
- **NEW**: Enhanced natural language processing with improved pattern recognition
- **NEW**: Mobile performance metrics and optimization tracking
- **IMPROVED**: Cross-platform compatibility and platform-specific optimizations
- **IMPROVED**: Safety controls and legal compliance features
- **REMOVED**: Separate drone tool registrations (now unified)

### v1.8 - Enhanced Drone Tools
- Enhanced cross-platform support
- Mobile optimization features
- Natural language interface
- Improved safety controls

## 📞 Support

For issues or questions regarding the Unified Drone Management Tool:

1. Check the troubleshooting section above
2. Review the audit logs for detailed operation information
3. Ensure proper environment configuration
4. Verify platform compatibility

---

**⚠️ Legal Disclaimer**: This tool is designed for authorized cybersecurity operations only. Offensive operations may violate laws and regulations. Ensure proper authorization and legal compliance before use.