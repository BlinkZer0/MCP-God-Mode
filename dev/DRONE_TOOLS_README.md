# 🛸 Drone Management Tools - MCP God Mode v1.8

Advanced drone management tools for cybersecurity threat response, providing both defensive and offensive capabilities with comprehensive safety controls and legal compliance features. **NEW in v1.8**: Enhanced interactive installer with comprehensive tool selection capabilities.

## 🚀 Overview

The Drone Management Tools provide automated threat response capabilities through virtual/simulated drones or real hardware integration via Flipper Zero bridge. These tools are designed for authorized cybersecurity operations with strict safety and legal compliance controls.

### Key Features

- **Defensive Operations**: Scan surroundings, deploy shields, evade threats
- **Offensive Operations**: Jam signals, deploy decoys, execute counter-strikes
- **Safety Controls**: Risk acknowledgment, double confirmation, compliance modes
- **Audit Logging**: Comprehensive operation logging for compliance
- **Cross-Platform**: Works on Windows, Linux, macOS with identical functionality
- **Flipper Zero Integration**: Real hardware control when enabled

## 🛠️ Installation & Setup

### Prerequisites

- Python 3.8+ (for modular build)
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
   
   # Simulation mode (recommended for testing)
   MCPGM_DRONE_SIM_ONLY=true
   
   # Require confirmation for operations
   MCPGM_REQUIRE_CONFIRMATION=true
   
   # Enable audit logging
   MCPGM_AUDIT_ENABLED=true
   ```

### Modular Build Setup

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Test the tools:
   ```bash
   python test_drone_tools.py
   ```

### Refactored Build Setup

1. Build the TypeScript:
   ```bash
   npm run build
   ```

2. Test the tools:
   ```bash
   node test_drone_tools_refactored.js
   ```

## 🛸 Drone Defense Tool

### Purpose
Deploy defensive drones to scan, shield, or evade attacks upon detection.

### Actions

#### 1. Scan Surroundings
- **Purpose**: Gather threat intelligence
- **Features**: Network scanning, device detection, threat indicator collection
- **Output**: Detailed scan report with suspicious devices and indicators

#### 2. Deploy Shield
- **Purpose**: Implement defensive measures
- **Features**: Firewall hardening, traffic filtering, DDoS protection
- **Output**: Shield deployment report with protection metrics

#### 3. Evade Threat
- **Purpose**: Avoid or redirect threats
- **Features**: Traffic rerouting, system isolation, backup channels
- **Output**: Evasion report with rerouting details

### Usage Examples

#### Python (Modular Build)
```bash
# Scan surroundings
python -m mcp_god_mode.tools.drone_defense --action "scan_surroundings" --target "192.168.1.0/24" --auto_confirm true

# Deploy shield for DDoS
python -m mcp_god_mode.tools.drone_defense --action "deploy_shield" --threat_type "ddos" --target "192.168.1.0/24" --auto_confirm true

# Evade intrusion threat
python -m mcp_god_mode.tools.drone_defense --action "evade_threat" --threat_type "intrusion" --target "192.168.1.0/24" --auto_confirm true
```

#### JavaScript (Refactored Build)
```javascript
// Via MCP tool call
const result = await mcpClient.callTool('drone_defense', {
  action: 'deploy_shield',
  threatType: 'ddos',
  target: '192.168.1.0/24',
  autoConfirm: true
});
```

## ⚔️ Drone Offense Tool

### Purpose
Deploy offensive drones for counter-strikes, only after defensive confirmation and strict safety checks.

### Actions

#### 1. Jam Signals
- **Purpose**: Disrupt attacker communications
- **Features**: Signal jamming, frequency targeting, effectiveness monitoring
- **Risk Level**: High
- **Requirements**: Risk acknowledgment, legal authorization

#### 2. Deploy Decoy
- **Purpose**: Mislead attackers with fake targets
- **Features**: Honeypot deployment, fake services, monitoring
- **Risk Level**: Medium
- **Requirements**: Risk acknowledgment

#### 3. Counter Strike
- **Purpose**: Execute ethical reconnaissance
- **Features**: Port scanning, intelligence gathering, ethical conduct
- **Risk Level**: Critical
- **Requirements**: Risk acknowledgment, double confirmation for high threats

### Usage Examples

#### Python (Modular Build)
```bash
# Jam signals (requires risk acknowledgment)
python -m mcp_god_mode.tools.drone_offense --action "jam_signals" --target_ip "192.168.1.100" --intensity "low" --risk_acknowledged true

# Deploy decoy
python -m mcp_god_mode.tools.drone_offense --action "deploy_decoy" --target_ip "192.168.1.100" --risk_acknowledged true

# Counter strike (high threat requires confirmation)
python -m mcp_god_mode.tools.drone_offense --action "counter_strike" --target_ip "192.168.1.100" --confirm true --risk_acknowledged true
```

#### JavaScript (Refactored Build)
```javascript
// Via MCP tool call
const result = await mcpClient.callTool('drone_offense', {
  action: 'jam_signals',
  targetIp: '192.168.1.100',
  intensity: 'low',
  riskAcknowledged: true,
  threatLevel: 8
});
```

## 🔄 Automated Workflow

### Drone Response Workflow
Automated workflow that chains defense → offense operations based on threat detection.

#### Workflow Steps
1. **Attack Detection**: Monitor for threats using security tools
2. **Defense Response**: Deploy appropriate defensive measures
3. **Offense Evaluation**: Assess if offensive response is warranted
4. **Offense Response**: Execute counter-strikes if threat level > 7

#### Usage
```bash
# Run complete workflow
python -m mcp_god_mode.tools.drone_response_workflow --target "192.168.1.0/24"
```

## 🔒 Safety & Compliance

### Safety Controls

#### Risk Acknowledgment
- **Required**: All offensive operations require explicit risk acknowledgment
- **Implementation**: `--risk_acknowledged true` flag or `riskAcknowledged: true` parameter

#### Double Confirmation
- **Trigger**: High threat operations (threat_level > 7)
- **Implementation**: `--confirm true` flag or `confirm: true` parameter

#### Compliance Modes
- **HIPAA Mode**: Disables offensive operations when `MCPGM_MODE_HIPAA=true`
- **GDPR Mode**: Disables offensive operations when `MCPGM_MODE_GDPR=true`

### Legal Disclaimers
All offensive operations include legal warnings:
```
⚠️ LEGAL WARNING: Offensive actions may violate laws and regulations. 
Use only for authorized security testing. Ensure proper authorization 
before deploying offensive capabilities.
```

### Audit Logging
- **Enabled by default**: `MCPGM_AUDIT_ENABLED=true`
- **Logs**: All operations, confirmations, and safety checks
- **Format**: Timestamped entries with operation details
- **Retention**: Configurable based on compliance requirements

## 🔌 Flipper Zero Integration

### Hardware Control
When `MCPGM_FLIPPER_ENABLED=true` and `MCPGM_DRONE_SIM_ONLY=false`:

- **BLE Commands**: Send commands to real drone hardware
- **USB Control**: Direct hardware interface
- **Real Operations**: Execute actual drone deployments

### Safety Considerations
- **Hard Lock**: Real hardware operations require explicit enablement
- **Legal Compliance**: Ensure proper authorization for real operations
- **Testing**: Always test in simulation mode first

## 🧪 Testing

### Test Suite
Comprehensive test suite covering all functionality:

```bash
# Modular build tests
python test_drone_tools.py

# Refactored build tests
node test_drone_tools_refactored.js
```

### Test Coverage
- ✅ Defensive operations (scan, shield, evade)
- ✅ Offensive operations (jam, decoy, counter-strike)
- ✅ Safety controls (risk acknowledgment, confirmation)
- ✅ Compliance modes (HIPAA, GDPR)
- ✅ Workflow automation
- ✅ Error handling

## 📊 Output Formats

### JSON Output
```json
{
  "operationId": "drone_def_1640995200000",
  "success": true,
  "threatLevel": 8,
  "actionsTaken": [
    {
      "actionType": "deploy_shield",
      "success": true,
      "message": "Defensive shield deployed successfully",
      "timestamp": "2025-01-27T12:00:00.000Z",
      "details": {
        "firewallRulesAdded": 12,
        "trafficFilters": 8,
        "ddosProtection": "activated"
      }
    }
  ],
  "auditLog": [
    "[2025-01-27T12:00:00.000Z] DroneDefenseManager initialized",
    "[2025-01-27T12:00:00.000Z] Deploying defensive shield for ddos on 192.168.1.0/24"
  ],
  "timestamp": "2025-01-27T12:00:00.000Z"
}
```

### Text Output
```
Operation ID: drone_def_1640995200000
Success: true
Threat Level: 8
Actions Taken: 1
  - deploy_shield: Defensive shield deployed successfully
Audit Log Entries: 2
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Confirmation Required
**Error**: "Confirmation required for drone deployment"
**Solution**: Set `MCPGM_REQUIRE_CONFIRMATION=false` or use `--auto_confirm true`

#### 2. Risk Not Acknowledged
**Error**: "Risk acknowledgment required for offensive operations"
**Solution**: Use `--risk_acknowledged true` or `riskAcknowledged: true`

#### 3. Compliance Mode Blocked
**Error**: "Offensive operations blocked due to compliance mode"
**Solution**: Disable HIPAA/GDPR modes or use only defensive operations

#### 4. Flipper Zero Not Connected
**Error**: "Flipper Zero device not found"
**Solution**: Ensure device is connected and `MCPGM_FLIPPER_ENABLED=true`

### Debug Mode
Enable detailed logging:
```bash
export MCPGM_AUDIT_ENABLED=true
export MCPGM_DRONE_SIM_ONLY=true
```

## 📚 API Reference

### Drone Defense Tool

#### Parameters
- `action`: `"scan_surroundings" | "deploy_shield" | "evade_threat"`
- `threatType`: `string` (default: "general")
- `target`: `string` (required)
- `autoConfirm`: `boolean` (default: false)

#### Response
- `operationId`: `string`
- `success`: `boolean`
- `threatLevel`: `number`
- `actionsTaken`: `DroneAction[]`
- `auditLog`: `string[]`
- `timestamp`: `string`

### Drone Offense Tool

#### Parameters
- `action`: `"jam_signals" | "deploy_decoy" | "counter_strike"`
- `targetIp`: `string` (required)
- `intensity`: `"low" | "medium" | "high"` (default: "low")
- `confirm`: `boolean` (default: false)
- `riskAcknowledged`: `boolean` (default: false)
- `threatLevel`: `number` (default: 5)

#### Response
- `operationId`: `string`
- `success`: `boolean`
- `riskAcknowledged`: `boolean`
- `actionsTaken`: `OffenseAction[]`
- `auditLog`: `string[]`
- `legalDisclaimer`: `string`
- `timestamp`: `string`

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Ensure 1:1 parity between modular and refactored builds
5. Submit pull request

### Code Standards
- **Python**: Follow PEP 8, use type hints
- **TypeScript**: Follow strict typing, use interfaces
- **Testing**: Maintain 100% test coverage
- **Documentation**: Update README and API docs

## 📄 License

This project is licensed under the MIT License. See LICENSE file for details.

## ⚠️ Legal Notice

**IMPORTANT**: These tools are designed for authorized cybersecurity operations only. Users are responsible for:

- Ensuring proper legal authorization before deployment
- Complying with local laws and regulations
- Using appropriate safety controls and confirmations
- Maintaining audit logs for compliance purposes

The authors and contributors are not responsible for misuse of these tools.

## 🆘 Support

For support and questions:
- **Issues**: GitHub Issues
- **Documentation**: This README and inline code comments
- **Community**: MCP God Mode community forums

---

**🛸 Ready to deploy your drone defense network!**
