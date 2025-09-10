# Wi-Fi Disruption Tool - Quick Reference

## 🚀 Quick Start

### Basic Deauthentication Attack
```bash
# Natural Language
"Disrupt wifi network on channel 6 for 30 seconds"

# API Call
{
  "action": "deauth_flood",
  "interface": "wlan0",
  "target_bssid": "AA:BB:CC:DD:EE:FF",
  "channel": 6,
  "duration": 30
}
```

### Malformed Packet Spam
```bash
# Natural Language
"Crash wifi access point with malformed packets"

# API Call
{
  "action": "malformed_spam",
  "interface": "wlan0",
  "channel": 11,
  "duration": 15
}
```

### Airtime Occupation
```bash
# Natural Language
"Jam wireless signal on channel 1"

# API Call
{
  "action": "airtime_occupation",
  "interface": "wlan0",
  "channel": 1,
  "duration": 60
}
```

## 📋 Parameters Reference

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `action` | string | Yes | - | Action to perform |
| `interface` | string | No | wlan0 | Wi-Fi interface name |
| `mode` | string | No | deauth | Disruption mode |
| `target_bssid` | string | No | all | Target BSSID or 'all' |
| `channel` | number | No | 1 | Wi-Fi channel (1-13, 36+) |
| `duration` | number | No | 10 | Duration in seconds |
| `power` | number | No | 20 | TX power in dBm |
| `auto_confirm` | boolean | No | false | Skip confirmation |

## 🎯 Disruption Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `deauth` | Send deauthentication frames | Disconnect clients from AP |
| `malformed` | Send invalid 802.11 frames | Crash/confuse vulnerable APs |
| `airtime` | Saturate medium with junk data | Block legitimate traffic |

## 🌍 Platform Support

| Platform | Support Level | Requirements |
|----------|---------------|--------------|
| **Linux** | ✅ Full | airmon-ng, root access |
| **Windows** | ✅ Full | Npcap, compatible driver |
| **macOS** | ⚠️ Limited | airport utility, 3rd-party kexts |
| **Android** | ⚠️ Limited | Termux, root, compatible hardware |
| **iOS** | ❌ Simulated | Jailbreak required for real functionality |

## 🔧 Installation Commands

```bash
# Install Python dependencies
pip install scapy>=2.4.0

# Linux setup
sudo apt-get install aircrack-ng

# Windows setup
# Download Npcap from https://npcap.com/

# Android (Termux)
pkg install python scapy-python3
```

## 🧠 Natural Language Examples

| Command | Parsed Parameters |
|---------|-------------------|
| "Jam wifi on channel 6" | `{mode: 'airtime', channel: 6}` |
| "Disconnect clients from AA:BB:CC:DD:EE:FF" | `{mode: 'deauth', target_bssid: 'AA:BB:CC:DD:EE:FF'}` |
| "Crash AP with malformed packets for 30 seconds" | `{mode: 'malformed', duration: 30}` |
| "Flood deauth packets on wlan0" | `{mode: 'deauth', interface: 'wlan0'}` |

## ⚠️ Safety Checklist

- [ ] **Authorization**: Written permission for target network
- [ ] **Scope**: Clearly defined testing boundaries
- [ ] **Legal**: Compliance with local laws and regulations
- [ ] **Hardware**: Compatible Wi-Fi adapter with monitor mode
- [ ] **Permissions**: Root/admin access for packet injection
- [ ] **Documentation**: Log all testing activities

## 🚨 Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Monitor mode fails | Check interface support: `iw list` |
| Permission denied | Run with root: `sudo python3 wifi_disrupt.py` |
| Scapy import error | Install: `pip install scapy` |
| No packets sent | Verify interface name and channel |
| Windows issues | Install Npcap, run as Administrator |

## 📊 Expected Output

```json
{
  "success": true,
  "wifi_disrupt_data": {
    "action": "deauth_flood",
    "packets_sent": 1200,
    "status": "success",
    "details": "Deauth flood completed on channel 6",
    "ethical_warning": "⚠️ LEGAL WARNING: Use only on networks you own or have explicit permission for."
  }
}
```

## 🔗 Related Tools

- `wifi_security_toolkit` - Comprehensive Wi-Fi security testing
- `wifi_hacking` - Advanced Wi-Fi penetration testing
- `packet_sniffer` - Network traffic capture and analysis
- `network_security` - Network security assessment

## 📞 Support

- **Documentation**: [Full Documentation](wifi_disrupt.md)
- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Community**: [Security Forums](https://example.com/forums)

---

**⚠️ REMEMBER**: This tool is for authorized testing only. Always ensure you have proper permission before using on any network.
