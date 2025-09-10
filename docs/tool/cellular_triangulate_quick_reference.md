# Cellular Triangulation Tool - Quick Reference

## 🚀 Quick Start

### Basic Location Triangulation
```bash
# Natural Language
"Triangulate my location using cell towers"

# API Call
{
  "action": "triangulate_location",
  "modem": "wwan0",
  "mode": "rssi",
  "api_key": "your_opencellid_key"
}
```

### TDOA Mode (Higher Accuracy)
```bash
# Natural Language
"Find location with TDOA triangulation"

# API Call
{
  "action": "triangulate_location",
  "modem": "wwan0",
  "mode": "tdoa",
  "max_towers": 5,
  "api_key": "your_opencellid_key"
}
```

### Tower Scanning
```bash
# Natural Language
"Scan for nearby cellular towers"

# API Call
{
  "action": "scan_towers",
  "modem": "wwan0",
  "max_towers": 10
}
```

## 📋 Parameters Reference

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `action` | string | ✅ | - | `triangulate_location`, `scan_towers`, `query_tower_location`, `parse_nl_command` |
| `modem` | string | ❌ | `wwan0` | Cellular modem interface |
| `mode` | string | ❌ | `rssi` | `rssi` or `tdoa` |
| `towers` | string | ❌ | `auto` | Cell IDs or `auto` |
| `api_key` | string | ❌ | - | OpenCellID API key |
| `max_towers` | number | ❌ | `3` | Max towers (min 3) |
| `nl_command` | string | ❌ | - | Natural language command |
| `auto_confirm` | boolean | ❌ | `false` | Skip confirmation |

## 🎯 Natural Language Commands

### Location Commands
- **"Find my location with cell towers"**
- **"Triangulate location using cellular signals"**
- **"Locate device using cell tower triangulation"**
- **"Estimate location with RSSI signals"**

### Scanning Commands
- **"Scan for nearby cellular towers"**
- **"Find available cell towers"**
- **"List cellular towers in range"**

### Advanced Commands
- **"Use TDOA mode for higher accuracy"**
- **"Triangulate with 5 towers maximum"**
- **"Query tower locations via OpenCellID"**

## 📱 Platform Support

| Platform | Support Level | Requirements | Notes |
|----------|---------------|--------------|-------|
| **Linux** | ✅ Full | ModemManager, mmcli | Best support, real-time data |
| **Windows** | ⚠️ Limited | Npcap, drivers | Mobile Broadband API |
| **macOS** | ⚠️ Limited | External modem | AT commands only |
| **Android** | ✅ Full | Termux + root | Telephony API access |
| **iOS** | ❌ Limited | Jailbreak required | API fallback only |

## 🔧 Installation Commands

### Linux
```bash
# Install ModemManager
sudo apt install modemmanager

# Install Python dependencies
pip install requests pyphonecontrol

# Test modem
mmcli -L
```

### Windows
```bash
# Install Npcap
# Download from https://nmap.org/npcap/

# Install Python dependencies
pip install requests pyphonecontrol

# Test modem
netsh mbn show interface
```

### Android (Termux)
```bash
# Install Termux and ensure root
# Install Python
pkg install python

# Install dependencies
pip install requests pyphonecontrol

# Test modem (requires root)
su -c 'mmcli -L'
```

## 📊 Output Examples

### Successful Triangulation
```json
{
  "success": true,
  "cellular_triangulate_data": {
    "action": "triangulate_location",
    "mode": "rssi",
    "towers_used": 3,
    "location": {
      "lat": 43.0731,
      "lon": -89.4012,
      "error_radius_m": 200
    },
    "status": "success",
    "details": "Location estimated using rssi mode with 3 towers."
  }
}
```

### Tower Scan Results
```json
{
  "success": true,
  "cellular_triangulate_data": {
    "action": "scan_towers",
    "towers_found": 5,
    "tower_data": [
      {
        "cid": "1234",
        "lac": "5678",
        "mcc": "310",
        "mnc": "410",
        "rssi": -70
      }
    ],
    "status": "success",
    "details": "Scanned 5 cellular towers"
  }
}
```

## ⚠️ Common Issues & Solutions

### Issue: "No cellular modem found"
**Solutions:**
- Check modem connection and drivers
- Try different interface names: `wwan0`, `Modem0`, `cellular0`
- Verify ModemManager is running: `sudo systemctl status ModemManager`

### Issue: "Insufficient tower data"
**Solutions:**
- Ensure you're in an area with multiple cell towers
- Check signal strength and connectivity
- Increase `max_towers` parameter
- Try different location

### Issue: "API key invalid"
**Solutions:**
- Verify OpenCellID API key is correct
- Check API key permissions and quota
- Ensure internet connectivity
- Try without API key (simulated data)

### Issue: "Platform not supported"
**Solutions:**
- Install platform-specific dependencies
- Check modem compatibility
- Use alternative platform or external modem

## 🔐 Security & Legal

### ⚠️ Legal Warning
- **Authorization Required**: Use only on devices you own or have explicit permission
- **Regulatory Compliance**: Cellular tower data access may be regulated
- **No Data Storage**: Tower IDs are not permanently stored
- **API Key Security**: Store keys securely and rotate regularly

### Ethical Guidelines
- ✅ **Authorized Testing**: Use for legitimate security testing
- ✅ **Emergency Services**: Appropriate for emergency location services
- ✅ **Educational Use**: Suitable for learning and research
- ❌ **Unauthorized Access**: Do not use without permission
- ❌ **Illegal Activities**: Do not use for illegal purposes

## 🚀 Advanced Usage

### Custom Tower List
```bash
{
  "action": "triangulate_location",
  "towers": "1234:5678:310:410:-70,1235:5679:310:410:-75,1236:5680:310:410:-80",
  "mode": "rssi"
}
```

### Mobile Security Integration
```bash
{
  "action": "cellular_triangulation",
  "device_id": "android_device_001",
  "platform": "android",
  "cellular_modem": "wwan0",
  "test_depth": "comprehensive"
}
```

### Batch Processing
```bash
# Process multiple devices
for device in device1 device2 device3; do
  cellular_triangulate --modem $device --mode rssi --api-key $API_KEY
done
```

## 📚 Additional Resources

### Documentation
- **Full Documentation**: [cellular_triangulate.md](./cellular_triangulate.md)
- **API Reference**: See full documentation for detailed API
- **Platform Guides**: Platform-specific setup instructions

### External Resources
- **OpenCellID**: [opencellid.org](https://opencellid.org) - Free cellular tower database
- **ModemManager**: [freedesktop.org/wiki/Software/ModemManager](https://freedesktop.org/wiki/Software/ModemManager)
- **Cellular Networks**: Learn about GSM/CDMA/LTE protocols

### Community
- **GitHub Issues**: Report bugs and feature requests
- **Community Forums**: Join discussions and get help
- **Professional Support**: Contact for commercial support

---

*Quick Reference v1.0.0 - December 2024*
