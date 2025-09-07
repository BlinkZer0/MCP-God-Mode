# MCP God Mode - Prompt Templates & Natural Language Guide

## 🎯 Overview

This guide provides comprehensive prompt templates and examples for using the MCP God Mode tools with natural language. All tools support natural language input and will automatically translate your requests into the appropriate function calls.

## 🚀 How to Use Natural Language

### Basic Pattern
Instead of remembering technical parameters, simply describe what you want to accomplish:

**❌ Technical Way:**
```
wifi_security_toolkit action=scan_networks interface=wlan0 channel=6
```

**✅ Natural Language Way:**
```
"Scan for Wi-Fi networks on channel 6"
"Find wireless networks around me"
"Show me all available Wi-Fi networks"
```

## 🔧 Core Tool Prompt Templates

### 1. **File Operations** (`file_ops`)

#### Copy Files
```
"Copy the project folder to my backup directory"
"Make a backup of my documents folder"
"Duplicate the source code to a new location"
```

#### Move Files
```
"Move the old files to the archive folder"
"Relocate the project to a different directory"
"Transfer the backup files to external storage"
```

#### Create Files/Directories
```
"Create a new project folder called 'MyProject'"
"Make a backup directory for my files"
"Create a log file with today's date"
```

#### Search Files
```
"Find all Python files in my project"
"Search for files containing 'password'"
"Look for log files from yesterday"
```

### 2. **Process Execution** (`proc_run`)

#### System Commands
```
"Show me what's in the current directory"
"List all running processes"
"Check the system status"
"Run a Python script"
```

#### Development Tools
```
"Start the development server"
"Run the test suite"
"Build the project"
"Install dependencies"
```

### 3. **Git Operations** (`git_status`)

```
"Check the status of my git repository"
"What's the current branch?"
"Show me what files have changed"
"Get git status for the project folder"
```

## 🛡️ Security Tool Prompt Templates

### 1. **Wi-Fi Security** (`wifi_security_toolkit`)

#### Network Discovery
```
"Scan for Wi-Fi networks in the area"
"Find all wireless networks nearby"
"Show me available Wi-Fi networks"
"Discover Wi-Fi networks on channel 6"
```

#### Handshake Capture
```
"Capture the WPA handshake from 'OfficeWiFi'"
"Get the handshake from the target network"
"Capture authentication data from the network"
"Sniff the handshake from 'HomeNetwork'"
```

#### Password Attacks
```
"Crack the password of the target network"
"Try to break the Wi-Fi password"
"Use a dictionary attack on the network"
"Perform a brute force attack"
```

#### Evil Twin Attacks
```
"Create an evil twin of the 'OfficeWiFi' network"
"Set up a rogue access point"
"Launch an evil twin attack on the target"
"Create a fake network to capture credentials"
```

#### WPS Exploitation
```
"Test WPS vulnerability on the router"
"Try to exploit WPS on the target network"
"Use pixie dust attack on the router"
"Test WPS security of the network"
```

### 2. **Bluetooth Security** (`bluetooth_security_toolkit`)

#### Device Discovery
```
"Scan for Bluetooth devices nearby"
"Find all Bluetooth devices in range"
"Discover Bluetooth speakers and phones"
"Look for Bluetooth devices in the area"
```

#### Service Enumeration
```
"Find services on the target Bluetooth device"
"Discover what services the device offers"
"Enumerate Bluetooth services on the target"
"List all available Bluetooth services"
```

#### Data Extraction
```
"Extract contacts from the Bluetooth device"
"Get calendar data from the target device"
"Extract messages from the Bluetooth phone"
"Download files from the Bluetooth device"
```

#### Security Testing
```
"Test Bluetooth authentication security"
"Check if the device is vulnerable to attacks"
"Test Bluetooth encryption strength"
"Verify Bluetooth security measures"
```

### 3. **SDR Security** (`sdr_security_toolkit`)

#### Hardware Detection
```
"Detect my SDR hardware"
"Find available SDR devices"
"List SDR devices connected to the system"
"Check what SDR hardware I have"
```

#### Signal Reception
```
"Tune to 100 MHz and capture signals"
"Listen to radio signals at 2.4 GHz"
"Capture signals from the target frequency"
"Record audio from the radio station"
```

#### Protocol Decoding
```
"Decode ADS-B signals from aircraft"
"Decode POCSAG pager messages"
"Decode APRS amateur radio signals"
"Decode AIS ship tracking signals"
```

#### Signal Analysis
```
"Analyze the captured radio signals"
"Perform spectrum analysis of the signals"
"Detect modulation type of the signal"
"Identify the radio protocol being used"
```

#### Broadcasting
```
"Transmit audio at 100 MHz using FM"
"Broadcast a signal at 2.4 GHz"
"Jam frequencies for testing purposes"
"Create interference on the target frequency"
```

## 🎭 Advanced Natural Language Patterns

### Complex Requests
```
"I want to hack the Wi-Fi network, capture handshakes, and crack passwords"
"Test Bluetooth security, discover services, and extract data"
"Analyze radio signals, decode protocols, and detect threats"
```

### Conditional Requests
```
"If the Wi-Fi network is vulnerable, try to crack the password"
"Only attack Bluetooth devices that are in pairing mode"
"Scan radio frequencies and alert me if you find suspicious signals"
```

### Multi-Step Operations
```
"First scan for Wi-Fi networks, then capture handshakes from the strongest one"
"Discover Bluetooth devices, connect to the target, and extract all available data"
"Tune to multiple frequencies, capture signals, and analyze each one"
```

## 🔍 Parameter Translation Examples

### Wi-Fi Parameters
| Natural Language | Parameter | Value |
|------------------|-----------|-------|
| "the network called 'OfficeWiFi'" | `target_ssid` | "OfficeWiFi" |
| "on channel 6" | `channel` | 6 |
| "for 5 minutes" | `duration` | 300 |
| "using my wireless adapter" | `interface` | "wlan0" |
| "with maximum power" | `power_level` | 100 |

### Bluetooth Parameters
| Natural Language | Parameter | Value |
|------------------|-----------|-------|
| "the iPhone nearby" | `target_name` | "iPhone" |
| "the device with address 00:11:22:33:44:55" | `target_address` | "00:11:22:33:44:55" |
| "audio devices only" | `device_class` | "Audio" |
| "for 10 minutes" | `duration` | 600 |
| "using passive scanning" | `attack_type` | "passive" |

### SDR Parameters
| Natural Language | Parameter | Value |
|------------------|-----------|-------|
| "my first SDR device" | `device_index` | 0 |
| "at 100 MHz" | `frequency` | 100000000 |
| "with high quality" | `sample_rate` | 8000000 |
| "using FM modulation" | `modulation` | "FM" |
| "for aircraft tracking" | `protocol` | "ADS-B" |

## 🚨 Security & Legal Considerations

### Authorized Use Only
- **All tools are for authorized security testing only**
- Use only on networks/devices you own or have permission to test
- Follow responsible disclosure practices

### Legal Compliance
- Ensure compliance with local laws and regulations
- Obtain proper authorization before testing
- Respect privacy and data protection requirements

### Ethical Guidelines
- Use tools for defensive security purposes
- Help improve security, not compromise it
- Report vulnerabilities responsibly

## 🎯 Best Practices

### 1. **Be Specific**
- Instead of "hack something", say "hack the Wi-Fi network called 'OfficeWiFi'"
- Instead of "test security", say "test the security of my Bluetooth speaker"

### 2. **Use Natural Language**
- Describe what you want to accomplish, not how to do it
- Use everyday language, not technical jargon
- Be clear about your target and goals

### 3. **Provide Context**
- Mention the target device/network name
- Specify timeframes when relevant
- Indicate your security testing goals

### 4. **Follow Up**
- Ask for clarification if needed
- Request additional information about results
- Ask for recommendations on next steps

## 📚 Example Conversations

### Wi-Fi Security Testing
```
User: "I want to test the security of my home Wi-Fi network"
System: "I'll help you test your home Wi-Fi security. Let me scan for networks first to identify yours."

User: "The network is called 'HomeNetwork'"
System: "Perfect! I'll scan for 'HomeNetwork' and then test its security. Let me start by scanning the area."

User: "What security vulnerabilities did you find?"
System: "I found several potential issues. Let me capture a handshake to test password strength and check for WPS vulnerabilities."
```

### Bluetooth Device Analysis
```
User: "I found a Bluetooth speaker, can you analyze its security?"
System: "I'll help you analyze the Bluetooth speaker's security. Let me scan for nearby devices first."

User: "It's called 'JBL Speaker'"
System: "Found it! Now I'll discover what services it offers and test its security features."

User: "What services does it have?"
System: "The JBL Speaker offers audio streaming, device control, and battery monitoring services. Let me test if any of these are vulnerable to attacks."
```

### Radio Signal Analysis
```
User: "I have an SDR device, can you help me analyze signals?"
System: "Absolutely! I'll help you analyze radio signals with your SDR. Let me first detect your SDR hardware."

User: "What frequencies should I scan?"
System: "I recommend starting with common frequencies: 100 MHz for FM radio, 2.4 GHz for Wi-Fi/Bluetooth, and 1090 MHz for aircraft ADS-B signals. Which interests you most?"

User: "Let's check for aircraft signals"
System: "Great choice! I'll tune to 1090 MHz and decode ADS-B signals to show you aircraft positions and information."
```

## 🎉 Summary

The MCP God Mode tools are designed to be **intuitive and natural language friendly**. You don't need to remember technical parameters or command syntax - just describe what you want to accomplish in plain English, and the system will:

1. **Understand your intent** from natural language
2. **Translate your request** into the appropriate tool calls
3. **Execute the operations** with optimal parameters
4. **Provide results** in an easy-to-understand format

This makes powerful security testing accessible to everyone while maintaining the sophisticated functionality that security professionals need.

---

**Remember**: Use these tools responsibly and only for authorized security testing! 🛡️
