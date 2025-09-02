# MCP God Mode - Parameter Reference Guide

## 🎯 Overview

This guide provides comprehensive documentation of all parameters for the MCP God Mode tools, with detailed descriptions, examples, and usage guidelines. All parameters are designed to be natural language friendly and include helpful examples.

## 🔧 Core Tool Parameters

### 1. **File Operations** (`file_ops`)

#### `action`
**Description**: The file operation to perform. Choose from: copy/move files, delete files/directories, create directories/files, get file information, list files recursively, search by content, compress/decompress files, manage permissions, create links, or monitor file changes.

**Available Values**: 
- `copy` - Copy files or directories
- `move` - Move files or directories  
- `delete` - Delete files or directories
- `create_dir` - Create new directories
- `create_file` - Create new files
- `get_info` - Get file/directory information
- `list_recursive` - List files recursively
- `find_by_content` - Search files by content
- `compress` - Compress files
- `decompress` - Decompress files
- `chmod` - Change file permissions
- `chown` - Change file ownership
- `symlink` - Create symbolic links
- `hardlink` - Create hard links
- `watch` - Monitor file changes
- `unwatch` - Stop monitoring files
- `get_size` - Get file sizes
- `get_permissions` - Get file permissions
- `set_permissions` - Set file permissions
- `compare_files` - Compare file contents

#### `source`
**Description**: The source file or directory path for operations like copy, move, delete, or get_info. Can be relative or absolute path.

**Examples**: 
- `'./file.txt'`
- `'/home/user/documents'`
- `'C:\\Users\\User\\Desktop'`
- `'../backup/data'`

#### `destination`
**Description**: The destination path for operations like copy, move, create_dir, or create_file. Can be relative or absolute path.

**Examples**:
- `'./backup/file.txt'`
- `'/home/user/backups'`
- `'C:\\Users\\User\\Backups'`
- `'../archive/project'`

#### `content`
**Description**: The content to write when creating a new file. Can be plain text, JSON, XML, or any text-based format.

**Examples**:
- `'Hello World'`
- `'{"key": "value"}'`
- `'<xml>data</xml>'`
- `'#!/bin/bash\necho "Hello"'`

#### `recursive`
**Description**: Whether to perform the operation recursively on directories and their contents. Required for copying, moving, or deleting directories.

**Default**: `false`
**Usage**: Set to `true` for directory operations, `false` for single file operations.

#### `overwrite`
**Description**: Whether to overwrite existing files at the destination. Set to true to replace existing files, false to fail if destination already exists.

**Default**: `false`
**Usage**: Useful for backup operations or when you want to update files.

#### `permissions`
**Description**: Unix-style file permissions in octal format or symbolic format.

**Examples**:
- `'755'` - Executable directories
- `'644'` - Readable files
- `'600'` - Private files
- `'rwxr-xr-x'` - Symbolic format
- `'u+rw'` - User read/write

#### `owner`
**Description**: The username to set as the owner of the file or directory.

**Examples**: `'john'`, `'root'`, `'www-data'`
**Note**: Only works on Unix-like systems with appropriate permissions.

#### `group`
**Description**: The group name to set for the file or directory.

**Examples**: `'users'`, `'admin'`, `'www-data'`
**Note**: Only works on Unix-like systems with appropriate permissions.

#### `pattern`
**Description**: File pattern for search operations. Supports glob patterns.

**Examples**:
- `'*.py'` - Python files
- `'**/*.log'` - JSON files in subdirectories
- `'backup*'` - Files starting with 'backup'
- `'*.{txt,md}'` - Text and markdown files

#### `search_text`
**Description**: Text content to search for within files. Used with 'find_by_content' action.

**Examples**: `'password'`, `'API_KEY'`, `'TODO'`, `'FIXME'`

#### `compression_type`
**Description**: The compression format to use.

**Available Values**:
- `'zip'` - Most universal, Windows compatibility
- `'tar'` - Preserves Unix permissions
- `'gzip'` - Fast compression
- `'bzip2'` - High compression

### 2. **Process Execution** (`proc_run`)

#### `command`
**Description**: The command to execute. Can be any executable available in your system PATH or full path to an executable.

**Examples**:
- `'ls'`, `'dir'`, `'cat'`, `'echo'`
- `'python'`, `'node'`, `'git'`, `'docker'`
- `'/usr/bin/python3'`, `'C:\\Program Files\\Git\\bin\\git.exe'`

#### `args`
**Description**: Array of command-line arguments to pass to the command.

**Examples**:
- `['-la']` for `'ls -la'`
- `['--version']` for version info
- `['filename.txt']` for file operations
- `['-p', '8080']` for port specification

#### `cwd`
**Description**: The working directory where the command will be executed.

**Examples**:
- `'./project'`
- `'/home/user/documents'`
- `'C:\\Users\\User\\Desktop'`
- Leave empty to use current working directory

### 3. **Git Operations** (`git_status`)

#### `dir`
**Description**: The directory containing the git repository to check.

**Examples**:
- `'./project'`
- `'/home/user/repos/myproject'`
- `'C:\\Users\\User\\Projects\\MyProject'`
- `'.'` for current directory

## 🛡️ Security Tool Parameters

### 1. **Wi-Fi Security Toolkit** (`wifi_security_toolkit`)

#### `action`
**Description**: The specific Wi-Fi security action to perform. Choose from network scanning, handshake capture, password attacks, evil twin attacks, WPS exploitation, or analysis tasks.

**Available Values**:
- **Sniffing & Handshake Capture**: `scan_networks`, `capture_handshake`, `capture_pmkid`, `sniff_packets`, `monitor_clients`
- **Password Attacks**: `crack_hash`, `dictionary_attack`, `brute_force_attack`, `rainbow_table_attack`
- **Evil Twin & Rogue AP**: `create_rogue_ap`, `evil_twin_attack`, `phishing_capture`, `credential_harvest`
- **WPS & Protocol Exploits**: `wps_attack`, `pixie_dust_attack`, `deauth_attack`, `fragmentation_attack`
- **Router/IoT Exploits**: `router_scan`, `iot_enumeration`, `vulnerability_scan`, `exploit_router`
- **Analysis & Reporting**: `analyze_captures`, `generate_report`, `export_results`, `cleanup_traces`

#### `target_ssid`
**Description**: The name/SSID of the target Wi-Fi network you want to attack or analyze.

**Examples**: `'OfficeWiFi'`, `'HomeNetwork'`, `'GuestWiFi'`
**Usage**: Required for most attacks that target specific networks.

#### `target_bssid`
**Description**: The MAC address (BSSID) of the target Wi-Fi access point. Useful for targeting specific devices when multiple networks have similar names.

**Format**: `XX:XX:XX:XX:XX:XX`
**Examples**: `'00:11:22:33:44:55'`, `'AA:BB:CC:DD:EE:FF'`

#### `interface`
**Description**: The wireless network interface to use for attacks.

**Examples**:
- Linux: `'wlan0'`, `'wlan1'`
- Windows: `'Wi-Fi'`, `'Wireless Network Connection'`
- macOS: `'en0'`, `'en1'`
- Leave empty for auto-detection

#### `wordlist`
**Description**: Path to a wordlist file containing potential passwords for dictionary attacks.

**Examples**: `'rockyou.txt'`, `'common_passwords.txt'`, `'custom_wordlist.txt'`
**Format**: One password per line

#### `output_file`
**Description**: File path where captured data, handshakes, or analysis results will be saved.

**Examples**:
- `'./captured_handshake.pcap'`
- `'./network_scan.json'`
- `'./cracked_passwords.txt'`
- `'./wifi_analysis_report.html'`

#### `duration`
**Description**: Duration in seconds for operations like packet sniffing, handshake capture, or network monitoring.

**Recommended Values**:
- Scanning: 30-60 seconds
- Handshake capture: 60-300 seconds
- Monitoring: 300-1800 seconds

#### `max_attempts`
**Description**: Maximum number of attempts for brute force attacks or WPS exploitation.

**Recommended Values**:
- WPS attacks: 1000-10000
- Brute force: 100000+
- Dictionary attacks: Unlimited (based on wordlist size)

#### `attack_type`
**Description**: The type of Wi-Fi security protocol to target.

**Available Values**:
- `'wpa'` - WPA (legacy)
- `'wpa2'` - WPA2 (most common)
- `'wpa3'` - WPA3 (newest)
- `'wep'` - WEP (outdated but still found)
- `'wps'` - WPS (works on vulnerable routers regardless of protocol)

#### `channel`
**Description**: Specific Wi-Fi channel to focus on.

**Ranges**:
- 2.4GHz: 1-13 (most countries), 1-14 (Japan)
- 5GHz: 36-165 (varies by country)
- Leave empty to scan all channels

#### `power_level`
**Description**: Transmit power level for attacks (0-100%).

**Usage Guidelines**:
- 20-50%: Stealth operations
- 50-80%: Balanced approach
- 80-100%: Maximum effectiveness (may be detected)

### 2. **Bluetooth Security Toolkit** (`bluetooth_security_toolkit`)

#### `action`
**Description**: The specific Bluetooth security action to perform.

**Available Values**:
- **Discovery & Enumeration**: `scan_devices`, `discover_services`, `enumerate_characteristics`, `scan_profiles`, `detect_devices`
- **Connection & Pairing**: `connect_device`, `pair_device`, `unpair_device`, `force_pairing`, `bypass_pairing`
- **Security Testing**: `test_authentication`, `test_authorization`, `test_encryption`, `test_integrity`, `test_privacy`
- **Attack Vectors**: `bluejacking_attack`, `bluesnarfing_attack`, `bluebugging_attack`, `car_whisperer`, `key_injection`
- **Data Extraction**: `extract_contacts`, `extract_calendar`, `extract_messages`, `extract_files`, `extract_audio`
- **Device Exploitation**: `exploit_vulnerabilities`, `inject_commands`, `modify_firmware`, `bypass_security`, `escalate_privileges`
- **Monitoring & Analysis**: `monitor_traffic`, `capture_packets`, `analyze_protocols`, `detect_anomalies`, `log_activities`
- **Reporting & Cleanup**: `generate_report`, `export_results`, `cleanup_traces`, `restore_devices`

#### `target_address`
**Description**: The Bluetooth MAC address of the target device to attack or analyze.

**Format**: `XX:XX:XX:XX:XX:XX`
**Examples**: `'00:11:22:33:44:55'`, `'AA:BB:CC:DD:EE:FF'`

#### `target_name`
**Description**: The friendly name of the target Bluetooth device. Useful when you don't know the MAC address.

**Examples**: `'iPhone'`, `'Samsung TV'`, `'JBL Speaker'`, `'Car Audio'`

#### `device_class`
**Description**: The Bluetooth device class to filter for during scanning.

**Examples**: `'Audio'`, `'Phone'`, `'Computer'`, `'Peripheral'`, `'Imaging'`, `'Wearable'`
**Usage**: Leave empty to scan all device types.

#### `service_uuid`
**Description**: The UUID of the specific Bluetooth service to target.

**Format**: 128-bit UUID
**Examples**: 
- `'0000110b-0000-1000-8000-00805f9b34fb'` (Audio Sink)
- `'0000110c-0000-1000-8000-00805f9b34fb'` (Audio Source)
- Leave empty to discover all services

#### `characteristic_uuid`
**Description**: The UUID of the specific Bluetooth characteristic to read/write. Required for data extraction and injection attacks.

**Format**: 128-bit UUID
**Usage**: Leave empty to enumerate all characteristics.

#### `attack_type`
**Description**: The type of attack to perform.

**Available Values**:
- `'passive'` - Eavesdropping without interaction
- `'active'` - Direct device interaction
- `'man_in_middle'` - Intercepting communications
- `'replay'` - Capturing and retransmitting data
- `'fuzzing'` - Sending malformed data to find vulnerabilities

#### `duration`
**Description**: Duration in seconds for scanning, monitoring, or attack operations.

**Recommended Values**:
- Scanning: 30-300 seconds
- Monitoring: 60-600 seconds
- Attacks: 30-1800 seconds

#### `max_attempts`
**Description**: Maximum number of attempts for pairing bypass, authentication testing, or brute force attacks.

**Recommended Values**:
- Pairing: 100-1000
- Authentication: 1000-10000
- Brute force: 10000+

#### `output_file`
**Description**: File path where captured data, extracted information, or analysis results will be saved.

**Examples**:
- `'./bluetooth_scan.json'`
- `'./extracted_contacts.txt'`
- `'./captured_packets.pcap'`
- `'./bluetooth_analysis.html'`

#### `interface`
**Description**: The Bluetooth interface to use for attacks.

**Examples**:
- Linux: `'hci0'`, `'hci1'`
- Windows: `'Bluetooth'`
- macOS: `'default'`
- Leave empty for auto-detection

#### `power_level`
**Description**: Bluetooth transmit power level (0-100%).

**Usage Guidelines**:
- 20-50%: Stealth operations
- 50-80%: Balanced approach
- 80-100%: Maximum effectiveness (may be detected)

### 3. **SDR Security Toolkit** (`sdr_security_toolkit`)

#### `action`
**Description**: The specific SDR security action to perform.

**Available Values**:
- **Hardware Detection & Setup**: `detect_sdr_hardware`, `list_sdr_devices`, `test_sdr_connection`, `configure_sdr`, `calibrate_sdr`
- **Signal Reception & Analysis**: `receive_signals`, `scan_frequencies`, `capture_signals`, `record_audio`, `record_iq_data`, `analyze_signals`, `detect_modulation`, `decode_protocols`, `identify_transmissions`
- **Wireless Security Testing**: `scan_wireless_spectrum`, `detect_unauthorized_transmissions`, `monitor_radio_traffic`, `capture_radio_packets`, `analyze_radio_security`, `test_signal_strength`
- **Protocol Analysis & Decoding**: `decode_ads_b`, `decode_pocsag`, `decode_aprs`, `decode_ais`, `decode_ads_c`, `decode_ads_s`, `decode_tcas`, `decode_mlat`, `decode_radar`, `decode_satellite`
- **Jamming & Interference Testing**: `test_jamming_resistance`, `analyze_interference`, `measure_signal_quality`, `test_spectrum_occupancy`, `detect_signal_spoofing`, `analyze_frequency_hopping`
- **Mobile & IoT Radio Security**: `scan_mobile_networks`, `analyze_cellular_signals`, `test_iot_radio_security`, `detect_unauthorized_devices`, `monitor_radio_communications`, `test_radio_privacy`
- **Advanced Analysis**: `spectrum_analysis`, `waterfall_analysis`, `time_domain_analysis`, `frequency_domain_analysis`, `correlation_analysis`, `pattern_recognition`, `anomaly_detection`, `trend_analysis`
- **Data Management & Export**: `export_captured_data`, `save_recordings`, `generate_reports`, `backup_data`, `cleanup_temp_files`, `archive_results`
- **Signal Broadcasting & Transmission**: `broadcast_signals`, `transmit_audio`, `transmit_data`, `jam_frequencies`, `create_interference`, `test_transmission_power`, `calibrate_transmitter`, `test_antenna_pattern`, `measure_coverage`

#### `device_index`
**Description**: The index number of the SDR device to use (0, 1, 2, etc.).

**Usage**: Use 0 for the first detected device. Run 'detect_sdr_hardware' first to see available devices and their indices.

#### `frequency`
**Description**: The radio frequency in Hz to tune to.

**Examples**:
- `100000000` for 100 MHz
- `2400000000` for 2.4 GHz
- `1090000000` for 1090 MHz (ADS-B)

**Common Ranges**:
- 30-300 MHz (VHF)
- 300-3000 MHz (UHF)
- 2.4-5 GHz (Wi-Fi/Bluetooth)

#### `sample_rate`
**Description**: The sampling rate in Hz for signal capture.

**Recommended Values**:
- Narrowband: 2-8 MHz
- Wideband: 20-40 MHz
- High quality: 40+ MHz

**Note**: Higher rates provide better signal quality but require more processing power.

#### `gain`
**Description**: The RF gain setting for the SDR (0-100%).

**Recommended Values**:
- Strong signals: 20-40%
- Medium signals: 40-60%
- Weak signals: 60-80%

**Note**: Higher gain improves signal reception but may cause overload on strong signals.

#### `bandwidth`
**Description**: The bandwidth in Hz to capture around the center frequency.

**Examples**:
- Narrowband FM: 12500 Hz
- Wideband FM: 200000 Hz
- Wi-Fi signals: 20000000 Hz

**Usage**: Should match your signal of interest.

#### `duration`
**Description**: Duration in seconds for signal capture, scanning, or monitoring operations.

**Recommended Values**:
- Analysis: 10-300 seconds
- Monitoring: 600+ seconds
- Scanning: 30-1800 seconds

**Note**: Longer durations capture more data but require more storage.

#### `output_file`
**Description**: File path where captured signals, recordings, or analysis results will be saved.

**Examples**:
- `'./captured_signal.iq'`
- `'./audio_recording.wav'`
- `'./spectrum_analysis.png'`
- `'./decoded_data.json'`

#### `modulation`
**Description**: The modulation type for signal transmission or decoding.

**Available Values**:
- `'AM'`, `'FM` - Broadcast radio
- `'USB'`, `'LSB'` - Amateur radio
- `'CW'` - Morse code
- `'PSK'`, `'QPSK'` - Digital communications
- `'FSK'`, `'MSK'`, `'GMSK'` - Data transmission

#### `protocol`
**Description**: The specific radio protocol to decode.

**Examples**:
- `'ADS-B'` - Aircraft tracking
- `'POCSAG'` - Pager messages
- `'APRS'` - Amateur radio position reporting
- `'AIS'` - Ship tracking
- `'P25'` - Public safety radio

#### `coordinates`
**Description**: GPS coordinates for location-based operations.

**Format**: `'latitude,longitude'`
**Examples**: `'40.7128,-74.0060'` (New York), `'51.5074,-0.1278'` (London)

**Usage**: Required for ADS-B decoding, useful for signal triangulation and coverage analysis.

#### `power_level`
**Description**: Transmit power level (0-100%) for broadcasting or jamming operations.

**Usage Guidelines**:
- 10-30%: Testing
- 30-70%: Normal operation
- 70-100%: Maximum effect (may be detected)

#### `antenna_type`
**Description**: The type of antenna to use for transmission or reception.

**Examples**: `'dipole'`, `'yagi'`, `'omnidirectional'`, `'directional'`, `'patch'`
**Usage**: Leave empty to use the default antenna or auto-detect the best available.

## 🎯 Parameter Best Practices

### 1. **Required vs Optional Parameters**
- **Required**: Always specify these for the tool to work properly
- **Optional**: Can be left empty for default behavior or auto-detection

### 2. **Parameter Validation**
- All parameters are automatically validated by the Zod schema
- Invalid values will result in clear error messages
- Type checking ensures data integrity

### 3. **Cross-Platform Compatibility**
- All tools work on Windows, Linux, and macOS
- Platform-specific parameters are automatically handled
- File paths support both Unix and Windows formats

### 4. **Security Considerations**
- All tools include built-in security checks
- Dangerous operations require explicit confirmation
- File operations are restricted to allowed directories

## 🚀 Getting Started

### 1. **Choose Your Tool**
- Identify what you want to accomplish
- Select the appropriate tool from the list above

### 2. **Understand Parameters**
- Read the parameter descriptions
- Note which parameters are required vs optional
- Understand the expected data types and formats

### 3. **Provide Values**
- Use the examples as a guide
- Be specific about your requirements
- Use natural language when possible

### 4. **Execute and Monitor**
- Run your tool with the specified parameters
- Monitor the output and results
- Adjust parameters as needed for optimal results

---

**Remember**: All tools are designed to be user-friendly and natural language compatible. When in doubt, describe what you want to accomplish in plain English! 🎯
