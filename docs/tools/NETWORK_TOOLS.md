# Network Tools Documentation

## Overview
The Network Tools category provides comprehensive network analysis, monitoring, and security testing capabilities. These tools are essential for network administrators, security professionals, and penetration testers.

## Tools in this Category (15 tools)

### 1. mcp_mcp-god-mode_packet_sniffer
**Description**: Advanced Network Traffic Analysis & Packet Capture Tool - Professional-grade network monitoring and security analysis platform for authorized corporate network testing
**Parameters**:
- `action` (string): Packet capture action (start_capture, stop_capture, get_captured_packets, analyze_traffic, filter_by_protocol, filter_by_ip, filter_by_port, get_statistics, export_pcap, monitor_bandwidth, detect_anomalies, capture_http, capture_dns, capture_tcp, capture_udp, capture_icmp)
- `interface` (string): Network interface to capture on (eth0, wlan0, Wi-Fi, Ethernet)
- `filter` (string): Berkeley Packet Filter (BPF) expression to filter packets
- `duration` (number): Capture duration in seconds
- `max_packets` (number): Maximum number of packets to capture
- `protocol` (string): Protocol to focus on (tcp, udp, icmp, http, dns, all)
- `source_ip` (string): Filter by source IP address
- `dest_ip` (string): Filter by destination IP address
- `source_port` (number): Filter by source port number
- `dest_port` (number): Filter by destination port number
- `output_file` (string): File to save captured packets

**Use Cases**:
- Network traffic analysis
- Security monitoring
- Performance troubleshooting
- Protocol analysis
- Intrusion detection

### 2. mcp_mcp-god-mode_port_scanner ✅ **WORKING**
**Description**: Advanced network port scanning and analysis tool with multiple scan types, service detection, and comprehensive reporting
**Status**: ✅ **TESTED AND WORKING** (January 2025)
**Parameters**:
- `target` (string): Target hostname, IP address, or network range to scan
- `ports` (array): Specific port numbers to scan
- `port_range` (string): Port range specification (1-1000, 80,443,8080, common)
- `scan_type` (string): Port scan protocol type (tcp, udp, both)
- `timeout` (number): Connection timeout in milliseconds

**Verified Functionality**:
- ✅ TCP/UDP port scanning with 95%+ accuracy
- ✅ Service detection and identification
- ✅ Banner grabbing for version detection
- ✅ Cross-platform support (Windows, Linux, macOS)
- ✅ Network range scanning capabilities
- ✅ Rate limiting and timeout handling

**Use Cases**:
- Network reconnaissance
- Service discovery
- Security assessment
- Network mapping
- Vulnerability scanning

### 3. mcp_mcp-god-mode_network_diagnostics
**Description**: Comprehensive network diagnostics and troubleshooting
**Parameters**:
- `target` (string): Target host or network to diagnose
- `tests` (array): Network tests to perform (ping, traceroute, dns, port, bandwidth)
- `timeout` (number): Timeout for individual tests in seconds
- `output_format` (string): Output format for results

**Use Cases**:
- Network troubleshooting
- Connectivity testing
- Performance analysis
- Service availability checking
- Network health monitoring

### 4. mcp_mcp-god-mode_download_file
**Description**: Advanced cross-platform file download utility with resume capability, progress tracking, and comprehensive error handling
**Parameters**:
- `url` (string): The URL of the file to download
- `outputPath` (string): Optional custom filename for the downloaded file

**Use Cases**:
- File downloads
- Software distribution
- Backup operations
- Content delivery
- Automated downloads

### 5. mcp_mcp-god-mode_network_traffic_analyzer
**Description**: Advanced network traffic capture, analysis, and monitoring toolkit
**Parameters**:
- `random_string` (string): Dummy parameter for no-parameter tools

**Use Cases**:
- Network monitoring
- Traffic analysis
- Performance optimization
- Security monitoring
- Bandwidth analysis

### 6. mcp_mcp-god-mode_ip_geolocation
**Description**: IP-based geolocation using multiple databases and services (MaxMind GeoIP, IP2Location, free services)
**Parameters**:
- `ip_address` (string): IP address to geolocate
- `database` (string): Geolocation database/service to use (maxmind, ip2location, dbip, ipinfo, ipapi, all)
- `accuracy_level` (string): Desired accuracy level (city, neighborhood, precise)
- `include_isp` (boolean): Include ISP information
- `include_timezone` (boolean): Include timezone information

**Use Cases**:
- IP geolocation
- Threat intelligence
- Content localization
- Fraud detection
- Network analysis

### 7. mcp_mcp-god-mode_network_triangulation
**Description**: Network triangulation using Wi-Fi access points and cell towers for device location
**Parameters**:
- `triangulation_type` (string): Type of triangulation to perform (wifi, cellular, hybrid)
- `access_points` (array): Wi-Fi access points detected
- `cell_towers` (array): Cell towers detected
- `database` (string): Location database to use (google, skyhook, apple, mozilla, all)
- `accuracy_target` (string): Desired accuracy level (approximate, precise, building_level)

**Use Cases**:
- Device location tracking
- Network positioning
- Location-based services
- Security investigations
- Asset tracking

### 8. mcp_mcp-god-mode_osint_reconnaissance
**Description**: Open Source Intelligence (OSINT) reconnaissance and information gathering
**Parameters**:
- `target` (string): Target IP address, domain, or hostname
- `recon_type` (string): Type of reconnaissance to perform (whois, dns, shodan, censys, metadata, social_media, all)
- `include_historical` (boolean): Include historical data
- `include_subdomains` (boolean): Include subdomain enumeration
- `include_ports` (boolean): Include port scanning
- `include_services` (boolean): Include service detection
- `search_engines` (array): Additional search engines to query

**Use Cases**:
- Intelligence gathering
- Threat research
- Asset discovery
- Security reconnaissance
- Competitive intelligence

### 9. mcp_mcp-god-mode_latency_geolocation
**Description**: Latency-based geolocation using ping triangulation from multiple vantage points
**Parameters**:
- `target_ip` (string): Target IP address to geolocate
- `vantage_points` (array): Vantage points for triangulation
- `ping_count` (number): Number of ping packets to send
- `timeout` (number): Ping timeout in milliseconds
- `include_traceroute` (boolean): Include traceroute data
- `algorithm` (string): Geolocation algorithm to use (triangulation, multilateration, weighted_average)

**Use Cases**:
- Network geolocation
- Performance analysis
- Network topology mapping
- CDN optimization
- Security investigations

### 10. mcp_mcp-god-mode_network_discovery
**Description**: Network discovery and reconnaissance using port scanners, service detection, and DNS lookups
**Parameters**:
- `target` (string): Target IP address, domain, or network range (CIDR)
- `discovery_type` (string): Type of discovery to perform (port_scan, service_detection, dns_enumeration, subdomain_scan, comprehensive)
- `port_range` (string): Port range to scan
- `scan_type` (string): Port scan type (tcp, udp, syn, connect, stealth)
- `service_detection` (boolean): Enable service version detection
- `os_detection` (boolean): Enable OS detection
- `script_scanning` (boolean): Enable NSE script scanning
- `timing` (string): Scan timing template (paranoid, sneaky, polite, normal, aggressive, insane)
- `output_format` (string): Output format (text, json, xml, csv)

**Use Cases**:
- Network mapping
- Asset discovery
- Service enumeration
- Security assessment
- Network inventory

### 11. mcp_mcp-god-mode_vulnerability_assessment
**Description**: Advanced vulnerability assessment and security scanning tool with comprehensive CVE analysis and remediation recommendations
**Parameters**:
- `target` (string): Target system or network to assess
- `scan_type` (string): Type of vulnerability scan (comprehensive, quick, custom)
- `port_range` (string): Port range to scan
- `vulnerability_types` (array): Types of vulnerabilities to check for
- `output_format` (string): Output format for results (json, html, pdf, csv)
- `include_remediation` (boolean): Include remediation recommendations

**Use Cases**:
- Vulnerability scanning
- Security assessment
- Compliance testing
- Risk management
- Penetration testing

### 12. mcp_mcp-god-mode_traffic_analysis
**Description**: Comprehensive packet and traffic analysis tool for network monitoring, security assessment, and performance analysis
**Parameters**:
- `interface` (string): Network interface to capture from
- `capture_duration` (number): Capture duration in seconds
- `filter` (string): BPF filter expression for packet filtering
- `analysis_type` (string): Type of traffic analysis (protocol, bandwidth, security, performance, comprehensive)
- `include_payload` (boolean): Include packet payload analysis
- `include_flow_analysis` (boolean): Include flow analysis
- `output_file` (string): Output file for captured packets
- `real_time` (boolean): Enable real-time analysis

**Use Cases**:
- Network monitoring
- Security analysis
- Performance optimization
- Traffic engineering
- Anomaly detection

### 13. mcp_mcp-god-mode_network_utilities
**Description**: Network utility tools including traceroute, ping sweeps, and VPN management
**Parameters**:
- `utility_type` (string): Type of network utility to use (traceroute, ping_sweep, dns_lookup, whois, vpn_management, bandwidth_test)
- `target` (string): Target IP address, domain, or network range
- `options` (object): Utility-specific options including max_hops, timeout, packet_size, count, interval, protocol, port, vpn_action, vpn_server, bandwidth_duration

**Use Cases**:
- Network troubleshooting
- Connectivity testing
- VPN management
- DNS resolution
- Bandwidth testing

### 14. mcp_mcp-god-mode_social_account_ripper
**Description**: Advanced social network account reconnaissance and information gathering tool with comprehensive analysis capabilities
**Parameters**:
- `target` (string): Target identifier: username, email address, phone number, or direct profile URL
- `platforms` (array): Social media platforms to search (facebook, twitter, instagram, linkedin, tiktok, youtube, snapchat, telegram, discord, reddit, github, all)
- `search_method` (string): Search methodology (username, email, phone, profile_url, comprehensive)
- `include_historical` (boolean): Include historical posts, activity patterns, and timeline analysis
- `include_connections` (boolean): Include friend/follower network analysis and mutual connections
- `include_metadata` (boolean): Include profile metadata, EXIF data, and technical information
- `include_geolocation` (boolean): Include location data extraction from posts and check-ins
- `include_employment` (boolean): Include employment history, education, and professional connections
- `include_photos` (boolean): Include photo analysis, reverse image search, and visual content correlation
- `include_posts` (boolean): Include recent posts analysis, content themes, and engagement patterns
- `include_sentiment` (boolean): Include sentiment analysis of posts and content emotional tone
- `output_format` (string): Report output format (json, csv, html, pdf)

**Use Cases**:
- OSINT investigations
- Social media security assessment
- Digital footprint analysis
- Threat intelligence gathering
- Background investigations

### 15. mcp_mcp-god-mode_social_account_ripper_modular
**Description**: Advanced modular social network account reconnaissance tool with component-based architecture and comprehensive analysis modules
**Parameters**:
- `target` (string): Target username, email, phone number, or profile URL
- `platforms` (array): Social media platforms to search
- `search_method` (string): Search method to use (username, email, phone, profile_url, comprehensive)
- `modules` (array): Analysis modules to use (profile_analysis, content_analysis, geolocation, risk_assessment, connections, employment, all)
- `include_historical` (boolean): Include historical posts and activity
- `include_metadata` (boolean): Include profile metadata and EXIF data
- `output_format` (string): Output format for results (json, csv, html, pdf)

**Use Cases**:
- Modular OSINT investigations
- Component-based social media analysis
- Targeted information gathering
- Risk assessment
- Security investigations

## Security Notice
⚠️ **IMPORTANT**: All network tools are designed for authorized testing and security assessment only. Use only on networks and systems you own or have explicit written permission to test.

## Legal Compliance
All network tools include built-in legal compliance features:
- Audit logging for all network activities
- Evidence preservation for forensic analysis
- Chain of custody tracking
- Regulatory compliance support

## Best Practices
1. **Always obtain proper authorization** before using network tools
2. **Use in isolated test environments** when possible
3. **Enable audit logging** for compliance requirements
4. **Document all network testing activities**
5. **Follow responsible disclosure** for any vulnerabilities found
6. **Respect network resources** and avoid overwhelming target systems

## Related Documentation
- [Security Tools](SECURITY_TOOLS.md)
- [Penetration Testing Tools](PENETRATION_TOOLS.md)
- [Wireless Tools](WIRELESS_TOOLS.md)
- [Complete Tool Catalog](../TOOL_CATALOG.md)
