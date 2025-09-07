# MCP God Mode - Comprehensive Tool Catalog

## Overview
MCP God Mode is an advanced security and network analysis platform with **111 fully implemented tools** across multiple categories. This document provides detailed information about each tool, its capabilities, and use cases.

## Tool Count Summary
- **Total TypeScript Files**: 143
- **Exported Tools**: 111
- **Actually Registered**: 116 (111 from index + 5 additional tools)
- **Server-Refactored**: 116 tools
- **Server-Modular**: 111 tools
- **Server-Minimal**: 15 tools

## Why Server-Refactored Has 116 Tools
The server-refactored implementation includes:
- **111 tools** from the comprehensive index.ts export
- **5 additional tools** registered separately:
  - Legal Compliance Manager
  - Additional system utilities
  - Enhanced security tools
  - Cross-platform compatibility tools

## Tool Categories

### 🔧 Core Tools (2 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_health` | Comprehensive system health check and readiness probe for monitoring MCP server status, configuration validation, and operational readiness | `random_string` (dummy parameter) |
| `mcp_mcp-god-mode_system_info` | Comprehensive system information including OS details, architecture, CPU specifications, memory usage, and hardware configuration | `random_string` (dummy parameter) |

### ⚖️ Legal Compliance Tools (1 tool)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_legal_compliance_manager` | Manage legal compliance, audit logging, evidence preservation, and legal hold capabilities | `action`, `enableAuditLogging`, `enableEvidencePreservation`, `enableLegalHold`, `enableChainOfCustody`, `enableDataIntegrity`, `caseName`, `caseDescription`, `createdBy`, `affectedData`, `custodian`, `legalBasis`, `caseId`, `sourcePath`, `evidenceType`, `metadata`, `legalHoldIds`, `evidenceId`, `custodyAction`, `toCustodian`, `purpose`, `location`, `witnesses`, `notes`, `fromCustodian`, `complianceFrameworks`, `auditRetentionDays`, `auditLogLevel`, `filePath`, `startDate`, `endDate`, `limit` |

### 📁 File System Tools (6 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_fs_list` | Advanced directory listing utility with cross-platform support for file and directory enumeration, metadata extraction, and path validation | `dir` (default: ".") |
| `mcp_mcp-god-mode_fs_read_text` | Advanced text file reader with UTF-8 encoding support, path validation, and comprehensive error handling for secure file access | `path` |
| `mcp_mcp-god-mode_fs_write_text` | Write a UTF-8 text file within the sandbox | `path`, `content` |
| `mcp_mcp-god-mode_fs_search` | Search for files by name pattern | `pattern`, `dir` (default: ".") |
| `mcp_mcp-god-mode_file_ops` | Advanced file operations and management | `action`, `source`, `destination`, `new_name`, `recursive`, `overwrite` |
| `mcp_mcp-god-mode_file_watcher` | Advanced file system watching and monitoring capabilities | `action`, `path`, `recursive`, `events`, `watcher_id` |

### ⚙️ Process Tools (2 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_proc_run` | Advanced cross-platform process execution and management with comprehensive output capture, timeout handling, and security controls | `command`, `args`, `working_dir`, `timeout`, `capture_output` |
| `mcp_mcp-god-mode_proc_run_elevated` | Elevated privilege process execution | `command`, `args`, `working_dir`, `timeout`, `reason` |

### 🖥️ System Tools (4 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_system_restore` | System backup and restore functionality | `action`, `backup_name`, `description`, `include_files`, `include_system` |
| `mcp_mcp-god-mode_elevated_permissions_manager` | Advanced elevated permissions management system with cross-platform support for privilege escalation, access control, and security policy enforcement | `action`, `permission`, `target` |
| `mcp_mcp-god-mode_cron_job_manager` | Cross-platform cron job and scheduled task management | `random_string` (dummy parameter) |
| `mcp_mcp-god-mode_system_monitor` | Comprehensive system monitoring and performance analysis toolkit | `random_string` (dummy parameter) |

### 📊 Git Tools (1 tool)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_git_status` | Git repository status and information | `repository_path`, `show_untracked`, `show_ignored`, `porcelain` |

### 🪟 Windows Tools (2 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_win_services` | Windows service management and control | `action`, `service_name`, `start_type`, `display_name`, `description`, `binary_path`, `dependencies` |
| `mcp_mcp-god-mode_win_processes` | Windows process management and monitoring | `action`, `process_name`, `process_id`, `priority`, `affinity`, `timeout` |

### 🌐 Network Tools (15 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_packet_sniffer` | Advanced Network Traffic Analysis & Packet Capture Tool - Professional-grade network monitoring and security analysis platform for authorized corporate network testing | `action`, `interface`, `filter`, `duration`, `max_packets`, `protocol`, `source_ip`, `dest_ip`, `source_port`, `dest_port`, `output_file` |
| `mcp_mcp-god-mode_port_scanner` | Advanced network port scanning and analysis tool with multiple scan types, service detection, and comprehensive reporting | `target`, `ports`, `port_range`, `scan_type`, `timeout` |
| `mcp_mcp-god-mode_network_diagnostics` | Comprehensive network diagnostics and troubleshooting | `target`, `tests`, `timeout`, `output_format` |
| `mcp_mcp-god-mode_download_file` | Advanced cross-platform file download utility with resume capability, progress tracking, and comprehensive error handling | `url`, `outputPath` |
| `mcp_mcp-god-mode_network_traffic_analyzer` | Advanced network traffic capture, analysis, and monitoring toolkit | `random_string` (dummy parameter) |
| `mcp_mcp-god-mode_ip_geolocation` | IP-based geolocation using multiple databases and services (MaxMind GeoIP, IP2Location, free services) | `ip_address`, `database`, `accuracy_level`, `include_isp`, `include_timezone` |
| `mcp_mcp-god-mode_network_triangulation` | Network triangulation using Wi-Fi access points and cell towers for device location | `triangulation_type`, `access_points`, `cell_towers`, `database`, `accuracy_target` |
| `mcp_mcp-god-mode_osint_reconnaissance` | Open Source Intelligence (OSINT) reconnaissance and information gathering | `target`, `recon_type`, `include_historical`, `include_subdomains`, `include_ports`, `include_services`, `search_engines` |
| `mcp_mcp-god-mode_latency_geolocation` | Latency-based geolocation using ping triangulation from multiple vantage points | `target_ip`, `vantage_points`, `ping_count`, `timeout`, `include_traceroute`, `algorithm` |
| `mcp_mcp-god-mode_network_discovery` | Network discovery and reconnaissance using port scanners, service detection, and DNS lookups | `target`, `discovery_type`, `port_range`, `scan_type`, `service_detection`, `os_detection`, `script_scanning`, `timing`, `output_format` |
| `mcp_mcp-god-mode_vulnerability_assessment` | Advanced vulnerability assessment and security scanning tool with comprehensive CVE analysis and remediation recommendations | `target`, `scan_type`, `port_range`, `vulnerability_types`, `output_format`, `include_remediation` |
| `mcp_mcp-god-mode_traffic_analysis` | Comprehensive packet and traffic analysis tool for network monitoring, security assessment, and performance analysis | `interface`, `capture_duration`, `filter`, `analysis_type`, `include_payload`, `include_flow_analysis`, `output_file`, `real_time` |
| `mcp_mcp-god-mode_network_utilities` | Network utility tools including traceroute, ping sweeps, and VPN management | `utility_type`, `target`, `options` |
| `mcp_mcp-god-mode_social_account_ripper` | Advanced social network account reconnaissance and information gathering tool with comprehensive analysis capabilities | `target`, `platforms`, `search_method`, `include_historical`, `include_connections`, `include_metadata`, `include_geolocation`, `include_employment`, `include_photos`, `include_posts`, `include_sentiment`, `output_format` |
| `mcp_mcp-god-mode_social_account_ripper_modular` | Advanced modular social network account reconnaissance tool with component-based architecture and comprehensive analysis modules | `target`, `platforms`, `search_method`, `modules`, `include_historical`, `include_metadata`, `output_format` |

### 🔒 Security Tools (13 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_vulnerability_scanner` | Advanced vulnerability scanning and assessment tool | `target`, `scan_type`, `port_range`, `vulnerability_types`, `output_format` |
| `mcp_mcp-god-mode_password_cracker` | Advanced Password Security Testing Tool - Comprehensive authentication testing framework for authorized corporate security assessments | `target`, `service`, `username`, `password_list`, `method`, `max_attempts`, `timeout`, `custom_port`, `verbose` |
| `mcp_mcp-god-mode_exploit_framework` | Advanced Exploit Framework & Vulnerability Testing Suite - Comprehensive penetration testing platform for authorized corporate security assessments | `action`, `target`, `exploit`, `payload`, `options`, `timeout`, `verbose`, `safe_mode` |
| `mcp_mcp-god-mode_network_security` | Comprehensive network security assessment and monitoring | `action`, `target`, `scan_type`, `duration` |
| `mcp_mcp-god-mode_blockchain_security` | Blockchain security analysis and vulnerability assessment | `action`, `blockchain_type`, `contract_address`, `network` |
| `mcp_mcp-god-mode_quantum_security` | Quantum-resistant cryptography and security analysis | `action`, `algorithm`, `key_size`, `threat_model` |
| `mcp_mcp-god-mode_iot_security` | Internet of Things security assessment and protection | `action`, `device_type`, `network_segment`, `protocol` |
| `mcp_mcp-god-mode_social_engineering` | Social engineering awareness and testing framework | `action`, `technique`, `target_group`, `scenario` |
| `mcp_mcp-god-mode_threat_intelligence` | Threat intelligence gathering and analysis | `action`, `threat_type`, `indicators`, `time_range` |
| `mcp_mcp-god-mode_compliance_assessment` | Regulatory compliance assessment and reporting | `action`, `framework`, `scope`, `evidence_path` |
| `mcp_mcp-god-mode_social_network_ripper` | Social network account information extraction and analysis tool for authorized security testing and OSINT operations | `target`, `platform`, `extraction_type`, `include_historical`, `include_private`, `include_geolocation`, `include_relationships`, `output_format`, `max_results` |
| `mcp_mcp-god-mode_metadata_extractor` | Comprehensive metadata extraction and geolocation tool for media files, URLs, and social media posts with platform-aware stripping detection and visual analysis | `input_type`, `input_source`, `extraction_type`, `include_exif`, `include_video_metadata`, `include_audio_metadata`, `platform_stripping_check`, `visual_analysis`, `cross_post_search`, `geotagging_assist`, `weather_lookup`, `sun_position_analysis`, `output_format`, `include_original_file` |
| `mcp_mcp-god-mode_encryption_tool` | Advanced encryption and cryptographic operations | `action`, `algorithm`, `input_data`, `key`, `mode` |
| `mcp_mcp-god-mode_malware_analysis` | Malware analysis and reverse engineering | `action`, `sample_path`, `analysis_type`, `sandbox` |

### 🎯 Penetration Tools (5 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_hack_network` | Comprehensive network hacking and penetration testing | `target_network`, `attack_vector`, `stealth_mode`, `output_format` |
| `mcp_mcp-god-mode_security_testing` | Advanced multi-domain security testing and vulnerability assessment platform | `test_type`, `target`, `scope`, `report_format` |
| `mcp_mcp-god-mode_network_penetration` | Advanced network penetration testing and exploitation | `target`, `technique`, `payload`, `evasion` |
| `mcp_mcp-god-mode_penetration_testing_toolkit` | Comprehensive penetration testing and ethical hacking toolkit | `action`, `target`, `scope`, `methodology`, `output_format` |
| `mcp_mcp-god-mode_social_engineering_toolkit` | Comprehensive social engineering assessment and awareness toolkit with phishing simulation, training modules, and vulnerability analysis | `action`, `target_group`, `campaign_type`, `training_module`, `output_format` |

### 📡 Wireless Tools (4 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_wifi_security_toolkit` | Advanced Wi-Fi security assessment and penetration testing toolkit with comprehensive network analysis, vulnerability scanning, and security validation | `action`, `target_network`, `wifiInterface`, `attack_type`, `output_format`, `stealth_mode` |
| `mcp_mcp-god-mode_wifi_hacking` | Advanced Wi-Fi penetration testing and security assessment toolkit | `action`, `target_network`, `wifiInterface`, `attack_type`, `output_format`, `stealth_mode` |
| `mcp_mcp-god-mode_wireless_security` | Wireless network security assessment and protection | `action`, `network_type`, `security_protocol`, `encryption_type` |
| `mcp_mcp-god-mode_wireless_network_scanner` | Advanced wireless network scanning and analysis toolkit with comprehensive signal strength monitoring, security assessment, and network discovery capabilities | `action`, `interface`, `scan_type`, `output_format`, `include_hidden` |

### 📶 Bluetooth Tools (3 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_bluetooth_security_toolkit` | Bluetooth security testing and vulnerability assessment | `action`, `target_device`, `test_type`, `output_format` |
| `mcp_mcp-god-mode_bluetooth_hacking` | Advanced Bluetooth security penetration testing and exploitation toolkit | `action`, `target_device`, `device_type`, `bluetoothInterface`, `attack_duration`, `payload`, `output_file` |
| `mcp_mcp-god-mode_bluetooth_device_manager` | Advanced Bluetooth device management and configuration toolkit | `action`, `device_address`, `device_name`, `timeout`, `scan_duration`, `output_format` |

### 📻 Radio Tools (3 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_sdr_security_toolkit` | Comprehensive Software Defined Radio (SDR) security and signal analysis toolkit with cross-platform support | `action`, `frequency`, `bandwidth`, `modulation`, `protocol`, `duration`, `output_file`, `device_id` |
| `mcp_mcp-god-mode_radio_security` | Software Defined Radio security and signal analysis | `action`, `frequency`, `bandwidth`, `modulation`, `power_level`, `duration`, `audio_file`, `output_file` |
| `mcp_mcp-god-mode_signal_analysis` | Advanced radio signal analysis and SDR toolkit with cross-platform support | `action`, `frequency`, `sample_rate`, `gain`, `protocol`, `duration`, `output_file`, `device_index` |

### 🖥️ Web Tools (7 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_web_scraper` | Advanced web scraping and data extraction tool | `url`, `selectors`, `output_format`, `include_metadata`, `follow_links`, `max_depth` |
| `mcp_mcp-god-mode_browser_control` | Cross-platform browser automation and control | `action`, `browser`, `url`, `selector`, `text`, `headless` |
| `mcp_mcp-god-mode_web_automation` | Advanced web automation and browser control toolkit | `action`, `url`, `selector`, `text`, `wait_time`, `screenshot`, `headless` |
| `mcp_mcp-god-mode_webhook_manager` | Advanced webhook management and testing toolkit | `action`, `url`, `method`, `headers`, `payload`, `timeout`, `retry_count` |
| `mcp_mcp-god-mode_universal_browser_operator` | Advanced cross-platform browser automation and web interaction toolkit | `action`, `url`, `selector`, `text`, `wait_time`, `screenshot`, `headless`, `timeout` |
| `mcp_mcp-god-mode_web_search` | Advanced web search and information retrieval tool | `query`, `search_engine`, `max_results`, `language`, `region`, `time_range`, `output_format` |
| `mcp_mcp-god-mode_form_completion` | Complete online forms automatically with intelligent field detection, validation, and CAPTCHA handling | `url`, `form_data`, `form_selector`, `captcha_handling`, `validation`, `submit_form`, `timeout`, `save_screenshot` |

### 📧 Email Tools (6 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_send_email` | Cross-platform email sending with SMTP support | `to`, `subject`, `body`, `from`, `smtp_server`, `attachments`, `html` |
| `mcp_mcp-god-mode_read_emails` | IMAP email retrieval and management | `imap_server`, `username`, `password`, `folder`, `limit`, `unread_only` |
| `mcp_mcp-god-mode_parse_email` | Email content parsing and analysis | `email_content`, `parse_type`, `extract_links`, `extract_attachments` |
| `mcp_mcp-god-mode_delete_emails` | Email deletion and management | `imap_server`, `username`, `password`, `email_ids`, `folder`, `permanent` |
| `mcp_mcp-god-mode_sort_emails` | Email sorting and organization | `emails`, `sort_by`, `order`, `group_by` |
| `mcp_mcp-god-mode_manage_email_accounts` | Multi-account email management and configuration | `action`, `account_name`, `email_address`, `smtp_server`, `imap_server`, `username`, `password` |

### 🎵 Media Tools (4 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_video_editing` | Advanced video editing and processing toolkit | `action`, `input_file`, `output_file`, `start_time`, `end_time`, `effects`, `quality`, `format` |
| `mcp_mcp-god-mode_ocr_tool` | Optical Character Recognition for text extraction from images | `image_path`, `language`, `output_format`, `confidence_threshold`, `preprocess` |
| `mcp_mcp-god-mode_image_editing` | Cross-platform image editing, enhancement, and processing tool | `action`, `input_file`, `output_file`, `width`, `height`, `filter`, `format` |
| `mcp_mcp-god-mode_audio_editing` | Advanced audio editing and manipulation tool with cross-platform support | `action`, `input_file`, `output_file`, `format`, `start_time`, `end_time`, `duration`, `sample_rate`, `bit_depth`, `channels`, `quality`, `effects`, `compression_level`, `audio_codec`, `bitrate`, `fade_duration`, `speed_factor`, `pitch_shift`, `noise_reduction_level`, `input_files`, `output_directory`, `device_name`, `recording_format`, `enable_monitoring`, `normalize_audio`, `preserve_metadata`, `create_backup` |

### 📸 Screenshot Tools (1 tool)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_screenshot` | Cross-platform screenshot capture and management tool | `action`, `output_path`, `area`, `delay`, `format` |

### 📱 Mobile Tools (13 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_mobile_device_info` | Mobile device information and diagnostics | `action`, `device_id`, `detailed` |
| `mcp_mcp-god-mode_mobile_file_ops` | Mobile device file operations and management | `action`, `path`, `content`, `destination`, `recursive` |
| `mcp_mcp-god-mode_mobile_system_tools` | Comprehensive mobile device system management toolkit with process control, system monitoring, and device administration capabilities for Android and iOS platforms | `action`, `process_id`, `process_name`, `force` |
| `mcp_mcp-god-mode_mobile_hardware` | Mobile device hardware information and diagnostics | `action`, `device_id`, `detailed` |
| `mcp_mcp-god-mode_mobile_device_management` | Mobile device management and policy enforcement | `action`, `device_id`, `policy_name`, `app_action`, `app_package`, `output_format` |
| `mcp_mcp-god-mode_mobile_app_analytics_toolkit` | Mobile application analytics and user behavior analysis | `action`, `app_package`, `analysis_period`, `user_segment`, `metrics`, `output_format` |
| `mcp_mcp-god-mode_mobile_app_deployment_toolkit` | Comprehensive mobile app deployment and management toolkit | `action`, `platform`, `app_path`, `package_name`, `device_id`, `build_type`, `signing_config` |
| `mcp_mcp-god-mode_mobile_app_optimization_toolkit` | Mobile app performance optimization and analysis toolkit | `action`, `platform`, `app_package`, `device_id`, `optimization_type`, `duration`, `output_format` |
| `mcp_mcp-god-mode_mobile_app_security_toolkit` | Comprehensive mobile app security testing and analysis toolkit | `action`, `platform`, `app_package`, `app_path`, `device_id`, `scan_type`, `output_format` |
| `mcp_mcp-god-mode_mobile_app_monitoring_toolkit` | Mobile application monitoring and analytics toolkit | `action`, `app_package`, `monitoring_period`, `metrics`, `alert_thresholds`, `output_format` |
| `mcp_mcp-god-mode_mobile_app_performance_toolkit` | Mobile application performance testing and optimization | `action`, `app_package`, `test_duration`, `test_scenario`, `output_format` |
| `mcp_mcp-god-mode_mobile_app_testing_toolkit` | Mobile application testing and quality assurance toolkit | `action`, `app_package`, `test_type`, `test_environment`, `output_format` |
| `mcp_mcp-god-mode_mobile_network_analyzer` | Mobile network traffic analysis and monitoring | `action`, `device_id`, `capture_duration`, `filter_protocol`, `output_format` |

### 🖥️ Virtualization Tools (2 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_vm_management` | Virtual machine management and control | `action`, `vm_name`, `vm_type`, `memory`, `cpu_cores`, `disk_size`, `network_config` |
| `mcp_mcp-god-mode_docker_management` | Docker container and image management | `action`, `container_name`, `image_name`, `command`, `ports` |

### 🧮 Utility Tools (9 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_calculator` | Basic mathematical calculator with standard operations | `operation`, `a`, `b`, `precision` |
| `mcp_mcp-god-mode_dice_rolling` | Advanced dice rolling simulator for tabletop games | `dice_notation`, `count`, `advantage`, `disadvantage` |
| `mcp_mcp-god-mode_math_calculate` | Advanced mathematical calculations and scientific computing | `expression`, `precision`, `variables`, `format` |
| `mcp_mcp-god-mode_data_analysis` | Advanced data analysis and statistical processing | `action`, `data_source`, `analysis_type`, `output_format` |
| `mcp_mcp-god-mode_machine_learning` | Machine learning model training and prediction | `action`, `model_type`, `data_path`, `hyperparameters` |
| `mcp_mcp-god-mode_chart_generator` | Chart and graph generation from data | `chart_type`, `data`, `title`, `x_label`, `y_label`, `output_format` |
| `mcp_mcp-god-mode_text_processor` | Text processing and manipulation utilities | `action`, `text`, `find_text`, `replace_text`, `case_type` |
| `mcp_mcp-god-mode_password_generator` | Secure password generation with customizable options | `length`, `include_uppercase`, `include_lowercase`, `include_numbers`, `include_symbols`, `exclude_similar`, `exclude_ambiguous` |
| `mcp_mcp-god-mode_data_analyzer` | Data analysis and statistical processing | `action`, `data`, `analysis_type`, `options` |

### ☁️ Cloud Tools (3 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_cloud_security` | Cloud infrastructure security assessment and compliance | `action`, `cloud_provider`, `service_type`, `region` |
| `mcp_mcp-god-mode_cloud_infrastructure_manager` | Cloud infrastructure management and monitoring | `action`, `cloud_provider`, `resource_type`, `region`, `resource_config` |
| `mcp_mcp-god-mode_cloud_security_toolkit` | Advanced cloud security assessment and compliance toolkit with comprehensive multi-cloud support, automated security scanning, and regulatory compliance validation | `action`, `cloud_provider`, `service_type`, `compliance_framework`, `output_format` |

### 🔍 Forensics Tools (3 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_forensics_analysis` | Digital forensics and incident response analysis | `action`, `evidence_type`, `source_path`, `output_format` |
| `mcp_mcp-god-mode_forensics_toolkit` | Advanced digital forensics and evidence analysis toolkit with comprehensive memory analysis, file carving, timeline reconstruction, and chain of custody management | `action`, `evidence_source`, `analysis_type`, `output_format`, `preserve_evidence` |
| `mcp_mcp-god-mode_malware_analysis_toolkit` | Comprehensive malware analysis and reverse engineering toolkit with static/dynamic analysis, behavioral monitoring, and advanced threat intelligence integration | `action`, `sample_path`, `analysis_environment`, `analysis_depth`, `output_format` |

### 🔍 Discovery Tools (2 tools)
| Tool | Description | Parameters |
|------|-------------|------------|
| `mcp_mcp-god-mode_tool_discovery` | Discover and explore all available tools using natural language queries | `query`, `category`, `capability` |
| `mcp_mcp-god-mode_explore_categories` | Explore all available tool categories and their capabilities | `category` |

## Server Implementations

### Server-Refactored (116 tools)
- **Primary server** with all 111 exported tools
- **5 additional tools** registered separately
- **Full feature set** with legal compliance
- **Production ready** with comprehensive error handling

### Server-Modular (111 tools)
- **Modular architecture** with imported tools
- **111 exported tools** from index
- **Streamlined implementation**
- **Development and testing focused**

### Server-Minimal (15 tools)
- **Core tools only** for basic functionality
- **Essential file system, process, and network tools**
- **Lightweight implementation**
- **Resource-constrained environments**

## Usage Guidelines

### Security Notice
⚠️ **PROFESSIONAL SECURITY NOTICE**: All tools are for authorized testing and security assessment ONLY
🔒 Use only on networks and systems you own or have explicit written permission to test

### Legal Compliance
- All tools include legal compliance features
- Audit logging and evidence preservation capabilities
- Chain of custody management for forensic tools
- Regulatory compliance frameworks (SOX, HIPAA, GDPR, PCI-DSS, ISO27001)

### Cross-Platform Support
- **Windows**: Full support with Windows-specific tools
- **Linux**: Complete compatibility with system tools
- **macOS**: Native support for all features
- **Mobile**: Android and iOS support for mobile tools

## Getting Started

1. **Choose your server implementation** based on your needs
2. **Review tool documentation** for specific use cases
3. **Ensure proper authorization** before using security tools
4. **Configure legal compliance** if required for your use case
5. **Test in isolated environments** before production use

## Support and Documentation

- **Tool Catalog**: This document provides comprehensive tool information
- **Individual Tool Docs**: Each tool has detailed parameter documentation
- **Server Documentation**: See README.md for server-specific information
- **Legal Compliance**: See legal-compliance.md for compliance features

---

*Last Updated: December 2024*
*Total Tools: 111 exported, 116 registered in server-refactored*
