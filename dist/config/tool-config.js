import * as fs from "node:fs/promises";
import * as path from "node:path";
// Default configuration - all tools enabled
export const DEFAULT_TOOL_CONFIG = {
    enabledTools: [], // Empty means all tools are enabled
    disabledTools: [],
    toolCategories: {},
    customTools: []
};
// Tool categories mapping
export const TOOL_CATEGORIES = {
    "core": {
        name: "Core System Tools",
        description: "Essential system monitoring and health check tools",
        tools: ["health", "system_info"]
    },
    "file_system": {
        name: "File System Tools",
        description: "Complete file and directory management capabilities",
        tools: ["file_ops", "file_watcher", "fs_list", "fs_read_text", "fs_search", "fs_write_text"]
    },
    "network": {
        name: "Network Tools",
        description: "Advanced network diagnostics, port scanning, and traffic analysis",
        tools: [
            "network_diagnostics", "network_discovery", "network_penetration", "network_security",
            "network_traffic_analyzer", "network_triangulation", "network_utilities", "osint_reconnaissance",
            "packet_sniffer", "port_scanner", "traffic_analysis", "vulnerability_assessment",
            "ip_geolocation", "latency_geolocation", "social_account_ripper", "social_account_ripper_modular"
        ]
    },
    "security": {
        name: "Security Tools",
        description: "Professional penetration testing, vulnerability assessment, and security auditing",
        tools: [
            "api_security_testing", "blockchain_security", "cloud_security_assessment", "compliance_assessment",
            "database_security_toolkit", "email_security_suite", "exploit_framework", "iot_security",
            "malware_analysis", "metadata_extractor", "password_cracker", "quantum_security",
            "security_testing", "siem_toolkit", "social_engineering", "social_network_ripper",
            "threat_intelligence", "vulnerability_scanner"
        ]
    },
    "mobile": {
        name: "Mobile Tools",
        description: "Comprehensive mobile device management, security analysis, and app testing",
        tools: [
            "mobile_app_analytics_toolkit", "mobile_app_deployment_toolkit", "mobile_app_monitoring_toolkit",
            "mobile_app_optimization_toolkit", "mobile_app_performance_toolkit", "mobile_app_security_toolkit",
            "mobile_app_testing_toolkit", "mobile_device_info", "mobile_device_management", "mobile_file_ops",
            "mobile_hardware", "mobile_network_analyzer", "mobile_system_tools"
        ]
    },
    "bluetooth": {
        name: "Bluetooth Security",
        description: "Bluetooth device security and management",
        tools: ["bluetooth_device_manager", "bluetooth_hacking", "bluetooth_security_toolkit"]
    },
    "radio": {
        name: "Radio/SDR Tools",
        description: "Software Defined Radio security and signal analysis",
        tools: ["radio_security", "sdr_security_toolkit", "signal_analysis"]
    },
    "media": {
        name: "Media Tools",
        description: "Professional audio/video editing, image processing, and OCR capabilities",
        tools: ["audio_editing", "image_editing", "ocr_tool", "video_editing"]
    },
    "email": {
        name: "Email Management",
        description: "Comprehensive email processing and management",
        tools: ["delete_emails", "email_utils", "manage_email_accounts", "parse_email", "read_emails", "send_email", "sort_emails"]
    },
    "cloud": {
        name: "Cloud Security",
        description: "Cloud infrastructure security and management",
        tools: ["cloud_infrastructure_manager", "cloud_security", "cloud_security_toolkit"]
    },
    "forensics": {
        name: "Digital Forensics",
        description: "Digital forensics and incident response",
        tools: ["forensics_analysis", "forensics_toolkit", "malware_analysis_toolkit"]
    },
    "penetration": {
        name: "Penetration Testing",
        description: "Advanced penetration testing and red team operations",
        tools: ["hack_network", "network_penetration", "penetration_testing_toolkit", "red_team_toolkit", "social_engineering_toolkit"]
    },
    "utilities": {
        name: "Utility Tools",
        description: "General purpose utilities and helper tools",
        tools: [
            "calculator", "chart_generator", "data_analysis", "data_analyzer", "dice_rolling",
            "download_file", "encryption_tool", "machine_learning", "math_calculate", "password_generator", "text_processor"
        ]
    },
    "web": {
        name: "Web Tools",
        description: "Web automation, scraping, and browser control",
        tools: ["browser_control", "web_automation", "web_scraper", "web_search", "webhook_manager"]
    },
    "wireless": {
        name: "Wireless Security",
        description: "WiFi security testing and wireless network analysis",
        tools: ["wifi_hacking", "wifi_security_toolkit", "wireless_network_scanner", "wireless_security"]
    },
    "rf_sense": {
        name: "RF Sense Tools (Experimental)",
        description: "⚠️ EXPERIMENTAL - RF sensing with through-wall detection capabilities",
        tools: ["rf_sense", "rf_sense_sim", "rf_sense_wifi_lab", "rf_sense_mmwave", "rf_sense_natural_language", "rf_sense_guardrails", "rf_sense_localize"]
    },
    "system": {
        name: "System Management",
        description: "System monitoring, permissions, and management",
        tools: ["cron_job_manager", "elevated_permissions_manager", "system_monitor", "system_restore"]
    },
    "process": {
        name: "Process Management",
        description: "Process execution and management",
        tools: ["proc_run", "proc_run_elevated"]
    },
    "legal": {
        name: "Legal Compliance",
        description: "Legal compliance and audit management",
        tools: ["legal_compliance_manager"]
    },
    "git": {
        name: "Git Integration",
        description: "Version control and repository management",
        tools: ["git_status"]
    },
    "discovery": {
        name: "Tool Discovery",
        description: "Tool discovery and exploration capabilities",
        tools: ["explore_categories", "tool_discovery"]
    },
    "social": {
        name: "Social Media Intelligence",
        description: "Social media analysis and intelligence gathering",
        tools: ["social_network_ripper"]
    },
    "drone": {
        name: "Drone Management",
        description: "Advanced drone deployment for cybersecurity threat response",
        tools: ["drone_defense", "drone_offense"]
    },
    "virtualization": {
        name: "Virtualization",
        description: "Virtual machine and container management",
        tools: ["docker_management", "vm_management"]
    },
    "windows": {
        name: "Windows Tools",
        description: "Windows-specific system tools",
        tools: ["win_processes", "win_services"]
    },
    "screenshot": {
        name: "Screenshot Tools",
        description: "Screenshot capture and management",
        tools: ["screenshot"]
    },
    "enhanced": {
        name: "Enhanced Tools",
        description: "Advanced enhanced tools with additional functionality beyond standard tools",
        tools: [
            "enhanced_legal_compliance",
            "advanced_security_assessment",
            "cross_platform_system_manager",
            "enterprise_integration_hub",
            "advanced_analytics_engine"
        ]
    },
    "mcp_web_ui_bridge": {
        name: "MCP Web UI Bridge",
        description: "Chat with AI services through web interfaces without APIs",
        tools: [
            "web_ui_chat",
            "providers_list",
            "provider_wizard",
            "macro_record",
            "macro_run",
            "session_management"
        ]
    },
    "unified_tools": {
        name: "Unified Comprehensive Tools",
        description: "Comprehensive unified tools combining multiple functionalities",
        tools: [
            "crime_reporter_unified",
            "zero_day_exploiter_unified",
            "drone_unified",
            "rf_sense",
            "mobile_app_unified"
        ]
    },
    "advanced_security": {
        name: "Advanced Security Operations",
        description: "Advanced security tools for threat hunting and incident response",
        tools: [
            "advanced_threat_hunting",
            "cyber_deception_platform",
            "zero_trust_architect",
            "quantum_cryptography_suite",
            "ai_security_orchestrator",
            "blockchain_forensics",
            "supply_chain_security",
            "privacy_engineering",
            "incident_commander",
            "security_metrics_dashboard"
        ]
    },
    "ai_tools": {
        name: "AI-Powered Security Tools",
        description: "AI-powered security tools and frameworks",
        tools: [
            "hack_gpt",
            "hack_gpt_natural_language",
            "hexstrike_ai",
            "hexstrike_ai_natural_language",
            "strix_ai",
            "strix_ai_natural_language",
            "pentest_plus_plus",
            "pentest_plus_plus_natural_language",
            "ai_adversarial_prompt",
            "ai_adversarial_nlp",
            "ai_adversarial_platform_info"
        ]
    },
    "competitive_intelligence": {
        name: "Competitive Intelligence",
        description: "Competitor analysis and market research tools",
        tools: [
            "competitive_intelligence",
            "competitive_intelligence_nl",
            "competitive_intelligence_test"
        ]
    },
    "specops_tools": {
        name: "SpecOps Penetration Tools",
        description: "Advanced penetration testing and red team tools",
        tools: [
            "metasploit_framework",
            "cobalt_strike",
            "empire_powershell",
            "bloodhound_ad",
            "mimikatz_credentials",
            "mimikatz_enhanced",
            "hexstrike_ai",
            "hexstrike_ai_natural_language",
            "nmap_scanner",
            "frida_toolkit",
            "ghidra_reverse_engineering",
            "pacu_aws_exploitation"
        ]
    },
    "psychology": {
        name: "Psychology Analysis Tools",
        description: "Psychological analysis and profiling tools",
        tools: [
            "psychology_tool"
        ]
    },
    "form_tools": {
        name: "Form Automation Tools",
        description: "Web form detection, completion, and validation",
        tools: [
            "form_detection",
            "form_completion",
            "form_validation",
            "form_pattern_recognition"
        ]
    },
    "captcha_tools": {
        name: "CAPTCHA Tools",
        description: "CAPTCHA detection and solving capabilities",
        tools: [
            "captcha_defeating"
        ]
    },
    "enhanced_media": {
        name: "Enhanced Media Tools",
        description: "Advanced media processing and editing capabilities",
        tools: [
            "enhanced_media_editor"
        ]
    },
    "enhanced_mobile": {
        name: "Enhanced Mobile Tools",
        description: "Advanced mobile app development and management",
        tools: [
            "enhanced_mobile_app_toolkit"
        ]
    },
    "grep_tools": {
        name: "Advanced Search Tools",
        description: "Advanced text search and pattern matching",
        tools: [
            "grep",
            "advanced_grep"
        ]
    },
    "tool_management": {
        name: "Tool Management",
        description: "Tool discovery and management utilities",
        tools: [
            "tool_burglar"
        ]
    }
};
// Load tool configuration from file
export async function loadToolConfig(configPath) {
    try {
        const defaultPath = path.join(process.cwd(), "tool-config.json");
        const configFile = configPath || defaultPath;
        const configData = await fs.readFile(configFile, "utf-8");
        const config = JSON.parse(configData);
        // Validate configuration
        return validateToolConfig(config);
    }
    catch (error) {
        console.log("No tool configuration found, using default (all tools enabled)");
        return DEFAULT_TOOL_CONFIG;
    }
}
// Save tool configuration to file
export async function saveToolConfig(config, configPath) {
    const defaultPath = path.join(process.cwd(), "tool-config.json");
    const configFile = configPath || defaultPath;
    const configData = JSON.stringify(config, null, 2);
    await fs.writeFile(configFile, configData, "utf-8");
}
// Validate tool configuration
export function validateToolConfig(config) {
    // Ensure all required fields exist
    const validated = {
        enabledTools: config.enabledTools || [],
        disabledTools: config.disabledTools || [],
        toolCategories: config.toolCategories || {},
        customTools: config.customTools || []
    };
    return validated;
}
// Get list of enabled tools based on configuration
export function getEnabledTools(config) {
    // If no specific tools are configured, return empty array (meaning all tools)
    if (config.enabledTools.length === 0 && config.disabledTools.length === 0 && Object.keys(config.toolCategories).length === 0) {
        return []; // Empty array means all tools are enabled
    }
    const enabledTools = new Set();
    // Add explicitly enabled tools
    config.enabledTools.forEach(tool => enabledTools.add(tool));
    // Add tools from enabled categories
    Object.entries(config.toolCategories).forEach(([category, categoryConfig]) => {
        if (categoryConfig.enabled) {
            categoryConfig.tools.forEach(tool => enabledTools.add(tool));
        }
    });
    // Add custom tools
    if (config.customTools) {
        config.customTools.forEach(tool => enabledTools.add(tool));
    }
    // Remove explicitly disabled tools
    config.disabledTools.forEach(tool => enabledTools.delete(tool));
    return Array.from(enabledTools);
}
// Create configuration from tool categories
export function createConfigFromCategories(enabledCategories, customTools) {
    const config = {
        enabledTools: [],
        disabledTools: [],
        toolCategories: {},
        customTools: customTools || []
    };
    // Set up category configurations
    Object.keys(TOOL_CATEGORIES).forEach(category => {
        config.toolCategories[category] = {
            enabled: enabledCategories.includes(category),
            tools: TOOL_CATEGORIES[category].tools
        };
    });
    return config;
}
// Create configuration from individual tools
export function createConfigFromTools(enabledTools, disabledTools) {
    const config = {
        enabledTools: enabledTools,
        disabledTools: disabledTools || [],
        toolCategories: {},
        customTools: []
    };
    // Set up category configurations (all disabled by default when using individual tools)
    Object.keys(TOOL_CATEGORIES).forEach(category => {
        config.toolCategories[category] = {
            enabled: false,
            tools: TOOL_CATEGORIES[category].tools
        };
    });
    return config;
}
// Create configuration from mixed sources (categories + individual tools)
export function createConfigFromMixed(enabledCategories, enabledTools, disabledTools) {
    const config = {
        enabledTools: enabledTools,
        disabledTools: disabledTools || [],
        toolCategories: {},
        customTools: []
    };
    // Set up category configurations
    Object.keys(TOOL_CATEGORIES).forEach(category => {
        config.toolCategories[category] = {
            enabled: enabledCategories.includes(category),
            tools: TOOL_CATEGORIES[category].tools
        };
    });
    return config;
}
// Validate individual tool names
export function validateToolNames(toolNames) {
    const allTools = new Set();
    // Collect all available tools from categories
    Object.values(TOOL_CATEGORIES).forEach(category => {
        category.tools.forEach(tool => allTools.add(tool));
    });
    const valid = [];
    const invalid = [];
    toolNames.forEach(tool => {
        if (allTools.has(tool)) {
            valid.push(tool);
        }
        else {
            invalid.push(tool);
        }
    });
    return { valid, invalid };
}
// Get all available tool names
export function getAllAvailableTools() {
    const allTools = new Set();
    Object.values(TOOL_CATEGORIES).forEach(category => {
        category.tools.forEach(tool => allTools.add(tool));
    });
    return Array.from(allTools).sort();
}
// Tool dependencies mapping
export const TOOL_DEPENDENCIES = {
    // Core tools that other tools might depend on
    "health": [],
    "system_info": [],
    // File system tools
    "fs_list": [],
    "fs_read_text": [],
    "fs_write_text": [],
    "fs_search": [],
    "file_ops": [],
    "file_watcher": [],
    // Process tools
    "proc_run": [],
    "proc_run_elevated": [],
    // Network tools that might depend on basic process execution
    "network_diagnostics": ["proc_run"],
    "network_discovery": ["proc_run"],
    "port_scanner": ["proc_run"],
    "packet_sniffer": ["proc_run"],
    // Security tools that might depend on network tools
    "vulnerability_scanner": ["network_discovery", "port_scanner"],
    "penetration_testing_toolkit": ["network_discovery", "port_scanner", "vulnerability_scanner"],
    // Mobile tools that might depend on basic system tools
    "mobile_device_info": ["system_info"],
    "mobile_device_management": ["system_info"],
    // Enhanced tools that depend on basic versions
    "enhanced_legal_compliance": ["legal_compliance_manager"],
    "advanced_security_assessment": ["security_testing"],
    // Default: no dependencies for most tools
};
// Validate tool dependencies
export function validateToolDependencies(requestedTools) {
    const valid = [];
    const missing = [];
    const warnings = [];
    const allAvailableTools = getAllAvailableTools();
    const requestedSet = new Set(requestedTools);
    requestedTools.forEach(tool => {
        if (!allAvailableTools.includes(tool)) {
            missing.push(tool);
            return;
        }
        valid.push(tool);
        // Check dependencies
        const dependencies = TOOL_DEPENDENCIES[tool] || [];
        dependencies.forEach(dep => {
            if (!requestedSet.has(dep)) {
                warnings.push(`${tool} depends on ${dep}, but ${dep} is not included`);
            }
        });
    });
    return { valid, missing, warnings };
}
// Auto-include dependencies for a tool list
export function includeToolDependencies(tools) {
    const result = new Set(tools);
    let changed = true;
    while (changed) {
        changed = false;
        const currentTools = Array.from(result);
        currentTools.forEach(tool => {
            const dependencies = TOOL_DEPENDENCIES[tool] || [];
            dependencies.forEach(dep => {
                if (!result.has(dep)) {
                    result.add(dep);
                    changed = true;
                }
            });
        });
    }
    return Array.from(result).sort();
}
// Create minimal configuration (core tools only)
export function createMinimalConfig() {
    return createConfigFromCategories(["core", "file_system", "discovery"]);
}
// Create full configuration (all tools)
export function createFullConfig() {
    return createConfigFromCategories(Object.keys(TOOL_CATEGORIES));
}
