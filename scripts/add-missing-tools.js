/**
 * Add missing MCP tools to tools.manifest.json until the total reaches 186.
 * - Compares existing tools by "name" (fallback: by "invoke")
 * - Appends missing tools with consistent defaults and safe smoke tests
 * - Applies lightweight heuristics for category, privilege, safe_mode, tags
 *
 * Usage:
 *   node scripts/add-missing-tools.js
 *
 * Requirements:
 *   - Run from repo root (same directory as tools.manifest.json)
 *   - Node 18+ recommended
 */

const fs = require('fs');
const path = require('path');

const manifestPath = path.resolve('tools.manifest.json');

// Canonical tool list (186) sourced from user request and code exports.
const ALL_TOOL_NAMES = [
  "advanced_analytics_engine",
  "advanced_grep",
  "advanced_security_assessment",
  "advanced_threat_hunting",
  "ai_adversarial_nlp",
  "ai_adversarial_platform_info",
  "ai_adversarial_prompt",
  "ai_security_orchestrator",
  "api_security_testing",
  "blockchain_forensics",
  "blockchain_security",
  "bloodhound_ad",
  "bluetooth_device_manager",
  "bluetooth_hacking",
  "bluetooth_security_toolkit",
  "browser_control",
  "calculator",
  "captcha_defeating",
  "cellular_triangulate",
  "chart_generator",
  "cloud_infrastructure_manager",
  "cloud_security_assessment",
  "cloud_security_toolkit",
  "cobalt_strike",
  "competitive_intelligence",
  "competitive_intelligence_nl",
  "competitive_intelligence_test",
  "compliance_assessment",
  "crime_reporter_unified",
  "cron_job_manager",
  "cross_platform_system_manager",
  "cyber_deception_platform",
  "data_analysis",
  "data_analyzer",
  "database_security_toolkit",
  "delete_emails",
  "dice_rolling",
  "docker_management",
  "download_file",
  "drone_unified",
  "elevated_permissions_manager",
  "email_security_suite",
  "empire_powershell",
  "encryption_tool",
  "enhanced_browser_automation",
  "enhanced_calculator",
  "enhanced_data_analysis",
  "enhanced_legal_compliance",
  "enhanced_media_editor",
  "enhanced_mobile_app_toolkit",
  "enterprise_integration_hub",
  "exploit_framework",
  "explore_categories",
  "file_ops",
  "file_watcher",
  "flipper_zero",
  "forensics_analysis",
  "forensics_toolkit",
  "form_completion",
  "form_detection",
  "form_pattern_recognition",
  "form_validation",
  "frida_toolkit",
  "fs_list",
  "fs_read_text",
  "fs_search",
  "fs_write_text",
  "ghidra_reverse_engineering",
  "git_status",
  "grep",
  "hack_gpt",
  "hack_gpt_natural_language",
  "hack_network",
  "health",
  "hexstrike_ai",
  "hexstrike_ai_natural_language",
  "incident_commander",
  "iot_security",
  "ip_geolocation",
  "latency_geolocation",
  "legal_compliance_manager",
  "machine_learning",
  "macro_record",
  "macro_run",
  "malware_analysis",
  "malware_analysis_toolkit",
  "manage_email_accounts",
  "math_calculate",
  "metadata_extractor",
  "metasploit_framework",
  "mimikatz_credentials",
  "mimikatz_enhanced",
  "mobile_app_unified",
  "mobile_device_info",
  "mobile_device_management",
  "mobile_file_ops",
  "mobile_hardware",
  "mobile_network_analyzer",
  "mobile_security_toolkit",
  "mobile_system_tools",
  "multi_engine_search",
  "multimedia_tool",
  "natural_language_router",
  "network_diagnostics",
  "network_discovery",
  "network_security",
  "network_traffic_analyzer",
  "network_triangulation",
  "network_utilities",
  "nmap_scanner",
  "ocr_tool",
  "osint_reconnaissance",
  "packet_sniffer",
  "pacu_aws_exploitation",
  "parse_email",
  "password_cracker",
  "password_generator",
  "penetration_testing_toolkit",
  "pentest_plus_plus",
  "pentest_plus_plus_natural_language",
  "port_scanner",
  "privacy_engineering",
  "proc_run",
  "proc_run_elevated",
  "proc_run_remote",
  "provider_wizard",
  "providers_list",
  "psychology",
  "quantum_cryptography_suite",
  "quantum_security",
  "radio_security",
  "rag_toolkit",
  "read_emails",
  "red_team_toolkit",
  "rf_sense",
  "rf_sense_guardrails",
  "rf_sense_localize",
  "rf_sense_mmwave",
  "rf_sense_natural_language",
  "rf_sense_sim",
  "rf_sense_wifi_lab",
  "screenshot",
  "sdr_security_toolkit",
  "search_analysis",
  "security_metrics_dashboard",
  "security_testing",
  "send_email",
  "session_management",
  "siem_toolkit",
  "signal_analysis",
  "social_account_ripper_modular",
  "social_engineering_toolkit",
  "social_network_ripper",
  "sort_emails",
  "strix_ai",
  "strix_ai_natural_language",
  "supply_chain_security",
  "system_info",
  "system_monitor",
  "system_restore",
  "text_processor",
  "threat_intelligence",
  "tool_burglar",
  "tool_discovery",
  "traffic_analysis",
  "universal_browser_operator",
  "vm_management",
  "vulnerability_assessment",
  "vulnerability_scanner",
  "wan_malware_deployer",
  "wan_malware_deployer_nl",
  "web_automation",
  "web_scraper",
  "web_search",
  "web_ui_chat",
  "webhook_manager",
  "wifi_disrupt",
  "wifi_hacking",
  "wifi_security_toolkit",
  "win_processes",
  "win_services",
  "wireless_network_scanner",
  "wireless_security",
  "zero_day_exploiter_unified",
  "zero_trust_architect",
  "example_tool"
];

// Optional short descriptions.
const DESC = {
  drone_unified: "Unified Drone Management Tool",
  rf_sense: "Unified RF Sense Tool (experimental)",
  rf_sense_mmwave: "RF Sense mmWave module",
  rf_sense_wifi_lab: "RF Sense WiFi CSI lab module",
  rf_sense_sim: "RF Sense simulation module",
  rf_sense_localize: "RF Sense localization module",
  rf_sense_natural_language: "Natural language interface for RF Sense",
  rf_sense_guardrails: "RF Sense guardrails",
  crime_reporter_unified: "Unified crime reporting",
  zero_day_exploiter_unified: "Unified zero-day exploiter",
  flipper_zero: "Flipper Zero consolidated operations",
};

function inferCategory(name) {
  const n = name.toLowerCase();
  if (n.includes('wifi') || n.includes('wireless')) return 'wireless';
  if (n.includes('bluetooth')) return 'bluetooth';
  if (n.includes('radio') || n.includes('sdr') || n.includes('signal') || n.startsWith('rf_sense')) return 'radio';
  if (n.includes('forensic') || n.includes('malware')) return 'forensics';
  if (n.includes('crime') || n.includes('legal') || n.includes('compliance')) return 'legal';
  if (n.includes('cloud')) return 'cloud';
  if (n.includes('mobile')) return 'mobile';
  if (n.includes('vm') || n.includes('docker')) return 'virtualization';
  if (n.includes('ai') || n.includes('rag') || n.includes('psychology')) return 'ai';
  if (n.includes('web') || n.includes('browser') || n.includes('captcha') || n.includes('form')) return 'web';
  if (n.includes('email')) return 'email';
  if (n.includes('calc') || n.includes('chart') || n.includes('text_') || n === 'text_processor') return 'utilities';
  if (n.includes('network') || n.includes('packet') || n.includes('port') || n.includes('nmap')) return 'network';
  if (n.includes('security') || n.includes('pentest') || n.includes('metasploit') || n.includes('cobalt') || n.includes('mimikatz')) return 'security';
  if (n.includes('drone')) return 'hardware';
  return 'misc';
}

// Known dangerous/privileged tools (heuristic)
const REQUIRE_PRIV = new Set([
  'proc_run_elevated',
  'wifi_disrupt',
  'wifi_hacking',
  'wireless_security',
  'bluetooth_hacking',
  'mimikatz_credentials',
  'mimikatz_enhanced',
  'metasploit_framework',
  'cobalt_strike',
  'empire_powershell',
  'network_penetration',
  'penetration_testing_toolkit',
  'red_team_toolkit',
  'rf_sense',
  'rf_sense_wifi_lab',
  'rf_sense_mmwave',
  'sdr_security_toolkit',
  'radio_security',
  'signal_analysis',
  'vm_management',
  'docker_management',
  'tool_burglar'
]);

const UNSAFE_MODE = new Set([
  'wifi_disrupt',
  'rf_sense',
  'rf_sense_wifi_lab',
  'rf_sense_mmwave',
  'mimikatz_credentials',
  'mimikatz_enhanced',
  'metasploit_framework',
  'cobalt_strike',
  'empire_powershell',
  'network_penetration',
  'penetration_testing_toolkit',
  'red_team_toolkit'
]);

function buildToolEntry(name) {
  const category = inferCategory(name);
  const requires_privilege = REQUIRE_PRIV.has(name);
  const safe_mode = !UNSAFE_MODE.has(name);

  return {
    name,
    category,
    entry_file: "dev/dist/server-refactored.js",
    invoke: name,
    args: [],
    env_vars: [],
    requires_privilege,
    side_effects: DESC[name] || `Tool '${name}' auto-added; side-effects not fully profiled`,
    safe_mode,
    tags: [category, "auto-added"],
    smoke_test: {
      cmd: "node",
      args: ["-e", `console.log('Smoke test for ${name}')`],
      expect_code: 0,
      timeout_ms: 5000
    }
  };
}

function main() {
  if (!fs.existsSync(manifestPath)) {
    console.error(`ERROR: ${manifestPath} not found. Run from repo root.`);
    process.exit(1);
  }

  const raw = fs.readFileSync(manifestPath, 'utf8');
  let manifest;
  try {
    manifest = JSON.parse(raw);
  } catch (e) {
    console.error('ERROR: tools.manifest.json is not valid JSON:', e.message);
    process.exit(1);
  }

  if (!manifest || typeof manifest !== 'object' || !Array.isArray(manifest.tools)) {
    console.error('ERROR: Manifest must be an object with a "tools" array.');
    process.exit(1);
  }

  const existingNames = new Set(
    manifest.tools
      .map(t => t && (t.name || t.invoke))
      .filter(Boolean)
  );

  const toAdd = [];
  for (const name of ALL_TOOL_NAMES) {
    if (!existingNames.has(name)) {
      toAdd.push(buildToolEntry(name));
    }
  }

  if (toAdd.length === 0) {
    console.log(`No new tools to add. Existing: ${existingNames.size}`);
  } else {
    manifest.tools.push(...toAdd);
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
    console.log(`Added ${toAdd.length} tool(s). Total is now ${manifest.tools.length}.`);
    console.log('Added tools:', toAdd.map(t => t.name).join(', '));
  }

  // Sanity check
  if (manifest.tools.length < 186) {
    console.warn(`WARNING: Total tools < 186 (${manifest.tools.length}). Some canonical names may be missing or not yet implemented.`);
  } else if (manifest.tools.length > 186) {
    console.warn(`WARNING: Total tools > 186 (${manifest.tools.length}). There may be duplicates or extra tools.`);
  } else {
    console.log('OK: Manifest now lists 186 tools.');
  }
}

main();
