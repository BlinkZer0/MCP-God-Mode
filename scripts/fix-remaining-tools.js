#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Define schemas for the remaining 49 tools based on their implementations and documentation
const remainingToolSchemas = {
  // Hardware Tools
  drone_unified: [
    { name: "action", type: "enum[status,takeoff,land,move,hover,rotate,set_altitude,get_telemetry,start_mission,stop_mission,return_home,calibrate,arm,disarm]", required: true, description: "Drone operation to perform" },
    { name: "direction", type: "enum[forward,backward,left,right,up,down]", required: false, description: "Movement direction" },
    { name: "distance", type: "number", required: false, description: "Distance to move in meters" },
    { name: "altitude", type: "number", required: false, description: "Target altitude in meters" },
    { name: "speed", type: "number", required: false, description: "Movement speed (0-100%)" },
    { name: "duration", type: "number", required: false, description: "Operation duration in seconds" }
  ],

  // RF Sense Tools (Radio Frequency Sensing)
  rf_sense: [
    { name: "action", type: "enum[scan,detect,analyze,monitor,calibrate,configure]", required: true, description: "RF sensing action to perform" },
    { name: "frequency_range", type: "string", required: false, description: "Frequency range to scan (e.g., '2.4-2.5GHz')" },
    { name: "duration", type: "number", required: false, description: "Scan duration in seconds" },
    { name: "sensitivity", type: "number", required: false, description: "Detection sensitivity (1-10)" },
    { name: "output_file", type: "string", required: false, description: "Output file for results" }
  ],

  rf_sense_guardrails: [
    { name: "action", type: "enum[check_compliance,set_limits,validate_operation,get_restrictions]", required: true, description: "Guardrail action to perform" },
    { name: "frequency", type: "number", required: false, description: "Frequency to check in Hz" },
    { name: "power_level", type: "number", required: false, description: "Power level to validate" },
    { name: "region", type: "string", required: false, description: "Regulatory region (e.g., 'US', 'EU', 'JP')" }
  ],

  rf_sense_localize: [
    { name: "action", type: "enum[triangulate,locate_source,map_signals,calibrate_position]", required: true, description: "Localization action to perform" },
    { name: "target_frequency", type: "number", required: false, description: "Target signal frequency" },
    { name: "reference_points", type: "array[object]", required: false, description: "Reference measurement points" },
    { name: "accuracy_threshold", type: "number", required: false, description: "Required accuracy in meters" }
  ],

  rf_sense_mmwave: [
    { name: "action", type: "enum[scan_mmwave,detect_objects,measure_distance,analyze_doppler]", required: true, description: "mmWave radar action" },
    { name: "frequency_band", type: "enum[24GHz,60GHz,77GHz,79GHz]", required: false, description: "mmWave frequency band" },
    { name: "range_max", type: "number", required: false, description: "Maximum detection range in meters" },
    { name: "resolution", type: "enum[low,medium,high]", required: false, description: "Detection resolution" }
  ],

  rf_sense_natural_language: [
    { name: "command", type: "string", required: true, description: "Natural language command for RF operations" },
    { name: "context", type: "string", required: false, description: "Additional context for the command" }
  ],

  rf_sense_sim: [
    { name: "action", type: "enum[create_scenario,run_simulation,analyze_results,export_data]", required: true, description: "Simulation action to perform" },
    { name: "scenario_type", type: "enum[indoor,outdoor,urban,rural]", required: false, description: "Environment scenario" },
    { name: "num_objects", type: "number", required: false, description: "Number of objects to simulate" },
    { name: "duration", type: "number", required: false, description: "Simulation duration in seconds" }
  ],

  rf_sense_wifi_lab: [
    { name: "action", type: "enum[capture_csi,analyze_channel,measure_rssi,detect_motion]", required: true, description: "WiFi CSI lab action" },
    { name: "channel", type: "number", required: false, description: "WiFi channel to analyze" },
    { name: "interface", type: "string", required: false, description: "WiFi interface to use" },
    { name: "duration", type: "number", required: false, description: "Capture duration in seconds" }
  ],

  // Core System Tools
  health: [
    { name: "check_type", type: "enum[basic,detailed,system,network,security]", required: false, description: "Type of health check to perform" },
    { name: "include_metrics", type: "boolean", required: false, description: "Include performance metrics" }
  ],

  system_info: [
    { name: "info_type", type: "enum[basic,detailed,hardware,software,network]", required: false, description: "Type of system information to retrieve" },
    { name: "format", type: "enum[json,text,table]", required: false, description: "Output format" }
  ],

  // File System Tools
  file_watcher: [
    { name: "action", type: "enum[watch,unwatch,list_watchers,get_events]", required: true, description: "File watcher action" },
    { name: "path", type: "string", required: false, description: "Path to watch" },
    { name: "events", type: "array[string]", required: false, description: "Events to watch for" },
    { name: "recursive", type: "boolean", required: false, description: "Watch subdirectories recursively" },
    { name: "watcher_id", type: "string", required: false, description: "Watcher ID for management" }
  ],

  // System Management Tools
  cron_job_manager: [
    { name: "action", type: "enum[list,add,remove,enable,disable,status]", required: true, description: "Cron job management action" },
    { name: "job_name", type: "string", required: false, description: "Name of the cron job" },
    { name: "schedule", type: "string", required: false, description: "Cron schedule expression" },
    { name: "command", type: "string", required: false, description: "Command to execute" },
    { name: "description", type: "string", required: false, description: "Job description" }
  ],

  // Network Tools
  network_traffic_analyzer: [
    { name: "interface", type: "string", required: true, description: "Network interface to analyze" },
    { name: "analysis_type", type: "enum[protocol,bandwidth,security,performance,comprehensive]", required: true, description: "Type of traffic analysis" },
    { name: "capture_duration", type: "number", required: false, description: "Capture duration in seconds" },
    { name: "filter", type: "string", required: false, description: "BPF filter expression" },
    { name: "output_file", type: "string", required: false, description: "Output file for captured packets" },
    { name: "real_time", type: "boolean", required: false, description: "Enable real-time analysis" }
  ],

  // Bluetooth Tools
  bluetooth_device_manager: [
    { name: "action", type: "enum[scan,connect,disconnect,pair,unpair,list,info]", required: true, description: "Bluetooth device management action" },
    { name: "device_address", type: "string", required: false, description: "Bluetooth device MAC address" },
    { name: "device_name", type: "string", required: false, description: "Bluetooth device name" },
    { name: "scan_duration", type: "number", required: false, description: "Scan duration in seconds" },
    { name: "service_uuid", type: "string", required: false, description: "Service UUID to filter" }
  ],

  // Discovery Tools
  tool_discovery: [
    { name: "query", type: "string", required: true, description: "Natural language query to find relevant tools" },
    { name: "category", type: "string", required: false, description: "Optional tool category to focus on" },
    { name: "capability", type: "string", required: false, description: "Specific capability or feature to search for" }
  ],

  explore_categories: [
    { name: "category", type: "string", required: false, description: "Specific category to explore, or leave empty to see all categories" }
  ],

  natural_language_router: [
    { name: "query", type: "string", required: true, description: "Natural language query to route to appropriate tools" },
    { name: "context", type: "string", required: false, description: "Additional context about the request" },
    { name: "user_intent", type: "string", required: false, description: "User's intended goal or objective" }
  ],

  // Email Tools
  sort_emails: [
    { name: "emails", type: "array[object]", required: true, description: "Array of emails to sort" },
    { name: "sort_by", type: "enum[date,sender,subject,priority,size]", required: true, description: "Sorting criteria" },
    { name: "order", type: "enum[asc,desc]", required: false, description: "Sorting order" },
    { name: "group_by", type: "string", required: false, description: "Group emails by criteria" }
  ],

  // Security Tools
  supply_chain_security: [
    { name: "action", type: "enum[scan_dependencies,analyze_vulnerabilities,check_licenses,audit_supply_chain]", required: true, description: "Supply chain security action" },
    { name: "project_path", type: "string", required: false, description: "Path to project to analyze" },
    { name: "package_manager", type: "enum[npm,pip,maven,gradle,composer]", required: false, description: "Package manager type" },
    { name: "output_format", type: "enum[json,csv,html,pdf]", required: false, description: "Output format" }
  ],

  privacy_engineering: [
    { name: "action", type: "enum[privacy_audit,data_mapping,consent_analysis,gdpr_compliance]", required: true, description: "Privacy engineering action" },
    { name: "data_source", type: "string", required: false, description: "Data source to analyze" },
    { name: "regulation", type: "enum[GDPR,CCPA,PIPEDA,LGPD]", required: false, description: "Privacy regulation to check against" },
    { name: "scope", type: "string", required: false, description: "Scope of privacy analysis" }
  ],

  incident_commander: [
    { name: "action", type: "enum[create_incident,update_status,assign_responder,escalate,close_incident,generate_report]", required: true, description: "Incident management action" },
    { name: "incident_id", type: "string", required: false, description: "Incident identifier" },
    { name: "severity", type: "enum[low,medium,high,critical]", required: false, description: "Incident severity" },
    { name: "description", type: "string", required: false, description: "Incident description" },
    { name: "responder", type: "string", required: false, description: "Assigned responder" }
  ],

  security_metrics_dashboard: [
    { name: "action", type: "enum[get_metrics,generate_dashboard,export_data,configure_alerts]", required: true, description: "Security metrics action" },
    { name: "metric_type", type: "enum[vulnerabilities,incidents,compliance,risk_score]", required: false, description: "Type of metrics to retrieve" },
    { name: "time_range", type: "string", required: false, description: "Time range for metrics (e.g., '7d', '30d')" },
    { name: "format", type: "enum[json,csv,dashboard,chart]", required: false, description: "Output format" }
  ],

  // Legal Tools
  crime_reporter_unified: [
    { name: "command", type: "string", required: false, description: "Crime reporter command" },
    { name: "mode", type: "enum[command,natural_language,test]", required: false, description: "Operation mode" },
    { name: "naturalLanguageCommand", type: "string", required: false, description: "Natural language command for crime reporting" },
    { name: "parameters", type: "object", required: false, description: "Command parameters" }
  ],

  // Misc Tools
  zero_day_exploiter_unified: [
    { name: "action", type: "enum[scan,exploit,analyze,report]", required: true, description: "Zero-day exploitation action" },
    { name: "target", type: "string", required: false, description: "Target system or application" },
    { name: "exploit_type", type: "enum[buffer_overflow,sql_injection,xss,rce,privilege_escalation]", required: false, description: "Type of exploit to attempt" },
    { name: "payload", type: "string", required: false, description: "Custom payload" },
    { name: "safe_mode", type: "boolean", required: false, description: "Run in safe mode (simulation only)" }
  ],

  // AI Tools
  ai_adversarial_nlp: [
    { name: "action", type: "enum[generate_adversarial,test_robustness,analyze_vulnerabilities,defend_model]", required: true, description: "Adversarial NLP action" },
    { name: "model_type", type: "string", required: false, description: "Target model type" },
    { name: "input_text", type: "string", required: false, description: "Input text for adversarial testing" },
    { name: "attack_method", type: "enum[textfooler,bert_attack,deepwordbug,hotflip]", required: false, description: "Adversarial attack method" }
  ],

  ai_adversarial_platform_info: [
    { name: "action", type: "enum[get_info,list_methods,test_defenses,generate_report]", required: true, description: "Platform information action" },
    { name: "platform", type: "string", required: false, description: "Target AI platform" },
    { name: "info_type", type: "enum[capabilities,vulnerabilities,defenses,metrics]", required: false, description: "Type of information to retrieve" }
  ],

  // SpecOps Tools
  bloodhound_ad: [
    { name: "action", type: "enum[collect,analyze,query,visualize,export]", required: true, description: "BloodHound AD action" },
    { name: "domain", type: "string", required: false, description: "Active Directory domain" },
    { name: "collection_method", type: "enum[all,dconly,group,localadmin,rdp,dcom,psremote]", required: false, description: "Data collection method" },
    { name: "output_path", type: "string", required: false, description: "Output path for collected data" }
  ],

  mimikatz_credentials: [
    { name: "action", type: "enum[sekurlsa,kerberos,crypto,lsadump,vault,dpapi]", required: true, description: "Mimikatz credential action" },
    { name: "target", type: "string", required: false, description: "Target system or process" },
    { name: "output_file", type: "string", required: false, description: "Output file for credentials" },
    { name: "elevated", type: "boolean", required: false, description: "Require elevated privileges" }
  ],

  mimikatz_enhanced: [
    { name: "action", type: "enum[sekurlsa,kerberos,crypto,lsadump,vault,dpapi,privilege,process,service,token]", required: true, description: "Enhanced Mimikatz action" },
    { name: "module", type: "string", required: false, description: "Specific Mimikatz module" },
    { name: "parameters", type: "object", required: false, description: "Module-specific parameters" },
    { name: "output_format", type: "enum[text,json,csv]", required: false, description: "Output format" }
  ],

  // Mobile Tools
  frida_toolkit: [
    { name: "action", type: "enum[attach,spawn,inject,hook,trace,dump]", required: true, description: "Frida toolkit action" },
    { name: "target", type: "string", required: false, description: "Target application or process" },
    { name: "script", type: "string", required: false, description: "Frida script to execute" },
    { name: "device", type: "string", required: false, description: "Target device identifier" },
    { name: "output_file", type: "string", required: false, description: "Output file for results" }
  ],

  ghidra_reverse_engineering: [
    { name: "action", type: "enum[analyze,decompile,disassemble,export,import,script]", required: true, description: "Ghidra reverse engineering action" },
    { name: "binary_path", type: "string", required: false, description: "Path to binary file to analyze" },
    { name: "project_name", type: "string", required: false, description: "Ghidra project name" },
    { name: "script_path", type: "string", required: false, description: "Path to Ghidra script" },
    { name: "output_format", type: "enum[c,java,xml,json]", required: false, description: "Output format for decompiled code" }
  ],

  // Cloud Tools
  pacu_aws_exploitation: [
    { name: "action", type: "enum[enumerate,exploit,escalate,persist,exfiltrate]", required: true, description: "Pacu AWS exploitation action" },
    { name: "module", type: "string", required: false, description: "Specific Pacu module to run" },
    { name: "target_service", type: "enum[ec2,s3,iam,lambda,rds,cloudtrail]", required: false, description: "Target AWS service" },
    { name: "region", type: "string", required: false, description: "AWS region" },
    { name: "session_name", type: "string", required: false, description: "Pacu session name" }
  ],

  // Social Tools
  competitive_intelligence: [
    { name: "action", type: "string", required: true, description: "Competitive intelligence action" },
    { name: "companyName", type: "string", required: false, description: "Company name for the operation" },
    { name: "homepageUrl", type: "string", required: false, description: "Homepage URL to scrape" },
    { name: "sitemapUrl", type: "string", required: false, description: "Sitemap URL to analyze" },
    { name: "categories", type: "array[string]", required: false, description: "Categories to include" },
    { name: "keywords", type: "array[string]", required: false, description: "Keywords for sitemap filtering" }
  ],

  competitive_intelligence_nl: [
    { name: "command", type: "string", required: true, description: "Natural language command for competitive intelligence" }
  ],

  // Utility Tools
  multi_engine_search: [
    { name: "query", type: "string", required: true, description: "Search query to execute" },
    { name: "engines", type: "array[string]", required: true, description: "Search engines to use" },
    { name: "max_results_per_engine", type: "number", required: false, description: "Maximum results per engine" },
    { name: "include_snippets", type: "boolean", required: false, description: "Whether to include result snippets" },
    { name: "timeout", type: "number", required: false, description: "Timeout in milliseconds" }
  ],

  search_analysis: [
    { name: "results", type: "array[object]", required: true, description: "Search results to analyze" },
    { name: "analysis_type", type: "enum[trends,domains,keywords,sentiment,comprehensive]", required: true, description: "Type of analysis to perform" },
    { name: "include_visualization", type: "boolean", required: false, description: "Generate visualization data" }
  ]
};

function updateRemainingTools() {
  const manifestPath = path.join(__dirname, '..', 'tools.manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  
  let updatedCount = 0;
  let notFoundCount = 0;
  
  console.log('🔧 Updating remaining tools with empty schemas...\n');
  
  // Update tools that have schemas defined
  Object.keys(remainingToolSchemas).forEach(toolName => {
    const toolIndex = manifest.tools.findIndex(tool => tool.name === toolName);
    if (toolIndex !== -1) {
      const currentTool = manifest.tools[toolIndex];
      if (Array.isArray(currentTool.args) && currentTool.args.length === 0) {
        manifest.tools[toolIndex].args = remainingToolSchemas[toolName];
        console.log(`✅ Updated ${toolName} with ${remainingToolSchemas[toolName].length} parameters`);
        updatedCount++;
      } else {
        console.log(`⚠️  ${toolName} already has args (${currentTool.args.length} parameters), skipping`);
      }
    } else {
      console.log(`❌ Tool ${toolName} not found in manifest`);
      notFoundCount++;
    }
  });
  
  if (updatedCount > 0) {
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
    console.log(`\n✅ Updated ${updatedCount} tools with proper schemas`);
    console.log(`📁 Manifest saved to ${manifestPath}`);
  }
  
  if (notFoundCount > 0) {
    console.log(`\n⚠️  ${notFoundCount} tools not found in manifest`);
  }
  
  return { updatedCount, notFoundCount };
}

if (require.main === module) {
  console.log('🚀 Fixing Remaining 49 Tools with Missing Schemas\n');
  const result = updateRemainingTools();
  
  console.log('\n📊 Final Summary:');
  console.log(`   - Tools updated: ${result.updatedCount}`);
  console.log(`   - Tools not found: ${result.notFoundCount}`);
  console.log(`   - Total processed: ${Object.keys(remainingToolSchemas).length}`);
}

module.exports = { remainingToolSchemas, updateRemainingTools };
