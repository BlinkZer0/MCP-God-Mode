#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Define schemas for critical tools that are missing proper args
const criticalToolSchemas = {
  // Network Tools
  nmap_scanner: [
    { name: "action", type: "enum[host_discovery,port_scan,service_scan,os_detection,vulnerability_scan,stealth_scan,udp_scan,sctp_scan,ip_protocol_scan,idle_scan,fragment_scan,xmas_scan,null_scan,fin_scan,ack_scan,window_scan,maimon_scan,custom_scan,script_scan,timing_scan]", required: true, description: "Nmap scan action to perform" },
    { name: "target", type: "string", required: true, description: "Target host or network (e.g., '192.168.1.1', '192.168.1.0/24')" },
    { name: "ports", type: "string", required: false, description: "Port range or specific ports (e.g., '1-1000', '22,80,443')" },
    { name: "scan_type", type: "enum[tcp_syn,tcp_connect,tcp_ack,tcp_window,tcp_maimon,tcp_null,tcp_fin,tcp_xmas,udp,sctp,ip_protocol]", required: false, description: "Scan type" },
    { name: "timing", type: "enum[T0,T1,T2,T3,T4,T5]", required: false, description: "Timing template" },
    { name: "scripts", type: "array[string]", required: false, description: "NSE scripts to run" },
    { name: "output_file", type: "string", required: false, description: "Output file path" },
    { name: "verbose", type: "boolean", required: false, description: "Enable verbose output" }
  ],

  // Security Tools
  vulnerability_scanner: [
    { name: "scan_type", type: "enum[network,web,database,os,comprehensive]", required: true, description: "Type of vulnerability scan to perform" },
    { name: "target", type: "string", required: true, description: "Target system or application to scan" },
    { name: "scan_level", type: "enum[light,standard,aggressive,custom]", required: false, description: "Scan intensity level" },
    { name: "custom_rules", type: "array[string]", required: false, description: "Custom scanning rules to apply" }
  ],

  metasploit_framework: [
    { name: "action", type: "enum[search,info,use,set,exploit,payload,generate,sessions,jobs]", required: true, description: "Metasploit action to perform" },
    { name: "module", type: "string", required: false, description: "Module name or search term" },
    { name: "target", type: "string", required: false, description: "Target host or IP address" },
    { name: "payload", type: "string", required: false, description: "Payload to use" },
    { name: "options", type: "object", required: false, description: "Module options and parameters" }
  ],

  // Web Tools
  web_scraper: [
    { name: "url", type: "string", required: true, description: "Target URL to scrape" },
    { name: "extract_type", type: "enum[text,links,images,tables,forms,all]", required: false, description: "Type of content to extract" },
    { name: "selectors", type: "array[string]", required: false, description: "CSS selectors for specific content extraction" },
    { name: "follow_links", type: "boolean", required: false, description: "Whether to follow and scrape linked pages" },
    { name: "max_pages", type: "number", required: false, description: "Maximum number of pages to scrape" }
  ],

  enhanced_browser_automation: [
    { name: "action", type: "enum[launch,close,navigate,back,forward,refresh,reload,click,type,fill,select,check,uncheck,hover,scroll,screenshot,extract,get_text,get_html,get_attributes,execute_script,evaluate,inject_script,form_fill,form_submit,form_reset,wait,wait_for_element,wait_for_text,wait_for_navigation,upload_file,download_file,set_viewport,set_geolocation,block_resources,automate_workflow,record_actions,playback_actions]", required: true, description: "Browser automation action to perform" },
    { name: "url", type: "string", required: false, description: "URL to navigate to" },
    { name: "selector", type: "string", required: false, description: "CSS selector, XPath, or element identifier for targeting elements" },
    { name: "text", type: "string", required: false, description: "Text content to search for or input" },
    { name: "browser", type: "enum[chrome,firefox,safari,edge,auto]", required: false, description: "Browser to use (auto selects platform default)" },
    { name: "headless", type: "boolean", required: false, description: "Run browser in headless mode" },
    { name: "timeout", type: "number", required: false, description: "Operation timeout in milliseconds" }
  ],

  // Media Tools
  multimedia_tool: [
    { name: "action", type: "enum[status,open,edit,export,batch_process,create_project,get_session,delete_session,record_audio,get_audio_devices,start_recording,generate_svg,generate_ai_image]", required: true, description: "Multimedia tool action to perform" },
    { name: "source", type: "string", required: false, description: "Media source path (local file) or URL (http/https) to open for editing" },
    { name: "operation", type: "enum[trim,normalize,fade,gain,reverse,time_stretch,pitch_shift,resize,crop,rotate,flip,filter,enhance,adjust,vignette,border,cut,merge,convert,resize_video,add_audio,add_subtitles,apply_effects,composite,watermark,batch_process]", required: false, description: "Editing operation to apply" },
    { name: "sessionId", type: "string", required: false, description: "Unique session identifier for referencing an existing editing session" },
    { name: "format", type: "string", required: false, description: "Output format for export operations" },
    { name: "quality", type: "number", required: false, description: "Output quality setting (1-100)" }
  ],

  // System Tools
  system_monitor: [
    { name: "action", type: "enum[get_status,monitor,get_processes,get_services,get_network,get_disk,get_memory,get_cpu,get_system_info]", required: true, description: "System monitoring action" },
    { name: "duration", type: "number", required: false, description: "Monitoring duration in seconds" },
    { name: "interval", type: "number", required: false, description: "Monitoring interval in seconds" },
    { name: "output_format", type: "enum[json,table,summary]", required: false, description: "Output format" },
    { name: "include_details", type: "boolean", required: false, description: "Include detailed information" }
  ],

  // Mobile Tools
  mobile_security_toolkit: [
    { name: "action", type: "enum[scan_device,analyze_app,extract_data,security_audit,privacy_check,malware_scan,network_analysis,forensic_extraction]", required: true, description: "Mobile security action to perform" },
    { name: "device_id", type: "string", required: false, description: "Target device identifier" },
    { name: "app_package", type: "string", required: false, description: "Application package name to analyze" },
    { name: "scan_type", type: "enum[static,dynamic,comprehensive]", required: false, description: "Type of security scan" },
    { name: "output_format", type: "enum[json,xml,html,pdf]", required: false, description: "Output format for results" }
  ],

  // AI Tools
  rag_toolkit: [
    { name: "action", type: "enum[search_documents,query_with_context,embed_text,similarity_search,build_index,retrieve_context,generate_answer]", required: true, description: "RAG action to perform" },
    { name: "query", type: "string", required: false, description: "Search query or question" },
    { name: "documents", type: "array[string]", required: false, description: "Array of documents to search" },
    { name: "text", type: "string", required: false, description: "Text to embed or process" },
    { name: "top_k", type: "number", required: false, description: "Number of top results to return" },
    { name: "similarity_threshold", type: "number", required: false, description: "Minimum similarity threshold" }
  ],

  // Psychology Tool
  psychology: [
    { name: "action", type: "enum[analyze_text,diagnostic_reference,natural_language,platform_info,rag_query,crisis_check,security_assessment,knowledge_base_query,dark_psychology_analysis,manipulation_detection,body_language_analysis,nlp_techniques,emotional_intelligence_assessment,knowledge_base_stats]", required: true, description: "Psychology analysis action" },
    { name: "query", type: "string", required: false, description: "Search query for diagnostic criteria, conditions, or symptoms" },
    { name: "textSamples", type: "array[string]", required: false, description: "Array of text samples for analysis" },
    { name: "command", type: "string", required: false, description: "Natural language command for psychology operations" },
    { name: "mode", type: "enum[support,security_awareness]", required: false, description: "Mode of operation" },
    { name: "application", type: "enum[helping,exploiting,defense,all]", required: false, description: "Application context" }
  ]
};

function updateManifestWithSchemas() {
  const manifestPath = path.join(__dirname, '..', 'tools.manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  
  let updatedCount = 0;
  
  // Update tools that have schemas defined
  Object.keys(criticalToolSchemas).forEach(toolName => {
    const toolIndex = manifest.tools.findIndex(tool => tool.name === toolName);
    if (toolIndex !== -1) {
      const currentTool = manifest.tools[toolIndex];
      if (Array.isArray(currentTool.args) && currentTool.args.length === 0) {
        manifest.tools[toolIndex].args = criticalToolSchemas[toolName];
        console.log(`✅ Updated ${toolName} with ${criticalToolSchemas[toolName].length} parameters`);
        updatedCount++;
      } else {
        console.log(`⚠️  ${toolName} already has args, skipping`);
      }
    } else {
      console.log(`❌ Tool ${toolName} not found in manifest`);
    }
  });
  
  if (updatedCount > 0) {
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
    console.log(`\n✅ Updated ${updatedCount} tools with proper schemas`);
    console.log(`📁 Manifest saved to ${manifestPath}`);
  } else {
    console.log('\n⚠️  No tools were updated');
  }
  
  return updatedCount;
}

if (require.main === module) {
  console.log('🔧 Adding Critical Tool Schemas to Manifest\n');
  updateManifestWithSchemas();
}

module.exports = { criticalToolSchemas, updateManifestWithSchemas };
