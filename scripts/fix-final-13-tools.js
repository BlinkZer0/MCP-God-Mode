#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Define schemas for the final 13 remaining tools
const finalToolSchemas = {
  // Web Tools
  webhook_manager: [
    { name: "action", type: "enum[create,list,delete,update,test,trigger]", required: true, description: "Webhook management action" },
    { name: "webhook_id", type: "string", required: false, description: "Webhook identifier" },
    { name: "url", type: "string", required: false, description: "Webhook URL endpoint" },
    { name: "method", type: "enum[GET,POST,PUT,DELETE,PATCH]", required: false, description: "HTTP method" },
    { name: "headers", type: "object", required: false, description: "HTTP headers" },
    { name: "payload", type: "object", required: false, description: "Webhook payload data" }
  ],

  form_detection: [
    { name: "url", type: "string", required: true, description: "URL of the page containing the form" },
    { name: "form_selector", type: "string", required: false, description: "CSS selector for specific form" },
    { name: "save_screenshot", type: "boolean", required: false, description: "Save screenshot of the form" },
    { name: "timeout", type: "number", required: false, description: "Timeout in milliseconds" }
  ],

  form_validation: [
    { name: "form_data", type: "object", required: true, description: "Form data to validate" },
    { name: "validation_rules", type: "object", required: false, description: "Custom validation rules for specific fields" },
    { name: "strict_mode", type: "boolean", required: false, description: "Use strict validation mode" }
  ],

  form_pattern_recognition: [
    { name: "url", type: "string", required: true, description: "URL of the page containing the form" },
    { name: "form_selector", type: "string", required: false, description: "CSS selector for specific form" },
    { name: "timeout", type: "number", required: false, description: "Timeout in milliseconds" }
  ],

  web_automation: [
    { name: "action", type: "enum[navigate,click,type,screenshot,extract,wait,scroll,execute_script,form_fill,get_elements]", required: true, description: "Web automation action to perform" },
    { name: "url", type: "string", required: false, description: "Target URL for web automation operations" },
    { name: "selector", type: "string", required: false, description: "CSS selector, XPath, or element identifier" },
    { name: "text", type: "string", required: false, description: "Text content to input into form fields" },
    { name: "browser", type: "enum[chrome,firefox,edge,auto]", required: false, description: "Browser engine to use" },
    { name: "headless", type: "boolean", required: false, description: "Run browser in headless mode" },
    { name: "wait_time", type: "number", required: false, description: "Wait duration in milliseconds" },
    { name: "output_file", type: "string", required: false, description: "File path for saving screenshots or data" },
    { name: "form_data", type: "object", required: false, description: "Key-value pairs for form field data" }
  ],

  // Mobile Tools
  mobile_app_unified: [
    { name: "action", type: "enum[install,uninstall,launch,close,analyze,test,debug,profile]", required: true, description: "Mobile app management action" },
    { name: "app_package", type: "string", required: false, description: "Application package name" },
    { name: "device_id", type: "string", required: false, description: "Target device identifier" },
    { name: "platform", type: "enum[android,ios]", required: false, description: "Mobile platform" },
    { name: "test_type", type: "enum[functional,performance,security,compatibility]", required: false, description: "Type of testing to perform" },
    { name: "output_path", type: "string", required: false, description: "Output path for results" }
  ],

  // Hardware Tools
  flipper_zero: [
    { name: "action", type: "enum[scan,transmit,receive,analyze,record,replay]", required: true, description: "Flipper Zero action to perform" },
    { name: "protocol", type: "enum[rfid,nfc,infrared,bluetooth,wifi,gpio,uart,spi,i2c]", required: false, description: "Communication protocol" },
    { name: "frequency", type: "number", required: false, description: "Frequency in Hz" },
    { name: "data", type: "string", required: false, description: "Data to transmit or analyze" },
    { name: "duration", type: "number", required: false, description: "Operation duration in seconds" },
    { name: "output_file", type: "string", required: false, description: "Output file for captured data" }
  ],

  // Security Tools
  cobalt_strike: [
    { name: "action", type: "enum[generate_payload,start_listener,deploy_beacon,execute_command,lateral_movement,persistence]", required: true, description: "Cobalt Strike action to perform" },
    { name: "target", type: "string", required: false, description: "Target system or IP address" },
    { name: "payload_type", type: "enum[exe,dll,powershell,hta,macro]", required: false, description: "Payload type to generate" },
    { name: "listener_port", type: "number", required: false, description: "Listener port number" },
    { name: "command", type: "string", required: false, description: "Command to execute on target" },
    { name: "output_path", type: "string", required: false, description: "Output path for generated payloads" }
  ],

  empire_powershell: [
    { name: "action", type: "enum[create_listener,generate_stager,execute_module,manage_agent,post_exploitation]", required: true, description: "Empire PowerShell action" },
    { name: "listener_name", type: "string", required: false, description: "Listener name" },
    { name: "stager_type", type: "enum[launcher,macro,ducky,hop]", required: false, description: "Stager type" },
    { name: "module_name", type: "string", required: false, description: "PowerShell module to execute" },
    { name: "agent_name", type: "string", required: false, description: "Agent identifier" },
    { name: "parameters", type: "object", required: false, description: "Module parameters" }
  ],

  // AI Tools
  hexstrike_ai: [
    { name: "action", type: "enum[analyze_target,generate_exploit,test_payload,automated_attack,report_generation]", required: true, description: "HexStrike AI action" },
    { name: "target", type: "string", required: false, description: "Target system or application" },
    { name: "attack_vector", type: "enum[web,network,social,physical]", required: false, description: "Attack vector to use" },
    { name: "payload_type", type: "string", required: false, description: "Type of payload to generate" },
    { name: "automation_level", type: "enum[manual,semi_auto,full_auto]", required: false, description: "Level of automation" },
    { name: "output_format", type: "enum[json,html,pdf]", required: false, description: "Output format for reports" }
  ],

  hexstrike_ai_natural_language: [
    { name: "command", type: "string", required: true, description: "Natural language command for HexStrike AI operations" },
    { name: "context", type: "string", required: false, description: "Additional context for the command" },
    { name: "target_info", type: "object", required: false, description: "Target system information" }
  ],

  // Test/Example Tools
  competitive_intelligence_test: [
    { name: "test_type", type: "enum[unit,integration,performance,security]", required: true, description: "Type of test to run" },
    { name: "target_company", type: "string", required: false, description: "Company to test intelligence gathering on" },
    { name: "test_data", type: "object", required: false, description: "Test data parameters" },
    { name: "expected_results", type: "object", required: false, description: "Expected test results" }
  ],

  example_tool: [
    { name: "action", type: "enum[demo,test,validate,benchmark]", required: true, description: "Example tool action" },
    { name: "input_data", type: "string", required: false, description: "Input data for the example" },
    { name: "parameters", type: "object", required: false, description: "Example parameters" },
    { name: "output_format", type: "enum[json,text,xml]", required: false, description: "Output format" }
  ]
};

function updateFinalTools() {
  const manifestPath = path.join(__dirname, '..', 'tools.manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  
  let updatedCount = 0;
  let notFoundCount = 0;
  let alreadyHasArgsCount = 0;
  
  console.log('🎯 Fixing the final 13 tools with missing schemas...\n');
  
  // Update tools that have schemas defined
  Object.keys(finalToolSchemas).forEach(toolName => {
    const toolIndex = manifest.tools.findIndex(tool => tool.name === toolName);
    if (toolIndex !== -1) {
      const currentTool = manifest.tools[toolIndex];
      if (Array.isArray(currentTool.args) && currentTool.args.length === 0) {
        manifest.tools[toolIndex].args = finalToolSchemas[toolName];
        console.log(`✅ Updated ${toolName} with ${finalToolSchemas[toolName].length} parameters`);
        updatedCount++;
      } else {
        console.log(`⚠️  ${toolName} already has ${currentTool.args.length} parameters, skipping`);
        alreadyHasArgsCount++;
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
  
  // Final verification
  const updatedManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const remainingEmpty = updatedManifest.tools.filter(t => Array.isArray(t.args) && t.args.length === 0);
  
  console.log('\n📊 Final Status:');
  console.log(`   - Tools updated: ${updatedCount}`);
  console.log(`   - Tools already had args: ${alreadyHasArgsCount}`);
  console.log(`   - Tools not found: ${notFoundCount}`);
  console.log(`   - Remaining empty: ${remainingEmpty.length}`);
  console.log(`   - Total tools with schemas: ${updatedManifest.tools.length - remainingEmpty.length}/${updatedManifest.tools.length}`);
  
  if (remainingEmpty.length > 0) {
    console.log('\n🔍 Still missing schemas:');
    remainingEmpty.forEach(t => console.log(`   - ${t.name} (${t.category})`));
  } else {
    console.log('\n🎉 ALL TOOLS NOW HAVE PROPER SCHEMAS!');
  }
  
  return { updatedCount, notFoundCount, alreadyHasArgsCount, remainingEmpty: remainingEmpty.length };
}

if (require.main === module) {
  console.log('🚀 Final Push: Completing All Tool Schemas\n');
  updateFinalTools();
}

module.exports = { finalToolSchemas, updateFinalTools };
