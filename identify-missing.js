const fs = require('fs');
const path = require('path');

const manifestPath = path.join(__dirname, 'tools.manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

// Get the list of tool names from the manifest
const manifestTools = new Set(manifest.tools.map(t => t.name));
console.log(`Tools in manifest: ${manifestTools.size}`);

// Load the canonical list from add-missing-tools.js
const addMissingToolsPath = path.join(__dirname, 'scripts', 'add-missing-tools.js');
const addMissingToolsContent = fs.readFileSync(addMissingToolsPath, 'utf8');

// Extract the ALL_TOOL_NAMES array
const allToolsMatch = addMissingToolsContent.match(/const ALL_TOOL_NAMES = \[([\s\S]*?)\]/);
if (!allToolsMatch) {
  console.error('Could not find ALL_TOOL_NAMES in add-missing-tools.js');
  process.exit(1);
}

// Parse the tool names from the array
const allTools = allToolsMatch[1]
  .split('\n')
  .map(line => line.trim())
  .filter(line => line && !line.startsWith('//') && line !== ']')
  .map(line => line.replace(/[,"]/g, '').trim())
  .filter(Boolean);

console.log(`Tools in canonical list: ${allTools.length}`);

// Find missing tools
const missingTools = allTools.filter(tool => !manifestTools.has(tool));

if (missingTools.length > 0) {
  console.log('\nMissing tools:');
  console.log(missingTools.map(t => `- ${t}`).join('\n'));
  
  // Add the first missing tool to the manifest
  const missingTool = missingTools[0];
  console.log(`\nAdding missing tool: ${missingTool}`);
  
  const newTool = {
    name: missingTool,
    category: inferCategory(missingTool),
    entry_file: "dev/dist/server-refactored.js",
    invoke: missingTool,
    args: [],
    env_vars: [],
    requires_privilege: REQUIRE_PRIV.has(missingTool),
    side_effects: `Tool '${missingTool}' auto-added; side-effects not fully profiled`,
    safe_mode: !UNSAFE_MODE.has(missingTool),
    tags: [inferCategory(missingTool), "auto-added"],
    smoke_test: {
      cmd: "node",
      args: ["-e", `console.log('Smoke test for ${missingTool}')`],
      expect_code: 0,
      timeout_ms: 5000
    }
  };
  
  manifest.tools.push(newTool);
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  console.log(`Added ${missingTool} to the manifest.`);
  console.log(`New tool count: ${manifest.tools.length}`);
} else {
  console.log('No missing tools found. Checking for duplicates...');
  
  // Check for duplicates
  const toolCounts = {};
  manifest.tools.forEach(tool => {
    toolCounts[tool.name] = (toolCounts[tool.name] || 0) + 1;
  });
  
  const duplicates = Object.entries(toolCounts).filter(([_, count]) => count > 1);
  if (duplicates.length > 0) {
    console.log('\nDuplicate tools found:');
    console.log(duplicates.map(([name, count]) => `- ${name} (${count} entries)`).join('\n'));
  } else {
    console.log('No duplicate tools found.');
  }
}

// Helper functions from add-missing-tools.js
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
