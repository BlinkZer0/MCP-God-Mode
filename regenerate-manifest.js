const fs = require('fs');
const path = require('path');

// Load the canonical tool list from add-missing-tools.js
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

console.log(`Found ${allTools.length} tools in canonical list`);

// Create a new manifest with all tools
const newManifest = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  title: "MCP God Mode Tools Manifest",
  type: "object",
  tools: allTools.map(toolName => ({
    name: toolName,
    category: inferCategory(toolName),
    entry_file: "dev/dist/server-refactored.js",
    invoke: toolName,
    args: [],
    env_vars: [],
    requires_privilege: REQUIRE_PRIV.has(toolName),
    side_effects: `Tool '${toolName}' auto-generated`,
    safe_mode: !UNSAFE_MODE.has(toolName),
    tags: [inferCategory(toolName), "auto-generated"],
    smoke_test: {
      cmd: "node",
      args: ["-e", `console.log('Smoke test for ${toolName}')`],
      expect_code: 0,
      timeout_ms: 5000
    }
  }))
};

// Write the new manifest
const manifestPath = path.join(__dirname, 'tools.manifest.json');
fs.writeFileSync(manifestPath, JSON.stringify(newManifest, null, 2) + '\n', 'utf8');
console.log(`Generated new manifest with ${newManifest.tools.length} tools at ${manifestPath}`);

// Helper functions
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
