import { z } from "zod";

// Comprehensive natural language patterns for all tools
export const naturalLanguagePatterns = {
  // Security Tools
  'advanced_security_assessment': {
    keywords: ['assess', 'security', 'evaluate', 'check', 'analyze', 'vulnerabilities', 'defenses'],
    examples: ['assess security', 'evaluate system security', 'check vulnerabilities', 'analyze security posture']
  },
  'blockchain_security': {
    keywords: ['blockchain', 'cryptocurrency', 'smart contract', 'defi', 'audit', 'crypto'],
    examples: ['audit smart contract', 'check blockchain security', 'analyze crypto security']
  },
  'cloud_security': {
    keywords: ['cloud', 'aws', 'azure', 'gcp', 'infrastructure', 'cloud security'],
    examples: ['check cloud security', 'audit cloud infrastructure', 'test cloud vulnerabilities']
  },
  'compliance_assessment': {
    keywords: ['compliance', 'regulatory', 'audit', 'standards', 'requirements'],
    examples: ['check compliance', 'assess regulatory compliance', 'audit compliance requirements']
  },
  'exploit_framework': {
    keywords: ['exploit', 'vulnerability', 'penetration', 'attack', 'test exploits'],
    examples: ['test vulnerabilities', 'run penetration tests', 'check for exploits']
  },
  'forensics_analysis': {
    keywords: ['forensics', 'investigation', 'evidence', 'incident', 'digital forensics'],
    examples: ['analyze digital evidence', 'investigate security incident', 'perform forensics']
  },
  'iot_security': {
    keywords: ['iot', 'smart device', 'connected device', 'internet of things'],
    examples: ['test iot security', 'check smart device vulnerabilities', 'assess connected device security']
  },
  'malware_analysis': {
    keywords: ['malware', 'virus', 'trojan', 'suspicious file', 'threat analysis'],
    examples: ['analyze suspicious file', 'check for malware', 'examine malicious software']
  },
  'penetration_testing_toolkit': {
    keywords: ['penetration test', 'pentest', 'security test', 'vulnerability assessment'],
    examples: ['run penetration test', 'perform security assessment', 'test system security']
  },
  'social_engineering': {
    keywords: ['social engineering', 'phishing', 'human factor', 'awareness'],
    examples: ['test social engineering', 'simulate phishing attack', 'assess human vulnerabilities']
  },
  'threat_intelligence': {
    keywords: ['threat intelligence', 'threat analysis', 'intelligence gathering'],
    examples: ['gather threat intelligence', 'analyze security threats', 'monitor threat landscape']
  },
  'vulnerability_assessment': {
    keywords: ['vulnerability', 'security assessment', 'weaknesses', 'security gaps'],
    examples: ['assess vulnerabilities', 'check for security flaws', 'test vulnerability management']
  },
  'vulnerability_scanner': {
    keywords: ['vulnerability scan', 'security scan', 'scan vulnerabilities'],
    examples: ['scan for vulnerabilities', 'check system security', 'test for weaknesses']
  },

  // Network Tools
  'network_diagnostics': {
    keywords: ['network', 'diagnose', 'connectivity', 'troubleshoot', 'ping', 'traceroute'],
    examples: ['diagnose network issues', 'check network connectivity', 'troubleshoot network problems']
  },
  'network_discovery': {
    keywords: ['discover', 'network devices', 'scan network', 'find devices'],
    examples: ['discover network devices', 'scan network topology', 'find network resources']
  },
  'network_security': {
    keywords: ['network security', 'network defenses', 'network vulnerabilities'],
    examples: ['check network security', 'test network defenses', 'assess network vulnerabilities']
  },
  'network_traffic_analyzer': {
    keywords: ['traffic analysis', 'network traffic', 'monitor traffic', 'analyze packets'],
    examples: ['analyze network traffic', 'monitor network communications', 'examine network packets']
  },
  'packet_sniffer': {
    keywords: ['packet capture', 'sniff packets', 'monitor traffic', 'capture packets'],
    examples: ['capture network packets', 'monitor network traffic', 'sniff network communications']
  },
  'port_scanner': {
    keywords: ['port scan', 'scan ports', 'check ports', 'open ports'],
    examples: ['scan network ports', 'check open ports', 'test port connectivity']
  },

  // Wi-Fi Tools
  'wifi_security_toolkit': {
    keywords: ['wifi', 'wireless', 'wifi security', 'wireless security', 'wifi testing', 'wireless testing'],
    examples: ['test wifi security', 'scan wifi networks', 'check wireless security', 'wifi penetration test']
  },
  'wifi_hacking': {
    keywords: ['wifi hack', 'wireless hack', 'wifi attack', 'wireless attack', 'wifi exploit'],
    examples: ['hack wifi network', 'attack wireless network', 'exploit wifi vulnerabilities', 'crack wifi password']
  },
  'wifi_disrupt': {
    keywords: ['wifi disrupt', 'wifi jam', 'wireless disrupt', 'wireless jam', 'wifi interference', 'wireless interference', 'deauth', 'deauthentication', 'wifi flood', 'wireless flood'],
    examples: ['disrupt wifi network', 'jam wireless signal', 'flood deauth packets', 'interfere with wifi', 'knock clients off wifi', 'crash wifi access point']
  },
  'cellular_triangulate': {
    keywords: ['cellular triangulate', 'cell tower triangulation', 'cellular location', 'cell tower location', 'triangulate location', 'cellular positioning', 'tower triangulation', 'cell location'],
    examples: ['triangulate location using cell towers', 'find location with cellular towers', 'locate using cell tower signals', 'cellular positioning system', 'tower-based location']
  },
  'mobile_security_toolkit': {
    keywords: ['mobile security', 'mobile device security', 'mobile testing', 'mobile analysis', 'mobile forensics', 'mobile penetration', 'mobile vulnerability', 'mobile assessment'],
    examples: ['test mobile device security', 'analyze mobile security', 'mobile penetration testing', 'mobile vulnerability assessment', 'mobile forensic analysis']
  },

  // System Tools
  'system_info': {
    keywords: ['system information', 'system details', 'system specs', 'host info'],
    examples: ['get system information', 'check system details', 'view system specs']
  },
  'system_monitor': {
    keywords: ['monitor system', 'system performance', 'system resources', 'system health'],
    examples: ['monitor system performance', 'track system resources', 'watch system activity']
  },
  'system_restore': {
    keywords: ['system restore', 'backup', 'recovery', 'restore point'],
    examples: ['restore system state', 'recover system backup', 'reset system configuration']
  },
  'proc_run': {
    keywords: ['run process', 'execute command', 'start program', 'launch application'],
    examples: ['run system processes', 'execute commands', 'start system programs']
  },
  'docker_management': {
    keywords: ['docker', 'container', 'docker management', 'containerized apps'],
    examples: ['manage docker containers', 'control docker services', 'deploy containerized apps']
  },
  'vm_management': {
    keywords: ['virtual machine', 'vm management', 'virtualization', 'hypervisor'],
    examples: ['manage virtual machines', 'control vm resources', 'deploy virtual machines']
  },

  // File System Tools
  'fs_list': {
    keywords: ['list files', 'directory listing', 'browse files', 'explore directory'],
    examples: ['list files and folders', 'browse directory contents', 'explore file system']
  },
  'fs_read_text': {
    keywords: ['read file', 'view file', 'open file', 'display file content'],
    examples: ['read text file', 'view file contents', 'display file information']
  },
  'fs_write_text': {
    keywords: ['write file', 'create file', 'save file', 'edit file'],
    examples: ['write text file', 'create new file', 'save file content']
  },
  'fs_search': {
    keywords: ['search files', 'find files', 'locate files', 'file search'],
    examples: ['search for files', 'find files by name', 'locate specific files']
  },
  'file_ops': {
    keywords: ['file operations', 'copy files', 'move files', 'file management'],
    examples: ['manage files and folders', 'copy or move files', 'organize file system']
  },
  'file_watcher': {
    keywords: ['watch files', 'monitor files', 'file changes', 'directory monitoring'],
    examples: ['monitor file changes', 'watch file system', 'track file modifications']
  },

  // Mobile Tools
  'mobile_device_info': {
    keywords: ['mobile device', 'device information', 'mobile specs', 'device details'],
    examples: ['get mobile device information', 'check device details', 'view device specs']
  },
  'mobile_hardware': {
    keywords: ['mobile hardware', 'device hardware', 'mobile sensors', 'device features'],
    examples: ['access mobile hardware', 'check device sensors', 'test mobile features']
  },
  'mobile_system_tools': {
    keywords: ['mobile system', 'mobile processes', 'mobile services', 'mobile management'],
    examples: ['manage mobile system', 'control mobile processes', 'monitor mobile services']
  },
  'mobile_file_ops': {
    keywords: ['mobile files', 'mobile file operations', 'mobile storage'],
    examples: ['manage mobile files', 'access mobile storage', 'organize mobile files']
  },

  // Web & Automation Tools
  'web_scraper': {
    keywords: ['scrape web', 'extract web data', 'web scraping', 'harvest data'],
    examples: ['scrape web content', 'extract web data', 'collect web information']
  },
  'browser_control': {
    keywords: ['browser control', 'automate browser', 'web automation', 'browser automation'],
    examples: ['control web browser', 'automate browser actions', 'navigate web pages']
  },
  'web_automation': {
    keywords: ['web automation', 'automate web', 'web tasks', 'web workflows'],
    examples: ['automate web tasks', 'control web applications', 'interact with websites']
  },
  'form_completion': {
    keywords: ['fill forms', 'complete forms', 'form automation', 'submit forms'],
    examples: ['fill out web forms', 'complete online forms', 'submit form data']
  },

  // Media & Content Tools
  'video_editing': {
    keywords: ['edit video', 'video processing', 'video manipulation', 'video effects'],
    examples: ['edit video files', 'process video content', 'modify video recordings']
  },
  'audio_editing': {
    keywords: ['edit audio', 'audio processing', 'audio manipulation', 'audio effects'],
    examples: ['edit audio files', 'process audio content', 'modify audio recordings']
  },
  'image_editing': {
    keywords: ['edit image', 'image processing', 'image manipulation', 'image effects'],
    examples: ['edit images', 'process image files', 'modify image content']
  },
  'ocr_tool': {
    keywords: ['extract text', 'ocr', 'text recognition', 'read text from image'],
    examples: ['extract text from image', 'read text from document', 'recognize handwriting']
  },

  // Utility Tools
  'calculator': {
    keywords: ['calculate', 'math', 'compute', 'solve', 'mathematical'],
    examples: ['calculate mathematical expressions', 'solve math problems', 'perform calculations']
  },
  'math_calculate': {
    keywords: ['advanced math', 'scientific calculation', 'mathematical functions'],
    examples: ['perform advanced calculations', 'use scientific functions', 'solve complex math']
  },
  'dice_rolling': {
    keywords: ['roll dice', 'dice game', 'random dice', 'tabletop game'],
    examples: ['roll dice for games', 'generate random dice results', 'simulate dice rolls']
  },
  'password_generator': {
    keywords: ['generate password', 'create password', 'strong password', 'secure password'],
    examples: ['generate secure passwords', 'create strong passwords', 'generate random passwords']
  },
  'encryption_tool': {
    keywords: ['encrypt', 'decrypt', 'cryptography', 'secure data', 'protect data'],
    examples: ['encrypt or decrypt data', 'secure file contents', 'protect sensitive information']
  },

  // Email Tools
  'send_email': {
    keywords: ['send email', 'email message', 'email communication', 'smtp'],
    examples: ['send email messages', 'deliver email content', 'transmit email communications']
  },
  'read_emails': {
    keywords: ['read email', 'email messages', 'email inbox', 'email access'],
    examples: ['read email messages', 'access email content', 'retrieve email data']
  },
  'delete_emails': {
    keywords: ['delete email', 'remove email', 'clean inbox', 'purge emails'],
    examples: ['delete email messages', 'remove email content', 'clean up email inbox']
  },

  // Data & Analytics Tools
  'data_analysis': {
    keywords: ['analyze data', 'data analysis', 'data insights', 'data processing'],
    examples: ['analyze data patterns', 'process data insights', 'generate data reports']
  },
  'machine_learning': {
    keywords: ['machine learning', 'ml', 'ai', 'train model', 'predict'],
    examples: ['train machine learning model', 'create ml predictions', 'build ml algorithms']
  },
  'chart_generator': {
    keywords: ['create charts', 'generate graphs', 'data visualization', 'charts'],
    examples: ['create charts and graphs', 'generate data visualizations', 'build chart displays']
  },

  // Cloud & Infrastructure Tools
  'cloud_infrastructure_manager': {
    keywords: ['cloud infrastructure', 'cloud management', 'cloud resources', 'cloud services'],
    examples: ['manage cloud infrastructure', 'control cloud resources', 'deploy cloud services']
  },

  // Discovery & Search Tools
  'tool_discovery': {
    keywords: ['discover tools', 'find tools', 'search tools', 'explore tools'],
    examples: ['discover available tools', 'find relevant tools', 'search tool capabilities']
  },
  'explore_categories': {
    keywords: ['explore categories', 'browse categories', 'tool categories', 'category overview'],
    examples: ['explore tool categories', 'browse available tools', 'find relevant tools']
  },

  // SpecOps Tools - Advanced Security Operations
  'metasploit_framework': {
    keywords: ['metasploit', 'exploit framework', 'exploit development', 'payload generation', 'post exploitation', 'msfconsole', 'msfvenom', 'exploit execution', 'penetration testing framework'],
    examples: ['use metasploit framework', 'develop exploits with metasploit', 'generate payloads with msfvenom', 'run metasploit exploits', 'execute post exploitation modules', 'use msfconsole for penetration testing']
  },
  'cobalt_strike': {
    keywords: ['cobalt strike', 'red team', 'threat simulation', 'beacon management', 'lateral movement', 'persistence', 'evasion techniques', 'team server', 'advanced threat simulation'],
    examples: ['use cobalt strike for red team operations', 'simulate advanced threats with cobalt strike', 'manage beacons in cobalt strike', 'perform lateral movement with cobalt strike', 'establish persistence with cobalt strike']
  },
  'empire_powershell': {
    keywords: ['empire powershell', 'powershell post exploitation', 'empire framework', 'powershell agent', 'windows post exploitation', 'powershell modules', 'empire listener', 'powershell stager'],
    examples: ['use empire powershell framework', 'run powershell post exploitation', 'deploy empire agents', 'execute powershell modules with empire', 'create empire listeners', 'generate empire stagers']
  },
  'bloodhound_ad': {
    keywords: ['bloodhound', 'active directory', 'ad attack paths', 'ad enumeration', 'privilege escalation paths', 'lateral movement', 'ad visualization', 'neo4j', 'ad reconnaissance'],
    examples: ['use bloodhound for ad analysis', 'enumerate active directory with bloodhound', 'find ad attack paths', 'analyze privilege escalation with bloodhound', 'visualize ad relationships', 'perform ad reconnaissance with bloodhound']
  },
  'mimikatz_credentials': {
    keywords: ['mimikatz', 'credential extraction', 'lsass dumping', 'credential harvesting', 'ticket manipulation', 'pass the hash', 'golden ticket', 'silver ticket', 'windows credentials'],
    examples: ['extract credentials with mimikatz', 'dump lsass memory with mimikatz', 'harvest windows credentials', 'manipulate kerberos tickets', 'perform pass the hash attacks', 'create golden tickets with mimikatz']
  },
  'mimikatz_enhanced': {
    keywords: ['enhanced mimikatz', 'cross platform mimikatz', 'advanced credential extraction', 'multi platform credentials', 'ios keychain', 'android keystore', 'macos keychain', 'linux keyring', 'evasion techniques'],
    examples: ['use enhanced mimikatz for cross platform credential extraction', 'extract ios keychain credentials', 'harvest android keystore data', 'access macos keychain with mimikatz', 'extract linux keyring credentials', 'perform advanced evasion with mimikatz']
  },
  'nmap_scanner': {
    keywords: ['nmap', 'network scanning', 'port scanning', 'service detection', 'os fingerprinting', 'vulnerability scanning', 'network discovery', 'host discovery', 'network reconnaissance'],
    examples: ['scan network with nmap', 'perform port scanning with nmap', 'detect services with nmap', 'fingerprint operating systems', 'scan for vulnerabilities with nmap', 'discover network hosts with nmap']
  },

  // Mobile & IoT Tools
  'frida_toolkit': {
    keywords: ['frida', 'dynamic instrumentation', 'function hooking', 'memory manipulation', 'api interception', 'runtime patching', 'mobile analysis', 'app analysis', 'dynamic analysis'],
    examples: ['use frida for dynamic analysis', 'hook functions with frida', 'instrument mobile apps with frida', 'patch memory with frida', 'intercept api calls with frida', 'analyze mobile applications with frida']
  },
  'ghidra_reverse_engineering': {
    keywords: ['ghidra', 'reverse engineering', 'binary analysis', 'disassembly', 'decompilation', 'function analysis', 'vulnerability detection', 'malware analysis', 'static analysis'],
    examples: ['analyze binary with ghidra', 'reverse engineer with ghidra', 'disassemble code with ghidra', 'decompile functions with ghidra', 'detect vulnerabilities with ghidra', 'analyze malware with ghidra']
  },

  // Cloud Security Tools
  'pacu_aws_exploitation': {
    keywords: ['pacu', 'aws exploitation', 'aws security testing', 'cloud security', 'aws enumeration', 'privilege escalation', 'data exfiltration', 'aws services', 'cloud infrastructure'],
    examples: ['use pacu for aws exploitation', 'test aws security with pacu', 'enumerate aws services with pacu', 'escalate privileges in aws with pacu', 'exfiltrate data from aws with pacu', 'test cloud security with pacu']
  }
};

// Enhanced natural language routing function
export function routeNaturalLanguageQuery(query: string): {
  suggestedTools: string[];
  confidence: number;
  reasoning: string;
} {
  const queryLower = query.toLowerCase();
  const suggestions: { tool: string; score: number }[] = [];
  
  // Score each tool based on keyword matches
  for (const [toolName, pattern] of Object.entries(naturalLanguagePatterns)) {
    let score = 0;
    
    // Check keyword matches
    for (const keyword of pattern.keywords) {
      if (queryLower.includes(keyword.toLowerCase())) {
        score += 2; // Higher weight for keyword matches
      }
    }
    
    // Check example matches
    for (const example of pattern.examples) {
      if (queryLower.includes(example.toLowerCase())) {
        score += 3; // Even higher weight for example matches
      }
    }
    
    // Check for partial matches
    const queryWords = queryLower.split(/\s+/);
    for (const word of queryWords) {
      if (word.length > 3) { // Only consider words longer than 3 characters
        for (const keyword of pattern.keywords) {
          if (keyword.toLowerCase().includes(word) || word.includes(keyword.toLowerCase())) {
            score += 1; // Lower weight for partial matches
          }
        }
      }
    }
    
    if (score > 0) {
      suggestions.push({ tool: toolName, score });
    }
  }
  
  // Sort by score and return top suggestions
  suggestions.sort((a, b) => b.score - a.score);
  const topSuggestions = suggestions.slice(0, 5).map(s => s.tool);
  
  // Calculate confidence based on top score
  const maxScore = suggestions.length > 0 ? suggestions[0].score : 0;
  const confidence = Math.min(maxScore / 10, 1); // Normalize to 0-1
  
  // Generate reasoning
  let reasoning = '';
  if (suggestions.length > 0) {
    const topTool = suggestions[0];
    reasoning = `Query matches "${topTool}" with score ${topTool.score} based on keyword and example pattern matching.`;
  } else {
    reasoning = 'No specific tool matches found. Consider using tool_discovery for general tool search.';
  }
  
  return {
    suggestedTools: topSuggestions,
    confidence,
    reasoning
  };
}

// Enhanced tool discovery with natural language support
export function enhancedToolDiscovery(query: string, category?: string, capability?: string) {
  const routing = routeNaturalLanguageQuery(query);
  
  // Get comprehensive tool list (this would be expanded with all tools)
  const allTools = [
    // Security Tools
    { name: 'advanced_security_assessment', description: 'Comprehensive security assessment and evaluation', category: 'security', capabilities: ['assessment', 'evaluation', 'security', 'vulnerabilities'] },
    { name: 'blockchain_security', description: 'Blockchain security analysis and vulnerability assessment', category: 'security', capabilities: ['blockchain', 'cryptocurrency', 'security', 'audit'] },
    { name: 'cloud_security', description: 'Cloud infrastructure security assessment', category: 'security', capabilities: ['cloud', 'security', 'infrastructure', 'assessment'] },
    { name: 'compliance_assessment', description: 'Regulatory compliance assessment and audit', category: 'security', capabilities: ['compliance', 'regulatory', 'audit', 'assessment'] },
    { name: 'exploit_framework', description: 'Exploit framework for vulnerability testing', category: 'security', capabilities: ['exploit', 'vulnerability', 'testing', 'framework'] },
    { name: 'forensics_analysis', description: 'Digital forensics and incident response analysis', category: 'security', capabilities: ['forensics', 'investigation', 'evidence', 'incident'] },
    { name: 'iot_security', description: 'Internet of Things security assessment', category: 'security', capabilities: ['iot', 'smart device', 'security', 'assessment'] },
    { name: 'malware_analysis', description: 'Malware analysis and reverse engineering', category: 'security', capabilities: ['malware', 'analysis', 'reverse engineering', 'threat'] },
    { name: 'penetration_testing_toolkit', description: 'Comprehensive penetration testing toolkit', category: 'security', capabilities: ['penetration', 'testing', 'security', 'assessment'] },
    { name: 'social_engineering', description: 'Social engineering awareness and testing', category: 'security', capabilities: ['social engineering', 'phishing', 'human factor', 'awareness'] },
    { name: 'threat_intelligence', description: 'Threat intelligence gathering and analysis', category: 'security', capabilities: ['threat', 'intelligence', 'gathering', 'analysis'] },
    { name: 'vulnerability_assessment', description: 'Vulnerability assessment and management', category: 'security', capabilities: ['vulnerability', 'assessment', 'security', 'testing'] },
    { name: 'vulnerability_scanner', description: 'Automated vulnerability scanning', category: 'security', capabilities: ['vulnerability', 'scanning', 'security', 'assessment'] },
    
    // Network Tools
    { name: 'network_diagnostics', description: 'Network diagnostics and troubleshooting', category: 'network', capabilities: ['network', 'diagnostics', 'troubleshooting', 'connectivity'] },
    { name: 'network_discovery', description: 'Network device discovery and mapping', category: 'network', capabilities: ['network', 'discovery', 'mapping', 'devices'] },
    { name: 'network_security', description: 'Network security assessment and monitoring', category: 'network', capabilities: ['network', 'security', 'monitoring', 'assessment'] },
    { name: 'network_traffic_analyzer', description: 'Network traffic analysis and monitoring', category: 'network', capabilities: ['network', 'traffic', 'analysis', 'monitoring'] },
    { name: 'packet_sniffer', description: 'Packet capture and network traffic analysis', category: 'network', capabilities: ['packet', 'capture', 'traffic', 'analysis'] },
    { name: 'port_scanner', description: 'Network port scanning and service detection', category: 'network', capabilities: ['port', 'scanning', 'service', 'detection'] },
    
    // Wi-Fi Tools
    { name: 'wifi_security_toolkit', description: 'Comprehensive Wi-Fi security and penetration testing toolkit', category: 'wireless', capabilities: ['wifi', 'wireless', 'security', 'penetration', 'testing'] },
    { name: 'wifi_hacking', description: 'Advanced Wi-Fi security penetration testing toolkit', category: 'wireless', capabilities: ['wifi', 'hacking', 'penetration', 'security', 'testing'] },
    { name: 'wifi_disrupt', description: 'Protocol-aware Wi-Fi interference and disruption tool', category: 'wireless', capabilities: ['wifi', 'disrupt', 'jam', 'interference', 'deauth', 'wireless'] },
    { name: 'cellular_triangulate', description: 'Location estimation using cellular tower triangulation', category: 'wireless', capabilities: ['cellular', 'triangulation', 'location', 'positioning', 'cell towers'] },
    { name: 'mobile_security_toolkit', description: 'Comprehensive mobile device security testing and analysis', category: 'mobile', capabilities: ['mobile', 'security', 'testing', 'analysis', 'forensics', 'penetration'] },
    
    // System Tools
    { name: 'system_info', description: 'System information and hardware details', category: 'system', capabilities: ['system', 'information', 'hardware', 'details'] },
    { name: 'system_monitor', description: 'System performance monitoring', category: 'system', capabilities: ['system', 'monitoring', 'performance', 'resources'] },
    { name: 'system_restore', description: 'System restore and backup management', category: 'system', capabilities: ['system', 'restore', 'backup', 'recovery'] },
    { name: 'proc_run', description: 'Process execution and management', category: 'system', capabilities: ['process', 'execution', 'management', 'command'] },
    { name: 'docker_management', description: 'Docker container and image management', category: 'system', capabilities: ['docker', 'container', 'image', 'management'] },
    { name: 'vm_management', description: 'Virtual machine management', category: 'system', capabilities: ['virtual machine', 'vm', 'management', 'virtualization'] },
    
    // File System Tools
    { name: 'fs_list', description: 'File and directory listing', category: 'file_system', capabilities: ['file', 'directory', 'listing', 'exploration'] },
    { name: 'fs_read_text', description: 'Text file reading and display', category: 'file_system', capabilities: ['file', 'reading', 'text', 'display'] },
    { name: 'fs_write_text', description: 'Text file writing and creation', category: 'file_system', capabilities: ['file', 'writing', 'text', 'creation'] },
    { name: 'fs_search', description: 'File search and discovery', category: 'file_system', capabilities: ['file', 'search', 'discovery', 'finding'] },
    { name: 'file_ops', description: 'File operations and management', category: 'file_system', capabilities: ['file', 'operations', 'management', 'copy', 'move'] },
    { name: 'file_watcher', description: 'File system monitoring and watching', category: 'file_system', capabilities: ['file', 'monitoring', 'watching', 'changes'] },
    
    // Mobile Tools
    { name: 'mobile_device_info', description: 'Mobile device information and details', category: 'mobile', capabilities: ['mobile', 'device', 'information', 'details'] },
    { name: 'mobile_hardware', description: 'Mobile hardware access and sensor data', category: 'mobile', capabilities: ['mobile', 'hardware', 'sensors', 'access'] },
    { name: 'mobile_system_tools', description: 'Mobile system management and administration', category: 'mobile', capabilities: ['mobile', 'system', 'management', 'administration'] },
    { name: 'mobile_file_ops', description: 'Mobile file operations and management', category: 'mobile', capabilities: ['mobile', 'file', 'operations', 'management'] },
    
    // Web & Automation Tools
    { name: 'web_scraper', description: 'Web scraping and data extraction', category: 'web', capabilities: ['web', 'scraping', 'extraction', 'data'] },
    { name: 'browser_control', description: 'Browser automation and control', category: 'web', capabilities: ['browser', 'automation', 'control', 'web'] },
    { name: 'web_automation', description: 'Web automation and task management', category: 'web', capabilities: ['web', 'automation', 'tasks', 'management'] },
    { name: 'form_completion', description: 'Web form completion and automation', category: 'web', capabilities: ['form', 'completion', 'automation', 'web'] },
    
    // Media & Content Tools
    { name: 'video_editing', description: 'Video editing and manipulation', category: 'media', capabilities: ['video', 'editing', 'manipulation', 'processing'] },
    { name: 'audio_editing', description: 'Audio editing and manipulation', category: 'media', capabilities: ['audio', 'editing', 'manipulation', 'processing'] },
    { name: 'image_editing', description: 'Image editing and manipulation', category: 'media', capabilities: ['image', 'editing', 'manipulation', 'processing'] },
    { name: 'ocr_tool', description: 'Optical Character Recognition', category: 'media', capabilities: ['ocr', 'text', 'extraction', 'recognition'] },
    
    // Utility Tools
    { name: 'calculator', description: 'Mathematical calculator and computation', category: 'utilities', capabilities: ['math', 'calculation', 'computation', 'scientific'] },
    { name: 'math_calculate', description: 'Advanced mathematical calculations', category: 'utilities', capabilities: ['math', 'advanced', 'calculation', 'scientific'] },
    { name: 'dice_rolling', description: 'Dice rolling and random number generation', category: 'utilities', capabilities: ['dice', 'random', 'gaming', 'probability'] },
    { name: 'password_generator', description: 'Secure password generation', category: 'utilities', capabilities: ['password', 'generation', 'security', 'random'] },
    { name: 'encryption_tool', description: 'Encryption and cryptographic operations', category: 'utilities', capabilities: ['encryption', 'cryptography', 'security', 'hash'] },
    
    // Email Tools
    { name: 'send_email', description: 'Email sending and communication', category: 'email', capabilities: ['email', 'sending', 'communication', 'smtp'] },
    { name: 'read_emails', description: 'Email reading and retrieval', category: 'email', capabilities: ['email', 'reading', 'retrieval', 'imap'] },
    { name: 'delete_emails', description: 'Email deletion and management', category: 'email', capabilities: ['email', 'deletion', 'management', 'cleanup'] },
    
    // Data & Analytics Tools
    { name: 'data_analysis', description: 'Data analysis and statistical processing', category: 'analytics', capabilities: ['data', 'analysis', 'statistical', 'processing'] },
    { name: 'machine_learning', description: 'Machine learning model training and prediction', category: 'analytics', capabilities: ['machine learning', 'ml', 'ai', 'training', 'prediction'] },
    { name: 'chart_generator', description: 'Chart and graph generation', category: 'analytics', capabilities: ['chart', 'graph', 'visualization', 'data'] },
    
    // Cloud & Infrastructure Tools
    { name: 'cloud_infrastructure_manager', description: 'Cloud infrastructure management', category: 'cloud', capabilities: ['cloud', 'infrastructure', 'management', 'resources'] },
    
    // Discovery & Search Tools
    { name: 'tool_discovery', description: 'Tool discovery and exploration', category: 'discovery', capabilities: ['discovery', 'search', 'tools', 'exploration'] },
    { name: 'explore_categories', description: 'Category exploration and browsing', category: 'discovery', capabilities: ['categories', 'browsing', 'exploration', 'overview'] },
    
    // SpecOps Tools - Advanced Security Operations
    { name: 'metasploit_framework', description: 'Advanced Metasploit Framework integration for exploit development and execution', category: 'specops', capabilities: ['metasploit', 'exploit', 'framework', 'payload', 'post exploitation', 'penetration testing'] },
    { name: 'cobalt_strike', description: 'Advanced Cobalt Strike integration for sophisticated threat simulation and red team operations', category: 'specops', capabilities: ['cobalt strike', 'red team', 'threat simulation', 'beacon', 'lateral movement', 'persistence'] },
    { name: 'empire_powershell', description: 'Advanced Empire PowerShell post-exploitation framework integration', category: 'specops', capabilities: ['empire', 'powershell', 'post exploitation', 'agent', 'listener', 'stager'] },
    { name: 'bloodhound_ad', description: 'Advanced BloodHound Active Directory attack path analysis and enumeration tool', category: 'specops', capabilities: ['bloodhound', 'active directory', 'ad', 'attack paths', 'enumeration', 'privilege escalation'] },
    { name: 'mimikatz_credentials', description: 'Advanced Mimikatz credential extraction and manipulation tool for Windows post-exploitation', category: 'specops', capabilities: ['mimikatz', 'credentials', 'extraction', 'lsass', 'tickets', 'pass the hash'] },
    { name: 'mimikatz_enhanced', description: 'Enhanced Mimikatz credential extraction with full cross-platform support', category: 'specops', capabilities: ['mimikatz', 'enhanced', 'cross platform', 'credentials', 'keychain', 'keystore', 'evasion'] },
    { name: 'nmap_scanner', description: 'Advanced Nmap network discovery and security auditing tool with cross-platform support', category: 'specops', capabilities: ['nmap', 'network', 'scanning', 'port scan', 'service detection', 'os fingerprinting'] },
    
    // Mobile & IoT Tools
    { name: 'frida_toolkit', description: 'Advanced Frida dynamic instrumentation toolkit with full cross-platform support', category: 'specops', capabilities: ['frida', 'dynamic instrumentation', 'function hooking', 'memory manipulation', 'api interception', 'mobile analysis'] },
    { name: 'ghidra_reverse_engineering', description: 'Advanced Ghidra reverse engineering framework with full cross-platform support', category: 'specops', capabilities: ['ghidra', 'reverse engineering', 'binary analysis', 'disassembly', 'decompilation', 'vulnerability detection'] },
    
    // Cloud Security Tools
    { name: 'pacu_aws_exploitation', description: 'Advanced Pacu AWS exploitation framework with full cross-platform support', category: 'specops', capabilities: ['pacu', 'aws exploitation', 'cloud security', 'aws enumeration', 'privilege escalation', 'data exfiltration'] }
  ];
  
  // Filter tools based on natural language routing
  let filteredTools = allTools;
  
  if (routing.suggestedTools.length > 0) {
    // Prioritize tools suggested by natural language routing
    const suggestedTools = allTools.filter(tool => routing.suggestedTools.includes(tool.name));
    const otherTools = allTools.filter(tool => !routing.suggestedTools.includes(tool.name));
    filteredTools = [...suggestedTools, ...otherTools];
  }
  
  // Apply additional filters
  if (category) {
    filteredTools = filteredTools.filter(tool => 
      tool.category.toLowerCase().includes(category.toLowerCase())
    );
  }
  
  if (capability) {
    filteredTools = filteredTools.filter(tool => 
      tool.capabilities.some(cap => cap.toLowerCase().includes(capability.toLowerCase()))
    );
  }
  
  return {
    tools: filteredTools,
    total_found: filteredTools.length,
    query: query,
    natural_language_routing: routing,
    suggested_tools: routing.suggestedTools,
    confidence: routing.confidence
  };
}
