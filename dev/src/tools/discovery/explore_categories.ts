import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export function registerExploreCategories(server: McpServer) {
  server.registerTool("explore_categories", {
    description: "Explore all available tool categories and their capabilities",
    inputSchema: {
      category: z.string().optional().describe("Specific category to explore, or leave empty to see all categories")
    },
    outputSchema: {
      categories: z.array(z.object({
        name: z.string(),
        description: z.string(),
        tool_count: z.number(),
        tools: z.array(z.object({
          name: z.string(),
          description: z.string(),
          capabilities: z.array(z.string())
        }))
      })),
      total_categories: z.number(),
      total_tools: z.number()
    }
  }, async ({ category }) => {
    const allCategories = [
      {
        name: "Core System",
        description: "Essential system tools for basic operations and information",
        tool_count: 2,
        tools: [
          {
            name: "health",
            description: "Liveness/readiness probe",
            capabilities: ["system", "monitoring", "health check"]
          },
          {
            name: "system_info",
            description: "Basic host info (OS, arch, cpus, memGB)",
            capabilities: ["system", "hardware", "information"]
          }
        ]
      },
      {
        name: "File System",
        description: "Advanced file operations, search, and management tools",
        tool_count: 5,
        tools: [
          {
            name: "fs_list",
            description: "List files/directories under a relative path",
            capabilities: ["file", "directory", "listing", "exploration"]
          },
          {
            name: "fs_read_text",
            description: "Read a UTF-8 text file within the sandbox",
            capabilities: ["file", "reading", "text", "content"]
          },
          {
            name: "fs_write_text",
            description: "Write a UTF-8 text file within the sandbox",
            capabilities: ["file", "writing", "text", "content"]
          },
          {
            name: "fs_search",
            description: "Search for files by name pattern",
            capabilities: ["file", "search", "pattern", "matching"]
          },
          {
            name: "file_ops",
            description: "Advanced cross-platform file operations",
            capabilities: ["file", "operations", "copy", "move", "delete", "compress"]
          }
        ]
      },
      {
        name: "Process & Git",
        description: "Process execution, management, and Git operations",
        tool_count: 3,
        tools: [
          {
            name: "proc_run",
            description: "Run a process with arguments",
            capabilities: ["process", "execution", "command", "system"]
          },
          {
            name: "proc_run_elevated",
            description: "Run a process with elevated privileges",
            capabilities: ["process", "elevated", "privileges", "admin", "root"]
          },
          {
            name: "git_status",
            description: "Get git status for a repository",
            capabilities: ["git", "version", "control", "repository", "status"]
          }
        ]
      },
      {
        name: "Network & Security",
        description: "Network diagnostics, security testing, and penetration testing",
        tool_count: 4,
        tools: [
          {
            name: "network_diagnostics",
            description: "Cross-platform network diagnostics and connectivity testing",
            capabilities: ["network", "diagnostics", "ping", "traceroute", "dns"]
          },
          {
            name: "packet_sniffer",
            description: "Advanced cross-platform packet sniffing and network traffic analysis",
            capabilities: ["packet", "sniffing", "network", "traffic", "analysis"]
          },
          {
            name: "port_scanner",
            description: "Cross-platform port scanning tool for network reconnaissance",
            capabilities: ["port", "scanning", "network", "reconnaissance", "security"]
          },
          {
            name: "download_file",
            description: "Download a file from URL",
            capabilities: ["download", "file", "url", "http", "https"]
          }
        ]
      },
      {
        name: "Wireless & Radio",
        description: "Wi-Fi, Bluetooth, and Software Defined Radio security testing",
        tool_count: 3,
        tools: [
          {
            name: "wifi_security_toolkit",
            description: "Comprehensive Wi-Fi security and penetration testing toolkit",
            capabilities: ["wifi", "security", "penetration", "testing", "wireless"]
          },
          {
            name: "bluetooth_security_toolkit",
            description: "Comprehensive Bluetooth security and penetration testing toolkit",
            capabilities: ["bluetooth", "security", "penetration", "testing", "wireless"]
          },
          {
            name: "sdr_security_toolkit",
            description: "Comprehensive Software Defined Radio security and signal analysis toolkit",
            capabilities: ["radio", "sdr", "security", "signal", "analysis", "frequency"]
          }
        ]
      },
      {
        name: "Security Testing",
        description: "Vulnerability scanning, password cracking, and exploit framework",
        tool_count: 11,
        tools: [
          {
            name: "vulnerability_scanner",
            description: "Cross-platform vulnerability scanner for security assessment",
            capabilities: ["vulnerability", "scanning", "security", "assessment", "testing"]
          },
          {
            name: "password_cracker",
            description: "Cross-platform password cracking tool for testing authentication security",
            capabilities: ["password", "cracking", "authentication", "security", "testing"]
          },
          {
            name: "exploit_framework",
            description: "Cross-platform exploit framework for testing known vulnerabilities",
            capabilities: ["exploit", "framework", "vulnerability", "testing", "security"]
          },
          {
            name: "hack_network",
            description: "Comprehensive network penetration testing and security assessment",
            capabilities: ["network", "penetration", "testing", "security", "assessment"]
          },
          {
            name: "security_testing",
            description: "Advanced multi-domain security testing and vulnerability assessment",
            capabilities: ["security", "testing", "vulnerability", "assessment", "multi-domain"]
          },
          {
            name: "blockchain_security",
            description: "Blockchain security analysis and vulnerability assessment tools",
            capabilities: ["blockchain", "cryptocurrency", "security", "analysis", "vulnerability"]
          },
          {
            name: "quantum_security",
            description: "Quantum-resistant cryptography and post-quantum security tools",
            capabilities: ["quantum", "cryptography", "post-quantum", "security", "resistant"]
          },
          {
            name: "iot_security",
            description: "Internet of Things security assessment and protection tools",
            capabilities: ["iot", "internet of things", "security", "assessment", "protection"]
          },
          {
            name: "social_engineering",
            description: "Social engineering awareness and testing tools",
            capabilities: ["social", "engineering", "human", "factor", "testing", "awareness"]
          },
          {
            name: "threat_intelligence",
            description: "Threat intelligence gathering and analysis tools",
            capabilities: ["threat", "intelligence", "gathering", "analysis", "correlation"]
          },
          {
            name: "compliance_assessment",
            description: "Compliance assessment and regulatory compliance tools",
            capabilities: ["compliance", "regulatory", "assessment", "audit", "standards"]
          }
        ]
      },
      {
        name: "Email Management",
        description: "SMTP, IMAP, email security, and account management",
        tool_count: 6,
        tools: [
          {
            name: "send_email",
            description: "Send emails using SMTP across all platforms",
            capabilities: ["email", "smtp", "communication", "messaging"]
          },
          {
            name: "read_emails",
            description: "Read emails from IMAP servers across all platforms",
            capabilities: ["email", "imap", "reading", "retrieval", "communication"]
          },
          {
            name: "parse_email",
            description: "Parse and analyze email content across all platforms",
            capabilities: ["email", "parsing", "analysis", "content", "extraction"]
          },
          {
            name: "delete_emails",
            description: "Delete emails from IMAP servers across all platforms",
            capabilities: ["email", "imap", "deletion", "management", "cleanup"]
          },
          {
            name: "sort_emails",
            description: "Sort and organize emails from IMAP servers",
            capabilities: ["email", "organization", "sorting", "filtering", "management"]
          },
          {
            name: "manage_email_accounts",
            description: "Manage multiple email accounts across all platforms",
            capabilities: ["email", "accounts", "management", "configuration", "multi-account"]
          }
        ]
      },
      {
        name: "Media & Content",
        description: "Audio, video, image processing, OCR, and screenshots",
        tool_count: 5,
        tools: [
          {
            name: "video_editing",
            description: "Advanced video editing and manipulation tool",
            capabilities: ["video", "editing", "processing", "conversion", "effects"]
          },
          {
            name: "ocr_tool",
            description: "Optical Character Recognition tool for extracting text from images",
            capabilities: ["ocr", "text", "extraction", "image", "recognition"]
          },
          {
            name: "audio_editing",
            description: "Cross-platform audio recording, editing, and processing tool",
            capabilities: ["audio", "recording", "editing", "processing", "conversion"]
          },
          {
            name: "image_editing",
            description: "Cross-platform image editing, enhancement, and processing tool",
            capabilities: ["image", "editing", "enhancement", "processing", "manipulation"]
          },
          {
            name: "screenshot",
            description: "Cross-platform screenshot capture and management tool",
            capabilities: ["screenshot", "capture", "screen", "image", "recording"]
          }
        ]
      },
      {
        name: "Web & Browser",
        description: "Browser automation and web scraping tools",
        tool_count: 2,
        tools: [
          {
            name: "web_scraper",
            description: "Advanced web scraping tool with CSS selector support",
            capabilities: ["web", "scraping", "extraction", "data", "content"]
          },
          {
            name: "browser_control",
            description: "Cross-platform browser automation and control tool",
            capabilities: ["browser", "automation", "control", "web", "testing"]
          }
        ]
      },
      {
        name: "Mobile Device",
        description: "Mobile device management, file operations, and hardware access",
        tool_count: 4,
        tools: [
          {
            name: "mobile_device_info",
            description: "Get comprehensive mobile device information",
            capabilities: ["mobile", "device", "information", "hardware", "software"]
          },
          {
            name: "mobile_file_ops",
            description: "Advanced mobile file operations with comprehensive Android and iOS support",
            capabilities: ["mobile", "file", "operations", "android", "ios"]
          },
          {
            name: "mobile_system_tools",
            description: "Comprehensive mobile system management and administration tools",
            capabilities: ["mobile", "system", "management", "administration", "tools"]
          },
          {
            name: "mobile_hardware",
            description: "Advanced mobile hardware access and sensor data collection",
            capabilities: ["mobile", "hardware", "sensors", "camera", "gps", "biometrics"]
          }
        ]
      },
      {
        name: "Virtualization & Containers",
        description: "Virtual machine management and Docker container orchestration",
        tool_count: 2,
        tools: [
          {
            name: "vm_management",
            description: "Cross-platform virtual machine management",
            capabilities: ["vm", "virtualization", "management", "hypervisor"]
          },
          {
            name: "docker_management",
            description: "Cross-platform Docker container and image management",
            capabilities: ["docker", "container", "image", "management", "orchestration"]
          }
        ]
      },
      {
        name: "Utilities",
        description: "Mathematical tools, encryption, data analysis, and random generation",
        tool_count: 4,
        tools: [
          {
            name: "calculator",
            description: "Advanced mathematical calculator with scientific functions",
            capabilities: ["math", "calculation", "scientific", "functions"]
          },
          {
            name: "dice_rolling",
            description: "Roll dice with various configurations and get random numbers",
            capabilities: ["random", "dice", "gaming", "probability"]
          },
          {
            name: "math_calculate",
            description: "Advanced mathematical calculator with scientific functions",
            capabilities: ["math", "calculation", "scientific", "advanced"]
          },
          {
            name: "encryption_tool",
            description: "Advanced encryption and cryptographic operations",
            capabilities: ["encryption", "cryptography", "security", "hash", "sign"]
          }
        ]
      },
      {
        name: "System & Forensics",
        description: "System restore, elevated permissions, and digital forensics",
        tool_count: 3,
        tools: [
          {
            name: "system_restore",
            description: "Cross-platform system restore points and backup management",
            capabilities: ["system", "restore", "backup", "recovery", "management"]
          },
          {
            name: "elevated_permissions_manager",
            description: "Manage and control elevated permissions across platforms",
            capabilities: ["permissions", "elevated", "privileges", "management", "security"]
          },
          {
            name: "forensics_analysis",
            description: "Digital forensics and incident response analysis tools",
            capabilities: ["forensics", "digital", "incident", "response", "analysis", "evidence"]
          }
        ]
      },
      {
        name: "Windows Services",
        description: "Windows-specific system administration tools",
        tool_count: 2,
        tools: [
          {
            name: "win_services",
            description: "List system services (cross-platform: Windows services, Linux systemd, macOS launchd)",
            capabilities: ["windows", "services", "systemd", "launchd", "administration"]
          },
          {
            name: "win_processes",
            description: "List system processes (cross-platform: Windows, Linux, macOS)",
            capabilities: ["windows", "processes", "system", "monitoring", "administration"]
          }
        ]
      },
      {
        name: "Tool Discovery",
        description: "Natural language search and category exploration tools",
        tool_count: 2,
        tools: [
          {
            name: "tool_discovery",
            description: "Discover and explore all available tools using natural language queries",
            capabilities: ["discovery", "search", "natural language", "tools", "exploration"]
          },
          {
            name: "explore_categories",
            description: "Explore all available tool categories and their capabilities",
            capabilities: ["categories", "browsing", "organization", "tools", "overview"]
          }
        ]
      }
    ];

    let filteredCategories = allCategories;
    if (category) {
      filteredCategories = allCategories.filter(cat => 
        cat.name.toLowerCase().includes(category.toLowerCase())
      );
    }

    const totalTools = filteredCategories.reduce((sum, cat) => sum + cat.tool_count, 0);

    return {
      content: [],
      structuredContent: {
        categories: filteredCategories,
        total_categories: filteredCategories.length,
        total_tools: totalTools
      }
    };
  });
}
