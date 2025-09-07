# 🛠️ MCP God Mode - Modular Tools System

This directory contains individual tool modules that can be easily imported, exported, and combined to create custom MCP servers.

## 📁 Directory Structure

```
tools/
├── core/           # Core system tools (health, system_info)
├── email/          # Email management tools
├── file_system/    # File system operations
├── security/       # Security and penetration testing tools
├── mobile/         # Mobile device tools
├── network/        # Network diagnostics and analysis
├── virtualization/  # VM and Docker management
├── utilities/      # Utility tools (calculator, git, etc.)
└── README.md       # This file
```

## 🚀 Quick Start

### 1. Build a Custom Server

Use the build script to create a custom server with only the tools you need:

```bash
# Build a server with only email tools
node build-server.js health system_info send_email parse_email

# Build a minimal server
node build-server.js health system_info fs_list send_email parse_email

# Build a security-focused server
node build-server.js health system_info wifi_security_toolkit bluetooth_security_toolkit

# Build with custom name and output file
node build-server.js health system_info send_email my-email-server.ts "Email Server"
```

### 2. Use Predefined Configurations

```bash
# Email-only server
npm run build:email-only

# Minimal server
npm run build:minimal

# Core-only server
npm run build:core-only

# Custom configuration
npm run build:custom
```

### 3. Available Tools

#### Core Tools
- `health` - System health check
- `system_info` - System information

#### Email Tools
- `send_email` - Send emails via SMTP
- `parse_email` - Parse email content

#### File System Tools
- `fs_list` - List files and directories

#### Security Tools (Coming Soon)
- `wifi_security_toolkit` - Wi-Fi security testing
- `bluetooth_security_toolkit` - Bluetooth security testing
- `sdr_security_toolkit` - Radio frequency security

#### Mobile Tools (Coming Soon)
- `mobile_device_info` - Mobile device information
- `mobile_file_ops` - Mobile file operations
- `mobile_system_tools` - Mobile system management
- `mobile_hardware` - Mobile hardware access

#### Network Tools (Coming Soon)
- `network_diagnostics` - Network testing
- `packet_sniffer` - Packet capture and analysis

#### Virtualization Tools (Coming Soon)
- `vm_management` - Virtual machine management
- `docker_management` - Docker container management

#### Utility Tools (Coming Soon)
- `calculator` - Mathematical calculations
- `math_calculate` - Advanced math functions
- `git_status` - Git operations
- `web_scraper` - Web scraping
- `browser_control` - Browser automation
- `system_restore` - System backup and restore

## 🔧 Creating Custom Tools

### 1. Create a New Tool Module

```typescript
// tools/my_category/my_tool.ts
import { z } from "zod";
import { PLATFORM } from "../../config/environment.js";

export function registerMyTool(server: any) {
  server.registerTool("my_tool", {
    description: "Description of what this tool does",
    inputSchema: {
      // Define your input parameters
      param1: z.string().describe("Description of parameter 1"),
      param2: z.number().describe("Description of parameter 2")
    },
    outputSchema: {
      // Define your output structure
      success: z.boolean().describe("Whether the operation succeeded"),
      result: z.string().describe("The result of the operation"),
      platform: z.string().describe("Platform where the tool was executed"),
      timestamp: z.string().describe("When the operation was performed")
    }
  }, async ({ param1, param2 }) => {
    try {
      // Your tool logic here
      const result = `Processed ${param1} with value ${param2}`;
      
      return {
        content: [],
        structuredContent: {
          success: true,
          result,
          platform: PLATFORM,
          timestamp: new Date().toISOString()
        }
      };
    } catch (error: any) {
      return {
        content: [],
        structuredContent: {
          success: false,
          result: undefined,
          platform: PLATFORM,
          timestamp: new Date().toISOString()
        }
      };
    }
  });
}
```

### 2. Add to Category Index

```typescript
// tools/my_category/index.ts
export { registerMyTool } from './my_tool.js';
```

### 3. Update Build Script

Add your tool to the `AVAILABLE_TOOLS` object in `build-server.js`:

```javascript
const AVAILABLE_TOOLS = {
  // ... existing tools ...
  my_tool: './tools/my_category/my_tool',
};
```

### 4. Use in Custom Server

```bash
node build-server.js health system_info my_tool
```

## 📊 Server Configurations

### Full Server (server-refactored.ts)
- **Tools**: All 43 tools
- **Use Case**: Complete functionality, development, testing
- **Size**: Large, comprehensive

### Minimal Server (server-minimal.ts)
- **Tools**: Core + essential tools
- **Use Case**: Production deployment, limited functionality
- **Size**: Medium, focused

### Ultra-Minimal Server (server-ultra-minimal.ts)
- **Tools**: Core tools only
- **Use Case**: Embedded systems, resource-constrained environments
- **Size**: Small, lightweight

### Custom Server
- **Tools**: User-selected tools
- **Use Case**: Specific requirements, specialized deployments
- **Size**: Variable, tailored

## 🎯 Best Practices

### 1. Tool Organization
- Group related tools in the same category
- Use descriptive names for tools and functions
- Maintain consistent naming conventions

### 2. Error Handling
- Always wrap tool logic in try-catch blocks
- Return structured error responses
- Include platform and timestamp information

### 3. Input Validation
- Use Zod schemas for input validation
- Provide clear descriptions for all parameters
- Include examples in parameter descriptions

### 4. Output Consistency
- Use consistent output structure across all tools
- Always include `success`, `platform`, and `timestamp` fields
- Provide meaningful error messages

### 5. Documentation
- Document all tool parameters and outputs
- Include usage examples
- Explain platform-specific behavior

## 🔍 Troubleshooting

### Common Issues

1. **Import Errors**
   - Check file paths in imports
   - Ensure TypeScript compilation succeeds
   - Verify module resolution settings

2. **Tool Registration Failures**
   - Check tool function names
   - Verify server parameter types
   - Ensure all dependencies are available

3. **Build Failures**
   - Check tool names in build script
   - Verify tool module exports
   - Check for syntax errors in generated code

### Debug Tips

1. **Check Generated Code**
   - Review the generated custom server
   - Verify import statements
   - Check tool registration calls

2. **Test Individual Tools**
   - Build minimal servers first
   - Test tools one by one
   - Check console output for errors

3. **Verify Dependencies**
   - Ensure all required packages are installed
   - Check TypeScript configuration
   - Verify module resolution settings

## 📚 Examples

### Email-Only Server
```bash
node build-server.js health system_info send_email parse_email email-server.ts "Email Management Server"
```

### Security Testing Server
```bash
node build-server.js health system_info wifi_security_toolkit bluetooth_security_toolkit security-server.ts "Security Testing Server"
```

### Mobile Development Server
```bash
node build-server.js health system_info mobile_device_info mobile_file_ops mobile_system_tools mobile_hardware mobile-server.ts "Mobile Development Server"
```

## 🚀 Next Steps

1. **Extract More Tools**: Continue moving tools from the main server to individual modules
2. **Add New Tools**: Create new tools for specific use cases
3. **Improve Build System**: Add more predefined configurations and validation
4. **Create Tool Templates**: Standardize tool creation with templates
5. **Add Testing**: Create tests for individual tool modules

---

**Happy Tool Building! 🛠️✨**
