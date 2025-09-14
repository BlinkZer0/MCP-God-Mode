# Web UI Chat Tool

## 🔍 **Overview**

The Web UI Chat Tool enables chatting with AI services through their web interfaces without APIs. This tool supports streaming responses and session persistence across ChatGPT, Grok, Claude, Hugging Face Chat, and custom providers.

## ⚠️ **IMPORTANT LEGAL NOTICE**

**This tool is for authorized AI service interaction only. Respect platform terms of service and usage policies.**

### **Legal Guidelines**
- ✅ **Terms of Service**: Respect platform terms of service and usage policies
- ✅ **Legal Compliance**: Compliance with applicable laws and regulations
- ✅ **Ethical Use**: Use only for authorized purposes
- ✅ **Audit Logging**: Complete audit trail of all activities

## 🎯 **Core Features**

### **Web UI Chat Capabilities**
- **Multi-Provider Support**: Support for ChatGPT, Grok, Claude, Hugging Face Chat, and custom providers
- **Streaming Responses**: Real-time streaming response support
- **Session Persistence**: Maintain chat sessions across interactions
- **Custom Providers**: Support for custom AI service providers
- **Cross-Platform**: Works on desktop, Android, and iOS platforms

### **Provider Support**
- **ChatGPT**: OpenAI ChatGPT web interface
- **Grok**: x.ai Grok web interface
- **Claude**: Anthropic Claude web interface
- **Hugging Face Chat**: Hugging Face chat interface
- **Custom Providers**: Support for custom AI service providers

## 🔧 **Tool Parameters**

### **Input Schema**
```json
{
  "provider": {
    "type": "string",
    "description": "Provider ID (e.g., 'chatgpt', 'grok', 'claude', 'huggingface', or custom provider)"
  },
  "prompt": {
    "type": "string",
    "description": "The message to send to the AI service"
  },
  "timeoutMs": {
    "type": "number",
    "default": 240000,
    "description": "Timeout in milliseconds"
  },
  "variables": {
    "type": "object",
    "description": "Variables to substitute in provider scripts/macros"
  },
  "platform": {
    "type": "string",
    "enum": ["desktop", "android", "ios"],
    "description": "Target platform (default: from environment)"
  },
  "headless": {
    "type": "boolean",
    "description": "Run browser in headless mode (default: false)"
  }
}
```

## 📚 **Additional Resources**

- **[Complete Tool Catalog](docs/general/TOOL_CATALOG.md)** - All available tools
- **[Legal Compliance Documentation](docs/legal/LEGAL_COMPLIANCE.md)** - Legal compliance guide
- **[Cross-Platform Compatibility](docs/CROSS_PLATFORM_COMPATIBILITY.md)** - Platform support details

---

**⚠️ Legal Disclaimer**: This tool is for authorized AI service interaction only. Respect platform terms of service and usage policies. Users are responsible for ensuring compliance with applicable laws and regulations.