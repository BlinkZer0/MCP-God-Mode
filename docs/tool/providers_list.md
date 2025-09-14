# Providers List Tool

## 🔍 **Overview**

The Providers List Tool lists all available AI service providers and their capabilities, with platform-specific filtering. This tool provides comprehensive information about supported AI service providers.

## ⚠️ **IMPORTANT LEGAL NOTICE**

**This tool provides information about AI service providers. Respect platform terms of service and usage policies.**

### **Legal Guidelines**
- ✅ **Terms of Service**: Respect platform terms of service and usage policies
- ✅ **Legal Compliance**: Compliance with applicable laws and regulations
- ✅ **Ethical Use**: Use only for authorized purposes
- ✅ **Audit Logging**: Complete audit trail of all activities

## 🎯 **Core Features**

### **Provider Information**
- **Provider Listing**: List all available AI service providers
- **Capability Information**: Detailed capability information for each provider
- **Platform Filtering**: Filter providers by platform support
- **Feature Support**: Information about supported features and capabilities
- **Configuration Info**: Provider-specific configuration information

### **Supported Platforms**
- **Desktop**: Windows, Linux, macOS support
- **Mobile**: Android, iOS support
- **Web**: Web-based provider support

## 🔧 **Tool Parameters**

### **Input Schema**
```json
{
  "platform": {
    "type": "string",
    "enum": ["desktop", "android", "ios"],
    "description": "Filter providers by platform"
  }
}
```

## 📚 **Additional Resources**

- **[Complete Tool Catalog](docs/general/TOOL_CATALOG.md)** - All available tools
- **[Web UI Chat Tool](web_ui_chat.md)** - Main web UI chat tool
- **[Cross-Platform Compatibility](docs/CROSS_PLATFORM_COMPATIBILITY.md)** - Platform support details

---

**⚠️ Legal Disclaimer**: This tool provides information about AI service providers. Respect platform terms of service and usage policies. Users are responsible for ensuring compliance with applicable laws and regulations.