# Provider Wizard Tool

## 🔍 **Overview**

The Provider Wizard Tool provides an interactive wizard to set up custom AI service providers by capturing selectors and testing the configuration. This tool enables users to create custom AI service provider configurations.

## ⚠️ **IMPORTANT LEGAL NOTICE**

**This tool is for setting up custom AI service providers. Respect platform terms of service and usage policies.**

### **Legal Guidelines**
- ✅ **Terms of Service**: Respect platform terms of service and usage policies
- ✅ **Legal Compliance**: Compliance with applicable laws and regulations
- ✅ **Ethical Use**: Use only for authorized purposes
- ✅ **Audit Logging**: Complete audit trail of all activities

## 🎯 **Core Features**

### **Provider Setup Wizard**
- **Interactive Setup**: Interactive wizard for provider configuration
- **Selector Capture**: Capture web selectors for provider interfaces
- **Configuration Testing**: Test provider configurations
- **Custom Providers**: Support for custom AI service providers
- **Cross-Platform**: Works on desktop, Android, and iOS platforms

### **Setup Process**
- **URL Configuration**: Configure provider URL and interface
- **Selector Capture**: Capture web selectors for automation
- **Configuration Testing**: Test the provider configuration
- **Validation**: Validate provider setup and functionality

## 🔧 **Tool Parameters**

### **Input Schema**
```json
{
  "startUrl": {
    "type": "string",
    "format": "uri",
    "description": "URL of the AI service chat interface"
  },
  "providerName": {
    "type": "string",
    "description": "Name for the provider (e.g., 'My Custom AI')"
  },
  "platform": {
    "type": "string",
    "enum": ["desktop", "android", "ios"],
    "description": "Target platform for the provider"
  },
  "headless": {
    "type": "boolean",
    "description": "Run browser in headless mode during setup"
  }
}
```

## 📚 **Additional Resources**

- **[Complete Tool Catalog](docs/general/TOOL_CATALOG.md)** - All available tools
- **[Web UI Chat Tool](web_ui_chat.md)** - Main web UI chat tool
- **[Cross-Platform Compatibility](docs/CROSS_PLATFORM_COMPATIBILITY.md)** - Platform support details

---

**⚠️ Legal Disclaimer**: This tool is for setting up custom AI service providers. Respect platform terms of service and usage policies. Users are responsible for ensuring compliance with applicable laws and regulations.