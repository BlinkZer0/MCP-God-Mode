# Macro Record Tool

## 🔍 **Overview**

The Macro Record Tool records macros by capturing user actions on a web page or app into a portable JSON script. This tool enables users to create reusable automation scripts for web interactions.

## ⚠️ **IMPORTANT LEGAL NOTICE**

**This tool is for recording automation macros. Respect platform terms of service and usage policies.**

### **Legal Guidelines**
- ✅ **Terms of Service**: Respect platform terms of service and usage policies
- ✅ **Legal Compliance**: Compliance with applicable laws and regulations
- ✅ **Ethical Use**: Use only for authorized purposes
- ✅ **Audit Logging**: Complete audit trail of all activities

## 🎯 **Core Features**

### **Macro Recording**
- **Action Capture**: Capture user actions on web pages and apps
- **Portable Scripts**: Generate portable JSON scripts for automation
- **Cross-Platform**: Works on desktop, Android, and iOS platforms
- **Multiple Scopes**: Support for DOM, driver, and auto recording scopes
- **Reusable Macros**: Create reusable automation scripts

### **Recording Scopes**
- **DOM Recording**: Record web element interactions
- **Driver Recording**: Record mobile app actions
- **Auto Recording**: Automatically choose the best recording scope

## 🔧 **Tool Parameters**

### **Input Schema**
```json
{
  "target": {
    "type": "object",
    "properties": {
      "provider": {
        "type": "string",
        "description": "Provider ID to record against"
      },
      "url": {
        "type": "string",
        "format": "uri",
        "description": "Direct URL to record against"
      }
    },
    "description": "Target for recording (either provider session or raw URL)"
  },
  "scope": {
    "type": "string",
    "enum": ["dom", "driver", "auto"],
    "default": "auto",
    "description": "Recording scope - DOM for web elements, driver for mobile actions, auto to choose best"
  },
  "name": {
    "type": "string",
    "description": "Name for the macro"
  },
  "description": {
    "type": "string",
    "description": "Description of what the macro does"
  },
  "platform": {
    "type": "string",
    "enum": ["desktop", "android", "ios"],
    "description": "Target platform for recording"
  }
}
```

## 📚 **Additional Resources**

- **[Complete Tool Catalog](docs/general/TOOL_CATALOG.md)** - All available tools
- **[Macro Run Tool](macro_run.md)** - Execute recorded macros
- **[Cross-Platform Compatibility](docs/CROSS_PLATFORM_COMPATIBILITY.md)** - Platform support details

---

**⚠️ Legal Disclaimer**: This tool is for recording automation macros. Respect platform terms of service and usage policies. Users are responsible for ensuring compliance with applicable laws and regulations.