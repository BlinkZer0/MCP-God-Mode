# Crime Reporter Unified Tool

## 🔍 **Overview**

The Crime Reporter Unified Tool is a comprehensive crime reporting system that consolidates all crime reporting functionality into a single, powerful tool. It provides jurisdiction resolution, case preparation, automated filing, natural language processing, and configuration testing with privacy protection, audit logging, and legal compliance features.

## ⚠️ **IMPORTANT LEGAL NOTICE**

**This tool is for authorized crime reporting only. False reporting is illegal and unethical.**

### **Legal Guidelines**
- ✅ **Authorization Required**: Explicit permission required for all reporting
- ✅ **Legal Compliance**: Compliance with applicable laws and regulations
- ✅ **Privacy Protection**: Built-in privacy protection and data minimization
- ✅ **Audit Logging**: Complete audit trail of all actions

## 🎯 **Core Features**

### **Unified Crime Reporting**
- **Jurisdiction Resolution**: Multi-source discovery and scoring
- **Case Preparation**: Normalization, redaction, and rendering
- **Automated Filing**: Puppeteer and email submission systems
- **Natural Language Processing**: Intuitive conversational interface
- **Configuration Testing**: Safe testing without actual submission

### **Legal Safeguards**
- **Privacy Protection**: Built-in privacy protection and data minimization
- **Audit Logging**: Complete audit trail of all actions
- **Evidence Preservation**: Chain of custody for all evidence and artifacts
- **False Report Warnings**: Clear warnings about perjury and false reporting laws

## 🔧 **Tool Parameters**

### **Input Schema**
```json
{
  "mode": {
    "type": "string",
    "enum": ["command", "natural_language", "test"],
    "description": "Operation mode: 'command' for structured commands, 'natural_language' for conversational interface, 'test' for configuration testing"
  },
  "command": {
    "type": "string",
    "description": "Crime reporter command: searchJurisdiction, prepareReport, fileReport, previewReport, getStatus, exportCase, testConfiguration"
  },
  "parameters": {
    "type": "object",
    "description": "Command parameters"
  },
  "naturalLanguageCommand": {
    "type": "string",
    "description": "Natural language command for crime reporting (e.g., 'Report a theft in Minneapolis with these photos, anonymously')"
  }
}
```

## 📚 **Additional Resources**

- **[Complete Tool Catalog](docs/general/TOOL_CATALOG.md)** - All available tools
- **[Legal Compliance Documentation](docs/legal/LEGAL_COMPLIANCE.md)** - Legal compliance guide
- **[Cross-Platform Compatibility](docs/CROSS_PLATFORM_COMPATIBILITY.md)** - Platform support details

---

**⚠️ Legal Disclaimer**: This tool is for authorized crime reporting only. False reporting is illegal and unethical. Users are responsible for ensuring compliance with applicable laws and regulations. All reporting must be conducted with proper authorization and in accordance with legal requirements.
