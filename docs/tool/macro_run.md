# Macro Run Tool

## 🔍 **Overview**

The Macro Run Tool executes saved macros with optional variable substitution and dry-run capability. This tool enables users to run recorded automation scripts with customizable parameters.

## ⚠️ **IMPORTANT LEGAL NOTICE**

**This tool is for executing automation macros. Respect platform terms of service and usage policies.**

### **Legal Guidelines**
- ✅ **Terms of Service**: Respect platform terms of service and usage policies
- ✅ **Legal Compliance**: Compliance with applicable laws and regulations
- ✅ **Ethical Use**: Use only for authorized purposes
- ✅ **Audit Logging**: Complete audit trail of all activities

## 🎯 **Core Features**

### **Macro Execution**
- **Script Execution**: Execute saved macro scripts
- **Variable Substitution**: Substitute variables in macro scripts
- **Dry-Run Mode**: Test macros without actual execution
- **Cross-Platform**: Works on desktop, Android, and iOS platforms
- **Error Handling**: Comprehensive error handling and reporting

### **Execution Features**
- **Variable Support**: Support for variable substitution in macros
- **Dry-Run Testing**: Test macros without actual execution
- **Execution Logging**: Complete logging of macro execution
- **Error Recovery**: Error recovery and rollback capabilities

## 🔧 **Tool Parameters**

### **Input Schema**
```json
{
  "macroId": {
    "type": "string",
    "description": "ID of the macro to execute"
  },
  "variables": {
    "type": "object",
    "description": "Variables to substitute in the macro"
  },
  "dryRun": {
    "type": "boolean",
    "default": false,
    "description": "Print the planned actions without executing them"
  }
}
```

## 📚 **Additional Resources**

- **[Complete Tool Catalog](docs/general/TOOL_CATALOG.md)** - All available tools
- **[Macro Record Tool](macro_record.md)** - Record automation macros
- **[Cross-Platform Compatibility](docs/CROSS_PLATFORM_COMPATIBILITY.md)** - Platform support details

---

**⚠️ Legal Disclaimer**: This tool is for executing automation macros. Respect platform terms of service and usage policies. Users are responsible for ensuring compliance with applicable laws and regulations.